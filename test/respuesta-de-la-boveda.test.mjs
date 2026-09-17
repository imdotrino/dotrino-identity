/**
 * LO QUE CONTESTA LA BÓVEDA AL ENROLARSE O AL RENOVAR (`checkVaultReply`).
 *
 * Hasta 0.92.0 cada cliente comparaba `acta.profileId` con la llave de la bóveda. Eso solo
 * es cierto en una cuenta que nació en esa bóveda: con una SEGUNDA bóveda (multivault) o con
 * una que ADOPTÓ la cuenta, la llave de la bóveda no es la del génesis y ningún aparato podía
 * entrar por ella —«the record is from a profile other than the one you saw»—. Lo destapó el
 * smoke `dos-bovedas` (dotrino-test), que llevaba desde el 2026-08-31 en 3/4.
 *
 * Y la comparación tampoco protegía: el acta no se verificaba, así que bastaba con escribir
 * ese `profileId` en una inventada. Estas pruebas fijan las dos mitades.
 */
import test from 'node:test'
import assert from 'node:assert/strict'
import { genesisActa, applyChanges, sealActa, checkVaultReply } from '../vault/acta.js'
import { makeDeviceKey, signDelegationWith } from '../vault/capabilities.js'

const ECDSA = { name: 'ECDSA', namedCurve: 'P-256' }
const sellar = (acta, k) => sealActa({ acta, privateJwk: k.privateJwk })

/** El papel que firma la bóveda `k` para la llave `sub`, mirando el acta `seq`. */
async function papel (k, sub, seq) {
  const privateKey = await crypto.subtle.importKey('jwk', k.privateJwk, ECDSA, false, ['sign'])
  return signDelegationWith(privateKey, k.publickey, { sub, scope: ['vault:sign'], iat: Date.now(), seq, nonce: 'n-' + Math.random() })
}

/** Una cuenta que nació en A; B ya es miembro, con o sin permiso de sellar. */
async function cuenta ({ bSella = true } = {}) {
  const A = await makeDeviceKey()
  const B = await makeDeviceKey()
  let acta = await sellar(genesisActa({ pub: A.publickey, label: 'bóveda A' }), A)
  acta = await applyChanges(acta, [
    { op: 'admit', member: { pub: B.publickey, label: 'bóveda B', caps: ['sign', 'read', 'store', ...(bSella ? ['sealer'] : [])] } }
  ], { by: A.publickey })
  acta = await sellar(acta, A)
  return { A, B, acta }
}

/** La bóveda `k` admite al aparato y le firma el papel: lo que hace aprobar un emparejamiento. */
async function admitir (acta, k, aparato) {
  const papelNuevo = await papel(k, aparato.publickey, acta.seq)
  let siguiente = await applyChanges(acta, [
    { op: 'admit', member: { pub: aparato.publickey, label: 'teléfono', caps: ['sign'] } }
  ], { by: k.publickey })
  siguiente = await sellar(siguiente, k)
  return { acta: siguiente, cert: papelNuevo }
}

test('una cuenta que nació en esta bóveda: se entra igual que siempre', async () => {
  const { A, acta } = await cuenta()
  const tel = await makeDeviceKey()
  const r = await admitir(acta, A, tel)
  assert.deepEqual(await checkVaultReply({ ...r, vault: A.publickey, sub: tel.publickey, justSealed: true }), { ok: true })
})

test('LA SEGUNDA BÓVEDA: un aparato entra por B aunque la cuenta naciera en A', async () => {
  const { B, acta } = await cuenta()
  const tel = await makeDeviceKey()
  const r = await admitir(acta, B, tel)
  assert.notEqual(r.acta.profileId, B.publickey, 'es justo el caso que la comparación vieja rechazaba')
  assert.deepEqual(await checkVaultReply({ ...r, vault: B.publickey, sub: tel.publickey, justSealed: true }), { ok: true })
})

test('al RENOVAR con B vale un acta que selló A después: las dos sellan la misma cuenta', async () => {
  const { A, B, acta } = await cuenta()
  const tel = await makeDeviceKey()
  let { acta: actual } = await admitir(acta, B, tel)
  // A cambia algo después: la última acta ya no la selló B.
  actual = await sellar(await applyChanges(actual, [{ op: 'label', pub: tel.publickey, label: 'móvil' }], { by: A.publickey }), A)
  const renovado = await papel(B, tel.publickey, actual.seq)
  assert.deepEqual(await checkVaultReply({ acta: actual, cert: renovado, vault: B.publickey, sub: tel.publickey }), { ok: true })
  // Al enrolar, en cambio, el acta tiene que ser la que esa bóveda acaba de sellar.
  const r = await checkVaultReply({ acta: actual, cert: renovado, vault: B.publickey, sub: tel.publickey, justSealed: true })
  assert.equal(r.reason, 'acta-de-otra-selladora')
})

test('una bóveda que NO puede sellar esa cuenta no sirve para entrar', async () => {
  const { B, acta } = await cuenta({ bSella: false })
  const tel = await makeDeviceKey()
  const cert = await papel(B, tel.publickey, acta.seq)
  const r = await checkVaultReply({ acta, cert, vault: B.publickey, sub: tel.publickey })
  assert.equal(r.reason, 'boveda-no-sella')
})

test('UN ACTA AJENA que nombra selladora a tu bóveda no sirve: no la selló ella ni firmó el papel', async () => {
  const { A } = await cuenta()
  const tel = await makeDeviceKey()
  const X = await makeDeviceKey()
  // Alguien por el camino arma una cuenta SUYA, bien firmada, y mete a la bóveda A como
  // selladora —para eso no necesita su llave: admitir a alguien es escribir su pública—.
  let falsa = await sellar(genesisActa({ pub: X.publickey }), X)
  falsa = await applyChanges(falsa, [
    { op: 'admit', member: { pub: A.publickey, label: 'bóveda A', caps: ['sign', 'sealer'] } },
    { op: 'admit', member: { pub: tel.publickey, label: 'teléfono', caps: ['sign'] } }
  ], { by: X.publickey })
  falsa = await sellar(falsa, X)
  const cert = await papel(X, tel.publickey, falsa.seq)

  const alEnrolar = await checkVaultReply({ acta: falsa, cert, vault: A.publickey, sub: tel.publickey, justSealed: true })
  assert.equal(alEnrolar.reason, 'acta-de-otra-selladora')
  const alRenovar = await checkVaultReply({ acta: falsa, cert, vault: A.publickey, sub: tel.publickey })
  assert.equal(alRenovar.reason, 'papel-de-otra-llave', 'y el papel no lo puede firmar nadie más que A')
})

test('un papel que no firmó la bóveda con la que hablas no pasa, aunque lo firme otra selladora', async () => {
  const { A, B, acta } = await cuenta()
  const tel = await makeDeviceKey()
  const r = await admitir(acta, B, tel)
  const deA = await papel(A, tel.publickey, r.acta.seq)
  const chk = await checkVaultReply({ acta: r.acta, cert: deA, vault: B.publickey, sub: tel.publickey, justSealed: true })
  assert.equal(chk.reason, 'papel-de-otra-llave')
})

test('un papel para OTRA llave no pasa', async () => {
  const { A, acta } = await cuenta()
  const tel = await makeDeviceKey()
  const otro = await makeDeviceKey()
  const r = await admitir(acta, A, tel)
  const chk = await checkVaultReply({ acta: r.acta, cert: await papel(A, otro.publickey, r.acta.seq), vault: A.publickey, sub: tel.publickey, justSealed: true })
  assert.equal(chk.reason, 'papel:sub')
})

test('sin acta, sin bóveda o sin llave del aparato se PARA, no se da por bueno', async () => {
  const { A, acta } = await cuenta()
  const tel = await makeDeviceKey()
  const r = await admitir(acta, A, tel)
  assert.equal((await checkVaultReply({ cert: r.cert, vault: A.publickey, sub: tel.publickey })).reason, 'sin-acta')
  assert.equal((await checkVaultReply({ ...r, sub: tel.publickey })).reason, 'sin-boveda')
  assert.equal((await checkVaultReply({ ...r, vault: A.publickey })).reason, 'sin-llave-del-aparato')
})
