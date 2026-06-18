// Tests de la DELEGACIÓN de capacidad: una sub-clave de dispositivo D recibe un
// cert firmado por la maestra P (scope/exp/revocación), firma acciones, y un
// verificador comprueba la cadena D←P OFFLINE. Garantía clave: robar el
// dispositivo solo permite lo del scope, hasta exp, y se revoca; la maestra intacta.
//
// Usa el adaptador headless de Node (sin iframe) + los helpers puros de capabilities.

import { test } from 'node:test'
import assert from 'node:assert'
import os from 'node:os'
import path from 'node:path'
import fs from 'node:fs'
import { Identity, makeDeviceKey, signWithDevice, verifyDelegation, verifyChain, MAX_DELEGATION_MS } from '../src/node.js'

let seq = 0
async function freshMaster () {
  const dir = path.join(os.tmpdir(), 'cci-caps-test', `${process.pid}-${seq++}`)
  fs.rmSync(dir, { recursive: true, force: true })
  return Identity.connect({ dir })
}
// Arma un pin firmado por la clave de dispositivo, con el cert dentro de payload.cap.
async function signedPin (D, cert, extra = {}) {
  const data = { publickey: D.publickey, lat: -0.18, lng: -78.46, payload: { cap: cert, ...extra }, issuedAt: Date.now() }
  const { signature } = await signWithDevice({ privateJwk: D.privateJwk, data })
  return { data, signature }
}

test('round-trip: la maestra firma un cert y verifyDelegation lo acepta', async () => {
  const P = await freshMaster()
  const D = await makeDeviceKey({ label: 'pixel-owntracks' })
  const { cert } = await P.signDelegation(D.publickey, 'geo:publish', { ttlMs: 3600000 })
  assert.equal(cert.v, 1)
  assert.equal(cert.iss, P.me.publickey)          // iss = maestra
  assert.equal(cert.sub, D.publickey)             // sub = dispositivo
  const r = await verifyDelegation({ cert, expectedScope: 'geo:publish', expectedSub: D.publickey })
  assert.equal(r.ok, true, r.reason)
})

test('iss no se puede falsificar: cambiar iss invalida la firma', async () => {
  const P = await freshMaster()
  const D = await makeDeviceKey()
  const { cert } = await P.signDelegation(D.publickey, 'geo:publish')
  const forged = { ...cert, iss: D.publickey }    // pretende que lo firmó otro emisor
  const r = await verifyDelegation({ cert: forged })
  assert.equal(r.ok, false)
  assert.equal(r.reason, 'bad-signature')
})

test('scope: rechaza un scope distinto; acepta si el array lo incluye', async () => {
  const P = await freshMaster()
  const D = await makeDeviceKey()
  const { cert } = await P.signDelegation(D.publickey, 'geo:publish')
  assert.equal((await verifyDelegation({ cert, expectedScope: 'store:write' })).reason, 'scope')
  const { cert: multi } = await P.signDelegation(D.publickey, ['geo:publish', 'geo:share:family'])
  assert.equal((await verifyDelegation({ cert: multi, expectedScope: 'geo:share:family' })).ok, true)
})

test('expiración: vencido y aún-no-válido', async () => {
  const P = await freshMaster()
  const D = await makeDeviceKey()
  const { cert } = await P.signDelegation(D.publickey, 'geo:publish', { ttlMs: 1000 })
  assert.equal((await verifyDelegation({ cert, now: cert.exp + 1 })).reason, 'expired')
  assert.equal((await verifyDelegation({ cert, now: cert.iat - 1 })).reason, 'not-yet-valid')
})

test('tope de vida MAX_DELEGATION_MS aunque pidan más', async () => {
  const P = await freshMaster()
  const D = await makeDeviceKey()
  const { cert } = await P.signDelegation(D.publickey, 'geo:publish', { ttlMs: 365 * 24 * 3600 * 1000 })
  assert.equal(cert.exp - cert.iat, MAX_DELEGATION_MS)
})

test('cadena feliz: D firma el pin, el cert prueba D←P, issuer fijado', async () => {
  const P = await freshMaster()
  const D = await makeDeviceKey()
  const { cert } = await P.signDelegation(D.publickey, 'geo:publish', { ttlMs: 3600000 })
  const { data, signature } = await signedPin(D, cert)
  const r = await verifyChain({ data, signature, cert, expectedScope: 'geo:publish', trustedIssuer: P.me.publickey })
  assert.equal(r.ok, true, r.reason)
  assert.equal(r.issuer, P.me.publickey)
  assert.equal(r.device, D.publickey)
})

test('dispositivo equivocado: cert.sub ≠ data.publickey', async () => {
  const P = await freshMaster()
  const D1 = await makeDeviceKey()
  const D2 = await makeDeviceKey()
  const { cert } = await P.signDelegation(D1.publickey, 'geo:publish')   // cert para D1
  const { data, signature } = await signedPin(D2, cert)                  // pero firma D2
  const r = await verifyChain({ data, signature, cert, expectedScope: 'geo:publish' })
  assert.equal(r.ok, false)
  assert.equal(r.reason, 'cert-device-mismatch')
})

test('pin alterado: mutar data sin re-firmar rompe la cadena', async () => {
  const P = await freshMaster()
  const D = await makeDeviceKey()
  const { cert } = await P.signDelegation(D.publickey, 'geo:publish')
  const { data, signature } = await signedPin(D, cert)
  data.lat = 0   // tamper
  const r = await verifyChain({ data, signature, cert, expectedScope: 'geo:publish' })
  assert.equal(r.ok, false)
  assert.equal(r.reason, 'bad-action-signature')
})

test('revocación: revocar el nonce mata la cadena (aunque no haya vencido)', async () => {
  const P = await freshMaster()
  const D = await makeDeviceKey()
  const { cert } = await P.signDelegation(D.publickey, 'geo:publish', { ttlMs: 3600000 })
  const { data, signature } = await signedPin(D, cert)
  assert.equal((await verifyChain({ data, signature, cert, expectedScope: 'geo:publish' })).ok, true)
  await P.revokeDelegation(cert.nonce)
  const { revoked } = await P.listDelegations()
  assert.ok(revoked.some(r => r.nonce === cert.nonce))
  const revFn = (nonce) => revoked.some(r => r.nonce === nonce)
  const r = await verifyChain({ data, signature, cert, expectedScope: 'geo:publish', revoked: revFn })
  assert.equal(r.ok, false)
  assert.equal(r.reason, 'revoked')
})

test('radio de daño: un cert geo:publish NO sirve para otro scope', async () => {
  const P = await freshMaster()
  const D = await makeDeviceKey()
  const { cert } = await P.signDelegation(D.publickey, 'geo:publish')
  const { data, signature } = await signedPin(D, cert)
  // el dispositivo robado intenta usar el cert para escribir en el store
  const r = await verifyChain({ data, signature, cert, expectedScope: 'store:write' })
  assert.equal(r.ok, false)
  assert.equal(r.reason, 'scope')
})

test('issuer no confiable: un cert de OTRA maestra es rechazado por trustedIssuer', async () => {
  const P = await freshMaster()
  const Other = await freshMaster()
  const D = await makeDeviceKey()
  const { cert } = await P.signDelegation(D.publickey, 'geo:publish')
  const { data, signature } = await signedPin(D, cert)
  const r = await verifyChain({ data, signature, cert, expectedScope: 'geo:publish', trustedIssuer: Other.me.publickey })
  assert.equal(r.ok, false)
  assert.equal(r.reason, 'untrusted-issuer')
})

test('listDelegations muestra las caps emitidas (para el gestor de dispositivos)', async () => {
  const P = await freshMaster()
  const D = await makeDeviceKey()
  const { cert } = await P.signDelegation(D.publickey, 'geo:publish', { label: 'Pixel de mamá' })
  const { issued } = await P.listDelegations()
  const row = issued.find(x => x.nonce === cert.nonce)
  assert.ok(row, 'la cap emitida aparece en la lista')
  assert.equal(row.sub, D.publickey)
  assert.equal(row.label, 'Pixel de mamá')
})
