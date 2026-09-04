// Tests de la DELEGACIÓN de capacidad: una sub-clave de dispositivo D recibe un cert
// firmado por una SELLADORA del perfil P (scope + revocación), firma acciones, y un
// verificador comprueba la cadena D←P OFFLINE.
//
// EL PAPEL NO CADUCA POR RELOJ (dueño, 2026-08-31): lleva el `seq` del acta con el que se
// emitió, y quien verifica pasa el acta que tiene (`actaSeq` + `sealers`). Lo que puede
// hacer el aparato HOY lo dice el acta de hoy. Por eso aquí ya no hay tests de vencimiento
// ni de margen de reloj: no son «tests que se cayeron», son conceptos que dejaron de
// existir.
//
// Usa el adaptador headless de Node (sin iframe) + los helpers puros de capabilities.

import { test } from 'node:test'
import assert from 'node:assert'
import os from 'node:os'
import path from 'node:path'
import fs from 'node:fs'
import { Identity, makeDeviceKey, signWithDevice, verifyDelegation, verifyChain } from '../src/node.js'
import { LEGACY_CERTS_UNTIL } from '../vault/capabilities.js'
import { sealersOf } from '../vault/acta.js'

/**
 * El contexto con el que se juzga un papel: el acta que tiene QUIEN VERIFICA. No se pasa el
 * acta entera porque `capabilities.js` no sabe de actas (`acta.js` importa de él, y mirar
 * para allá sería un ciclo): se le pasa el número y la lista de selladores.
 */
async function conActa (P) {
  const acta = (await P.profileActa()).acta
  return { actaSeq: acta.seq, sealers: sealersOf(acta) }
}

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
  const r = await verifyDelegation({ cert, ...(await conActa(P)), expectedScope: 'geo:publish', expectedSub: D.publickey })
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
  assert.equal((await verifyDelegation({ cert, ...(await conActa(P)), expectedScope: 'store:write' })).reason, 'scope')
  const { cert: multi } = await P.signDelegation(D.publickey, ['geo:publish', 'geo:share:family'])
  assert.equal((await verifyDelegation({ cert: multi, ...(await conActa(P)), expectedScope: 'geo:share:family' })).ok, true)
})

test('cadena feliz: D firma el pin, el cert prueba D←P, issuer fijado', async () => {
  const P = await freshMaster()
  const D = await makeDeviceKey()
  const { cert } = await P.signDelegation(D.publickey, 'geo:publish', { ttlMs: 3600000 })
  const { data, signature } = await signedPin(D, cert)
  const r = await verifyChain({ data, signature, cert, ...(await conActa(P)), expectedScope: 'geo:publish' })
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
  const r = await verifyChain({ data, signature, cert, ...(await conActa(P)), expectedScope: 'geo:publish' })
  assert.equal(r.ok, false)
  assert.equal(r.reason, 'cert-device-mismatch')
})

test('pin alterado: mutar data sin re-firmar rompe la cadena', async () => {
  const P = await freshMaster()
  const D = await makeDeviceKey()
  const { cert } = await P.signDelegation(D.publickey, 'geo:publish')
  const { data, signature } = await signedPin(D, cert)
  data.lat = 0   // tamper
  const r = await verifyChain({ data, signature, cert, ...(await conActa(P)), expectedScope: 'geo:publish' })
  assert.equal(r.ok, false)
  assert.equal(r.reason, 'bad-action-signature')
})

test('revocación: revocar el nonce mata la cadena (aunque no haya vencido)', async () => {
  const P = await freshMaster()
  const D = await makeDeviceKey()
  const { cert } = await P.signDelegation(D.publickey, 'geo:publish', { ttlMs: 3600000 })
  const { data, signature } = await signedPin(D, cert)
  assert.equal((await verifyChain({ data, signature, cert, ...(await conActa(P)), expectedScope: 'geo:publish' })).ok, true)
  await P.revokeDelegation(cert.nonce)
  const { revoked } = await P.listDelegations()
  assert.ok(revoked.some(r => r.nonce === cert.nonce))
  const revFn = (nonce) => revoked.some(r => r.nonce === nonce)
  const r = await verifyChain({ data, signature, cert, ...(await conActa(P)), expectedScope: 'geo:publish', revoked: revFn })
  assert.equal(r.ok, false)
  assert.equal(r.reason, 'revoked')
})

test('radio de daño: un cert geo:publish NO sirve para otro scope', async () => {
  const P = await freshMaster()
  const D = await makeDeviceKey()
  const { cert } = await P.signDelegation(D.publickey, 'geo:publish')
  const { data, signature } = await signedPin(D, cert)
  // el dispositivo robado intenta usar el cert para escribir en el store
  const r = await verifyChain({ data, signature, cert, ...(await conActa(P)), expectedScope: 'store:write' })
  assert.equal(r.ok, false)
  assert.equal(r.reason, 'scope')
})

/**
 * QUIEN EMITE TIENE QUE SER SELLADORA DE **ESTE** PERFIL.
 *
 * Esto se comprobaba contra UNA llave fija (`trustedIssuer`, la maestra), y por eso el
 * multivault no podía existir: la segunda bóveda sellaba el acta y luego sus papeles los
 * rechazaba todo el mundo. Ahora se compara contra la LISTA que dice el acta, así que
 * cualquiera a quien el dueño haya dado `sella` emite papeles válidos… y nadie más.
 */
test('quien emite tiene que ser selladora de este perfil, no una llave cualquiera', async () => {
  const P = await freshMaster()
  const Otro = await freshMaster()
  const D = await makeDeviceKey()
  const { cert } = await P.signDelegation(D.publickey, 'geo:publish')
  const { data, signature } = await signedPin(D, cert)

  // Con el acta de P: su maestra está en la lista de selladores, así que vale.
  assert.equal((await verifyChain({ data, signature, cert, ...(await conActa(P)), expectedScope: 'geo:publish' })).ok, true)

  // Con el acta de OTRO perfil: el mismo papel no vale, porque quien lo firmó no sella ahí.
  const r = await verifyChain({ data, signature, cert, ...(await conActa(Otro)), expectedScope: 'geo:publish' })
  assert.equal(r.ok, false)
  assert.equal(r.reason, 'untrusted-issuer')
})

/**
 * UN PAPEL DEL FUTURO NO SE JUZGA. Si el cert nombra un acta más nueva que la que tengo, mi
 * política está atrasada y decir que sí sería fiarme de algo que no he visto. Al revés —un
 * papel viejo— es lo NORMAL: el aparato estuvo apagado, y lo que puede hacer lo decide mi
 * acta, que es más nueva. Exigir que coincidieran dejaría tirado a cualquiera que se
 * hubiera perdido un cambio, y volver le exigiría una selladora abierta.
 */
test('un papel de un acta MÁS NUEVA no se juzga; uno viejo sí vale', async () => {
  const P = await freshMaster()
  const D = await makeDeviceKey()
  const { cert } = await P.signDelegation(D.publickey, 'geo:publish')
  const ctx = await conActa(P)

  assert.equal((await verifyDelegation({ cert, ...ctx, expectedScope: 'geo:publish' })).ok, true)
  // Mi acta va por detrás de la que nombra el papel.
  const atras = await verifyDelegation({ cert, ...ctx, actaSeq: cert.seq - 1, expectedScope: 'geo:publish' })
  assert.equal(atras.ok, false)
  assert.equal(atras.reason, 'acta-vieja')
  // Mi acta va por delante: normal, y el papel sigue sirviendo.
  assert.equal((await verifyDelegation({ cert, ...ctx, actaSeq: cert.seq + 5, expectedScope: 'geo:publish' })).ok, true)
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

// --- un aparato = un certificado vigente (bug: salía dos veces y no se le podía echar) ---

test('renovar RETIRA el cert anterior: el aparato no sale dos veces', async () => {
  const P = await freshMaster()
  const D = await makeDeviceKey()
  const a = await P.signDelegation(D.publickey, ['vault:sign', 'vault:read'], { label: 'pc-local' })
  const b = await P.signDelegation(D.publickey, ['vault:admin', 'vault:sign'], { label: 'pc-local' })
  const { issued } = await P.listDelegations()
  const mine = issued.filter(x => x.sub === D.publickey)
  assert.equal(mine.length, 1, 'una fila por aparato, no una por certificado')
  assert.equal(mine[0].nonce, b.cert.nonce, 'queda el recién emitido')
  const { revoked } = await P.listDelegations()
  assert.ok(revoked.some(r => r.nonce === a.cert.nonce), 'el anterior queda revocado')
})

test('un cert revocado ya NO aparece como emitido (la fila desaparece al quitarlo)', async () => {
  const P = await freshMaster()
  const D = await makeDeviceKey()
  const { cert } = await P.signDelegation(D.publickey, 'vault:sign')
  await P.revokeDelegation(cert.nonce)
  const { issued, revokedCerts } = await P.listDelegations()
  assert.equal(issued.find(x => x.nonce === cert.nonce), undefined, 'fuera de los vigentes')
  assert.ok(revokedCerts.some(x => x.nonce === cert.nonce), 'pero consta en el histórico retirado')
})

test('quitar el DISPOSITIVO retira todos sus certificados, no solo uno', async () => {
  const P = await freshMaster()
  const D = await makeDeviceKey()
  const otro = await makeDeviceKey()
  // Dos certs vivos de la misma llave (como los deja una bóveda vieja): se fuerza con
  // `supersede: false`, que es justo el comportamiento que causaba el bug.
  const a = await P.signDelegation(D.publickey, 'vault:sign', { supersede: false })
  const b = await P.signDelegation(D.publickey, 'vault:admin', { supersede: false })
  const c = await P.signDelegation(otro.publickey, 'vault:sign', { supersede: false })
  const r = await P.revokeDevice(D.publickey)
  assert.equal(r.nonces.length, 2, 'se retiran los dos, incluido el que llevaba admin')
  const { issued } = await P.listDelegations()
  assert.equal(issued.filter(x => x.sub === D.publickey).length, 0, 'el aparato queda fuera')
  assert.ok(issued.some(x => x.nonce === c.cert.nonce), 'no se toca a los demás aparatos')
  assert.ok([a, b].every(x => x.cert.nonce), 'los dos certs existieron')
})

// Aquí vivían los dos tests del MARGEN DE RELOJ (`PEER_SKEW_MS`): un teléfono 850 ms por
// detrás no podía enrolarse porque el cert recién sellado se leía como futuro. Se van con
// el reloj: un papel atado al `seq` del acta no tiene ventana temporal que ajustar, así que
// el problema que resolvían ya no puede ocurrir.

/**
 * EL REPLIEGUE DE MIGRACIÓN, y sus dos frenos.
 *
 * Un repliegue sin fecha es un agujero (`CLAUDE.md`), así que este tiene una escrita
 * —`LEGACY_CERTS_UNTIL`, 2026-10-01— y estas pruebas están para que se note cuando toque
 * quitarlo: el día que caduque, la primera se pondrá roja sola.
 */
test('MIGRACIÓN: un papel del modelo viejo pasa, pero solo hasta su propio vencimiento', async () => {
  // Se arma a mano una bóveda vieja: una llave que el acta nombra selladora, firmando un
  // cuerpo CON `exp` y SIN `seq`, que es exactamente lo que emitían las bóvedas < 0.73.
  const boveda = await makeDeviceKey()
  const D = await makeDeviceKey()
  const acta = { actaSeq: 12, sealers: [boveda.publickey] }
  const viejo = async (exp) => {
    const c = { v: 1, iss: boveda.publickey, sub: D.publickey, scope: ['vault:sign'], iat: Date.now() - 1000, exp, nonce: 'n-' + exp }
    const { signature } = await signWithDevice({ privateJwk: boveda.privateJwk, publickey: boveda.publickey, data: c })
    return { ...c, sig: signature }
  }

  const vivo = await verifyDelegation({ cert: await viejo(Date.now() + 86400000), ...acta, expectedSub: D.publickey })
  assert.equal(vivo.ok, true, vivo.reason)
  assert.equal(vivo.legacy, true, 'se marca como del modelo viejo, no se confunde con uno nuevo')
  assert.equal(vivo.seq, null, 'no nombra ninguna acta, y no se inventa una')

  // Su vencimiento SIGUE valiendo: el repliegue no le regala ni un día.
  const muerto = await verifyDelegation({ cert: await viejo(Date.now() - 1000), ...acta })
  assert.equal(muerto.reason, 'expired')

  assert.equal(Date.now() < LEGACY_CERTS_UNTIL, true,
    'llegó 2026-10-01: toca BORRAR el repliegue de `verifyDelegation` y estas dos pruebas')
})

test('MIGRACIÓN: el papel viejo no relaja nada más que la forma', async () => {
  // Lo que el repliegue NO toca: quien emite tiene que seguir pudiendo sellar. Un papel
  // viejo de una llave que el acta no nombra selladora se rechaza igual que uno nuevo.
  const P = await freshMaster()
  const Otro = await freshMaster()
  const D = await makeDeviceKey()
  const viejo = { v: 1, iss: Otro.me.publickey, sub: D.publickey, scope: ['vault:sign'], iat: Date.now() - 1000, exp: Date.now() + 86400000, nonce: 'n-x', sig: 'x' }
  const r = await verifyDelegation({ cert: viejo, ...(await conActa(P)) })
  assert.equal(r.ok, false)
  assert.ok(['bad-signature', 'untrusted-issuer'].includes(r.reason), r.reason)
})

/**
 * UNA RENUNCIA VALE ANTES DE QUE EL MASTER LA SELLE.
 *
 * Es la razón de ser de la renuncia y estaba a medias: `effectiveCaps` aceptaba
 * `extraRenounces` —«renuncias sueltas ya verificadas que todavía no absorbió el master»—
 * y los mostradores que de verdad deciden no lo pasaban ni podían: `memberCanScope`,
 * `memberCanReadSecrets` y `memberCanSign` NO tenían ese parámetro.
 *
 * O sea que entre que un aparato renuncia y que alguien abre la bóveda con su contraseña
 * —sellar es de la maestra—, ese aparato conservaba TODOS sus permisos. Justo el caso que
 * la renuncia existe para cubrir: te roban el teléfono y el ladrón sigue siendo admin.
 *
 * Honrarla sin la maestra es seguro por lo mismo que ya estaba escrito: una renuncia
 * **solo puede quitar**, así que no puede conceder nada a nadie.
 */
import { test as testR } from 'node:test'
import assertR from 'node:assert/strict'
import {
  genesisActa as genR, sealActa as sealR, applyChanges as applyR, makeRenounce,
  memberCan as canR, memberCanScope as canScopeR, memberCanReadSecrets as canSecretsR,
  memberCanSign as canSignR, memberScopes as scopesR
} from '../vault/acta.js'

const parR = async () => {
  const k = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify'])
  return {
    pub: JSON.stringify(await crypto.subtle.exportKey('jwk', k.publicKey)),
    privateJwk: await crypto.subtle.exportKey('jwk', k.privateKey)
  }
}

testR('una renuncia sin sellar ya quita el permiso en TODOS los mostradores', async () => {
  const master = await parR()
  const tel = await parR()
  const svc = await parR()
  const g = genR({ pub: master.pub, sealPub: master.pub })
  const conMiembros = await applyR(g, [
    { op: 'admit', member: { pub: tel.pub, caps: ['sign', 'admin'], label: 'teléfono' } },
    { op: 'admit', member: { pub: svc.pub, caps: ['secrets'], cn: 'proxy', label: 'proxio' } }
  ], { by: master.pub })
  const acta = await sealR({ acta: conMiembros, privateJwk: master.privateJwk })

  // Antes de renunciar, el teléfono puede todo lo suyo.
  assertR.equal(canR(acta, tel.pub, 'admin'), true)
  assertR.equal(canScopeR(acta, tel.pub, 'vault:admin'), true)
  assertR.equal(canSignR(acta, tel.pub), true)
  assertR.ok(scopesR(acta, tel.pub).length > 0)

  // Renuncia a TODO, firmado por él mismo. El master NO la ha sellado.
  const r = await makeRenounce({ member: tel.pub, caps: ['sign', 'admin'], privateJwk: tel.privateJwk })
  const sueltas = [r]

  assertR.equal(canR(acta, tel.pub, 'admin', sueltas), false)
  assertR.equal(canScopeR(acta, tel.pub, 'vault:admin', sueltas), false, 'el mostrador por scope tampoco')
  assertR.equal(canSignR(acta, tel.pub, null, sueltas), false, 'ni el de firmar')
  assertR.deepEqual(scopesR(acta, tel.pub, sueltas), [], 'y no le queda ni un scope que renovar')

  // Y el acta sin tocar sigue diciendo que sí: lo que cambia es quien la lee CON la
  // renuncia en la mano. Absorberla es lo que lo hace permanente.
  assertR.equal(canR(acta, tel.pub, 'admin'), true, 'el acta no se ha modificado')
})

testR('un servicio que renuncia deja de leer su cajón antes del sellado', async () => {
  const master = await parR()
  const svc = await parR()
  const g = genR({ pub: master.pub, sealPub: master.pub })
  const conSvc = await applyR(g, [
    { op: 'admit', member: { pub: svc.pub, caps: ['secrets'], cn: 'proxy', label: 'proxio' } }
  ], { by: master.pub })
  const acta = await sealR({ acta: conSvc, privateJwk: master.privateJwk })

  assertR.equal(canSecretsR(acta, svc.pub, 'proxy'), true)
  const r = await makeRenounce({ member: svc.pub, caps: ['secrets'], privateJwk: svc.privateJwk })
  assertR.equal(canSecretsR(acta, svc.pub, 'proxy', [r]), false)
  assertR.equal(canScopeR(acta, svc.pub, 'vault:secrets:proxy', [r]), false, 'y por el scope del cert también')
})

testR('una renuncia AJENA no quita nada: la firma tiene que ser del propio miembro', async () => {
  const master = await parR()
  const tel = await parR()
  const otro = await parR()
  const g = genR({ pub: master.pub, sealPub: master.pub })
  const conTel = await applyR(g, [
    { op: 'admit', member: { pub: tel.pub, caps: ['sign', 'admin'], label: 'teléfono' } }
  ], { by: master.pub })
  const acta = await sealR({ acta: conTel, privateJwk: master.privateJwk })

  // Firmada por OTRO pero nombrando al teléfono. `effectiveCaps` no verifica firmas —eso
  // lo hace quien la recibe, con `verifyRenounce`— así que lo que se fija aquí es que la
  // lista que se le pasa tiene que venir YA verificada, y que una renuncia de otro miembro
  // no toca al teléfono.
  const suya = await makeRenounce({ member: otro.pub, caps: ['admin'], privateJwk: otro.privateJwk })
  assertR.equal(canR(acta, tel.pub, 'admin', [suya]), true, 'la de otro no le quita nada a este')
})
