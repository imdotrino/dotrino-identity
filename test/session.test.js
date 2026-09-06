/**
 * ENTRAR SIN ENROLAR: el papel de sesión.
 *
 * Lo que se fija aquí es que la segunda autoridad que esto crea esté acotada de verdad —
 * que no amplíe, que venza, que muera con el aparato que la respalda y que no valga en
 * otra aplicación.
 */
import test from 'node:test'
import assert from 'node:assert/strict'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import { Identity, makeDeviceKey } from '../src/node.js'
import { signWithDevice } from '../vault/capabilities.js'
import {
  signSession, verifySession, verifySessionSigned, newSessionId, cleanSessionScopes,
  sessionBody, SESSION_MAX_TTL_MS, SESSION_DEFAULT_TTL_MS
} from '../vault/session.js'

const tmp = () => fs.mkdtempSync(path.join(os.tmpdir(), 'sesion-'))
const APP = 'https://chat.dotrino.com'

/** Una cuenta con un aparato que respalda sesiones, y una llave de sesión suelta. */
async function escenario ({ caps = ['sign', 'store', 'read'] } = {}) {
  const dir = tmp()
  const id = await Identity.connect({ dir })
  const aparato = await makeDeviceKey({ label: 'Teléfono' })
  await id.admitMember({ pub: aparato.publickey, label: 'Teléfono', caps })
  const sesion = await makeDeviceKey({ label: 'Navegador prestado' })
  const chain = await id.sealerChain()
  const firmarConAparato = (body) => signWithDevice({ privateJwk: aparato.privateJwk, data: body })
  const firmarConSesion = (data) => signWithDevice({ privateJwk: sesion.privateJwk, data })
  return {
    id, dir, chain, aparato, sesion, firmarConAparato, firmarConSesion,
    async papel (extra = {}) {
      return signSession({
        sid: newSessionId(), s: sesion.publickey, by: aparato.publickey,
        origin: APP, scopes: ['id:whoami', 'vault:store'], ...extra
      }, firmarConAparato)
    },
    limpia: () => fs.rmSync(dir, { recursive: true, force: true })
  }
}

test('una sesión vale mientras el acta respalde al aparato que la firmó', async () => {
  const e = await escenario()
  const papel = await e.papel()
  const v = await verifySession(papel, { chain: e.chain, origin: APP })
  assert.equal(v.ok, true, v.reason)
  assert.equal(v.by, e.aparato.publickey)
  assert.equal(v.s, e.sesion.publickey)
  assert.deepEqual(v.scopes, ['id:whoami', 'vault:store'])
  assert.equal(papel.exp - papel.iat, SESSION_DEFAULT_TTL_MS)
  e.limpia()
})

test('sin el acta no se puede juzgar, y se dice', async () => {
  const e = await escenario()
  const papel = await e.papel()
  assert.equal((await verifySession(papel, {})).ok, false)
  assert.match((await verifySession(papel, {})).reason, /^cadena:/)
  e.limpia()
})

/** El invariante que hace barata la revocación: quitar el aparato se lleva sus sesiones. */
test('si al aparato lo quitan del acta, su sesión deja de valer', async () => {
  const e = await escenario()
  const papel = await e.papel()
  assert.equal((await verifySession(papel, { chain: e.chain })).ok, true)

  await e.id.removeMember(e.aparato.publickey)
  const despues = await e.id.sealerChain()
  const v = await verifySession(papel, { chain: despues })
  assert.equal(v.ok, false)
  assert.equal(v.reason, 'aparato-no-es-del-perfil', 'y no hace falta avisar a nadie ni revocar el papel')
  e.limpia()
})

test('NUNCA amplía: si el aparato no puede guardar, su sesión tampoco', async () => {
  const e = await escenario({ caps: ['sign', 'read'] })   // sin `store`
  const papel = await e.papel({ scopes: ['id:whoami', 'vault:store'] })
  const v = await verifySession(papel, { chain: e.chain })
  assert.equal(v.ok, false)
  assert.equal(v.reason, 'aparato-sin-store')

  // Lo que sí tiene, pasa.
  const minimo = await e.papel({ scopes: ['id:whoami'] })
  assert.equal((await verifySession(minimo, { chain: e.chain })).ok, true)
  e.limpia()
})

test('y se comprueba contra el acta de HOY, no contra la de cuando se firmó', async () => {
  const e = await escenario()
  const papel = await e.papel({ scopes: ['id:whoami', 'vault:store'] })
  assert.equal((await verifySession(papel, { chain: e.chain })).ok, true)

  await e.id.setCaps(e.aparato.publickey, ['sign', 'read'])   // le quitan `store`
  const v = await verifySession(papel, { chain: await e.id.sealerChain() })
  assert.equal(v.ok, false)
  assert.equal(v.reason, 'aparato-sin-store')
  e.limpia()
})

test('vence por reloj, que es la mitad del producto', async () => {
  const e = await escenario()
  const papel = await e.papel({ ttlMs: 60 * 60 * 1000 })
  assert.equal((await verifySession(papel, { chain: e.chain, now: papel.exp - 1 })).ok, true)
  const tarde = await verifySession(papel, { chain: e.chain, now: papel.exp })
  assert.equal(tarde.reason, 'vencida')

  // Y el tope lo comprueba quien recibe: un papel estirado a mano no vale.
  const estirado = { ...papel, exp: papel.iat + 30 * 24 * 3600 * 1000 }
  assert.equal((await verifySession(estirado, { chain: e.chain })).reason, 'vigencia-excesiva')
  e.limpia()
})

test('un papel para una aplicación no vale en otra', async () => {
  const e = await escenario()
  const papel = await e.papel()
  assert.equal((await verifySession(papel, { chain: e.chain, origin: APP })).ok, true)
  const otra = await verifySession(papel, { chain: e.chain, origin: 'https://otra.dotrino.com' })
  assert.equal(otra.reason, 'otro-origen')
  e.limpia()
})

test('tocar el papel lo invalida', async () => {
  const e = await escenario()
  const papel = await e.papel({ scopes: ['id:whoami'] })
  const falso = { ...papel, scopes: ['id:whoami', 'vault:store'] }
  const v = await verifySession(falso, { chain: e.chain })
  assert.equal(v.ok, false)
  assert.equal(v.reason, 'firma-invalida')
  e.limpia()
})

test('la sesión firma con SU llave, y el papel dice hasta dónde', async () => {
  const e = await escenario()
  const papel = await e.papel({ scopes: ['id:whoami'] })
  const dato = { op: 'hola', ts: 1 }
  const { signature } = await e.firmarConSesion(dato)

  const ok = await verifySessionSigned({ data: dato, signature, session: papel, chain: e.chain, scope: 'id:whoami' })
  assert.equal(ok.ok, true, ok.reason)
  assert.equal(ok.profileId, (await e.id.profileActa())?.acta?.profileId)

  const fuera = await verifySessionSigned({ data: dato, signature, session: papel, chain: e.chain, scope: 'vault:store' })
  assert.equal(fuera.reason, 'fuera-de-alcance', 'el papel no concedía guardar')

  // Y la firma de otro no cuela, aunque el papel sea bueno.
  const ajena = await signWithDevice({ privateJwk: e.aparato.privateJwk, data: dato })
  const mal = await verifySessionSigned({ data: dato, signature: ajena.signature, session: papel, chain: e.chain })
  assert.equal(mal.reason, 'firma-invalida')
  e.limpia()
})

test('una sesión no puede pedir lo que una sesión no puede tener', async () => {
  assert.deepEqual(cleanSessionScopes(['vault:admin', 'secrets', 'inventado']), ['id:whoami'],
    'lo que no está en el catálogo se cae, y queda el mínimo')
  assert.deepEqual(cleanSessionScopes(['vault:store', 'id:whoami', 'vault:store']), ['id:whoami', 'vault:store'])
})

test('emitir sin lo imprescindible se para en el acto', async () => {
  const base = { sid: 's', s: 'S', by: 'B', origin: APP, iat: 1000, exp: 2000 }
  assert.throws(() => sessionBody({ ...base, sid: '' }), /sid/)
  assert.throws(() => sessionBody({ ...base, origin: '' }), /origin/)
  assert.throws(() => sessionBody({ ...base, exp: 500 }), /after iat/)
  assert.throws(() => sessionBody({ ...base, exp: base.iat + SESSION_MAX_TTL_MS + 1 }), /cap/)
})

test('basura no pasa por papel', async () => {
  for (const mala of [null, undefined, 7, 'texto', {}, { v: 2, op: 'session' }]) {
    const v = await verifySession(/** @type {any} */ (mala), { chain: [] })
    assert.equal(v.reason, 'shape', JSON.stringify(mala))
  }
})
