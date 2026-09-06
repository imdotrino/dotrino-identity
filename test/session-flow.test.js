/**
 * Las dos puntas de «entrar», contra un transporte falso: el navegador enseña la
 * invitación, el aparato la lee y le da el papel.
 */
import test from 'node:test'
import assert from 'node:assert/strict'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import { Identity, makeDeviceKey } from '../src/node.js'
import { signWithDevice } from '../vault/capabilities.js'
import { verifySession } from '../vault/session.js'
import { openSession, grantSession, denySession, parseInvite, sessionCode, SESSION_OP } from '../vault/sessionFlow.js'

const APP = 'https://chat.dotrino.com'
const tmp = () => fs.mkdtempSync(path.join(os.tmpdir(), 'flujo-'))

/** Bus en memoria con dos puntas: enruta por pubkey y sella de mentira (marca `sealed`). */
function bus () {
  const buzones = new Map()
  const punta = (pubkey) => {
    const handlers = []
    const ep = {
      url: 'wss://proxy.dotrino.com',
      on (ev, cb) { if (ev === 'message') { handlers.push(cb); return () => handlers.splice(handlers.indexOf(cb), 1) } return () => {} },
      async sendSealed (to, payload) { for (const t of to) buzones.get(t)?.entrega(pubkey, payload, { sealed: true }) },
      async sendByPubkey (to, payload) { buzones.get(to)?.entrega(pubkey, payload, { sealed: false }) },
      entrega (from, payload, meta) { for (const h of [...handlers]) h(from, payload, meta) }
    }
    buzones.set(pubkey, ep)
    return ep
  }
  return { punta }
}

async function escenario () {
  const dir = tmp()
  const id = await Identity.connect({ dir })
  const aparato = await makeDeviceKey({ label: 'Teléfono' })
  await id.admitMember({ pub: aparato.publickey, label: 'Teléfono', caps: ['sign', 'store', 'read'] })
  const sesion = await makeDeviceKey({ label: 'Prestado' })
  const red = bus()
  return {
    id, chain: await id.sealerChain(), aparato, sesion,
    navegador: red.punta(sesion.publickey),
    telefono: red.punta(aparato.publickey),
    firmar: (body) => signWithDevice({ privateJwk: aparato.privateJwk, data: body }),
    limpia: () => fs.rmSync(dir, { recursive: true, force: true })
  }
}

test('el navegador enseña la invitación y el teléfono le da el papel', async () => {
  const e = await escenario()
  let mostrado = null
  const entrando = openSession({
    transport: e.navegador, sessionPubkey: e.sesion.publickey, encPub: 'ENC-DEL-NAVEGADOR',
    origin: APP, scopes: ['id:whoami', 'vault:store'],
    onInvite: (x) => { mostrado = x }, timeoutMs: 2000
  })
  await new Promise((r) => setTimeout(r, 5))

  assert.ok(mostrado, 'la app recibe qué pintar')
  assert.equal(mostrado.code, sessionCode(mostrado.invite.sid))
  assert.match(mostrado.code, /^\d{6}$/)
  assert.equal(mostrado.invite.origin, APP)
  assert.equal(mostrado.invite.proxy, 'wss://proxy.dotrino.com', 'y por dónde contestar')

  await grantSession({ transport: e.telefono, invite: mostrado.qr, by: e.aparato.publickey, sign: e.firmar, chain: e.chain })

  const sesion = await entrando
  assert.equal(sesion.profileId, (await e.id.profileActa())?.acta?.profileId, 'entra como la PERSONA, no como el aparato')
  assert.deepEqual(sesion.scopes, ['id:whoami', 'vault:store'])
  assert.equal((await verifySession(sesion.paper, { chain: sesion.chain, origin: APP })).ok, true)
  e.limpia()
})

test('el teléfono puede conceder MENOS de lo que se pidió', async () => {
  const e = await escenario()
  let mostrado = null
  const entrando = openSession({
    transport: e.navegador, sessionPubkey: e.sesion.publickey, encPub: 'ENC',
    origin: APP, scopes: ['id:whoami', 'vault:store'], onInvite: (x) => { mostrado = x }, timeoutMs: 2000
  })
  await new Promise((r) => setTimeout(r, 5))
  await grantSession({ transport: e.telefono, invite: mostrado.invite, by: e.aparato.publickey, sign: e.firmar, chain: e.chain, scopes: ['id:whoami'] })
  const s = await entrando
  assert.deepEqual(s.scopes, ['id:whoami'], 'se concede lo que el dueño quiso, no lo que la app pidió')
  e.limpia()
})

test('decir que no corta la espera en vez de dejar la pantalla girando', async () => {
  const e = await escenario()
  let mostrado = null
  const entrando = openSession({
    transport: e.navegador, sessionPubkey: e.sesion.publickey, encPub: 'ENC',
    origin: APP, onInvite: (x) => { mostrado = x }, timeoutMs: 2000
  })
  await new Promise((r) => setTimeout(r, 5))
  await denySession({ transport: e.telefono, invite: mostrado.invite })
  await assert.rejects(() => entrando, (err) => err.code === 'session-denied')
  e.limpia()
})

test('un papel para OTRA llave no se acepta, aunque venga firmado', async () => {
  const e = await escenario()
  const otra = await makeDeviceKey({ label: 'Otra' })
  let mostrado = null
  const entrando = openSession({
    transport: e.navegador, sessionPubkey: e.sesion.publickey, encPub: 'ENC',
    origin: APP, onInvite: (x) => { mostrado = x }, timeoutMs: 2000
  })
  await new Promise((r) => setTimeout(r, 5))
  // El teléfono firma un papel válido… pero para la llave de otro.
  await grantSession({
    transport: e.telefono, invite: { ...mostrado.invite, s: otra.publickey }, by: e.aparato.publickey,
    sign: e.firmar, chain: e.chain
  })
  // Ese papel ni siquiera llega a esta punta (va dirigido a la otra llave), así que la
  // espera se agota: nadie le concedió nada a ESTE navegador.
  await assert.rejects(() => entrando, (err) => err.code === 'session-timeout')
  e.limpia()
})

test('sin llave de cifrado del otro lado no se manda en claro por su cuenta', async () => {
  const e = await escenario()
  await assert.rejects(
    () => grantSession({ transport: e.telefono, invite: { v: 1, t: 'session', sid: 'x', s: e.sesion.publickey, origin: APP }, by: e.aparato.publickey, sign: e.firmar, chain: e.chain }),
    (err) => err.code === 'unsealed'
  )
  e.limpia()
})

test('una invitación que no lo es se rechaza al leerla', () => {
  assert.equal(parseInvite('{}'), null)
  assert.equal(parseInvite('no es json'), null)
  assert.equal(parseInvite({ v: 1, t: 'otra-cosa' }), null)
  assert.equal(parseInvite({ v: 2, t: 'session', sid: 'a', s: 'b', origin: 'c' }), null)
  const ok = parseInvite({ v: 1, t: 'session', sid: 'a', s: 'b', origin: 'c', scopes: ['vault:admin'] })
  assert.deepEqual(ok.scopes, ['id:whoami'], 'y de paso se cae lo que una sesión no puede pedir')
})

test('el código sale del sid, así que las dos pantallas enseñan el mismo', () => {
  assert.equal(sessionCode('abc'), sessionCode('abc'))
  assert.notEqual(sessionCode('abc'), sessionCode('abd'))
  assert.equal(SESSION_OP.GRANT, 'session.grant')
})
