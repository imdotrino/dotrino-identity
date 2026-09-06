/**
 * PERMISO POR ORIGEN: qué se le deja ver a cada aplicación.
 *
 * Lo que se fija aquí es la regla de fondo — saber QUIÉN eres no cuesta permiso (quien
 * llega ya pasó el filtro de orígenes, y preguntarlo treinta veces al día por aplicaciones
 * del mismo dueño es ceremonia); cualquier DATO tuyo, sí. Y que sin nadie a quien
 * preguntar, la respuesta es no.
 */
import test from 'node:test'
import assert from 'node:assert/strict'
import { createIdentityCore } from '../vault/core.js'

const APP = 'https://chat.dotrino.com'

/** kv y peers en memoria: aquí lo que se prueba es el permiso, no dónde se guarda. */
function kvMemoria () {
  const m = new Map()
  return { getItem: (k) => (m.has(k) ? m.get(k) : null), setItem: (k, v) => m.set(k, String(v)), removeItem: (k) => m.delete(k) }
}
function peersMemoria () {
  let p = {}
  return {
    initPeerStorage: async () => {}, loadPeers: () => p, savePeers: (x) => { p = x },
    setPeersDirect: (x) => { p = x }, upsertPeer: (pk, patch) => { p[pk] = { ...(p[pk] || {}), publickey: pk, ...patch }; return p[pk] },
    onDirty: () => {}
  }
}

/** Un núcleo con una forma de preguntar que decide el test. */
async function nucleo (respuesta) {
  const preguntas = []
  const core = await createIdentityCore({
    kv: kvMemoria(),
    peers: peersMemoria(),
    askConsent: respuesta === undefined ? null : async (q) => { preguntas.push(q); return respuesta }
  })
  return { core, h: core.handlers, preguntas, limpia: () => {} }
}

const pedir = (h, scopes, origin = APP) =>
  h.requestAssertion({ audience: 'https://rep.dotrino.com', nonce: 'n' + Math.random(), scopes, __origin: origin })

test('saber quién eres no cuesta permiso; un dato tuyo, sí', async () => {
  const n = await nucleo(false)   // el usuario diría que no
  const a = await pedir(n.h, ['id:whoami'])
  assert.deepEqual(a.assertion.scopes, ['id:whoami'])
  assert.equal(n.preguntas.length, 0, 'no se pregunta por el mínimo')

  const b = await pedir(n.h, ['id:whoami', 'profile:email'])
  assert.equal(n.preguntas.length, 1, 'por el correo sí se pregunta')
  assert.deepEqual(n.preguntas[0].scopes, ['profile:email'])
  assert.deepEqual(b.assertion.scopes, ['id:whoami'], 'y si dice que no, no sale')
  assert.equal(b.assertion.claims.email, undefined)
  n.limpia()
})

test('lo que concedes se guarda por origen y no se vuelve a preguntar', async () => {
  const n = await nucleo(true)
  await n.h.updateMe({ patch: { nickname: 'Ada', email: 'ada@ejemplo.com' } })

  const a = await pedir(n.h, ['id:whoami', 'profile:name'])
  assert.deepEqual(a.assertion.scopes, ['id:whoami', 'profile:name'])
  assert.equal(a.assertion.claims.name, 'Ada')
  assert.equal(n.preguntas.length, 1)

  const b = await pedir(n.h, ['profile:name'])
  assert.equal(n.preguntas.length, 1, 'ya estaba concedido: no se vuelve a molestar')
  assert.equal(b.assertion.claims.name, 'Ada')

  // Pero un alcance NUEVO sí se pregunta, aunque el origen ya tuviera otros.
  await pedir(n.h, ['profile:name', 'profile:email'])
  assert.equal(n.preguntas.length, 2)
  assert.deepEqual(n.preguntas[1].scopes, ['profile:email'], 'solo lo que falta')
  n.limpia()
})

test('lo concedido es de UN origen, no de todos', async () => {
  const n = await nucleo(true)
  await n.h.updateMe({ patch: { nickname: 'Ada' } })
  await pedir(n.h, ['profile:name'], 'https://chat.dotrino.com')
  assert.equal(n.preguntas.length, 1)
  await pedir(n.h, ['profile:name'], 'https://otra.dotrino.com')
  assert.equal(n.preguntas.length, 2, 'otra aplicación, otra pregunta')
  n.limpia()
})

test('se puede ver y retirar, que es lo que hace que conceder signifique algo', async () => {
  const n = await nucleo(true)
  await n.h.updateMe({ patch: { nickname: 'Ada', email: 'ada@ejemplo.com' } })
  await pedir(n.h, ['profile:name', 'profile:email'])

  const lista = await n.h.listGrants()
  assert.equal(lista.length, 1)
  assert.equal(lista[0].origin, APP)
  assert.deepEqual(lista[0].scopes, ['profile:email', 'profile:name'])

  assert.deepEqual(await n.h.revokeGrant({ origin: APP }), { ok: true })
  assert.deepEqual(await n.h.listGrants(), [])
  assert.deepEqual(await n.h.revokeGrant({ origin: 'https://nadie.dotrino.com' }), { ok: false })

  // Y tras retirarlo se vuelve a preguntar.
  await pedir(n.h, ['profile:name'])
  assert.equal(n.preguntas.length, 2)
  n.limpia()
})

test('sin nadie a quien preguntar, la respuesta es NO (y no se amplía en silencio)', async () => {
  const n = await nucleo(undefined)   // sin `askConsent`: el caso de Node
  await n.h.updateMe({ patch: { nickname: 'Ada', email: 'ada@ejemplo.com' } })
  const a = await pedir(n.h, ['id:whoami', 'profile:email'])
  assert.deepEqual(a.assertion.scopes, ['id:whoami'])
  assert.equal(a.assertion.claims.email, undefined, 'el correo no sale porque nadie lo concedió')
  n.limpia()
})

test('sin origen tampoco se amplía: no habría a quién apuntarle lo concedido', async () => {
  const n = await nucleo(true)
  await n.h.updateMe({ patch: { email: 'ada@ejemplo.com' } })
  const a = await n.h.requestAssertion({ audience: 'https://rep.dotrino.com', nonce: 'x', scopes: ['id:whoami', 'profile:email'] })
  assert.deepEqual(a.assertion.scopes, ['id:whoami'])
  assert.equal(n.preguntas.length, 0)
  n.limpia()
})
