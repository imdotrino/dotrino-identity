import { test } from 'node:test'
import assert from 'node:assert/strict'
import { syncPeers, stampOf, PEERS_THREAD } from '../vault/peerSync.js'

// Una bóveda de mentira con las reglas del almacén: por id gana la entrada más nueva (ts).
function fakeVault () {
  const t = new Map()
  return async (method, args) => {
    if (method === 'getThreadIndexes') return { indexes: { [PEERS_THREAD]: { items: [...t.values()].map((e) => [e.id, e.ts]), tombs: [] } }, next: null }
    if (method === 'getEntries') return { threads: { [PEERS_THREAD]: (args.refs[PEERS_THREAD] || []).map((id) => t.get(id)).filter(Boolean) }, rest: null }
    if (method === 'importThreads') {
      for (const e of args.threads[PEERS_THREAD] || []) if (!t.has(e.id) || e.ts > t.get(e.id).ts) t.set(e.id, structuredClone(e))
      return { ok: true }
    }
    throw new Error('unexpected ' + method)
  }
}

// Fundir como la identidad: gana la ficha más reciente (stampOf), también para ser contacto.
function mergeInto (book, incoming) {
  for (const r of incoming) {
    const here = book[r.publickey]
    if (!here || stampOf(r) > stampOf(here)) book[r.publickey] = { ...r }
  }
}

test('un contacto de un aparato llega al otro, y quitarlo también llega', async () => {
  const vault = fakeVault()
  const a = { X: { publickey: 'X', nickname: 'Ana', isContact: true, firstSeen: 1, lastSeen: 100 } }
  const b = {}

  assert.equal((await syncPeers({ peers: a, call: vault })).pushed, 1)
  const r1 = await syncPeers({ peers: b, call: vault }); mergeInto(b, r1.incoming)
  assert.equal(b.X.isContact, true)
  assert.equal(b.X.nickname, 'Ana')

  // B lo quita: es un cambio con fecha, y gana sobre la ficha vieja de A.
  delete b.X.isContact; b.X.changedAt = 200
  await syncPeers({ peers: b, call: vault })
  const r2 = await syncPeers({ peers: a, call: vault }); mergeInto(a, r2.incoming)
  assert.equal(a.X.isContact, undefined, 'el contacto quitado no vuelve')

  // Ya al día: nadie sube nada más.
  assert.equal((await syncPeers({ peers: a, call: vault })).pushed, 0)
  assert.equal((await syncPeers({ peers: b, call: vault })).pushed, 0)
})

test('la fecha de una ficha es la última vez que se vio o se tocó', () => {
  assert.equal(stampOf({ lastSeen: 5, changedAt: 9 }), 9)
  assert.equal(stampOf({ lastSeen: 12 }), 12)
  assert.equal(stampOf(null), 0)
})
