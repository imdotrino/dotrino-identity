// Test del almacén del peer book del vault: migración localStorage → IndexedDB,
// carga desde IDB, write-through, y fallback a localStorage si IDB no está.
// Usa fake-indexeddb y un mock de localStorage/navigator.

import 'fake-indexeddb/auto'
import { test, beforeEach } from 'node:test'
import assert from 'node:assert'

// Mocks de entorno de navegador, antes de importar el módulo.
const ls = {
  _d: {},
  getItem (k) { return k in this._d ? this._d[k] : null },
  setItem (k, v) { this._d[k] = String(v) },
  removeItem (k) { delete this._d[k] },
  clear () { this._d = {} }
}
globalThis.localStorage = ls
// navigator es read-only en Node y el módulo ya protege navigator.storage?.persist

const {
  PEERS_STORAGE, initPeerStorage, loadPeers, savePeers, setPeersDirect, upsertPeer,
  onDirty, flushPeers, _resetForTest
} = await import('../vault/peerStore.js')

function deleteDb (name) {
  return new Promise((resolve) => {
    const r = indexedDB.deleteDatabase(name)
    r.onsuccess = r.onerror = r.onblocked = () => resolve()
  })
}

// Escribe directo en IndexedDB (sin pasar por el módulo) para simular estados
// previos, p.ej. el bug que dejaba peers.v1={} sin flag de migración.
function rawIdbPut (key, val) {
  return new Promise((resolve, reject) => {
    const req = indexedDB.open('cc-identity', 1)
    req.onupgradeneeded = () => {
      const db = req.result
      if (!db.objectStoreNames.contains('kv')) db.createObjectStore('kv')
    }
    req.onsuccess = () => {
      const db = req.result
      const tx = db.transaction('kv', 'readwrite')
      tx.objectStore('kv').put(val, key)
      tx.oncomplete = () => { db.close(); resolve() }
      tx.onerror = () => reject(tx.error)
    }
    req.onerror = () => reject(req.error)
  })
}

beforeEach(async () => {
  _resetForTest()
  ls.clear()
  await deleteDb('cc-identity')
})

test('migra el peer book del localStorage viejo a IndexedDB (one-time)', async () => {
  const seed = { pkA: { publickey: 'pkA', myRating: { rating: 5 } } }
  ls.setItem(PEERS_STORAGE, JSON.stringify(seed))

  await initPeerStorage()
  assert.deepStrictEqual(loadPeers(), seed)              // cargado en memoria
  await flushPeers()
  // El localStorage viejo se conserva (rollback seguro).
  assert.ok(ls.getItem(PEERS_STORAGE))

  // Una segunda init NO debe re-migrar: lee de IDB aunque cambie el localStorage.
  _resetForTest()
  ls.setItem(PEERS_STORAGE, JSON.stringify({ otro: { publickey: 'otro' } }))
  await initPeerStorage()
  assert.deepStrictEqual(loadPeers(), seed)              // gana lo de IDB, ignora el LS nuevo
})

test('recupera contactos si un bug previo dejó IndexedDB en {} sin flag', async () => {
  // Estado del bug: peers.v1={} en IDB y SIN flag, pero los contactos siguen
  // en el localStorage viejo (la migración no lo borra).
  const seed = { pkX: { publickey: 'pkX', nickname: 'Zoe', isContact: true } }
  ls.setItem(PEERS_STORAGE, JSON.stringify(seed))
  await rawIdbPut('peers.v1', {})

  await initPeerStorage()
  assert.deepStrictEqual(loadPeers(), seed)              // recuperado del localStorage
  await flushPeers()

  // Reconciliación one-time: una segunda init ya NO mira el localStorage.
  _resetForTest()
  ls.setItem(PEERS_STORAGE, JSON.stringify({ pkY: { publickey: 'pkY' } }))
  await initPeerStorage()
  assert.deepStrictEqual(loadPeers(), seed)              // IDB manda, ignora LS nuevo
})

test('savePeers/upsertPeer hacen write-through a IndexedDB', async () => {
  await initPeerStorage()
  upsertPeer('pkB', { nickname: 'Bob' })
  await flushPeers()

  // Reabrir desde cero: debe leer lo persistido en IDB.
  _resetForTest()
  await initPeerStorage()
  assert.strictEqual(loadPeers().pkB?.nickname, 'Bob')
})

test('loadPeers devuelve la referencia viva (mutar + savePeers persiste)', async () => {
  await initPeerStorage()
  const p = loadPeers()
  p.pkC = { publickey: 'pkC' }
  savePeers(p)
  await flushPeers()
  _resetForTest()
  await initPeerStorage()
  assert.ok(loadPeers().pkC)
})

test('onDirty se dispara en savePeers pero NO en setPeersDirect', async () => {
  await initPeerStorage()
  let dirty = 0
  onDirty(() => { dirty++ })
  savePeers({ x: { publickey: 'x' } })
  assert.strictEqual(dirty, 1)
  setPeersDirect({ y: { publickey: 'y' } })
  assert.strictEqual(dirty, 1)                            // setPeersDirect no marca dirty
  await flushPeers()
})

test('fallback a localStorage si IndexedDB no está disponible', async () => {
  const realIdb = globalThis.indexedDB
  globalThis.indexedDB = { open () { throw new Error('IDB bloqueado') } }
  try {
    ls.setItem(PEERS_STORAGE, JSON.stringify({ pkD: { publickey: 'pkD' } }))
    await initPeerStorage()
    assert.strictEqual(loadPeers().pkD?.publickey, 'pkD') // leyó de localStorage
    upsertPeer('pkE', { nickname: 'Eve' })
    // En fallback persiste en localStorage de inmediato.
    const persisted = JSON.parse(ls.getItem(PEERS_STORAGE))
    assert.strictEqual(persisted.pkE?.nickname, 'Eve')
  } finally {
    globalThis.indexedDB = realIdb
  }
})
