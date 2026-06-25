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
  PEERS_STORAGE, setProfile, initPeerStorage, loadPeers, savePeers, setPeersDirect, upsertPeer,
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

test('multi-perfil: setProfile namespacea el peer book (aislamiento por perfil)', async () => {
  // Perfil p1: un contacto.
  setProfile('p1')
  await initPeerStorage()
  upsertPeer('pkA', { nickname: 'Alice' })
  await flushPeers()

  // Perfil p2: peer book vacío (aislado de p1).
  _resetForTest()
  setProfile('p2')
  await initPeerStorage()
  assert.deepStrictEqual(loadPeers(), {})
  upsertPeer('pkB', { nickname: 'Bob' })
  await flushPeers()

  // Volver a p1: conserva SU peer book y NO ve el de p2.
  _resetForTest()
  setProfile('p1')
  await initPeerStorage()
  assert.strictEqual(loadPeers().pkA?.nickname, 'Alice')
  assert.ok(!loadPeers().pkB)
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
    ls.setItem('peers.v1', JSON.stringify({ pkD: { publickey: 'pkD' } })) // clave del perfil por defecto
    await initPeerStorage()
    assert.strictEqual(loadPeers().pkD?.publickey, 'pkD') // leyó de localStorage
    upsertPeer('pkE', { nickname: 'Eve' })
    // En fallback persiste en localStorage de inmediato.
    const persisted = JSON.parse(ls.getItem('peers.v1'))
    assert.strictEqual(persisted.pkE?.nickname, 'Eve')
  } finally {
    globalThis.indexedDB = realIdb
  }
})
