/**
 * Almacén del peer book del vault (nicknames + ratings + endorsements firmados).
 *
 * Migrado de localStorage (~5 MB de techo, compartido) a IndexedDB (cuota grande,
 * non-evictable con `persist()`), porque el peer book crece con los contactos y,
 * sobre todo, con los endorsements del registro de reputación. Patrón idéntico
 * al del store del ecosistema:
 *   - `_peers` en memoria es la fuente de verdad en runtime.
 *   - `loadPeers()` es SÍNCRONA (lee la cache) → los handlers del vault no cambian.
 *   - `initPeerStorage()` (async, en el bootstrap) la rellena desde IndexedDB,
 *     MIGRANDO una sola vez del localStorage viejo. Si IndexedDB no está (modo
 *     privado) cae a localStorage para no perder función.
 *   - `savePeers()` actualiza la cache y hace write-through async a IndexedDB.
 *
 * El módulo es independiente del resto del vault (testeable en aislamiento).
 */

export const PEERS_STORAGE = 'dotrino.identity.peers' // clave del localStorage VIEJO (migración/fallback)
const IDB_NAME = 'cc-identity'
const IDB_STORE = 'kv'
const IDB_PEERS_KEY = 'peers.v1'
// Flag de reconciliación one-time. Distingue "IndexedDB vacío porque ya
// migramos y el usuario no tiene peers" de "vacío porque nunca migramos (o un
// bug previo escribió {} y enmascaró la migración)". Sin esto, un `{}` escrito
// por error quedaba como objeto truthy y la migración NO se reintentaba jamás,
// perdiendo contactos que SIGUEN intactos en el localStorage viejo.
const IDB_MIGRATED_KEY = 'peers.migrated.v1'

let _peers = {}
let _fallback = false
let _idb = null
let _writeChain = Promise.resolve()
let _markDirty = null
let _pid = null

/** Registra el callback que marca el estado como "sucio" para el sync. */
export function onDirty (fn) { _markDirty = fn }

/** Multi-perfil: namespacea el peer book por perfil. El core lo llama antes de initPeerStorage. */
export function setProfile (pid) { _pid = pid || null }
function peersKey () { return _pid ? `peers.${_pid}.v1` : IDB_PEERS_KEY }

function openIdb () {
  return new Promise((resolve, reject) => {
    let req
    try { req = indexedDB.open(IDB_NAME, 1) } catch (e) { reject(e); return }
    req.onupgradeneeded = () => {
      const db = req.result
      if (!db.objectStoreNames.contains(IDB_STORE)) db.createObjectStore(IDB_STORE)
    }
    req.onsuccess = () => resolve(req.result)
    req.onerror = () => reject(req.error)
  })
}
function idbGet (db, key) {
  return new Promise((resolve, reject) => {
    const tx = db.transaction(IDB_STORE, 'readonly')
    const r = tx.objectStore(IDB_STORE).get(key)
    r.onsuccess = () => resolve(r.result)
    r.onerror = () => reject(r.error)
  })
}
function idbPut (db, key, val) {
  return new Promise((resolve, reject) => {
    const tx = db.transaction(IDB_STORE, 'readwrite')
    tx.objectStore(IDB_STORE).put(val, key)
    tx.oncomplete = () => resolve()
    tx.onerror = () => reject(tx.error)
  })
}

function readLocalPeers () {
  try { const raw = localStorage.getItem(PEERS_STORAGE); return raw ? (JSON.parse(raw) || {}) : {} }
  catch (_) { return {} }
}

export async function initPeerStorage () {
  try { if (typeof navigator !== 'undefined' && navigator.storage?.persist) await navigator.storage.persist() }
  catch (_) { /* best-effort */ }
  try {
    _idb = await openIdb()
    const stored = await idbGet(_idb, peersKey()) // peer book DEL perfil activo (namespaceado)
    _peers = (stored && typeof stored === 'object') ? stored : {}
  } catch (e) {
    console.warn('[cc-identity] IndexedDB no disponible, uso localStorage:', e?.message)
    _fallback = true
    _idb = null
    try { const raw = localStorage.getItem(peersKey()); _peers = raw ? (JSON.parse(raw) || {}) : {} }
    catch (_) { _peers = {} }
  }
  return _peers
}

function persistPeers () {
  const key = peersKey()
  if (_fallback || !_idb) {
    try { localStorage.setItem(key, JSON.stringify(_peers)) }
    catch (e) { console.warn('[cc-identity] persist (ls) falló:', e?.message) }
    return _writeChain
  }
  const snapshot = _peers
  _writeChain = _writeChain
    .then(() => idbPut(_idb, key, snapshot))
    .catch(e => console.warn('[cc-identity] persist (idb) falló:', e?.message))
  return _writeChain
}

/** Promesa que resuelve cuando se completaron los write-through pendientes (tests). */
export function flushPeers () { return _writeChain }

export function loadPeers () { return _peers }

export function savePeers (peers) {
  _peers = peers
  persistPeers()
  if (_markDirty) _markDirty()
}

/** Escritura directa (merge del sync): persiste sin marcar dirty. */
export function setPeersDirect (peers) {
  _peers = peers
  persistPeers()
}

export function upsertPeer (publickey, patch) {
  const peers = loadPeers()
  const existing = peers[publickey] || { publickey, firstSeen: Date.now() }
  peers[publickey] = { ...existing, ...patch, publickey, lastSeen: Date.now() }
  savePeers(peers)
  return peers[publickey]
}

// Sólo para tests: resetea el estado del módulo (y cierra la conexión IDB).
export function _resetForTest () {
  try { if (_idb && _idb.close) _idb.close() } catch (_) {}
  _peers = {}; _fallback = false; _idb = null; _writeChain = Promise.resolve(); _markDirty = null; _pid = null
}
