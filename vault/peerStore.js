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

/**
 * La ficha de un contacto: `publickey` y lo que sus pantallas apunten (apodo, avatar, fechas).
 * @typedef {{ publickey: string, firstSeen?: number, lastSeen?: number, changedAt?: number } & Record<string, any>} PeerRecord
 */
/** El libro de contactos: pubkey → ficha. @typedef {Record<string, PeerRecord>} PeerBook */
/**
 * Dónde guarda la app el libro (el almacén de la app nativa).
 * @typedef {{ get (key: string): Promise<any>, put (key: string, val: any): Promise<void> }} PeerBackend
 */

/** @type {PeerBook} */
let _peers = {}
let _fallback = false
/** @type {IDBDatabase | null} */
let _idb = null
/** @type {Promise<void>} */
let _writeChain = Promise.resolve()
/** @type {(() => void) | null} */
let _markDirty = null
/** @type {string | null} */
let _pid = null
/**
 * La cuenta abierta es VOLÁTIL (se entró con usuario y contraseña sin «Recordar»): sus
 * contactos viven en memoria y no se escriben en ninguna parte. Dejar el libro de contactos
 * de alguien en el disco de un equipo prestado sería justo lo que esa forma de entrar
 * promete no hacer.
 */
let _volatile = false

/**
 * Otro almacén para el libro, en vez del IndexedDB de la página: el de la app de iOS
 * (`nativeStore.js`), que es uno para todas las páginas. `{ get(key), put(key, val) }`.
 * Se pone antes de `initPeerStorage`.
 */
/** @type {PeerBackend | null} */
let _backend = null
/** @param {PeerBackend | null | undefined} b */
export function useBackend (b) { _backend = b || null }

/**
 * Registra el callback que marca el estado como "sucio" para el sync.
 * @param {(() => void) | null} fn
 */
export function onDirty (fn) { _markDirty = fn }

/**
 * Multi-perfil: namespacea el peer book por perfil. El core lo llama antes de initPeerStorage.
 * @param {string | null | undefined} pid
 * @param {{ volatile?: boolean }} [opts]
 */
export function setProfile (pid, { volatile: esVolatil = false } = {}) {
  _pid = pid || null
  _volatile = !!esVolatil
  if (_volatile) _peers = {}   // se entra sin contactos y se sale sin dejarlos
}
function peersKey () { return _pid ? `peers.${_pid}.v1` : IDB_PEERS_KEY }

/**
 * Migración: copia el peer book VIEJO (pre-multi-perfil, sin namespace) al perfil `pid`.
 * @param {string} pid
 */
export async function adoptLegacy (pid) {
  if (_backend) return   // el almacén de la app nació después: no hay libro viejo que adoptar
  try {
    _idb = _idb || await openIdb()
    let legacy = await idbGet(_idb, IDB_PEERS_KEY) // 'peers.v1' (viejo)
    if (!legacy || typeof legacy !== 'object' || !Object.keys(legacy).length) {
      try { const raw = localStorage.getItem(PEERS_STORAGE); legacy = raw ? JSON.parse(raw) : null } catch (_) { legacy = null }
    }
    if (legacy && typeof legacy === 'object' && Object.keys(legacy).length) {
      await idbPut(_idb, `peers.${pid}.v1`, legacy)
    }
  } catch (_) { /* sin peers viejos que adoptar */ }
}

/** @returns {Promise<IDBDatabase>} */
function openIdb () {
  return new Promise((resolve, reject) => {
    /** @type {IDBOpenDBRequest} */
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
/** @param {IDBDatabase} db @param {string} key @returns {Promise<any>} */
function idbGet (db, key) {
  return new Promise((resolve, reject) => {
    const tx = db.transaction(IDB_STORE, 'readonly')
    const r = tx.objectStore(IDB_STORE).get(key)
    r.onsuccess = () => resolve(r.result)
    r.onerror = () => reject(r.error)
  })
}
/** @param {IDBDatabase} db @param {string} key @param {any} val @returns {Promise<void>} */
function idbPut (db, key, val) {
  return new Promise(/** @param {(v?: void) => void} resolve @param {(e: unknown) => void} reject */ (resolve, reject) => {
    const tx = db.transaction(IDB_STORE, 'readwrite')
    tx.objectStore(IDB_STORE).put(val, key)
    tx.oncomplete = () => resolve()
    tx.onerror = () => reject(tx.error)
  })
}

/** @returns {PeerBook} */
function readLocalPeers () {
  try { const raw = localStorage.getItem(PEERS_STORAGE); return raw ? (JSON.parse(raw) || {}) : {} }
  catch (_) { return {} }
}

/** @returns {Promise<PeerBook>} */
export async function initPeerStorage () {
  try { if (typeof navigator !== 'undefined' && navigator.storage?.persist) await navigator.storage.persist() }
  catch (_) { /* best-effort */ }
  if (_volatile) { _peers = {}; return _peers }
  if (_backend) {
    const stored = await _backend.get(peersKey())
    _peers = (stored && typeof stored === 'object') ? stored : {}
    return _peers
  }
  try {
    _idb = await openIdb()
    const stored = await idbGet(_idb, peersKey()) // peer book DEL perfil activo (namespaceado)
    _peers = (stored && typeof stored === 'object') ? stored : {}
  } catch (e) {
    console.warn('[cc-identity] IndexedDB unavailable, falling back to localStorage:', /** @type {{ message?: string } | null} */ (e)?.message)
    _fallback = true
    _idb = null
    try { const raw = localStorage.getItem(peersKey()); _peers = raw ? (JSON.parse(raw) || {}) : {} }
    catch (_) { _peers = {} }
  }
  return _peers
}

/** @returns {Promise<void>} */
function persistPeers () {
  if (_volatile) return _writeChain   // cuenta volátil: en memoria y en ningún disco
  const key = peersKey()
  if (_backend) {
    const snapshot = _peers
    _writeChain = _writeChain
      .then(() => /** @type {PeerBackend} */ (_backend).put(key, snapshot))
      .catch(e => console.warn('[cc-identity] persist (app) failed:', e?.message))
    return _writeChain
  }
  if (_fallback || !_idb) {
    try { localStorage.setItem(key, JSON.stringify(_peers)) }
    catch (e) { console.warn('[cc-identity] persist (ls) failed:', /** @type {{ message?: string } | null} */ (e)?.message) }
    return _writeChain
  }
  const snapshot = _peers
  _writeChain = _writeChain
    .then(() => idbPut(/** @type {IDBDatabase} */ (_idb), key, snapshot))
    .catch(e => console.warn('[cc-identity] persist (idb) failed:', e?.message))
  return _writeChain
}

/**
 * Promesa que resuelve cuando se completaron los write-through pendientes (tests).
 * @returns {Promise<void>}
 */
export function flushPeers () { return _writeChain }

/** @returns {PeerBook} */
export function loadPeers () { return _peers }

/** @param {PeerBook} peers */
export function savePeers (peers) {
  _peers = peers
  persistPeers()
  if (_markDirty) _markDirty()
}

/**
 * Escritura directa (merge del sync): persiste sin marcar dirty.
 * @param {PeerBook} peers
 */
export function setPeersDirect (peers) {
  _peers = peers
  persistPeers()
}

/**
 * @param {string} publickey
 * @param {Record<string, any>} patch
 * @returns {PeerRecord}
 */
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
  _peers = {}; _fallback = false; _idb = null; _writeChain = Promise.resolve(); _markDirty = null; _pid = null; _volatile = false
}
