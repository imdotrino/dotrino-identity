/**
 * Dotrino Identity — adaptador headless para Node.js.
 *
 * Expone la MISMA API pública que el cliente de navegador (`./index.js`), pero
 * sin iframe ni postMessage: llama directamente a los handlers de
 * `../vault/core.js`. El keypair, `me`, los nonces y el peer book se persisten
 * en archivos JSON dentro de un directorio por identidad, de modo que cada
 * directorio es un "usuario" distinto y estable entre ejecuciones.
 *
 * La criptografía es byte-idéntica a la del vault del navegador (mismo core),
 * así que un bot Node es plenamente interoperable con usuarios reales:
 * firmas verificables por el proxy e `identify`, y cifrado E2E (ECDH+AES-GCM)
 * descifrable por la app web y viceversa.
 *
 * Requiere Node ≥ 20 (crypto.subtle, btoa/atob, TextEncoder globales).
 */

import fs from 'node:fs'
import path from 'node:path'
import os from 'node:os'
import { createIdentityCore } from '../vault/core.js'

/** kv síncrono respaldado por un archivo JSON (estilo localStorage). */
function fileKv (filePath) {
  let data = {}
  try {
    if (fs.existsSync(filePath)) data = JSON.parse(fs.readFileSync(filePath, 'utf8')) || {}
  } catch (_) { data = {} }
  const flush = () => {
    fs.mkdirSync(path.dirname(filePath), { recursive: true })
    fs.writeFileSync(filePath, JSON.stringify(data))
  }
  return {
    getItem: (k) => (k in data ? data[k] : null),
    setItem: (k, v) => { data[k] = String(v); flush() },
    removeItem: (k) => { delete data[k]; flush() }
  }
}

/** Peer book respaldado por un archivo JSON (interfaz de vault/peerStore.js). */
function filePeers (filePath) {
  let peers = {}
  let markDirty = null
  let pid = null // multi-perfil: el peer book se namespacea por perfil
  const fileFor = () => pid ? path.join(path.dirname(filePath), `peers.${pid}.json`) : filePath
  const flush = () => {
    const f = fileFor()
    fs.mkdirSync(path.dirname(f), { recursive: true })
    fs.writeFileSync(f, JSON.stringify(peers))
  }
  return {
    setProfile (p) { pid = p || null },
    async initPeerStorage () {
      const f = fileFor()
      try {
        peers = (fs.existsSync(f)) ? (JSON.parse(fs.readFileSync(f, 'utf8')) || {}) : {}
      } catch (_) { peers = {} }
      return peers
    },
    loadPeers: () => peers,
    savePeers: (next) => { peers = next; flush(); if (markDirty) markDirty() },
    setPeersDirect: (next) => { peers = next; flush() },
    upsertPeer: (publickey, patch) => {
      const existing = peers[publickey] || { publickey, firstSeen: Date.now() }
      peers[publickey] = { ...existing, ...patch, publickey, lastSeen: Date.now() }
      flush()
      if (markDirty) markDirty()
      return peers[publickey]
    },
    onDirty: (fn) => { markDirty = fn }
  }
}

const DEFAULT_DIR = path.join(os.homedir(), '.dotrino', 'identity')

export class Identity {
  /**
   * @param {Object} [options]
   * @param {string} [options.dir]  Directorio de persistencia de esta identidad.
   *   Cada directorio = un usuario distinto. Default: ~/.dotrino/identity
   */
  constructor (options = {}) {
    this._dir = options.dir || DEFAULT_DIR
    this._core = null
    this._listeners = new Map()
  }

  /**
   * Crea/abre una identidad headless. A diferencia del navegador NO es singleton:
   * cada `dir` distinto devuelve una identidad independiente (para correr muchos
   * bots-usuario en el mismo proceso).
   */
  static async connect (options = {}) {
    const inst = new Identity(options)
    await inst.ready()
    return inst
  }

  async ready () {
    if (this._core) return this
    this._core = await createIdentityCore({
      kv: fileKv(path.join(this._dir, 'identity.json')),
      peers: filePeers(path.join(this._dir, 'peers.json')),
      makeSync: null
    })
    this._core.onSyncStatus((payload) => this._emit('sync', payload))
    this._core.onVaultEvent((payload) => this._emit('vault', payload))
    return this
  }

  destroy () { this._core = null }

  get me () { return this._core?.me || null }

  _h (method, params = {}) {
    if (!this._core) throw new Error('Identity not ready — call ready()/connect() first')
    return this._core.handlers[method](params)
  }

  // ----- API pública (espeja src/index.js) -----

  makeChallenge () { return this._h('makeChallenge') }
  signChallenge (nonce) { return this._h('signChallenge', { nonce }) }
  verifyResponse ({ nonce, publickey, signature, encryptionPubkey }) {
    return this._h('verifyResponse', { nonce, publickey, signature, encryptionPubkey })
  }
  getPeer (publickey) { return this._h('getPeer', { publickey }) }
  setNickname (publickey, nickname) { return this._h('setNickname', { publickey, nickname }) }
  setRating (publickey, rating, notes) { return this._h('setRating', { publickey, rating, notes }) }
  listPeers () { return this._h('listPeers') }
  forgetPeer (publickey) { return this._h('forgetPeer', { publickey }) }
  addContact ({ publickey, nickname, encryptionPubkey, lastToken, notes } = {}) {
    return this._h('addContact', { publickey, nickname, encryptionPubkey, lastToken, notes })
  }
  updateContact (publickey, patch) { return this._h('updateContact', { publickey, patch }) }
  removeContact (publickey) { return this._h('removeContact', { publickey }) }
  listContacts () { return this._h('listContacts') }
  signData (data) { return this._h('signData', { data }) }
  // Delegación de capacidad (sub-clave de dispositivo con scope/exp/revocación)
  signDelegation (sub, scope, opts = {}) { return this._h('signDelegation', { sub, scope, ...opts }) }
  revokeDelegation (nonce) { return this._h('revokeDelegation', { nonce }) }
  listDelegations () { return this._h('listDelegations') }
  // Emparejar ESTE dispositivo con el vault del usuario (Fase 1)
  enrollDevice (qr) { return this._h('vaultPair', { qr }) }
  vaultStatus () { return this._h('vaultStatus') }
  unpairDevice () { return this._h('vaultUnpair') }
  vaultSign (payload) { return this._h('vaultSign', { payload }) }
  vaultStore (method, args) { return this._h('vaultStore', { method, args }) }
  listVaultDevices () { return this._h('listVaultDevices') }
  getVaultCert () { return this._h('getVaultCert') }
  onVault (handler) { return this.on('vault', handler) }
  // Multi-perfil por dispositivo (crear/cambiar reinicializa con el nuevo perfil activo).
  listProfiles () { return this._h('listProfiles') }
  currentProfile () { return this._h('currentProfile') }
  createProfile (name) { return this._h('createProfile', { name }) }
  switchProfile (id) { return this._h('switchProfile', { id }) }
  renameProfile (id, name) { return this._h('renameProfile', { id, name }) }
  deleteProfile (id) { return this._h('deleteProfile', { id }) }
  mergeEndorsements (subject, endorsements, askerPubkey) {
    return this._h('mergeEndorsements', { subject, endorsements, askerPubkey })
  }
  getRatingsForSubject (subject) { return this._h('getRatingsForSubject', { subject }) }
  recordQuery (askerPubkey, subject) { return this._h('recordQuery', { askerPubkey, subject }) }
  async setMyNickname (nickname) {
    const result = await this._h('setMyNickname', { nickname })
    return result
  }
  getEncryptionPubkey () { return this._h('getEncryptionPubkey') }
  encrypt (recipients, plaintext) { return this._h('encrypt', { recipients, plaintext }) }
  decrypt (senderEncryptionPubkey, myToken, envelope) {
    return this._h('decrypt', { senderEncryptionPubkey, myToken, envelope })
  }
  exportIdentity () { return this._h('exportIdentity') }
  async importIdentity (blob) { return this._h('importIdentity', blob || {}) }

  // Sync (Google Drive) no disponible headless — los handlers responden acorde.
  syncConnect (clientId) { return this._h('syncConnect', { clientId }) }
  syncDisconnect () { return this._h('syncDisconnect') }
  syncUnlock (passphrase) { return this._h('syncUnlock', { passphrase }) }
  syncLock () { return this._h('syncLock') }
  syncStatus () { return this._h('syncStatus') }
  syncNow () { return this._h('syncNow') }

  onSync (handler) { return this.on('sync', handler) }
  on (event, handler) {
    if (!this._listeners.has(event)) this._listeners.set(event, new Set())
    this._listeners.get(event).add(handler)
    return () => this._listeners.get(event)?.delete(handler)
  }
  _emit (event, payload) {
    const set = this._listeners.get(event)
    if (!set) return
    for (const h of set) { try { h(payload) } catch (e) { console.error(e) } }
  }
}

export default Identity

// Helpers de capacidad SIN clave maestra (lado dispositivo + verificación), para que
// un bridge/bot Node pueda crear su clave, firmar acciones y verificar cadenas D←P.
export { makeDeviceKey, signWithDevice, verifyDelegation, verifyChain, pubkeyId, deriveSAS, verifyDeviceSig, makePairingCode, commitCode, avatarSvg, avatarDataUri, MAX_DELEGATION_MS, DEFAULT_DELEGATION_MS } from '../vault/capabilities.js'
