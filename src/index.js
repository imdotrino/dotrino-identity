/**
 * Dotrino Identity client.
 *
 * Loads a hidden iframe pointing at the vault origin and exchanges
 * postMessage requests. The vault holds the user's keypair and the
 * peer ratings/nicknames in its own localStorage, so all apps that
 * use this library share identity even across different origins.
 */

const DEFAULT_VAULT_URL = 'https://id.dotrino.com/'

let singleton = null

export class Identity {
  constructor (options = {}) {
    this.vaultUrl = options.vaultUrl || DEFAULT_VAULT_URL
    this.timeoutMs = options.timeoutMs ?? 5000
    this._iframe = null
    this._ready = null
    this._readyResolve = null
    this._nextId = 1
    this._pending = new Map()
    this._handler = null
    this._me = null
  }

  static async connect (options = {}) {
    if (!singleton) singleton = new Identity(options)
    // Esperar SIEMPRE a ready(): si otro caller creó el singleton pero su
    // handshake con el vault aún no resolvió, devolver el singleton "pelado"
    // dejaba `me` en null y las apps no encontraban el nickname (carrera).
    // ready() es idempotente (devuelve la misma promesa), así que esto es
    // seguro de llamar en cada connect().
    await singleton.ready()
    return singleton
  }

  static current () {
    return singleton
  }

  ready () {
    if (this._ready) return this._ready

    this._ready = new Promise((resolve, reject) => {
      this._readyResolve = resolve

      const iframe = document.createElement('iframe')
      iframe.src = this.vaultUrl
      iframe.style.display = 'none'
      iframe.setAttribute('aria-hidden', 'true')
      iframe.setAttribute('title', 'Dotrino identity vault')
      iframe.referrerPolicy = 'origin'
      this._iframe = iframe

      const timeout = setTimeout(() => {
        reject(new Error(`Vault did not respond within ${this.timeoutMs}ms`))
      }, this.timeoutMs)

      this._handler = (event) => {
        if (event.source !== iframe.contentWindow) return
        const msg = event.data
        if (!msg || msg._cci !== true) return

        if (msg.type === 'ready') {
          clearTimeout(timeout)
          this._me = msg.me
          this._readyResolve(this)
          return
        }

        if (msg.type === 'response') {
          const pending = this._pending.get(msg.id)
          if (!pending) return
          this._pending.delete(msg.id)
          clearTimeout(pending.timer)
          if (msg.error) pending.reject(new Error(msg.error))
          else pending.resolve(msg.result)
          return
        }

        if (msg.type === 'event') {
          this._emit(msg.event, msg.payload)
        }
      }

      window.addEventListener('message', this._handler)
      document.body.appendChild(iframe)
    })

    return this._ready
  }

  destroy () {
    if (this._handler) window.removeEventListener('message', this._handler)
    if (this._iframe && this._iframe.parentNode) this._iframe.parentNode.removeChild(this._iframe)
    this._iframe = null
    this._handler = null
    if (singleton === this) singleton = null
  }

  // ----- public API -----

  get me () { return this._me }

  /**
   * Identify a peer by token: the peer must respond to our challenge by
   * signing it with their private key. The vault holds and applies the rating.
   *
   * The host app is responsible for delivering the challenge to the peer
   * and bringing back the signed response — see makeChallenge / verifyResponse.
   */
  async makeChallenge () {
    return this._call('makeChallenge')
  }

  async signChallenge (nonce) {
    return this._call('signChallenge', { nonce })
  }

  async verifyResponse ({ nonce, publickey, signature }) {
    return this._call('verifyResponse', { nonce, publickey, signature })
  }

  async getPeer (publickey) {
    return this._call('getPeer', { publickey })
  }

  async setNickname (publickey, nickname) {
    return this._call('setNickname', { publickey, nickname })
  }

  async setRating (publickey, rating, notes) {
    return this._call('setRating', { publickey, rating, notes })
  }

  async listPeers () {
    return this._call('listPeers')
  }

  async forgetPeer (publickey) {
    return this._call('forgetPeer', { publickey })
  }

  /**
   * Add (or refresh) a contact in the shared address book. Idempotent —
   * existing peer records are upserted with the new metadata. Contacts are
   * stored alongside the rating/endorsement record for the same pubkey, so
   * any app in the ecosystem (chat, chess, messenger, …) sees the same list.
   */
  async addContact ({ publickey, nickname, encryptionPubkey, lastToken, notes } = {}) {
    return this._call('addContact', { publickey, nickname, encryptionPubkey, lastToken, notes })
  }

  /** Patch contact metadata (nickname / lastToken / encryptionPubkey / contactNotes). */
  async updateContact (publickey, patch) {
    return this._call('updateContact', { publickey, patch })
  }

  /** Remove the `isContact` flag while preserving rating/endorsement history. */
  async removeContact (publickey) {
    return this._call('removeContact', { publickey })
  }

  /** List peers flagged as contacts, sorted by lastSeen desc. */
  async listContacts () {
    return this._call('listContacts')
  }

  /**
   * Sign an arbitrary JSON-serializable payload with the vault's ECDSA key
   * using canonical JSON encoding. Returns `{ signature, publickey }` —
   * compatible with the proxy's `verifySignatureWithJWK` (used by
   * `identify` to bind a stable pubkey to the proxy connection).
   */
  async signData (data) {
    return this._call('signData', { data })
  }

  /**
   * Firma un CERTIFICADO DE DELEGACIÓN: autoriza a una sub-clave de dispositivo
   * `sub` (JWK string) a hacer `scope` en tu nombre, hasta `exp`, revocable por
   * `nonce`. La clave maestra NUNCA sale del vault. `opts`: { ttlMs?, exp?, label?, nonce? }.
   * @returns {Promise<{ cert: object }>}
   */
  async signDelegation (sub, scope, opts = {}) {
    return this._call('signDelegation', { sub, scope, ...opts })
  }

  /** Revoca una delegación por su `nonce` (queda en la lista de revocación). */
  async revokeDelegation (nonce) {
    return this._call('revokeDelegation', { nonce })
  }

  /** Lista las delegaciones emitidas + la lista de revocación (para el gestor de dispositivos). */
  async listDelegations () {
    return this._call('listDelegations')
  }

  // ----- Emparejar ESTE navegador/dispositivo con el vault del usuario (Fase 1) -----

  /**
   * Empareja este dispositivo con el vault del usuario a partir del QR (v2) que
   * muestra `dotrino-vault pair`. Genera la sub-clave D DENTRO del iframe (su privada
   * nunca sale), hace el emparejamiento endurecido por el proxy y guarda el cert.
   * Emite un evento 'vault' { phase:'challenge', deviceId, sas } para que muestres el
   * código a comparar; resuelve cuando el dueño aprueba en su PC (espera hasta 3 min).
   * @returns {Promise<{ ok:boolean, deviceId:string, master:string, exp:number, scope:string[] }>}
   */
  async enrollDevice (qr) {
    return this._call('vaultPair', { qr }, 200000)
  }

  /** Estado de emparejamiento: { paired, deviceId?, master?, scope?, exp?, pairedAt? }. */
  async vaultStatus () {
    return this._call('vaultStatus')
  }

  /** Desvincula este dispositivo del vault (borra la sub-clave + el cert locales). */
  async unpairDevice () {
    return this._call('vaultUnpair')
  }

  /**
   * Firma DELEGADA: pide a la maestra del vault (tu PC) que firme `payload`, usando
   * el cert de este dispositivo. Aditivo y explícito — NO cambia `signData` (local).
   * Requiere estar emparejado y el vault encendido. Devuelve { signature, publickey }
   * donde publickey es tu identidad MAESTRA.
   */
  async vaultSign (payload) {
    return this._call('vaultSign', { payload }, 20000)
  }

  /**
   * Store DELEGADO: lee/escribe el store de hilos+aperturas (appendMessage,
   * listThread, recordOpen, getOpens, getStats, …) EN tu vault, usando el cert de
   * este dispositivo. Reusa el mismo emparejamiento. Requiere el vault encendido.
   */
  async vaultStore (method, args) {
    return this._call('vaultStore', { method, args }, 20000)
  }

  /** Lista (solo lectura) los dispositivos enrolados en tu vault: { devices, revoked }. */
  async listVaultDevices () {
    return this._call('listVaultDevices', {}, 20000)
  }

  /**
   * El cert de delegación de este dispositivo (o null si no está emparejado). El
   * transporte lo presenta al proxy en `identify` → "una identidad": el proxy enruta
   * los mensajes dirigidos a tu maestra M también a este dispositivo. No tiene secretos.
   */
  async getVaultCert () {
    return this._call('getVaultCert')
  }

  /** Suscribe a eventos de emparejamiento ('vault'): { phase:'challenge'|'paired'|'unpaired', ... }. */
  onVault (handler) {
    return this.on('vault', handler)
  }

  // ----- multi-perfil por dispositivo -----
  // Podés tener varios perfiles (identidades) en el mismo navegador, cada uno conectado o no
  // a su propio vault. Crear/cambiar setea el perfil activo; la app RECARGA la página y toma
  // el nuevo (no reactivo: las apps abiertas conservan el perfil con el que cargaron).
  /** Lista de perfiles: [{ id, name, pubkey, current }]. */
  async listProfiles () { return this._call('listProfiles') }
  /** El perfil activo: { id, name, pubkey }. */
  async currentProfile () { return this._call('currentProfile') }
  /** Crea un perfil nuevo (identidad fresca) y lo deja activo. La app debe recargar. */
  async createProfile (name) { return this._call('createProfile', { name }) }
  /** Cambia el perfil activo. La app debe recargar la página. */
  async switchProfile (id) { return this._call('switchProfile', { id }) }
  /** Renombra un perfil (o el activo si no se pasa id). */
  async renameProfile (id, name) { return this._call('renameProfile', { id, name }) }
  /** Borra un perfil y sus datos (no el único). */
  async deleteProfile (id) { return this._call('deleteProfile', { id }) }

  /**
   * Merge endorsements (signed ratings from third parties) about a subject
   * into the local peer book. Returns { merged, total }.
   */
  async mergeEndorsements (subject, endorsements, askerPubkey) {
    return this._call('mergeEndorsements', { subject, endorsements, askerPubkey })
  }

  /**
   * Return what this vault knows about a subject for the purpose of
   * answering a RATING_QUERY: { mine: signedEnvelopeOrNull, endorsements: [] }.
   */
  async getRatingsForSubject (subject) {
    return this._call('getRatingsForSubject', { subject })
  }

  /**
   * Record that a peer asked us about a subject. Used for suspicion stats.
   */
  async recordQuery (askerPubkey, subject) {
    return this._call('recordQuery', { askerPubkey, subject })
  }

  /** Update own nickname (broadcast to the vault, not to other apps automatically) */
  async setMyNickname (nickname) {
    const result = await this._call('setMyNickname', { nickname })
    if (result?.me) this._me = result.me
    return result
  }

  /**
   * Actualiza tu PERFIL (merge): `{ nickname?, avatar?, avatarVisible?, links?, fields?,
   * nombres?, apellidos?, email?, telefono?, direccion? }` (+ sus flags `<campo>Visible`).
   * `avatar` = data-URI 250×250 (o null para quitarla); `links`/`fields` = arrays con `visible`
   * por ítem (oculto = no se comparte). `telefono`/`direccion` son sensibles: ocultos por
   * defecto (solo se comparten si su flag === true). No pisa lo que no mandes.
   */
  async updateMe (patch) {
    const result = await this._call('updateMe', { patch })
    if (result?.me) this._me = result.me
    return result
  }

  /** Tu `me` completo (incluye ocultos). */
  async getMe () { return this._call('getMe') }
  /** Subconjunto PÚBLICO de tu perfil (solo lo visible) — para compartir/publicar. */
  async publicMe () { return this._call('publicMe') }

  /** Pubkey ECDH (JWK string) propio para encripción. */
  async getEncryptionPubkey () {
    return this._call('getEncryptionPubkey')
  }

  /**
   * Cifra `plaintext` para una lista de destinatarios usando ECDH+AES-GCM.
   * @param {Array<{token:string, encryptionPubkey:string}>} recipients
   * @param {string} plaintext
   * @returns {Promise<Object>} Envelope { v, iv, ct, wrap }
   */
  async encrypt (recipients, plaintext) {
    return this._call('encrypt', { recipients, plaintext })
  }

  /**
   * Descifra un envelope dirigido a este vault.
   * @param {string} senderEncryptionPubkey JWK string del emisor
   * @param {string} myToken token efímero al que iba dirigido el wrap
   * @param {Object} envelope
   */
  async decrypt (senderEncryptionPubkey, myToken, envelope) {
    return this._call('decrypt', { senderEncryptionPubkey, myToken, envelope })
  }

  /**
   * Export the full identity (private key + peer book) as a JSON-serializable object.
   * The blob can be saved to a file by the host app and re-imported later.
   * The private key is sensitive — handle accordingly.
   */
  async exportIdentity () {
    return this._call('exportIdentity')
  }

  /**
   * Import a previously exported identity blob, replacing the current one.
   * Throws if the blob is malformed or keys are invalid.
   */
  async importIdentity (blob) {
    const result = await this._call('importIdentity', blob)
    if (result?.me) this._me = result.me
    return result
  }

  // ----- Auto-sync (Google Drive encrypted backup) -----

  /**
   * Connect a Google account for encrypted backup to Drive's appDataFolder.
   * Pops up a Google sign-in window. `clientId` is your Google OAuth Web client ID
   * with Authorized JavaScript Origin = the vault origin (id.dotrino.com).
   */
  async syncConnect (clientId) {
    return this._call('syncConnect', { clientId })
  }

  async syncDisconnect () {
    return this._call('syncDisconnect')
  }

  /**
   * Unlock auto-sync by providing the passphrase used to encrypt the backup.
   * Must be ≥ 8 chars. After unlock the sync engine pulls remote, merges,
   * and pushes on every local change (debounced).
   */
  async syncUnlock (passphrase) {
    return this._call('syncUnlock', { passphrase })
  }

  async syncLock () {
    return this._call('syncLock')
  }

  /** { connected, unlocked, dirty, lastError } */
  async syncStatus () {
    return this._call('syncStatus')
  }

  /** Force an immediate pull-then-push cycle. */
  async syncNow () {
    return this._call('syncNow')
  }

  /**
   * Subscribe to sync status events emitted by the vault. Handler receives
   * `{ kind, status, error?, ts }` where status is one of
   * 'connected' | 'disconnected' | 'unlocked' | 'locked' | 'syncing' |
   * 'synced' | 'conflict' | 'offline' | 'error'.
   */
  onSync (handler) {
    return this.on('sync', handler)
  }

  on (event, handler) {
    if (!this._listeners) this._listeners = new Map()
    if (!this._listeners.has(event)) this._listeners.set(event, new Set())
    this._listeners.get(event).add(handler)
    return () => this._listeners.get(event)?.delete(handler)
  }

  _emit (event, payload) {
    const set = this._listeners?.get(event)
    if (!set) return
    for (const h of set) {
      try { h(payload) } catch (e) { console.error(e) }
    }
  }

  _call (method, params = {}, timeoutMs = this.timeoutMs) {
    return new Promise((resolve, reject) => {
      if (!this._iframe?.contentWindow) {
        return reject(new Error('Vault not ready'))
      }
      const id = `req_${this._nextId++}`
      const timer = setTimeout(() => {
        this._pending.delete(id)
        reject(new Error(`Vault timeout for ${method}`))
      }, timeoutMs)
      this._pending.set(id, { resolve, reject, timer })

      // Usamos targetOrigin='*' por compatibilidad: en algunos navegadores el
      // origin que el browser asocia al postMessage SALIENTE no coincide con
      // el de las respuestas (mismatch interno tras la navegación cross-origin
      // del iframe), provocando rechazos espurios. El handler del lado padre
      // sí filtra `event.source === iframe.contentWindow` y `_cci === true`,
      // lo cual es la defensa real. El contenido de los mensajes salientes
      // no contiene secretos (solo nombres de método y params); las claves
      // privadas viven en el localStorage de la propia vault.
      this._iframe.contentWindow.postMessage(
        { _cci: true, type: 'request', id, method, params },
        '*'
      )
    })
  }
}

// Helpers de capacidad SIN clave maestra (lado dispositivo + verificación), reutilizables
// por apps/bridges sin cargar el iframe del vault.
export { makeDeviceKey, signWithDevice, verifyDelegation, verifyChain, pubkeyId, deriveSAS, verifyDeviceSig, makePairingCode, commitCode, avatarSvg, avatarDataUri, MAX_DELEGATION_MS, DEFAULT_DELEGATION_MS } from '../vault/capabilities.js'
