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
    // Perfil protegido con contraseña/PIN (candado LOCAL del dispositivo): pedirla
    // aquí, una vez por PESTAÑA (el iframe recuerda el desbloqueo en sessionStorage
    // → no re-pide al refrescar). Las apps no tienen que hacer nada.
    if (singleton._locked && typeof document !== 'undefined' && options.promptUnlock !== false) {
      await singleton._promptUnlock()
    }
    return singleton
  }

  /** Overlay mínimo de desbloqueo (PIN/contraseña). Resuelve al desbloquear. */
  async _promptUnlock () {
    const es = !(navigator.language || 'es').startsWith('en')
    const T = es
      ? { t: 'Perfil protegido', p: 'PIN o contraseña', b: 'Desbloquear', e: 'Contraseña incorrecta' }
      : { t: 'Protected profile', p: 'PIN or password', b: 'Unlock', e: 'Wrong password' }
    return new Promise((resolve) => {
      const back = document.createElement('div')
      back.style.cssText = 'position:fixed;inset:0;background:rgba(10,8,20,.8);z-index:2147483000;display:flex;align-items:center;justify-content:center;font-family:system-ui,sans-serif'
      back.innerHTML = `<form style="background:#171331;border:1px solid #2a2350;border-radius:16px;padding:22px;min-width:260px;max-width:90vw;color:#e7e3ff">
        <div style="font-weight:700;margin-bottom:10px">🔒 ${T.t}</div>
        <input type="password" inputmode="numeric" autocomplete="current-password" placeholder="${T.p}"
               style="width:100%;box-sizing:border-box;padding:10px 12px;border-radius:10px;border:1px solid #2a2350;background:#0b0820;color:inherit;font:inherit" />
        <div data-err style="color:#e5484d;font-size:13px;min-height:18px;margin:6px 0 8px"></div>
        <button type="submit" style="width:100%;padding:10px;border-radius:10px;border:0;background:#7c3aed;color:#fff;font:inherit;font-weight:600;cursor:pointer">${T.b}</button>
      </form>`
      const form = back.firstElementChild
      const input = form.querySelector('input')
      const err = form.querySelector('[data-err]')
      form.addEventListener('submit', async (e) => {
        e.preventDefault()
        err.textContent = ''
        try {
          await this._call('unlockProfile', { password: input.value })
          this._locked = false
          try { this._me = await this._call('getMe') } catch (_) {}
          back.remove()
          resolve(this)
        } catch (ex) {
          err.textContent = /incorrecta/.test(ex.message) ? T.e : ex.message
          input.select()
        }
      })
      document.body.appendChild(back)
      input.focus()
    })
  }

  /** Estado del candado del perfil activo: { protected, locked }. */
  async profileLockStatus () { return this._call('profileLockStatus') }
  /** Desbloquea el perfil (la prueba queda en sessionStorage: por pestaña). */
  async unlockProfile (password) {
    const r = await this._call('unlockProfile', { password })
    this._locked = false
    try { this._me = await this._call('getMe') } catch (_) {}
    return r
  }
  /** Protege el perfil ACTIVO con contraseña/PIN — LOCAL de este dispositivo. */
  async setProfilePassword (password) { return this._call('setProfilePassword', { password }) }
  /** Quita la protección (requiere estar desbloqueado). */
  async removeProfilePassword () { return this._call('removeProfilePassword') }

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
          this._me = msg.me || null
          this._locked = !!msg.locked
          this._readyResolve(this)
          return
        }

        if (msg.type === 'response') {
          const pending = this._pending.get(msg.id)
          if (!pending) return
          this._pending.delete(msg.id)
          clearTimeout(pending.timer)
          // El rechazo llega con su `code` (y `detail`) puestos, como si el error se hubiera
          // lanzado aquí: quien lo atrapa comprueba `e.code`, nunca la frase.
          if (msg.error) {
            const err = new Error(msg.error)
            if (msg.code) err.code = msg.code
            if (msg.detail) err.detail = msg.detail
            pending.reject(err)
          }
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

  /**
   * QUITA EL DISPOSITIVO: retira **todos** los certificados vigentes de esa llave.
   * Revocar por `nonce` retira un papel; un aparato puede tener otros y seguir entrando.
   */
  async revokeDevice (sub) {
    return this._call('revokeDevice', { sub })
  }

  /** Lista las delegaciones emitidas + la lista de revocación (para el gestor de dispositivos). */
  async listDelegations () {
    return this._call('listDelegations')
  }

  // ----- Acta de perfil: qué llaves son tuyas y qué puede hacer cada una -----
  // Un perfil es un conjunto de llaves ligadas por certificados, con una política firmada
  // por UN solo sellador (el «master»). Ninguna llave privada viaja nunca.
  // Diseño: dotrino-vault/docs/acta-de-perfil.md

  /** El acta vigente + si este dispositivo es el master + sus capacidades efectivas. */
  async profileActa () { return this._call('profileActa') }

  /** Miembros del perfil, ya con id legible y capacidades efectivas. */
  async profileMembers () { return this._call('profileMembers') }

  /** Dónde estoy yo: { inProfile, profileId, seq, isMaster, caps, id }. */
  async myMembership () { return this._call('myMembership') }
  /** La cadena de actas desde `sinceSeq` (ver la nota en `node.js`). */
  async actaHistory (opts) { return this._call('actaHistory', opts || {}) }

  /** ¿Es ESTE dispositivo el master (el único que puede cambiar el acta)? */
  async isMaster () { return this._call('isMaster') }

  /** Admite un miembro nuevo (solo el master). */
  async admitMember (member) { return this._call('admitMember', member) }
  /** Registra la llave de cifrado de un miembro ya admitido (evita re-enrolarlo). */
  async setMemberEncPub (args) { return this._call('setMemberEncPub', args) }

  /** Cambia las capacidades de un miembro (solo el master). */
  async setCaps (pub, caps) { return this._call('setCaps', { pub, caps }) }
  async setLabel (pub, label) { return this._call('setLabel', { pub, label }) }

  /** Expulsa a un miembro (solo el master; al master no se le puede expulsar). */
  async removeMember (pub) { return this._call('removeMember', { pub }) }

  /**
   * Traspasa el master a otro miembro — dispositivo → bóveda, o bóveda → bóveda al mudarse
   * de PC. Si `member` viene, se admite y se nombra en el MISMO seq (sin ventana intermedia).
   */
  async handoverMaster (to, member = null) { return this._call('handoverMaster', { to, member }) }

  /**
   * Este dispositivo se quita capacidades a sí mismo (p. ej. dejar de firmar). Es
   * unilateral y funciona con la bóveda apagada, que es justo cuando hace falta.
   */
  async renounceCaps (caps) { return this._call('renounceCaps', { caps }) }

  /** Absorbe en el acta una renuncia de otro miembro (solo el master). */
  async absorbRenounce (record) { return this._call('absorbRenounce', { record }) }

  /** Adopta un acta recibida de otro miembro (gana el seq mayor; a igual seq, el traspaso). */
  async adoptActa (acta) { return this._call('adoptActa', { acta }) }
  /**
   * Une ESTE perfil a la cuenta de otro (la de una bóveda). No es adoptar una versión nueva
   * de la tuya: esta llave pasa a ser de OTRA cuenta y deja de tener la suya, así que solo
   * procede sobre un perfil creado con `{ forVault: true }`. Si no, devuelve
   * `{ joined: false, reason: 'perfil-con-datos' }` y no escribe nada.
   */
  async joinProfile (acta) { return this._call('joinProfile', { acta }) }
  /** Marca este perfil como nacido para ADOPTAR la cuenta de otro (camino A). */
  async prepareForAdoption () { return this._call('prepareForAdoption') }
  /** MI tarjeta de perfil: lo mínimo que un contacto necesita para cifrarme a todos mis
   *  dispositivos (perfil, versión y llaves). Sin etiquetas ni permisos. */
  async profileCard () { return this._call('profileCard') }
  /** Guarda la tarjeta de otra persona en su ficha de contacto (verificándola). */
  async adoptPeerCard (card) { return this._call('adoptPeerCard', { card }) }
  /** La clave de contenido del perfil, abierta con la llave de cifrado de este dispositivo. */
  async contentKey () { return this._call('contentKey') }
  /** Cifra con la clave de contenido del perfil (la privada de cifrado no sale del vault). */
  async sealContent (plaintext) { return this._call('sealContent', { plaintext }) }
  /** Abre un sobre de contenido con el llavero del perfil. */
  async openContent (envelope) { return this._call('openContent', { envelope }) }
  /** Rota la clave de contenido (corta el acceso al contenido FUTURO de quien ya no está). */
  async rotateContentKey () { return this._call('rotateContentKey') }

  // ----- Emparejar ESTE navegador/dispositivo con el vault del usuario (Fase 1) -----

  /**
   * Empareja este dispositivo con el vault del usuario a partir del QR (v2) que
   * muestra `dotrino-vault pair`. Genera la sub-clave D DENTRO del iframe (su privada
   * nunca sale), hace el emparejamiento endurecido por el proxy y guarda el cert.
   * Emite un evento 'vault' { phase:'challenge', deviceId, sas } para que muestres el
   * código a comparar; resuelve cuando el dueño aprueba en su PC (espera hasta 3 min).
   *
   * `join` dice **de qué cuenta se está hablando** (`vinculacion-de-cuentas.md` §3):
   *   · `'new'`     → crea aquí una cuenta MÁS, con llave nueva, y es esa la que entra en la
   *                   bóveda. La que estabas usando no se toca. **Es lo normal.**
   *   · `'current'` → sigue con la cuenta abierta; solo vale si nació para adoptar o si ya
   *                   está emparejada con esa misma bóveda. Si no, falla antes de tocar la red.
   * @returns {Promise<{ ok:boolean, deviceId:string, master:string, exp:number, scope:string[] }>}
   */
  async enrollDevice (qr, { label = '', join = 'current' } = {}) {
    return this._call('vaultPair', { qr, label, join }, 200000)
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

  /**
   * CONSOLA REMOTA: administra el perfil desde este dispositivo, contra la bóveda
   * (`dotrino-vault/docs/consola-remota.md`). `op`: `pending` · `pair` · `approve` ·
   * `reject` · `revoke` · `audit`.
   *
   * Requiere que el cert de este aparato lleve `vault:admin`, que **no se recibe al
   * emparejar**: se concede a mano en la bóveda. Cambiar permisos y traspasar el mando
   * NO se administran a distancia — siguen siendo del master, en su máquina.
   */
  async vaultAdmin (op, args) {
    return this._call('vaultAdmin', { op, ...(args || {}) }, 20000)
  }

  /** ¿El cert de este dispositivo le permite administrar el perfil a distancia? */
  async canAdminVault () {
    return this._call('canAdminVault', {}, 20000)
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

  // ----- Self-vault: ESTE dispositivo actúa como su propia bóveda/CA -----
  // El daemon device-vault vive dentro del iframe (no requiere el binario del PC).
  // Se gestiona desde profile.dotrino.com/#myvault. Cualquier app puede activarlo,
  // generar códigos de emparejamiento, aprobar SAS y revocar máquinas — todo por RPC
  // al iframe. El daemon sólo corre en una pestaña visible a la vez (navigator.locks),
  // pero los getters (status/pending/machines) y revoke sirven desde cualquier pestaña.
  /** { enabled, running }: si el modo self está activado y si esta pestaña sostiene el daemon. */
  async selfVaultStatus () { return this._call('selfVaultStatus') }
  /** Activa/desactiva el modo self-vault en este dispositivo. */
  async setSelfVault (enabled) { return this._call('setSelfVault', { enabled }) }
  /** Genera un código de emparejamiento + QR para enlazar otra máquina. Sólo sirve desde la pestaña activa. */
  async selfVaultPairing (opts) { return this._call('selfVaultPairing', opts || {}, 60000) }
  /** Lista de solicitudes de emparejamiento pendientes de aprobar. */
  async selfVaultPending () { return this._call('selfVaultPending') }
  /** Máquinas/agentes enrolados (delegaciones vigentes con scope vault:sign). */
  async selfVaultMachines () { return this._call('selfVaultMachines') }
  /** Aprueba una solicitud de emparejamiento comparando el código SAS. */
  async selfVaultApprove (deviceId, code) { return this._call('selfVaultApprove', { deviceId, code }) }
  /** Rechaza una solicitud de emparejamiento pendiente. */
  async selfVaultReject (deviceId) { return this._call('selfVaultReject', { deviceId }) }
  /**
   * QUITA una máquina/agente enrolado en esta bóveda. Se le pasa **el aparato**
   * (`{ sub }`, su llave): sale del acta y se le retiran todos sus certificados.
   *
   * Un `nonce` suelto (string, o `{ nonce }`) retira UN certificado y deja al aparato
   * dentro del acta: eso no es quitarlo, y quien queda así ya no recibe nunca el aviso
   * de expulsión. Se acepta por compatibilidad, no como la forma normal.
   */
  async selfVaultRevoke (target) {
    const p = typeof target === 'string' ? { nonce: target } : { sub: target?.sub, nonce: target?.nonce }
    return this._call('selfVaultRevoke', p)
  }
  /** Presencia online (ping/pong) de las máquinas enroladas. Devuelve { online: [pubkeys] }. */
  async selfVaultProbe (pubkeys) { return this._call('selfVaultProbe', { pubkeys }, 10000) }
  /** Suscribe a eventos del self-vault ('selfVault'): { running?, pending?, error? }. */
  onSelfVault (handler) { return this.on('selfVault', handler) }

  // ----- multi-perfil por dispositivo -----
  // Podés tener varios perfiles (identidades) en el mismo navegador, cada uno conectado o no
  // a su propio vault. Crear/cambiar setea el perfil activo; la app RECARGA la página y toma
  // el nuevo (no reactivo: las apps abiertas conservan el perfil con el que cargaron).
  /** Lista de perfiles: [{ id, name, pubkey, current }]. */
  async listProfiles () { return this._call('listProfiles') }
  /** El perfil activo: { id, name, pubkey }. */
  async currentProfile () { return this._call('currentProfile') }
  /**
   * Crea un perfil nuevo (identidad fresca) y lo deja activo. La app debe recargar.
   *
   * `forVault: true` lo marca como **nacido para adoptar** la cuenta de una bóveda (camino B
   * de `vinculacion-de-cuentas.md`): es el único permiso que acepta `joinProfile`, y se
   * consume al unirse. Sin esa marca, la cuenta es de este dispositivo y nadie se la lleva.
   */
  async createProfile (name, { forVault = false } = {}) { return this._call('createProfile', { name, forVault }) }
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
export { makeDeviceKey, makeDeviceEncKey, importDeviceEncKey, signWithDevice, verifyDelegation, verifyChain, pubkeyId, deriveSAS, verifyDeviceSig, makePairingCode, commitCode, avatarSvg, avatarDataUri, MAX_DELEGATION_MS, DEFAULT_DELEGATION_MS } from '../vault/capabilities.js'
