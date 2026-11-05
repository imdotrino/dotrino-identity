/**
 * LA IDENTIDAD COMO OBJETO, sobre un core ya creado (`createIdentityCore`).
 *
 * Es la misma API que usa el binario (`@dotrino/identity/node`, que la extiende creando el
 * core sobre archivos) y la que necesita la bóveda del navegador: allí el core ya lo creó el
 * iframe o la extensión, y la bóveda lo envuelve con esto. Una sola envoltura, para que la
 * bóveda llame a lo mismo en las tres versiones.
 */
/** @typedef {Awaited<ReturnType<typeof import('./core.js').createIdentityCore>>} IdentityCore */

export class IdentityFacade {
  /** @param {IdentityCore | null} [core]  el resultado de `createIdentityCore` */
  constructor (core = null) {
    /** @type {IdentityCore | null} */
    this._core = core
    /** @type {Map<string, Set<(payload: any) => void>>} */
    this._listeners = new Map()
    if (core) this._wire()
  }

  /** Engancha los eventos del core a `on()`. Lo llama quien pone el core. */
  _wire () {
    const core = /** @type {any} */ (this._core)
    core.onSyncStatus?.((/** @type {any} */ payload) => this._emit('sync', payload))
    core.onVaultEvent?.((/** @type {any} */ payload) => this._emit('vault', payload))
  }

  destroy () { this._core = null }

  get me () { return this._core?.me || null }

  // ----- candado de la maestra -----
  /** `true` si la maestra está sellada: esta identidad NO puede firmar nada. */
  get masterLocked () { return !!this._core?.masterLocked }
  /** Sella la maestra que ya existe (se llama al abrir el perfil, con la llave en la mano). */
  sealMasterKey () { return this._core?.sealMasterKey?.() }
  /** Vuelve a cargar el par tras abrir el candado, sin reabrir la identidad. */
  reloadMasterKey () { return this._core?.reloadMasterKey?.() }
  /**
   * Ver `core.js`: al abrir, los aparatos muertos salen del acta en una sola.
   * @param {number} now
   */
  pruneExpiredDevices (now) { return this._core?.pruneExpiredDevices?.(now) }
  /** Ver `core.js`: al abrir, la clave de contenido llega a todos los miembros. */
  completeKeyring () { return this._core?.completeKeyring?.() }

  /** @param {string} method @param {any} [params] @returns {any} */
  _h (method, params = {}) {
    if (!this._core) throw new Error('Identity not ready — call ready()/connect() first')
    return /** @type {Record<string, (params: any) => any>} */ (this._core.handlers)[method](params)
  }

  // ----- API pública (espeja src/index.js) -----

  makeChallenge () { return this._h('makeChallenge') }
  /** @param {string} nonce */
  signChallenge (nonce) { return this._h('signChallenge', { nonce }) }
  /** @param {{ nonce: string, publickey: string, signature: string, encryptionPubkey?: string }} args */
  verifyResponse ({ nonce, publickey, signature, encryptionPubkey }) {
    return this._h('verifyResponse', { nonce, publickey, signature, encryptionPubkey })
  }
  /** @param {string} publickey */
  getPeer (publickey) { return this._h('getPeer', { publickey }) }
  /**
   * @param {string} publickey
   * @param {string} nickname
   */
  setNickname (publickey, nickname) { return this._h('setNickname', { publickey, nickname }) }
  /**
   * @param {string} publickey
   * @param {boolean} blocked
   */
  setBlocked (publickey, blocked) { return this._h('setBlocked', { publickey, blocked }) }
  /**
   * @param {string} publickey
   * @param {number} rating
   * @param {string} notes
   */
  setRating (publickey, rating, notes) { return this._h('setRating', { publickey, rating, notes }) }
  listPeers () { return this._h('listPeers') }
  /** @param {string} publickey */
  forgetPeer (publickey) { return this._h('forgetPeer', { publickey }) }
  /** @param {{ publickey: string, nickname?: string, encryptionPubkey?: string, lastToken?: string, notes?: string }} args */
  addContact ({ publickey, nickname, encryptionPubkey, lastToken, notes } = /** @type {any} */ ({})) {
    return this._h('addContact', { publickey, nickname, encryptionPubkey, lastToken, notes })
  }
  /**
   * @param {string} publickey
   * @param {Record<string, any>} patch
   */
  updateContact (publickey, patch) { return this._h('updateContact', { publickey, patch }) }
  /** @param {string} publickey */
  removeContact (publickey) { return this._h('removeContact', { publickey }) }
  listContacts () { return this._h('listContacts') }
  /** @param {any} data */
  signData (data) { return this._h('signData', { data }) }
  /**
   * Prueba firmada con destinatario y vigencia (ver `vault/assertion.js`). Un servicio en
   * Node la pide igual que una app: `{ audience, nonce, scopes?, ttlMs? }`.
   *
   * @param {{ audience: string, nonce: string, scopes?: string[], ttlMs?: number }} args
   */
  async requestAssertion ({ audience, nonce, scopes, ttlMs } = /** @type {any} */ ({})) {
    const { assertion } = await this._h('requestAssertion', { audience, nonce, scopes, ttlMs })
    return assertion
  }
  // Delegación de capacidad (sub-clave de dispositivo con scope/exp/revocación)
  /** @param {string} sub @param {string | string[]} scope @param {Record<string, any>} [opts] */
  signDelegation (sub, scope, opts = {}) { return this._h('signDelegation', { sub, scope, ...opts }) }
  /** @param {string} nonce */
  revokeDelegation (nonce) { return this._h('revokeDelegation', { nonce }) }
  /**
   * Quitar el DISPOSITIVO: retira todos sus certificados vigentes, no solo uno.
   * @param {string} sub
   */
  revokeDevice (sub) { return this._h('revokeDevice', { sub }) }
  listDelegations () { return this._h('listDelegations') }
  // Acta de perfil (qué llaves son del perfil y qué puede cada una; ver acta-de-perfil.md)
  profileActa () { return this._h('profileActa') }
  /** La cadena de selladores, para mandarla con una firma (ver `vault/acta.js`). */
  sealerChain () { return this._h('sealerChain') }
  profileMembers () { return this._h('profileMembers') }
  /**
   * Quien SELLA SOBRES (la bóveda) registra aquí cómo estrenar su llave de sellado: se
   * llama al sellar cada acta, porque esa llave rota con el acta (§8.9 de
   * `dotrino-vault/docs/secretos-sellados.md`). Va por aquí y no por el iframe porque
   * este puente es en-proceso: al navegador no se le puede pasar una función, y tampoco
   * la necesita — no sella secretos de nadie.
   */
  /**
   * Abre un sobre sellado A ESTE aparato (envoltura + sobre). Ver `core.js`.
   * @param {any} wrap
   * @param {any} envelope
   */
  openSealedValue (wrap, envelope) { return this._h('openSealedValue', { wrap, envelope }) }
  /**
   * Re-envuelve para otro miembro una llave que este aparato ya puede abrir.
   * @param {any} wrap
   * @param {string} encPub
   */
  rewrapFor (wrap, encPub) { return this._h('rewrapFor', { wrap, encPub }) }
  /** @param {any} provider */
  setSealKeyProvider (provider) { return this._h('setSealKeyProvider', { provider }) }
  /** Estrena la llave de sellado en un acta nueva, sin tocar a ningún miembro. */
  rotateSealKey () { return this._h('rotateSealKey') }
  /**
   * Con qué llave se comprueban los sobres que se firmaron con el acta `seq`.
   * @param {number} seq
   * @param {string | null} [vault]
   */
  sealKeyAt (seq, vault = null) { return this._h('sealKeyAt', { seq, vault }) }
  myMembership () { return this._h('myMembership') }
  /**
   * La CADENA de actas desde `sinceSeq` (para que un dispositivo que estuvo apagado
   * compruebe el encadenamiento en vez de tragarse un salto a ciegas).
   *
   * Vivía en el núcleo pero NO estaba aquí, así que `identity.actaHistory` era
   * `undefined` en el daemon: al pedir la lista de dispositivos con un `sinceSeq`
   * —que es lo que manda SIEMPRE un navegador ya emparejado— reventaba con
   * «is not a function», la bóveda respondía error, y el aparato NUNCA volvía a
   * sincronizar su acta. Se quedaba con la copia del día que emparejó.
   * @param {any} opts
   */
  actaHistory (opts) { return this._h('actaHistory', opts || {}) }
  /** Los que estuvieron en las actas de la ventana y el acta actual ya no nombra. */
  pastMembers () { return this._h('pastMembers') }
  isMaster () { return this._h('isMaster') }
  /** @param {any} member */
  admitMember (member) { return this._h('admitMember', member) }
  /**
   * Registra la llave de cifrado de un miembro ya admitido (evita re-enrolarlo).
   * @param {any} args
   */
  setMemberEncPub (args) { return this._h('setMemberEncPub', args) }
  /**
   * Dice de qué bóveda es una llave de comunicación ya admitida.
   * @param {any} args
   */
  setMemberVault (args) { return this._h('setMemberVault', args) }
  /**
   * @param {string} pub
   * @param {string[]} caps
   */
  setCaps (pub, caps) { return this._h('setCaps', { pub, caps }) }
  /** @param {any} changes */
  setCapsMany (changes) { return this._h('setCapsMany', { changes }) }
  /**
   * @param {string} pub
   * @param {string} label
   */
  setLabel (pub, label) { return this._h('setLabel', { pub, label }) }
  /** @param {string} pub */
  removeMember (pub) { return this._h('removeMember', { pub }) }
  /**
   * @param {string} to
   * @param {any} [member]
   */
  handoverMaster (to, member = null) { return this._h('handoverMaster', { to, member }) }
  /** @param {string[]} caps */
  renounceCaps (caps) { return this._h('renounceCaps', { caps }) }
  /** @param {any} record */
  absorbRenounce (record) { return this._h('absorbRenounce', { record }) }
  /** @param {any} acta */
  adoptActa (acta) { return this._h('adoptActa', { acta }) }
  /**
   * Adopta una cadena de actas, eslabón a eslabón (para ponerse al día tras estar apagado).
   * @param {any[]} chain
   */
  adoptActaChain (chain) { return this._h('adoptActaChain', { chain }) }
  /**
   * Se pone al día por la cadena de selladoras: sin las actas de en medio, desde la que se tiene.
   * @param {any[]} sealerChain
   */
  adoptActaBySealerChain (sealerChain) { return this._h('adoptActaBySealerChain', { sealerChain }) }
  /**
   * Completa el historial con las actas que falten detrás de la vigente, comprobadas por hash.
   * @param {any[]} actas
   */
  fillActaHistory (actas) { return this._h('fillActaHistory', { actas }) }
  /**
   * Las últimas actas guardadas, con la vigente.
   * @param {number} count
   */
  recentActas (count) { return this._h('recentActas', { count }) }
  /**
   * Une ESTE perfil a la cuenta de otro (solo si nació para eso: `createProfile(n, { forVault: true })`).
   * @param {any} acta
   */
  joinProfile (acta) { return this._h('joinProfile', { acta }) }
  /** Marca este perfil como nacido para ADOPTAR la cuenta de otro (camino A: lo usa la bóveda). */
  prepareForAdoption () { return this._h('prepareForAdoption') }
  /** MI tarjeta de perfil: lo mínimo que un contacto necesita para cifrarme a todos mis
   *  dispositivos (perfil, versión y llaves). Sin etiquetas ni permisos. */
  profileCard () { return this._h('profileCard') }
  /**
   * Guarda la tarjeta de otra persona en su ficha de contacto (verificándola).
   * @param {any} card
   */
  adoptPeerCard (card) { return this._h('adoptPeerCard', { card }) }
  /** La clave de contenido del perfil, abierta con la llave de cifrado de este dispositivo. */
  contentKey () { return this._h('contentKey') }
  /**
   * Cifra con la clave de contenido del perfil (la privada de cifrado no sale del vault).
   * @param {string} plaintext
   */
  sealContent (plaintext) { return this._h('sealContent', { plaintext }) }
  /**
   * Abre un sobre de contenido con el llavero del perfil.
   * @param {any} envelope
   */
  openContent (envelope) { return this._h('openContent', { envelope }) }
  /** Rota la clave de contenido (corta el acceso al contenido FUTURO de quien ya no está). */
  rotateContentKey () { return this._h('rotateContentKey') }
  // Emparejar ESTE dispositivo con el vault del usuario (Fase 1)
  /**
   * @param {any} qr
   * @param {{ label?: string, join?: string, account?: string | null, requireCaps?: string[] | null }} [opts]
   */
  enrollDevice (qr, { label = '', join = 'current', account = null, requireCaps = null } = {}) { return this._h('vaultPair', { qr, label, join, account, requireCaps }) }
  vaultStatus () { return this._h('vaultStatus') }
  unpairDevice () { return this._h('vaultUnpair') }
  /** @param {any} payload */
  vaultSign (payload) { return this._h('vaultSign', { payload }) }
  /** @param {string} method @param {any} args @param {{ wake?: boolean }} [opts] */
  vaultStore (method, args, { wake = true } = {}) { return this._h('vaultStore', { method, args, wake }) }
  /** @param {any} opts */
  listVaultDevices (opts) { return this._h('listVaultDevices', opts || {}) }
  getVaultCert () { return this._h('getVaultCert') }
  /**
   * @param {string} op
   * @param {any} args
   */
  vaultApprovals (op, args) { return this._h('vaultApprovals', { op, ...(args || {}) }) }
  /**
   * Los pedidos de TODAS las cuentas que aprueban, sin cambiar la activa.
   * @param {any} args
   */
  vaultApprovalsAll (args) { return this._h('vaultApprovalsAll', args || {}) }
  /** @param {(payload: any) => void} handler */
  onVault (handler) { return this.on('vault', handler) }
  // Multi-perfil por dispositivo (crear/cambiar reinicializa con el nuevo perfil activo).
  listProfiles () { return this._h('listProfiles') }
  currentProfile () { return this._h('currentProfile') }
  /** @param {string} name @param {{ forVault?: boolean }} [opts] */
  createProfile (name, { forVault = false } = {}) { return this._h('createProfile', { name, forVault }) }
  /** @param {string} id */
  switchProfile (id) { return this._h('switchProfile', { id }) }
  /**
   * @param {string} id
   * @param {string} name
   */
  renameProfile (id, name) { return this._h('renameProfile', { id, name }) }
  /** @param {string} id */
  deleteProfile (id) { return this._h('deleteProfile', { id }) }
  /**
   * @param {string} subject
   * @param {any[]} endorsements
   * @param {string} askerPubkey
   */
  mergeEndorsements (subject, endorsements, askerPubkey) {
    return this._h('mergeEndorsements', { subject, endorsements, askerPubkey })
  }
  /** @param {string} subject */
  getRatingsForSubject (subject) { return this._h('getRatingsForSubject', { subject }) }
  /**
   * @param {string} askerPubkey
   * @param {string} subject
   */
  recordQuery (askerPubkey, subject) { return this._h('recordQuery', { askerPubkey, subject }) }
  /** @param {string} nickname */
  async setMyNickname (nickname) {
    const result = await this._h('setMyNickname', { nickname })
    return result
  }
  /** @param {Record<string, any>} patch */
  async updateMe (patch) { return this._h('updateMe', { patch }) }
  getMe () { return this._h('getMe') }
  publicMe () { return this._h('publicMe') }
  /** Cómo fue el último empujón del perfil a la bóveda: `{ ok, at, error }`. */
  profilePushState () { return this._h('profilePushState') }
  getEncryptionPubkey () { return this._h('getEncryptionPubkey') }
  /**
   * @param {any[]} recipients
   * @param {string} plaintext
   */
  encrypt (recipients, plaintext) { return this._h('encrypt', { recipients, plaintext }) }
  /**
   * @param {string} senderEncryptionPubkey
   * @param {string | null} myToken
   * @param {any} envelope
   */
  decrypt (senderEncryptionPubkey, myToken, envelope) {
    return this._h('decrypt', { senderEncryptionPubkey, myToken, envelope })
  }
  exportIdentity () { return this._h('exportIdentity') }
  /** @param {any} blob */
  async importIdentity (blob) { return this._h('importIdentity', blob || {}) }

  // Sync (Google Drive) no disponible headless — los handlers responden acorde.
  /** @param {string} clientId */
  syncConnect (clientId) { return this._h('syncConnect', { clientId }) }
  syncDisconnect () { return this._h('syncDisconnect') }
  /** @param {string} passphrase */
  syncUnlock (passphrase) { return this._h('syncUnlock', { passphrase }) }
  syncLock () { return this._h('syncLock') }
  syncStatus () { return this._h('syncStatus') }
  syncNow () { return this._h('syncNow') }

  /** @param {(payload: any) => void} handler */
  onSync (handler) { return this.on('sync', handler) }
  /**
   * @param {string} event
   * @param {(payload: any) => void} handler
   */
  on (event, handler) {
    let set = this._listeners.get(event)
    if (!set) { set = new Set(); this._listeners.set(event, set) }
    set.add(handler)
    return () => this._listeners.get(event)?.delete(handler)
  }
  /**
   * @param {string} event
   * @param {any} payload
   */
  _emit (event, payload) {
    const set = this._listeners.get(event)
    if (!set) return
    for (const h of set) { try { h(payload) } catch (e) { console.error(e) } }
  }
}

export default IdentityFacade
