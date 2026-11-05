/**
 * Dotrino Identity client.
 *
 * Loads a hidden iframe pointing at the vault origin and exchanges
 * postMessage requests. The vault holds the user's keypair and the
 * peer ratings/nicknames in its own localStorage, so all apps that
 * use this library share identity even across different origins.
 */

import { browserMachine } from '../vault/machine.js'

/** @typedef {import('./index.js').Identity} IdentityApi  la API pública, tal como la publica `index.d.ts` */

const DEFAULT_VAULT_URL = 'https://id.dotrino.com/'

/** @type {Identity | null} */
let singleton = null

export class Identity {
  /** @param {import('./index.js').IdentityOptions} [options] */
  constructor (options = {}) {
    this.vaultUrl = options.vaultUrl || DEFAULT_VAULT_URL
    this.timeoutMs = options.timeoutMs ?? 5000
    /** @type {HTMLIFrameElement | null} */
    this._iframe = null
    /** @type {Promise<IdentityApi> | null} */
    this._ready = null
    /** @type {((id: IdentityApi) => void) | null} */
    this._readyResolve = null
    this._nextId = 1
    /** @type {Map<string, { resolve: (v: any) => void, reject: (e: Error) => void, timer: ReturnType<typeof setTimeout> }>} */
    this._pending = new Map()
    /** @type {((event: MessageEvent) => void) | null} */
    this._handler = null
    /** @type {import('./index.js').Me | null} */
    this._me = null
    /** @type {boolean | undefined} el perfil está bajo contraseña (lo dice el `ready` del iframe) */
    this._locked // eslint-disable-line no-unused-expressions
    /** @type {Map<string, Set<(payload: any) => void>> | undefined} */
    this._listeners // eslint-disable-line no-unused-expressions
  }

  /**
   * @param {import('./index.js').IdentityOptions} [options]
   * @returns {Promise<Identity>}
   */
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
  /** @returns {Promise<Identity>} */
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
      // El formulario se acaba de escribir arriba: los tres elementos están.
      const form = /** @type {HTMLFormElement} */ (back.firstElementChild)
      const input = /** @type {HTMLInputElement} */ (form.querySelector('input'))
      const err = /** @type {HTMLElement} */ (form.querySelector('[data-err]'))
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
          const msg = /** @type {{ message?: string }} */ (ex).message
          err.textContent = /incorrecta/.test(/** @type {string} */ (msg)) ? T.e : /** @type {string} */ (msg)
          input.select()
        }
      })
      document.body.appendChild(back)
      input.focus()
    })
  }

  /**
   * Estado del candado del perfil activo: { protected, locked }.
   * @type {IdentityApi['profileLockStatus']}
   */
  async profileLockStatus () { return this._call('profileLockStatus') }
  /**
   * Desbloquea el perfil (la prueba queda en sessionStorage: por pestaña).
   * @type {IdentityApi['unlockProfile']}
   */
  async unlockProfile (password) {
    const r = await this._call('unlockProfile', { password })
    this._locked = false
    try { this._me = await this._call('getMe') } catch (_) {}
    return r
  }
  /**
   * Protege el perfil ACTIVO con contraseña/PIN — LOCAL de este dispositivo.
   * @type {IdentityApi['setProfilePassword']}
   */
  async setProfilePassword (password) { return this._call('setProfilePassword', { password }) }
  /**
   * Quita la protección (requiere estar desbloqueado).
   * @type {IdentityApi['removeProfilePassword']}
   */
  async removeProfilePassword () { return this._call('removeProfilePassword') }

  /** @returns {Identity | null} */
  static current () {
    return singleton
  }

  /** @type {IdentityApi['ready']} */
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
          ;/** @type {(id: IdentityApi) => void} */ (this._readyResolve)(this)
          // Dónde corre esta página (`vault/machine.js`), para los pedidos a la bóveda. Un
          // iframe viejo no conoce el método: no pasa nada, solo no se manda.
          this._call('setMachine', { machine: browserMachine() }).catch(() => {})
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
            const err = /** @type {Error & { code?: string, detail?: any, reason?: string }} */ (new Error(msg.error))
            if (msg.code) err.code = msg.code
            if (msg.detail) err.detail = msg.detail
            if (msg.reason) err.reason = msg.reason
            pending.reject(err)
          }
          else pending.resolve(msg.result)
          return
        }

        if (msg.type === 'event') {
          // MOSTRAR EL IFRAME PARA QUE PREGUNTE. El panel de permiso lo pinta la bóveda,
          // en su propio origen: esta página no puede pulsar ahí dentro ni leerlo. Lo
          // único que hace aquí es dejar sitio. Si una aplicación decidiera no hacerlo,
          // no obtiene el permiso — que es el lado correcto en el que fallar.
          if (msg.event === 'consent:open') this._showVault(true)
          if (msg.event === 'consent:close') this._showVault(false)
          this._emit(msg.event, msg.payload)
        }
      }

      window.addEventListener('message', this._handler)
      document.body.appendChild(iframe)
    })

    return this._ready
  }

  /** Deja ver la bóveda (a pantalla completa) mientras pregunta, y la devuelve a su sitio. */
  /** @param {boolean} visible */
  _showVault (visible) {
    const f = this._iframe
    if (!f) return
    f.style.cssText = visible
      ? 'position:fixed;inset:0;width:100%;height:100%;border:0;z-index:2147483000'
      : 'display:none'
    f.setAttribute('aria-hidden', visible ? 'false' : 'true')
  }

  /** @type {IdentityApi['destroy']} */
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
   * @type {IdentityApi['makeChallenge']}
   */
  async makeChallenge () {
    return this._call('makeChallenge')
  }

  /** @type {IdentityApi['signChallenge']} */
  async signChallenge (nonce) {
    return this._call('signChallenge', { nonce })
  }

  /** @type {IdentityApi['verifyResponse']} */
  async verifyResponse ({ nonce, publickey, signature }) {
    return this._call('verifyResponse', { nonce, publickey, signature })
  }

  /** @type {IdentityApi['getPeer']} */
  async getPeer (publickey) {
    return this._call('getPeer', { publickey })
  }

  /**
   * Bloquear (o desbloquear) a alguien: privado, viaja con tus contactos y no se publica.
   * @type {IdentityApi['setBlocked']}
   */
  async setBlocked (publickey, blocked) {
    return this._call('setBlocked', { publickey, blocked })
  }

  /** @type {IdentityApi['setNickname']} */
  async setNickname (publickey, nickname) {
    return this._call('setNickname', { publickey, nickname })
  }

  /** @type {IdentityApi['setRating']} */
  async setRating (publickey, rating, notes) {
    return this._call('setRating', { publickey, rating, notes })
  }

  /** @type {IdentityApi['listPeers']} */
  async listPeers () {
    return this._call('listPeers')
  }

  /** @type {IdentityApi['forgetPeer']} */
  async forgetPeer (publickey) {
    return this._call('forgetPeer', { publickey })
  }

  /**
   * Add (or refresh) a contact in the shared address book. Idempotent —
   * existing peer records are upserted with the new metadata. Contacts are
   * stored alongside the rating/endorsement record for the same pubkey, so
   * any app in the ecosystem (chat, chess, messenger, …) sees the same list.
   * @type {IdentityApi['addContact']}
   */
  async addContact ({ publickey, nickname, encryptionPubkey, lastToken, notes } = /** @type {any} */ ({})) {
    return this._call('addContact', { publickey, nickname, encryptionPubkey, lastToken, notes })
  }

  /**
   * Patch contact metadata (nickname / lastToken / encryptionPubkey / contactNotes).
   * @type {IdentityApi['updateContact']}
   */
  async updateContact (publickey, patch) {
    return this._call('updateContact', { publickey, patch })
  }

  /**
   * Remove the `isContact` flag while preserving rating/endorsement history.
   * @type {IdentityApi['removeContact']}
   */
  async removeContact (publickey) {
    return this._call('removeContact', { publickey })
  }

  /**
   * List peers flagged as contacts, sorted by lastSeen desc.
   * @type {IdentityApi['listContacts']}
   */
  async listContacts () {
    return this._call('listContacts')
  }

  /**
   * Sign an arbitrary JSON-serializable payload with the vault's ECDSA key
   * using canonical JSON encoding. Returns `{ signature, publickey }` —
   * compatible with the proxy's `verifySignatureWithJWK` (used by
   * `identify` to bind a stable pubkey to the proxy connection).
   * @type {IdentityApi['signData']}
   */
  async signData (data) {
    return this._call('signData', { data })
  }

  /**
   * Una prueba firmada PARA ALGUIEN EN CONCRETO y por un rato: `signData` dice «lo firmé
   * yo», y esto dice además para quién, contestando a qué reto y hasta cuándo. Es lo que
   * un servicio (o una aplicación ajena) tiene que pedir en vez de una firma suelta, que
   * le sirve igual a otro servicio.
   *
   * `audience` es quien va a verificarla —su URL— y `nonce` lo pone él, de un solo uso.
   * `scopes` es lo que se le deja ver, del catálogo cerrado de `@dotrino/identity/assertion`;
   * `id:whoami` (solo quién eres) es el mínimo y el valor por defecto.
   *
   * @returns {Promise<object>} la prueba, lista para mandar. Se comprueba con
   * `verifyAssertion(prueba, { audience, nonce })`.
   */
  /**
   * Qué le has concedido a cada aplicación. Sin esto, conceder no significaría nada.
   * @type {IdentityApi['listGrants']}
   */
  async listGrants () { return this._call('listGrants') }
  /**
   * Retirar lo concedido a una aplicación: la próxima vez que pida, se vuelve a preguntar.
   * Las que entran por el puente llegan todas desde el mismo origen, así que a esas se las
   * nombra con `onBehalfOf` (el que trae su fila de `listGrants`).
   * @type {IdentityApi['revokeGrant']}
   */
  async revokeGrant (origin, onBehalfOf) { return this._call('revokeGrant', { origin, ...(onBehalfOf ? { onBehalfOf } : {}) }) }

  /** @type {IdentityApi['requestAssertion']} */
  async requestAssertion ({ audience, nonce, scopes, ttlMs, onBehalfOf } = /** @type {any} */ ({})) {
    // ESPERA LO QUE TARDE UNA PERSONA. Los cinco segundos de siempre valen para una
    // llamada que solo hace cuentas; esta puede abrir la pantalla de permiso (§permiso por
    // origen) y ahí quien contesta es un humano. Con el plazo corto, el cliente se rendía
    // con «Vault timeout» mientras el usuario todavía miraba el panel — y pulsar «Permitir»
    // ya no servía de nada. El tope es un poco mayor que el del propio panel, para que el
    // error que llegue sea «no lo concedió», que dice lo que pasó.
    const { assertion } = await this._call('requestAssertion', { audience, nonce, scopes, ttlMs, onBehalfOf }, 65000)
    return assertion
  }

  /**
   * Firma un CERTIFICADO DE DELEGACIÓN: autoriza a una sub-clave de dispositivo
   * `sub` (JWK string) a hacer `scope` en tu nombre, hasta `exp`, revocable por
   * `nonce`. La clave maestra NUNCA sale del vault. `opts`: { ttlMs?, exp?, label?, nonce? }.
   * @returns {Promise<{ cert: object }>}
   * @type {IdentityApi['signDelegation']}
   */
  async signDelegation (sub, scope, opts = {}) {
    return this._call('signDelegation', { sub, scope, ...opts })
  }

  /**
   * Revoca una delegación por su `nonce` (queda en la lista de revocación).
   * @type {IdentityApi['revokeDelegation']}
   */
  async revokeDelegation (nonce) {
    return this._call('revokeDelegation', { nonce })
  }

  /**
   * QUITA EL DISPOSITIVO: retira **todos** los certificados vigentes de esa llave.
   * Revocar por `nonce` retira un papel; un aparato puede tener otros y seguir entrando.
   * @type {IdentityApi['revokeDevice']}
   */
  async revokeDevice (sub) {
    return this._call('revokeDevice', { sub })
  }

  /**
   * Lista las delegaciones emitidas + la lista de revocación (para el gestor de dispositivos).
   * @type {IdentityApi['listDelegations']}
   */
  async listDelegations () {
    return this._call('listDelegations')
  }

  // ----- Acta de perfil: qué llaves son tuyas y qué puede hacer cada una -----
  // Un perfil es un conjunto de llaves ligadas por certificados, con una política firmada
  // por UN solo sellador (el «master»). Ninguna llave privada viaja nunca.
  // Diseño: dotrino-vault/docs/acta-de-perfil.md

  /**
   * El acta vigente + si este dispositivo es el master + sus capacidades efectivas.
   * @type {IdentityApi['profileActa']}
   */
  async profileActa () { return this._call('profileActa') }
  /**
   * La cadena de selladores, para mandarla con una firma (ver `vault/acta.js`).
   * @type {IdentityApi['sealerChain']}
   */
  async sealerChain () { return this._call('sealerChain') }

  /**
   * Miembros del perfil, ya con id legible y capacidades efectivas.
   * @type {IdentityApi['profileMembers']}
   */
  async profileMembers () { return this._call('profileMembers') }

  /**
   * Dónde estoy yo: { inProfile, profileId, seq, isMaster, caps, id }.
   * @type {IdentityApi['myMembership']}
   */
  async myMembership () { return this._call('myMembership') }
  /**
   * La cadena de actas desde `sinceSeq` (ver la nota en `node.js`).
   * @type {IdentityApi['actaHistory']}
   */
  async actaHistory (opts) { return this._call('actaHistory', opts || {}) }
  /**
   * Los que estuvieron en las actas de la ventana del historial y ya no están.
   * @type {IdentityApi['pastMembers']}
   */
  async pastMembers () { return this._call('pastMembers', {}) }

  /**
   * ¿Es ESTE dispositivo el master (el único que puede cambiar el acta)?
   * @type {IdentityApi['isMaster']}
   */
  async isMaster () { return this._call('isMaster') }

  /**
   * Admite un miembro nuevo (solo el master).
   * @type {IdentityApi['admitMember']}
   */
  async admitMember (member) { return this._call('admitMember', member) }
  /**
   * Registra la llave de cifrado de un miembro ya admitido (evita re-enrolarlo).
   * @type {IdentityApi['setMemberEncPub']}
   */
  async setMemberEncPub (args) { return this._call('setMemberEncPub', args) }

  /**
   * Cambia las capacidades de un miembro (solo el master).
   * @type {IdentityApi['setCaps']}
   */
  async setCaps (pub, caps) { return this._call('setCaps', { pub, caps }) }
  /**
   * Cambia las capacidades de VARIOS miembros en una sola acta: `[{ pub, caps }]`.
   * @type {IdentityApi['setCapsMany']}
   */
  async setCapsMany (changes) { return this._call('setCapsMany', { changes }) }
  /** @type {IdentityApi['setLabel']} */
  async setLabel (pub, label) { return this._call('setLabel', { pub, label }) }

  /**
   * Expulsa a un miembro (solo el master; al master no se le puede expulsar).
   * @type {IdentityApi['removeMember']}
   */
  async removeMember (pub) { return this._call('removeMember', { pub }) }

  /**
   * Traspasa el master a otro miembro — dispositivo → bóveda, o bóveda → bóveda al mudarse
   * de PC. Si `member` viene, se admite y se nombra en el MISMO seq (sin ventana intermedia).
   * @type {IdentityApi['handoverMaster']}
   */
  async handoverMaster (to, member = null) { return this._call('handoverMaster', { to, member }) }

  /**
   * Este dispositivo se quita capacidades a sí mismo (p. ej. dejar de firmar). Es
   * unilateral y funciona con la bóveda apagada, que es justo cuando hace falta.
   * @type {IdentityApi['renounceCaps']}
   */
  async renounceCaps (caps) { return this._call('renounceCaps', { caps }) }

  /**
   * Absorbe en el acta una renuncia de otro miembro (solo el master).
   * @type {IdentityApi['absorbRenounce']}
   */
  async absorbRenounce (record) { return this._call('absorbRenounce', { record }) }

  /**
   * Adopta un acta recibida de otro miembro (gana el seq mayor; a igual seq, el traspaso).
   * @type {IdentityApi['adoptActa']}
   */
  async adoptActa (acta) { return this._call('adoptActa', { acta }) }
  /**
   * Une ESTE perfil a la cuenta de otro (la de una bóveda). No es adoptar una versión nueva
   * de la tuya: esta llave pasa a ser de OTRA cuenta y deja de tener la suya, así que solo
   * procede sobre un perfil creado con `{ forVault: true }`. Si no, devuelve
   * `{ joined: false, reason: 'profile-has-data' }` y no escribe nada.
   * @type {IdentityApi['joinProfile']}
   */
  async joinProfile (acta) { return this._call('joinProfile', { acta }) }
  /**
   * Marca este perfil como nacido para ADOPTAR la cuenta de otro (camino A).
   * @type {IdentityApi['prepareForAdoption']}
   */
  async prepareForAdoption () { return this._call('prepareForAdoption') }
  /** MI tarjeta de perfil: lo mínimo que un contacto necesita para cifrarme a todos mis
   *  dispositivos (perfil, versión y llaves). Sin etiquetas ni permisos. */
  /** @type {IdentityApi['profileCard']} */
  async profileCard () { return this._call('profileCard') }
  /**
   * Guarda la tarjeta de otra persona en su ficha de contacto (verificándola).
   * @type {IdentityApi['adoptPeerCard']}
   */
  async adoptPeerCard (card) { return this._call('adoptPeerCard', { card }) }
  /**
   * La clave de contenido del perfil, abierta con la llave de cifrado de este dispositivo.
   * @type {IdentityApi['contentKey']}
   */
  async contentKey () { return this._call('contentKey') }
  /**
   * Cifra con la clave de contenido del perfil (la privada de cifrado no sale del vault).
   * @type {IdentityApi['sealContent']}
   */
  async sealContent (plaintext) { return this._call('sealContent', { plaintext }) }
  /**
   * Abre un sobre de contenido con el llavero del perfil.
   * @type {IdentityApi['openContent']}
   */
  async openContent (envelope) { return this._call('openContent', { envelope }) }
  /**
   * Rota la clave de contenido (corta el acceso al contenido FUTURO de quien ya no está).
   * @type {IdentityApi['rotateContentKey']}
   */
  async rotateContentKey () { return this._call('rotateContentKey') }
  /**
   * Abre un sobre de un CAJÓN DE SECRETOS con la envoltura dirigida a este aparato.
   *
   * Distinto de `openContent`, que usa el llavero del perfil: aquí la envoltura llega suelta
   * y la privada de cifrado de este dispositivo —que nunca sale del iframe— la abre. Es lo
   * que le permite a quien administra LEER una variable pública sin teclear ninguna
   * contraseña, y solo las que la bóveda le haya envuelto.
   * @type {IdentityApi['openSealedValue']}
   */
  async openSealedValue ({ wrap, envelope } = {}) { return this._call('openSealedValue', { wrap, envelope }) }

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
   * @type {IdentityApi['enrollDevice']}
   */
  async enrollDevice (qr, { label = '', join = 'current', account = null } = {}) {
    // DÓNDE CORRE se mira AQUÍ, en la página, y no dentro del iframe: el iframe no ve si la
    // página es una extensión o la app nativa (`vault/machine.js`).
    return this._call('vaultPair', { qr, label, join, account, machine: browserMachine() }, 200000)
  }

  /**
   * Estado de emparejamiento: { paired, deviceId?, master?, scope?, exp?, pairedAt? }.
   * @type {IdentityApi['vaultStatus']}
   */
  async vaultStatus () {
    return this._call('vaultStatus')
  }

  /**
   * Desvincula este dispositivo del vault (borra la sub-clave + el cert locales).
   * @type {IdentityApi['unpairDevice']}
   */
  async unpairDevice () {
    return this._call('vaultUnpair')
  }

  /**
   * Firma DELEGADA: pide a la maestra del vault (tu PC) que firme `payload`, usando
   * el cert de este dispositivo. Aditivo y explícito — NO cambia `signData` (local).
   * Requiere estar emparejado y el vault encendido. Devuelve { signature, publickey }
   * donde publickey es tu identidad MAESTRA.
   * @type {IdentityApi['vaultSign']}
   */
  async vaultSign (payload) {
    return this._call('vaultSign', { payload }, 20000)
  }

  /**
   * Store DELEGADO: lee/escribe el store de hilos+aperturas (appendMessage,
   * listThread, recordOpen, getOpens, getStats, …) EN tu vault, usando el cert de
   * este dispositivo. Reusa el mismo emparejamiento. Requiere el vault encendido.
   * @type {IdentityApi['vaultStore']}
   */
  async vaultStore (method, args, { wake = true } = {}) {
    return this._call('vaultStore', { method, args, wake }, 20000)
  }

  /**
   * CONSOLA REMOTA: administra el perfil desde este dispositivo, contra la bóveda
   * (`dotrino-vault/docs/consola-remota.md`). `op`: `pending` · `pair` · `approve` ·
   * `reject` · `revoke` · `audit`.
   *
   * Requiere que el cert de este aparato lleve `vault:admin`, que **no se recibe al
   * emparejar**: se concede a mano en la bóveda. Cambiar permisos y traspasar el mando
   * NO se administran a distancia — siguen siendo del master, en su máquina.
   *
   * `args.to`: la llave de comunicación de UNA bóveda de la cuenta (`vault` en el acta), para
   * hablarle a esa y no a la que conteste primero. Espera más: una alojada dormida tarda.
   * @type {IdentityApi['vaultAdmin']}
   */
  async vaultAdmin (op, args) {
    return this._call('vaultAdmin', { op, ...(args || {}) }, args?.to ? 50000 : 20000)
  }

  /**
   * PEDIDOS DE APROBACIÓN de la bóveda (cajones con `approval`): `op` = `approvals` ·
   * `approve` · `deny` (estos dos con `{ id }`). Requiere `vault:approve` en el cert.
   *
   * `args.notify` (solo con `approvals`): `true`/`false` según a este aparato le lleguen los
   * avisos de pedidos. La bóveda lo apunta, y para actualizarse solo pide permiso si hay un
   * aprobador que pueda enterarse. No pasarlo no cambia lo ya dicho.
   *
   * `args.profile` apunta a OTRA cuenta de este dispositivo (la que diga
   * `vaultApprovalsAll`); sin él es la activa.
   * @type {IdentityApi['vaultApprovals']}
   */
  async vaultApprovals (op, args) {
    return this._call('vaultApprovals', { op, ...(args || {}) }, 20000)
  }

  /**
   * LOS PEDIDOS DE TODAS TUS CUENTAS, SIN CAMBIARTE DE CUENTA.
   *
   * Una entrada por cuenta de este dispositivo que pueda aprobar: `{ profile, name,
   * current, items }`, o `{ ..., error }` si a esa no se le pudo preguntar. El timbre no
   * dice a qué cuenta llamó, así que quien enseña Pedidos tiene que mirar en todas —y
   * hacerlo cambiando la cuenta activa significaba una recarga por cuenta, con el avatar
   * y el icono de la app cambiando a la vista.
   *
   * Aprobar uno de otra cuenta: `vaultApprovals('approve', { id, profile })`.
   * @type {IdentityApi['vaultApprovalsAll']}
   */
  async vaultApprovalsAll (args) {
    return this._call('vaultApprovalsAll', args || {}, 30000)
  }

  /**
   * Registra el token de push de la app nativa (FCM/APNs) bajo la llave de este aparato.
   * @type {IdentityApi['registerPush']}
   */
  async registerPush (args) {
    return this._call('registerPush', args || {}, 20000)
  }

  /**
   * ¿El cert de este dispositivo le permite aprobar pedidos de la bóveda?
   * @type {IdentityApi['canApproveVault']}
   */
  async canApproveVault () {
    return this._call('canApproveVault', {}, 20000)
  }

  /**
   * ¿El cert de este dispositivo le permite administrar el perfil a distancia?
   * @type {IdentityApi['canAdminVault']}
   */
  async canAdminVault () {
    return this._call('canAdminVault', {}, 20000)
  }

  /**
   * Lista (solo lectura) los dispositivos enrolados en tu vault: { devices, revoked }.
   * @type {IdentityApi['listVaultDevices']}
   */
  async listVaultDevices () {
    return this._call('listVaultDevices', {}, 20000)
  }

  /**
   * El cert de delegación de este dispositivo (o null si no está emparejado). El
   * transporte lo presenta al proxy en `identify` → "una identidad": el proxy enruta
   * los mensajes dirigidos a tu maestra M también a este dispositivo. No tiene secretos.
   * @type {IdentityApi['getVaultCert']}
   */
  async getVaultCert () {
    return this._call('getVaultCert')
  }

  /**
   * Suscribe a eventos de emparejamiento ('vault'): { phase:'challenge'|'paired'|'unpaired', ... }.
   * @type {IdentityApi['onVault']}
   */
  onVault (handler) {
    return this.on('vault', handler)
  }

  // ----- Self-vault: ESTE dispositivo actúa como su propia bóveda/CA -----
  // El daemon device-vault vive dentro del iframe (no requiere el binario del PC).
  // Se gestiona desde profile.dotrino.com/#myvault. Cualquier app puede activarlo,
  // generar códigos de emparejamiento, aprobar SAS y revocar máquinas — todo por RPC
  // al iframe. El daemon sólo corre en una pestaña visible a la vez (navigator.locks),
  // pero los getters (status/pending/machines) y revoke sirven desde cualquier pestaña.
  /**
   * { enabled, running }: si el modo self está activado y si esta pestaña sostiene el daemon.
   * @type {IdentityApi['selfVaultStatus']}
   */
  async selfVaultStatus () { return this._call('selfVaultStatus') }
  /**
   * Activa/desactiva el modo self-vault en este dispositivo.
   * @type {IdentityApi['setSelfVault']}
   */
  async setSelfVault (enabled) { return this._call('setSelfVault', { enabled }) }
  /**
   * Genera un código de emparejamiento + QR para enlazar otra máquina. Sólo sirve desde la pestaña activa.
   * @type {IdentityApi['selfVaultPairing']}
   */
  async selfVaultPairing (opts) { return this._call('selfVaultPairing', opts || {}, 60000) }
  /**
   * Lista de solicitudes de emparejamiento pendientes de aprobar.
   * @type {IdentityApi['selfVaultPending']}
   */
  async selfVaultPending () { return this._call('selfVaultPending') }
  /**
   * Máquinas/agentes enrolados (delegaciones vigentes con scope vault:sign).
   * @type {IdentityApi['selfVaultMachines']}
   */
  async selfVaultMachines () { return this._call('selfVaultMachines') }
  /**
   * Aprueba una solicitud de emparejamiento comparando el código SAS.
   * @type {IdentityApi['selfVaultApprove']}
   */
  async selfVaultApprove (deviceId, code) { return this._call('selfVaultApprove', { deviceId, code }) }
  /**
   * Rechaza una solicitud de emparejamiento pendiente.
   * @type {IdentityApi['selfVaultReject']}
   */
  async selfVaultReject (deviceId) { return this._call('selfVaultReject', { deviceId }) }
  /**
   * QUITA una máquina/agente enrolado en esta bóveda. Se le pasa **el aparato**
   * (`{ sub }`, su llave): sale del acta y se le retiran todos sus certificados.
   *
   * Un `nonce` suelto (string, o `{ nonce }`) retira UN certificado y deja al aparato
   * dentro del acta: eso no es quitarlo, y quien queda así ya no recibe nunca el aviso
   * de expulsión. Se acepta por compatibilidad, no como la forma normal.
   * @type {IdentityApi['selfVaultRevoke']}
   */
  async selfVaultRevoke (target) {
    const p = typeof target === 'string' ? { nonce: target } : { sub: target?.sub, nonce: target?.nonce }
    return this._call('selfVaultRevoke', p)
  }
  /**
   * Presencia online (ping/pong) de las máquinas enroladas. Devuelve { online: [pubkeys] }.
   * @type {IdentityApi['selfVaultProbe']}
   */
  async selfVaultProbe (pubkeys) { return this._call('selfVaultProbe', { pubkeys }, 10000) }
  /**
   * Suscribe a eventos del self-vault ('selfVault'): { running?, pending?, error? }.
   * @type {IdentityApi['onSelfVault']}
   */
  onSelfVault (handler) { return this.on('selfVault', handler) }

  // ----- entrar con usuario y contraseña, cuando la bóveda es ESTA pestaña -----
  //
  // La pestaña ya atendía el inicio de sesión desde el primer día; lo que faltaba era poder
  // CREARLO, y sin eso solo el binario daba de alta el aparato — que rompe la regla de las
  // tres versiones. Todo esto exige que esta pestaña sea la bóveda activa; si no lo es, se
  // dice con `code: 'not-the-vault'` en vez de contestar una lista vacía.

  /**
   * Los aparatos que se abren con usuario y contraseña, con sus sesiones abiertas.
   * @type {IdentityApi['selfVaultLogins']}
   */
  async selfVaultLogins () { return this._call('selfVaultLogins') }

  /**
   * Da de alta uno. La contraseña **no sale del iframe**: se comprueba con OPAQUE y de ella
   * deriva la llave que cierra el paquete con las privadas del aparato nuevo.
   *
   * Devuelve su dirección `nombre@AB12-CD34-EF56`, que es lo que hay que teclear al entrar.
   * @type {IdentityApi['selfVaultLoginAdd']}
   */
  async selfVaultLoginAdd (opts) { return this._call('selfVaultLoginAdd', opts || {}, 60000) }

  /**
   * Cambia la contraseña: hace falta la vieja, y lo que estuviera abierto se cierra.
   * @type {IdentityApi['selfVaultLoginPasswd']}
   */
  async selfVaultLoginPasswd (opts) { return this._call('selfVaultLoginPasswd', opts || {}, 60000) }

  // ----- el RESPALDO, cuando la bóveda es ESTA pestaña (solo desde la consola) -----
  //
  // Bóveda abierta y origen de la consola (`vault.dotrino.com`): cualquier otro recibe
  // `code: 'not-the-console'`. El archivo vuelve YA CIFRADO con la contraseña dada.

  /**
   * Los cajones que hay: `[{ owner, count, device? }]`.
   * @type {IdentityApi['selfVaultBackupDrawers']}
   */
  async selfVaultBackupDrawers () { return this._call('selfVaultBackupDrawers', {}, 30000) }
  /**
   * Exporta todo (`drawers: null`) o esos cajones. Devuelve `{ file, summary }`.
   * @type {IdentityApi['selfVaultBackupExport']}
   */
  async selfVaultBackupExport (opts) { return this._call('selfVaultBackupExport', opts || {}, 120000) }
  /**
   * El plan de importar `file` (qué es nuevo, igual o choca). No escribe nada.
   * @type {IdentityApi['selfVaultBackupPlan']}
   */
  async selfVaultBackupPlan (opts) { return this._call('selfVaultBackupPlan', opts || {}, 120000) }
  /**
   * Importa. Con un choque sin decidir lanza `BACKUP_CONFLICTS` y no escribe nada.
   * @type {IdentityApi['selfVaultBackupImport']}
   */
  async selfVaultBackupImport (opts) { return this._call('selfVaultBackupImport', opts || {}, 120000) }

  /**
   * Cierra un inicio de sesión abierto (sin `sid`, todos los de ese usuario).
   * @type {IdentityApi['selfVaultLoginClose']}
   */
  async selfVaultLoginClose (opts) { return this._call('selfVaultLoginClose', opts || {}) }

  /**
   * Quita la espera que dejan los intentos fallidos.
   * @type {IdentityApi['selfVaultLoginUnblock']}
   */
  async selfVaultLoginUnblock (user) { return this._call('selfVaultLoginUnblock', { user }) }

  /**
   * Lo quita, y saca su llave del acta: las dos cosas, o ninguna.
   * @type {IdentityApi['selfVaultLoginRemove']}
   */
  async selfVaultLoginRemove (user) { return this._call('selfVaultLoginRemove', { user }, 30000) }

  // ----- multi-perfil por dispositivo -----
  // Podés tener varios perfiles (identidades) en el mismo navegador, cada uno conectado o no
  // a su propio vault. Crear/cambiar setea el perfil activo; la app RECARGA la página y toma
  // el nuevo (no reactivo: las apps abiertas conservan el perfil con el que cargaron).
  /**
   * Lista de perfiles: `[{ id, name, pubkey, avatar, current, pendingJoin, vault, approve }]`.
   *
   * `vault` = ese perfil está conectado a una bóveda · `approve` = además su certificado
   * le deja aprobar pedidos. Los dos salen de leer el cert guardado de cada perfil, sin
   * cambiar el activo ni firmar nada — es lo que necesita la pantalla de Pedidos para
   * saber a QUÉ perfil pertenece lo que timbró el teléfono.
   * @type {IdentityApi['listProfiles']}
   */
  async listProfiles () { return this._call('listProfiles') }
  /**
   * El perfil activo: { id, name, pubkey }.
   * @type {IdentityApi['currentProfile']}
   */
  async currentProfile () { return this._call('currentProfile') }
  /**
   * Crea un perfil nuevo (identidad fresca) y lo deja activo. La app debe recargar.
   *
   * `forVault: true` lo marca como **nacido para adoptar** la cuenta de una bóveda (camino B
   * de `vinculacion-de-cuentas.md`): es el único permiso que acepta `joinProfile`, y se
   * consume al unirse. Sin esa marca, la cuenta es de este dispositivo y nadie se la lleva.
   * @type {IdentityApi['createProfile']}
   */
  async createProfile (name, { forVault = false } = {}) { return this._call('createProfile', { name, forVault }) }
  /**
   * Cambia el perfil activo. La app debe recargar la página.
   * @type {IdentityApi['switchProfile']}
   */
  async switchProfile (id) { return this._call('switchProfile', { id }) }
  /**
   * Renombra un perfil (o el activo si no se pasa id).
   * @type {IdentityApi['renameProfile']}
   */
  async renameProfile (id, name) { return this._call('renameProfile', { id, name }) }
  /**
   * Borra un perfil y sus datos (no el único).
   * @type {IdentityApi['deleteProfile']}
   */
  async deleteProfile (id) { return this._call('deleteProfile', { id }) }

  // ----- entrar con usuario y contraseña (`temporary-access.md`) -----

  /**
   * ENTRAR en un aparato de tu cuenta desde un navegador que no te conoce, con la dirección
   * `nombre@AB12-CD34-EF56` y su contraseña. Devuelve `{ id, name, address, user, sid,
   * volatile }` y la app debe **recargar**: este navegador pasa a ser ese aparato.
   *
   * `remember: false` (lo normal en un equipo prestado) deja la cuenta en MEMORIA —se va al
   * cerrar o recargar la pestaña y no toca el disco de esa máquina—; `true` la guarda como
   * cualquier otra de este navegador, con la llave no extraíble, hasta que salgas.
   *
   * La contraseña no sale de aquí: se comprueba con OPAQUE, que no la manda ni deja
   * adivinarla. Los errores llegan con su `code`: `login-failed` (dirección o contraseña),
   * `too-many-tries` (con `waitMs`), `no-vault` (ninguna bóveda encendida en esa dirección).
   * @type {IdentityApi['loginWithPassword']}
   */
  async loginWithPassword ({ address, password, remember = false, label = '', proxyUrl = null } = /** @type {any} */ ({})) {
    return this._call('loginWithPassword', { address, password, remember, label, proxyUrl }, 60000)
  }

  /**
   * SALIR del inicio de sesión con contraseña (el activo, o el que digas). Recargar después.
   * @type {IdentityApi['logoutLogin']}
   */
  async logoutLogin (id = null) { return this._call('logoutLogin', { id }, 30000) }

  /**
   * Merge endorsements (signed ratings from third parties) about a subject
   * into the local peer book. Returns { merged, total }.
   * @type {IdentityApi['mergeEndorsements']}
   */
  async mergeEndorsements (subject, endorsements, askerPubkey) {
    return this._call('mergeEndorsements', { subject, endorsements, askerPubkey })
  }

  /**
   * Return what this vault knows about a subject for the purpose of
   * answering a RATING_QUERY: { mine: signedEnvelopeOrNull, endorsements: [] }.
   * @type {IdentityApi['getRatingsForSubject']}
   */
  async getRatingsForSubject (subject) {
    return this._call('getRatingsForSubject', { subject })
  }

  /**
   * Record that a peer asked us about a subject. Used for suspicion stats.
   * @type {IdentityApi['recordQuery']}
   */
  async recordQuery (askerPubkey, subject) {
    return this._call('recordQuery', { askerPubkey, subject })
  }

  /**
   * Update own nickname (broadcast to the vault, not to other apps automatically)
   * @type {IdentityApi['setMyNickname']}
   */
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
   * @type {IdentityApi['updateMe']}
   */
  async updateMe (patch) {
    const result = await this._call('updateMe', { patch })
    if (result?.me) this._me = result.me
    return result
  }

  /**
   * Tu `me` completo (incluye ocultos).
   * @type {IdentityApi['getMe']}
   */
  async getMe () { return this._call('getMe') }
  /**
   * Subconjunto PÚBLICO de tu perfil (solo lo visible) — para compartir/publicar.
   * @type {IdentityApi['publicMe']}
   */
  async publicMe () { return this._call('publicMe') }
  /**
   * CÓMO FUE EL ÚLTIMO EMPUJÓN del perfil a la bóveda: `{ ok, at, error }`.
   *
   * El núcleo lo lleva desde la fase 3 y aquí no estaba, así que una app no podía
   * preguntarlo — que es justo para lo que se guardó: poder decir «esto no se guardó» en
   * vez de enseñar tan tranquila un perfil que solo vive en este aparato.
   * @type {IdentityApi['profilePushState']}
   */
  async profilePushState () { return this._call('profilePushState') }

  /**
   * Pubkey ECDH (JWK string) propio para encripción.
   * @type {IdentityApi['getEncryptionPubkey']}
   */
  async getEncryptionPubkey () {
    return this._call('getEncryptionPubkey')
  }

  /**
   * Cifra `plaintext` para una lista de destinatarios usando ECDH+AES-GCM.
   * @param {Array<{token:string, encryptionPubkey:string}>} recipients
   * @param {string} plaintext
   * @returns {Promise<Object>} Envelope { v, iv, ct, wrap }
   * @type {IdentityApi['encrypt']}
   */
  async encrypt (recipients, plaintext) {
    return this._call('encrypt', { recipients, plaintext })
  }

  /**
   * Descifra un envelope dirigido a este vault.
   * @param {string} senderEncryptionPubkey JWK string del emisor
   * @param {string} myToken token efímero al que iba dirigido el wrap
   * @param {Object} envelope
   * @type {IdentityApi['decrypt']}
   */
  async decrypt (senderEncryptionPubkey, myToken, envelope) {
    return this._call('decrypt', { senderEncryptionPubkey, myToken, envelope })
  }

  /**
   * Export the full identity (private key + peer book) as a JSON-serializable object.
   * The blob can be saved to a file by the host app and re-imported later.
   * The private key is sensitive — handle accordingly.
   * @type {IdentityApi['exportIdentity']}
   */
  async exportIdentity () {
    return this._call('exportIdentity')
  }

  /**
   * Import a previously exported identity blob, replacing the current one.
   * Throws if the blob is malformed or keys are invalid.
   * @type {IdentityApi['importIdentity']}
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
   * @type {IdentityApi['syncConnect']}
   */
  async syncConnect (clientId) {
    return this._call('syncConnect', { clientId })
  }

  /** @type {IdentityApi['syncDisconnect']} */
  async syncDisconnect () {
    return this._call('syncDisconnect')
  }

  /**
   * Unlock auto-sync by providing the passphrase used to encrypt the backup.
   * Must be ≥ 8 chars. After unlock the sync engine pulls remote, merges,
   * and pushes on every local change (debounced).
   * @type {IdentityApi['syncUnlock']}
   */
  async syncUnlock (passphrase) {
    return this._call('syncUnlock', { passphrase })
  }

  /** @type {IdentityApi['syncLock']} */
  async syncLock () {
    return this._call('syncLock')
  }

  /**
   * { connected, unlocked, dirty, lastError }
   * @type {IdentityApi['syncStatus']}
   */
  async syncStatus () {
    return this._call('syncStatus')
  }

  /**
   * Force an immediate pull-then-push cycle.
   * @type {IdentityApi['syncNow']}
   */
  async syncNow () {
    return this._call('syncNow')
  }

  /**
   * Subscribe to sync status events emitted by the vault. Handler receives
   * `{ kind, status, error?, ts }` where status is one of
   * 'connected' | 'disconnected' | 'unlocked' | 'locked' | 'syncing' |
   * 'synced' | 'conflict' | 'offline' | 'error'.
   * @type {IdentityApi['onSync']}
   */
  onSync (handler) {
    return this.on('sync', handler)
  }

  /** @type {IdentityApi['on']} */
  on (event, handler) {
    if (!this._listeners) this._listeners = new Map()
    const listeners = this._listeners
    let set = listeners.get(event)
    if (!set) { set = new Set(); listeners.set(event, set) }
    set.add(handler)
    return () => this._listeners?.get(event)?.delete(handler)
  }

  /** @param {string} event @param {any} payload */
  _emit (event, payload) {
    const set = this._listeners?.get(event)
    if (!set) return
    for (const h of set) {
      try { h(payload) } catch (e) { console.error(e) }
    }
  }

  /**
   * @param {string} method
   * @param {Record<string, any>} [params]
   * @param {number} [timeoutMs]
   * @returns {Promise<any>}
   */
  _call (method, params = {}, timeoutMs = this.timeoutMs) {
    return new Promise((resolve, reject) => {
      const win = this._iframe?.contentWindow
      if (!win) {
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
      win.postMessage(
        { _cci: true, type: 'request', id, method, params },
        '*'
      )
    })
  }
}

// Helpers de capacidad SIN clave maestra (lado dispositivo + verificación), reutilizables
// por apps/bridges sin cargar el iframe del vault.
export { makeDeviceKey, makeDeviceEncKey, importDeviceEncKey, signWithDevice, verifyDelegation, verifyChain, pubkeyId, deriveSAS, verifyDeviceSig, makePairingCode, commitCode, avatarSvg, avatarDataUri } from '../vault/capabilities.js'

// PARA QUIÉN vale una firma, y hasta cuándo. Verificar NO necesita el iframe ni la clave
// de nadie, así que un servicio puede importarlo suelto (`@dotrino/identity/assertion`, que
// no arrastra el cliente del vault); aquí se reexporta para quien ya tiene esto cargado.
export { cleanMachine, machineLine, browserMachine, MACHINE_KINDS } from '../vault/machine.js'
export { verifyAssertion, verifySignedFor, newAssertionNonce, cleanScopes, claimsAllowed, assertionBody, SCOPES, SCOPE_CLAIMS, ASSERTION_MAX_TTL_MS, ASSERTION_DEFAULT_TTL_MS, ASSERTION_MAX_SKEW_MS } from '../vault/assertion.js'
