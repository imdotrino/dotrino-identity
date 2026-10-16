// EL LADO QUE RESPONDE, con el formato sellado.
//
// Hace lo mismo que `VaultResponder` —es donde vive la política: quién puede pedir, qué
// exige un dedo encima y qué queda anotado— con una diferencia que lo cambia todo: **esta
// bóveda no puede abrir nada**. Así que lo que entrega son sobres, y lo que comprueba es lo
// que se puede comprobar sin ninguna llave.
//
// Va aparte del responder de siempre y no dentro de él porque el protocolo es OTRO
// (`pm2.*`, ver `../transport/protocol.js`): mezclarlos daría una clase con dos modos, que
// es como se acaba sirviendo el formato viejo «mientras tanto» — o sea, el agujero otra vez.

import { isRequest, reply, replyError, SEALED_OPS } from '../transport/protocol.js'
import { ApprovalGate } from './approval.js'
import { ALWAYS_PRIVATE } from '../fields.js'
import { CODES } from './errors.js'
import { PASSKEY_FIELD } from '../sealed/entry.js'

/** Lo que es privado POR LO QUE ES, sin mirar ninguna marca. */
const SIEMPRE_PRIVADO = new Set([...ALWAYS_PRIVATE.filter((k) => k !== 'webauthn'), PASSKEY_FIELD, 'wa.userHandle'])

export class SealedResponder {
  /**
   * @param {object} opts
   *   `client`    cliente de `@dotrino/proxy-client` conectado e identificado
   *   `store`     una `SealedStore`
   *   `recipients()` → `{ recoveryPub, main, passkeys }`, del acta
   *   `isAllowed(pubkey)`  quién puede pedir (el acta: `passwords`). Por defecto NADIE.
   *   `needsApproval(pubkey)`  si ese aparato tiene que pedir permiso (el acta:
   *      `unattended`). Se compone con el criterio de abajo: **solo lo privado pregunta**.
   *   `approve({ op, payload, pubkey })`  pide el visto bueno y espera
   *   `encPubOf(pubkey)`  para sellarle la respuesta
   *   `onRequest(record)` la bitácora
   */
  constructor ({ client, store, recipients, isAllowed, needsApproval, approve, encPubOf, onRequest } = {}) {
    this.client = client
    this.store = store
    this.recipients = recipients || (async () => ({ recoveryPub: null, main: [], passkeys: [] }))
    this.isAllowed = isAllowed || (() => false)
    this.encPubOf = encPubOf || (() => null)
    this.needsApproval = needsApproval || (async () => true)
    this.approve = approve || (async () => false)
    this.onRequest = onRequest || (() => {})
    this._handler = null
    this.gate = new ApprovalGate({
      ask: ({ op, payload, pubkey }) => this.approve({ op, payload, pubkey }),
      scope: ({ pubkey }) => pubkey
    })
  }

  revokeApproval (pubkey) { this.gate.revoke(pubkey || null) }
  isApproved (pubkey) { return this.gate.granted(pubkey) }

  /**
   * ¿LO QUE SE PIDE ES PRIVADO? Aquí se contesta SIN abrir nada, y por eso hace falta la
   * lista en claro de la entrada (`priv`): la bóveda no ve la vista.
   *
   * Sin `keys` se pide la entrada entera, y eso siempre es privado: pedir todo es pedir la
   * contraseña.
   */
  async wantsPrivate (op, payload) {
    if (op !== 'pm2.get') return false
    const keys = payload?.keys
    if (!Array.isArray(keys)) return true
    const priv = new Set(await this.store.privateKeysOf(payload?.id))
    return keys.some((k) => SIEMPRE_PRIVADO.has(k) || priv.has(k))
  }

  start () {
    if (this._handler) return
    this._handler = async (from, msg, meta) => {
      const p = typeof msg === 'string' ? (() => { try { return JSON.parse(msg) } catch (_) { return null } })() : msg
      if (!isRequest(p)) return
      // QUIÉN PREGUNTA lo dice el proxio (`fromPubkey`: la llave con la que se identificó esa
      // conexión) o un saludo previo (`pubkeyOfToken`). Aquí se leía `meta.pubkey`, que no
      // existe, y se caía al token: ninguna bóveda sabía a quién sellarle la respuesta, no
      // contestaba, y del otro lado se veía «nadie respondió». Sin llave no hay a quién
      // contestar sellado, así que no se contesta — el token no es una llave.
      const pubkey = meta?.fromPubkey || this.client?.pubkeyOfToken?.(from) || null
      if (!pubkey) { this.onRequest({ op: p.op, outcome: 'anonymous', from: null }); return }
      await this.handle({ from, pubkey, msg: p, sealed: meta?.sealed === true })
    }
    this.client.on('message', this._handler)
  }

  stop () {
    if (!this._handler) return
    this.client.off?.('message', this._handler)
    this._handler = null
  }

  /** Contesta UNA petición. Público para que las pruebas no tengan que fingir un socket. */
  async handle ({ from, pubkey, msg, sealed = true }) {
    const { rid, op, payload } = msg
    const anota = (outcome, extra = {}) => this.onRequest({ op, outcome, from: pubkey, ...extra })
    // EL SELLADO DEL TRANSPORTE NO ES OPCIONAL (CONVENCIONES §4.1): lo que llega en claro
    // no se atiende, porque contestarlo sería mandar sobres a quien no sabemos que es.
    //
    // Los códigos son los del responder de siempre (`responder.js`): «la política dice que
    // no» es `denied` y «el humano dijo que no» es `not-approved`. Se arreglan distinto —uno
    // dando permiso al aparato, el otro volviendo a pedir— y quien pide los distingue así.
    if (!sealed) { anota('unsealed'); return this.#send(from, pubkey, replyError(rid, CODES.UNSEALED, 'unsealed request')) }
    if (!SEALED_OPS.includes(op)) { anota('unknown-op'); return this.#send(from, pubkey, replyError(rid, CODES.DENIED, 'operation not allowed: ' + op)) }
    if (!this.isAllowed(pubkey)) { anota('denied'); return this.#send(from, pubkey, replyError(rid, CODES.DENIED, 'this device cannot ask for passwords')) }

    try {
      if (await this.#needsApproval(op, payload, pubkey)) {
        // `allow`, no `ask`: es el que RECUERDA el sí y junta las simultáneas. `ask` es la
        // función cruda de preguntar, y usarla directamente hacía sonar el teléfono en cada
        // petición — que es como se enseña a aprobar sin mirar.
        const ok = await this.gate.allow({ op, payload, pubkey })
        if (!ok) { anota('rejected'); return this.#send(from, pubkey, replyError(rid, CODES.NOT_APPROVED, 'not approved on the trusted device')) }
      }
      const result = await this.#run(op, payload, pubkey)
      anota('ok')
      return this.#send(from, pubkey, reply(rid, result))
    } catch (e) {
      anota('error', { code: e?.code })
      return this.#send(from, pubkey, replyError(rid, e?.code || CODES.UNKNOWN, e?.message || 'error'))
    }
  }

  async #needsApproval (op, payload, pubkey) {
    return await this.needsApproval(pubkey) && await this.wantsPrivate(op, payload)
  }

  async #run (op, payload = {}, pubkey) {
    switch (op) {
      case 'pm2.recipients': return this.recipients()
      case 'pm2.profile':
        // Con `set` se estrena (al convertir); sin él, se pide la que hay.
        if (payload.set) return this.store.setProfile(payload.set)
        return this.store.profile({ pub: pubkey })
      case 'pm2.views': return this.store.views({ pub: pubkey })
      case 'pm2.find': return this.store.find({ pub: pubkey, idx: payload.idx || [] })
      case 'pm2.passkey': return this.store.findPasskey({ pub: pubkey, rp: payload.rp, cred: payload.cred })
      case 'pm2.get': return this.store.get(payload.id, { pub: pubkey, keys: payload.keys })
      case 'pm2.put': return this.store.putSealed({ ...payload, by: pubkey })
      case 'pm2.patch': return this.store.patchSealed({ ...payload, by: pubkey })
      case 'pm2.remove': return this.store.remove(payload.id)
      default: throw Object.assign(new Error('operation not allowed: ' + op), { code: CODES.DENIED })
    }
  }

  /** `to` es por dónde se contesta (el token); `pubkey`, a quién se le sella. */
  #send (to, pubkey, msg) {
    const encPub = this.encPubOf(pubkey)
    // La respuesta va SELLADA: el proxio enruta pero no cifra. Si no se puede sellar, no se
    // manda — mandarlo en claro sería entregar los sobres y las envolturas a quien mire.
    if (encPub && typeof this.client.sendSealedTo === 'function') {
      return this.client.sendSealedTo(to, msg, { peerEncPub: encPub })
    }
    if (typeof this.client.sendSealed === 'function' && encPub) {
      return this.client.sendSealed([to], msg, { peerEncPub: encPub })
    }
    throw Object.assign(new Error('cannot seal the reply to that device: it has no encryption key in the record'), { code: 'no-encpub' })
  }
}

export default SealedResponder
