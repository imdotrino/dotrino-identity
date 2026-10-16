// El lado que RESPONDE: la bóveda de verdad (el vault del PC, la app nativa).
//
// Es donde vive la política, y por eso está aquí y no repartida por cada aparato:
// quién puede pedir, qué puede pedir, qué exige aprobación y qué queda anotado. Un
// aparato que pide no decide nada.

import { isRequest, reply, replyError, REMOTE_OPS, ADMIN_OPS } from '../transport/protocol.js'
import { ApprovalGate } from './approval.js'
import { privateKeysOf } from '../fields.js'
import { projectEntry } from '../model.js'
import { CODES } from './errors.js'

export class VaultResponder {
  /**
   * @param {object} opts
   *   `client`   cliente de @dotrino/proxy-client conectado e identificado
   *   `vault`    una bóveda con la CEK (LocalVault desbloqueada)
   *   `isAllowed(pubkey) -> boolean`  qué aparatos pueden pedir. Por defecto NADIE:
   *              una bóveda que responde a cualquiera no es una bóveda.
   *   `needsApproval(op, payload, pubkey) -> boolean|Promise`  qué exige un dedo encima.
   *              Por defecto: **solo `get`, y solo si lo pedido incluye algo privado**
   *              (dueño, 2026-08-29). Rellenar un nombre no es sacar un secreto.
   *   `approve({ op, payload, pubkey }) -> Promise<boolean>`  cómo se pide ese dedo
   *   `onRequest(record)`  la bitácora
   *   `admin`  `{ devices(), unlink(pubkey) }` — opcional. Sin esto, un aparato no
   *            puede administrar nada, que es el valor por defecto correcto.
   *
   * **La aprobación es del APARATO, no de cada credencial.** Se pide una vez y vale
   * mientras esta bóveda siga encendida; apagarla la retira. Es el mismo modelo que
   * `pair --approval` del vault: una por arranque, sin ventana de tiempo que vigilar.
   *
   * No se ata a la conexión a propósito: un service worker se duerme cada poco y
   * reconecta constantemente, así que «por conexión» sería pedir el dedo todo el rato.
   * Quien manda es la bóveda, que es la que el usuario apaga cuando quiere cortar.
   */
  constructor ({ client, vault, isAllowed, needsApproval, approve, onRequest, encPubOf, admin } = {}) {
    this.admin = admin || null
    this.client = client
    this.vault = vault
    // La pública de cifrado de cada aparato, para sellarle la respuesta. Abrir lo que
    // llega es cosa del cliente del pilar (`requireSealed` + `myEncPrivateKey`).
    this.encPubOf = encPubOf || (() => null)
    this.isAllowed = isAllowed || (() => false)
    this.needsApproval = needsApproval || ((op, payload) => this.wantsPrivate(op, payload))
    this.approve = approve || (async () => false)
    this.onRequest = onRequest || (() => {})
    this._handler = null
    // La puerta es la MISMA que la de la bóveda de dentro de la extensión
    // (`GuardedVault`): dedupe de simultáneas, el sí recordado, el no nunca. Aquí se
    // recuerda por APARATO, que es lo que dice §2.0, y vive en memoria — apagar la
    // bóveda retira lo aprobado, que es el diseño.
    this.gate = new ApprovalGate({
      ask: ({ op, payload, pubkey }) => this.approve({ op, payload, pubkey }),
      scope: ({ pubkey }) => pubkey,
    })
  }

  /** Retira la aprobación de un aparato sin apagar la bóveda. */
  revokeApproval (pubkey) {
    this.gate.revoke(pubkey || null)
  }

  isApproved (pubkey) {
    return this.gate.granted(pubkey)
  }

  /**
   * ¿Lo que se pide incluye algo PRIVADO? Es la pregunta que decide si hace falta un dedo
   * encima, y solo la puede contestar quien tiene la llave: hay que abrir la entrada para
   * saber qué campos marcó el usuario (§4.2).
   *
   * Es **pública** para que una bóveda con su propia política la componga en vez de
   * reescribirla: el vault del ecosistema, por ejemplo, aprueba por aparato *y* quiere
   * este criterio encima (`needsApproval(pubkey) && responder.wantsPrivate(op, payload)`).
   * Sin esto, cada bóveda acabaría con su propia idea de qué es privado.
   *
   * Si no se puede abrir, se contesta que **sí**: ante la duda, se pregunta.
   */
  async wantsPrivate (op, payload) {
    if (op !== 'get') return false
    try {
      const open = await this.vault.get(payload.id)
      const privadas = privateKeysOf(open)
      if (!Array.isArray(payload.keys)) return privadas.size > 0
      return payload.keys.some(k => privadas.has(k))
    } catch { return true }
  }

  start () {
    if (this._handler) return
    this._handler = (from, payload, meta) => {
      this.#handle(payload, meta?.fromPubkey || from, meta).catch(() => {})
    }
    this.client.on('message', this._handler)
  }

  stop () {
    if (this._handler && this.client.off) this.client.off('message', this._handler)
    this._handler = null
  }

  async #send (pubkey, msg) {
    try {
      // La respuesta lleva la credencial: se sella al aparato que la pidió, o no sale.
      const encPub = this.encPubOf(pubkey)
      if (!encPub) return
      await this.client.sendSealed([pubkey], msg, { peerEncPub: encPub })
    } catch { /* el que pidió reintentará */ }
  }

  async #handle (msg, fromPubkey, meta) {
    if (!isRequest(msg)) return

    // **Nada sin cifrar entra.** El cliente del pilar abre los sobres y marca
    // `meta.sealed`; aquí se exige esa marca. Sin ella bastaría con mandar la petición
    // en claro para saltarse el sellado entero, y el proxio vería qué se pide.
    if (meta?.sealed !== true) {
      this.onRequest({ op: msg.op, from: fromPubkey, ts: Date.now(), outcome: 'unsealed' })
      return
    }

    const record = { op: msg.op, from: fromPubkey, ts: Date.now() }

    // 1. ¿Es un aparato que conozco? Si no, ni se le contesta qué falló.
    if (!fromPubkey || !this.isAllowed(fromPubkey)) {
      this.onRequest({ ...record, outcome: 'denied' })
      return this.#send(fromPubkey, replyError(msg.rid, CODES.DENIED, 'aparato no autorizado'))
    }

    // 2. `list` no está en la lista, y esa ausencia es el diseño: si un aparato
    //    pudiera pedir la bóveda entera, el "de a una" no significaría nada.
    const esAdmin = ADMIN_OPS.includes(msg.op)
    if (!REMOTE_OPS.includes(msg.op) && !esAdmin) {
      this.onRequest({ ...record, outcome: 'denied' })
      return this.#send(fromPubkey, replyError(msg.rid, CODES.DENIED, 'operación no permitida en remoto'))
    }
    if (esAdmin && !this.admin) {
      this.onRequest({ ...record, outcome: 'denied' })
      return this.#send(fromPubkey, replyError(msg.rid, CODES.DENIED, 'esta bóveda no se administra en remoto'))
    }

    try {
      const payload = msg.payload || {}

      // Administrar SIEMPRE se aprueba, y aparte: retirar un aparato desde otro
      // aparato es tan delicado como entregar una contraseña, y en el otro sentido.
      // Que el aparato ya esté aprobado para pedir credenciales no le da esto.
      if (esAdmin) {
        const ok = await this.approve({ op: msg.op, payload, pubkey: fromPubkey, admin: true })
        if (!ok) {
          this.onRequest({ ...record, outcome: 'refused' })
          return this.#send(fromPubkey, replyError(msg.rid, CODES.NOT_APPROVED, 'no aprobado'))
        }
        const result = msg.op === 'devices'
          ? await this.admin.devices()
          : await this.admin.unlink(payload.pubkey)
        this.onRequest({ ...record, outcome: 'served' })
        return this.#send(fromPubkey, reply(msg.rid, result ?? null))
      }

      if (await this.needsApproval(msg.op, payload, fromPubkey)) {
        const ok = await this.gate.allow({ op: msg.op, payload, pubkey: fromPubkey })
        if (!ok) {
          this.onRequest({ ...record, outcome: 'refused' })
          return this.#send(fromPubkey, replyError(msg.rid, CODES.NOT_APPROVED, 'no aprobado'))
        }
      }

      let result
      switch (msg.op) {
        case 'find': result = await this.vault.find(payload.url); break
        // Solo lo pedido sale por el cable: sin este recorte, rellenar un nombre mandaba
        // la entrada entera —contraseña incluida— al aparato que preguntó.
        case 'get':
          result = projectEntry(await this.vault.get(payload.id),
            Array.isArray(payload.keys) ? payload.keys : null)
          break
        case 'put': result = await this.vault.put(payload.entry); break
        case 'patch': result = await this.vault.patch(payload.id, payload.changes); break
        case 'sites': result = await this.vault.sites(); break
        case 'search': result = await this.vault.search(payload.q, { limit: payload.limit }); break
        case 'remove': result = await this.vault.remove(payload.id); break
      }

      this.onRequest({ ...record, outcome: 'served', id: payload.id })
      await this.#send(fromPubkey, reply(msg.rid, result ?? null))
    } catch (e) {
      this.onRequest({ ...record, outcome: 'error', code: e?.code })
      await this.#send(fromPubkey, replyError(msg.rid, e?.code || 'error', e?.message))
    }
  }
}
