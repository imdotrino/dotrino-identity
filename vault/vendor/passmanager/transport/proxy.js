// Transporte del lado que PIDE (la extensión, la app).
//
// Cumple `{ request(op, payload) }`, que es lo único que `RemoteVault` necesita. El
// cliente del proxio se recibe ya construido y conectado: así esta pieza se prueba
// con un cliente falso y no arrastra la librería entera a los tests.

import { TYPE, REPLY, request as mkRequest, isReply } from './protocol.js'
import { VaultError, CODES } from '../vault/errors.js'

let counter = 0

function newRid () {
  const r = globalThis.crypto?.randomUUID
    ? globalThis.crypto.randomUUID()
    : String(++counter) + '-' + Math.floor(performance.now())
  return r
}

export class ProxyTransport {
  /**
   * @param {object} opts
   *   `client`      cliente de @dotrino/proxy-client ya conectado e identificado
   *   `peerPubkey`  pubkey de FIRMA de la bóveda: por ahí la enruta el proxio
   *   `peerEncPub`  pubkey de CIFRADO de la bóveda: a ella se sella el contenido
   *   `myEncPrivateKey`  mi privada de cifrado, para abrir lo que me devuelvan
   *   `timeoutMs`   cuánto se espera. Generoso a propósito: al otro lado puede
   *                 haber alguien poniendo el dedo en el teléfono.
   */
  constructor ({ client, peerPubkey, peerEncPub, myEncPrivateKey, timeoutMs = 90_000 }) {
    this.client = client
    this.peerPubkey = peerPubkey
    this.peerEncPub = peerEncPub
    this.myEncPrivateKey = myEncPrivateKey
    this.timeoutMs = timeoutMs
    this.pending = new Map()

    this.client.on('message', (_from, payload, meta) => {
      this.#onMessage(payload, meta).catch(() => {})
    })
  }

  async #onMessage (payload, meta) {
    // **Ninguna respuesta en claro se acepta.** El cliente del pilar es quien abre los
    // sobres (`requireSealed` + `myEncPrivateKey`) y marca `meta.sealed`; aquí solo se
    // exige esa marca. Si se aceptara texto plano, cualquiera podría contestar por la
    // bóveda: no podría leer lo que se pidió, pero sí colar una credencial falsa en un
    // formulario.
    if (!isReply(payload)) return
    if (meta?.sealed !== true) {
      this.#fail(payload.rid, CODES.UNSEALED, 'respuesta sin cifrar')
      return
    }

    const p = this.pending.get(payload.rid)
    if (!p) return // respuesta a algo que ya venció; se ignora
    this.pending.delete(payload.rid)
    clearTimeout(p.timer)
    if (payload.error) {
      p.reject(new VaultError(payload.error.code || 'error', payload.error.message))
    } else {
      p.resolve(payload.result)
    }
  }

  #fail (rid, code, message) {
    const p = this.pending.get(rid)
    if (!p) return
    this.pending.delete(rid)
    clearTimeout(p.timer)
    p.reject(new VaultError(code, message))
  }

  request (op, payload) {
    const rid = newRid()
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        this.pending.delete(rid)
        // No es "no hay nadie": es que nadie contestó. Suele ser el teléfono sin
        // que nadie lo mire, y el código lo distingue para poder decirlo bien.
        reject(new VaultError(CODES.APPROVAL_TIMEOUT, 'nadie respondió a tiempo'))
      }, this.timeoutMs)

      this.pending.set(rid, { resolve, reject, timer })

      // Sale SELLADO, y de eso se encarga el pilar. Por pubkey y no por token: así
      // entra la cola offline del proxio y la petición sobrevive a que la bóveda esté
      // reconectando.
      this.client
        .sendSealed([this.peerPubkey], mkRequest(rid, op, payload), { peerEncPub: this.peerEncPub })
        .catch(e => {
          this.pending.delete(rid)
          clearTimeout(timer)
          // Se CONSERVA el código del error. Envolverlo todo en `unreachable` haría que
          // «no tengo la llave del otro lado» y «se cayó la red» se vieran igual desde
          // arriba, y son cosas distintas: una se arregla enlazando, la otra esperando.
          if (e instanceof VaultError) return reject(e)
          reject(new VaultError(e?.code || CODES.UNREACHABLE, e?.message || 'no se pudo enviar'))
        })
    })
  }

  /** Cancela lo que esté esperando. Se llama al cerrar el popup o al desenlazar. */
  close (code = CODES.UNREACHABLE) {
    for (const [rid, p] of this.pending) {
      clearTimeout(p.timer)
      p.reject(new VaultError(code, 'transporte cerrado'))
      this.pending.delete(rid)
    }
  }
}

export { TYPE, REPLY }
