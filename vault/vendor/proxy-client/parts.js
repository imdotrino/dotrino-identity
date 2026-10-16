/**
 * MENSAJES GRANDES, EN PARTES (0.33.0).
 *
 * Un mensaje dirigido tiene techo en cada camino: el canal directo (WebRTC) rechaza lo que
 * pasa de 64 KiB hacia libwebrtc y la trama del proxio es de 1 MB. Antes, lo que no cabía
 * en el canal directo se iba callado por el proxio (y llegaba desordenado), y lo que no
 * cabía en la trama no salía. Ahora el pilar parte el mensaje y la otra punta lo rearma:
 * la app manda y recibe un objeto entero, como siempre.
 *
 * La regla del dueño (2026-10-15), que es lo que decide los topes:
 *   - por el canal directo (WebRTC, también por TURN) NO HAY TOPE;
 *   - por el proxio EN VIVO (los dos conectados, sin canal directo), como mucho 25 MB de
 *     archivo: cada parte cruza el VPS dos veces, y uno de 25 MB ya son ~90 MB de tráfico.
 *     Más que eso lanza `too-big-for-relay`, y sale cuando haya canal directo;
 *   - lo que se queda ESPERANDO en el proxio (por pubkey, el otro desconectado) es como
 *     mucho 8 MB de archivo: una foto de teléfono pesa 2-5 MB, y con 1 MB (lo primero que se
 *     pensó) casi ninguna habría podido esperar. Lo que pasa de ahí no se deja en el proxio:
 *     se lanza `too-big-for-queue`.
 *
 * Cada parte va SELLADA por su cuenta (el pilar sella cada una como cualquier mensaje), así
 * que el proxio no ve ni el contenido ni cuántas partes son de qué. El rearmado agrupa por la
 * llave que selló: nadie más puede colar una parte en el mensaje de otro.
 */

import { pack, unpack, concatBytes } from './binpack.js'

export const PART_TAG = '__dotrino_part'

/** Parte por el canal directo: por debajo de los 64 KiB que acepta libwebrtc, ya sellada. */
export const DIRECT_PART_CHARS = 40 * 1024
/** Parte por el proxio: sellada (×1,37) cabe holgada en la trama de 1 MB. */
export const PROXY_PART_CHARS = 512 * 1024
/**
 * Lo más que se deja esperando en el proxio. Se mide sobre el JSON del mensaje: 8 MB de
 * archivo en base64 ocupan ~10,7 MB, y se deja margen para lo que va alrededor.
 */
export const QUEUE_MAX_CHARS = 11 * 1024 * 1024
/** Lo más que pasa por el proxio EN VIVO: 25 MB de archivo son ~33,4 MB en base64. */
export const RELAY_MAX_CHARS = 34 * 1024 * 1024

/**
 * LOS MISMOS TOPES PARA UN MENSAJE CON BYTES (0.35.0), medidos sobre su paquete (binpack.js),
 * que ocupa lo que el archivo más unos pocos bytes: 8 MB y 25 MB de archivo, con 64 KB de
 * margen para el texto que va alrededor (nombre, tipo, pie de foto).
 */
export const QUEUE_MAX_BYTES = 8 * 1024 * 1024 + 64 * 1024
export const RELAY_MAX_BYTES = 25 * 1024 * 1024 + 64 * 1024
/**
 * Parte binaria por el canal directo: bajo los 64 KiB de libwebrtc, con sitio para el sobre
 * de la llave, que la bóveda envuelve para cada aparato del destinatario.
 */
export const DIRECT_PART_BYTES = 48 * 1024
/** Parte binaria por el proxio: cabe en su trama de 1 MB con la cabecera y el sobre. */
export const PROXY_PART_BYTES = 768 * 1024

/** Rearmado: lo que se acepta guardar a medias, y cuánto se espera a la parte siguiente. */
const RECV_MAX_CHARS = 512 * 1024 * 1024
const RECV_IDLE_MS = 5 * 60 * 1000
const MAX_PARTS = 1 << 20

/** El id de un mensaje en partes: al azar, para que dos mensajes no se mezclen. */
export function partId () {
  const b = new Uint8Array(12)
  globalThis.crypto.getRandomValues(b)
  return Array.from(b, (x) => x.toString(16).padStart(2, '0')).join('')
}

/** Las partes (ya como objetos para sellar) de un JSON de `json.length` > `size`. */
export function splitParts (json, size) {
  const n = Math.ceil(json.length / size)
  const id = partId()
  const out = []
  for (let i = 0; i < n; i++) out.push({ [PART_TAG]: { id, i, n }, d: json.slice(i * size, (i + 1) * size) })
  return out
}

/**
 * Las partes de un paquete de `bytes.length` > `size`, cada una ya empaquetada (lista para
 * cifrar como bytes). El rearmado une los trozos y desempaqueta el resultado.
 */
export function splitBinParts (bytes, size) {
  const n = Math.ceil(bytes.byteLength / size)
  const id = partId()
  const out = []
  for (let i = 0; i < n; i++) out.push(pack({ [PART_TAG]: { id, i, n }, d: bytes.subarray(i * size, (i + 1) * size) }))
  return out
}

export const isPart = (o) => !!(o && typeof o === 'object' && o[PART_TAG])

/**
 * Rearma los mensajes. `add` devuelve el mensaje entero cuando llega la última parte, `null`
 * mientras falten, y lanza con `code` si la parte no vale (se dice: una parte mala no puede
 * desaparecer en silencio, porque el mensaje entero se pierde con ella).
 */
export class Reassembler {
  constructor ({ onExpire = () => {} } = {}) {
    this._open = new Map()
    this._chars = 0
    this._onExpire = onExpire
  }

  /** @param {string} sender quién selló (agrupa) @param {any} part */
  add (sender, part) {
    const p = part[PART_TAG]
    const d = part.d
    if (!p || typeof p.id !== 'string' || p.id.length > 64 ||
        !Number.isInteger(p.n) || !Number.isInteger(p.i) || p.n < 2 || p.n > MAX_PARTS ||
        p.i < 0 || p.i >= p.n || (typeof d !== 'string' && !(d instanceof Uint8Array))) {
      throw Object.assign(new Error('malformed message part'), { code: 'bad-part' })
    }
    const key = `${sender}|${p.id}`
    let a = this._open.get(key)
    if (!a) {
      a = { n: p.n, bin: d instanceof Uint8Array, got: new Array(p.n), count: 0, chars: 0, timer: null }
      this._open.set(key, a)
    }
    if (a.n !== p.n || a.bin !== (d instanceof Uint8Array)) {
      this._drop(key)
      throw Object.assign(new Error('message parts disagree on their count or kind'), { code: 'bad-part' })
    }
    if (a.got[p.i] === undefined) {
      if (this._chars + d.length > RECV_MAX_CHARS) {
        this._drop(key)
        throw Object.assign(new Error('too much of a message in parts is pending'), { code: 'parts-too-big' })
      }
      // Una copia: `d` es una vista sobre la trama entera, y guardarla retendría la trama.
      a.got[p.i] = a.bin ? d.slice() : d
      a.count++
      a.chars += d.length
      this._chars += d.length
    }
    if (a.timer) clearTimeout(a.timer)
    if (a.count === a.n) {
      this._drop(key)
      try { return a.bin ? unpack(concatBytes(a.got)) : JSON.parse(a.got.join('')) }
      catch (_) { throw Object.assign(new Error('a message in parts did not join into a message'), { code: 'bad-part' }) }
    }
    a.timer = setTimeout(() => {
      const missing = a.n - a.count
      this._drop(key)
      this._onExpire({ id: p.id, parts: a.n, missing })
    }, RECV_IDLE_MS)
    a.timer.unref?.()
    return null
  }

  _drop (key) {
    const a = this._open.get(key)
    if (!a) return
    if (a.timer) clearTimeout(a.timer)
    this._chars -= a.chars
    this._open.delete(key)
  }

  clear () { for (const k of [...this._open.keys()]) this._drop(k) }
}
