/**
 * BYTES QUE VIAJAN COMO BYTES (0.35.0).
 *
 * Hasta aquí un archivo viajaba dos veces en base64: la app lo metía en base64 en el JSON
 * del mensaje (×1,33), el sellado cifraba ese JSON y lo volvía a pasar a base64 (×1,33), y
 * el resultado iba como texto. Medido: 1,78 veces el tamaño del archivo en el cable.
 *
 * Ahora una app puede poner `Uint8Array` dentro de lo que manda, y el pilar lo lleva tal
 * cual: lo empaqueta (`pack`), lo cifra como bytes y lo manda en una trama BINARIA, al
 * proxio y al canal directo. Lo que no lleva bytes sale exactamente como antes, en texto:
 * así las piezas que no saben de esto (las apps nativas, las versiones anteriores) siguen
 * hablando con todos para lo de siempre.
 *
 * Dos formatos, y los dos son de este archivo para que no haya una segunda copia:
 *
 *   · EL PAQUETE (`pack`/`unpack`): un objeto con bytes dentro.
 *       [0xB1][u32 largo del JSON][JSON][bytes, uno detrás de otro]
 *     Cada `Uint8Array` del objeto queda en el JSON como `{"__dotrino_bin":[desde,largo]}`.
 *
 *   · LA TRAMA (`encodeFrame`/`decodeFrame`): lo que va por el WebSocket del proxio.
 *       [0x01][u32 largo de la cabecera][cabecera JSON][cuerpo]
 *     La cabecera es la trama de texto de siempre sin `message`; el cuerpo es el `message`.
 *     El proxio lee la cabecera para enrutar y no mira el cuerpo, que va sellado.
 */

import { errorWithCode } from './errors.js'

export const BIN_TAG = '__dotrino_bin'
const PACK_MAGIC = 0xB1
const FRAME_VERSION = 0x01

const enc = new TextEncoder()
const dec = new TextDecoder()

/** Bytes, sin importar de qué vista vengan (`Buffer`, `ArrayBuffer`, `Uint8Array`). */
export function asBytes (v) {
  if (v instanceof Uint8Array) return v
  if (v instanceof ArrayBuffer) return new Uint8Array(v)
  if (ArrayBuffer.isView(v)) return new Uint8Array(v.buffer, v.byteOffset, v.byteLength)
  return null
}

/** ¿Lleva bytes este valor, a cualquier profundidad? Es lo que decide texto o binario. */
export function hasBinary (v) {
  if (v instanceof Uint8Array || v instanceof ArrayBuffer) return true
  if (Array.isArray(v)) return v.some(hasBinary)
  if (v && typeof v === 'object') {
    for (const k in v) if (hasBinary(v[k])) return true
  }
  return false
}

/** Un objeto con bytes dentro → un solo `Uint8Array`. */
export function pack (obj) {
  const blobs = []
  let off = 0
  const json = JSON.stringify(obj, function (k, v) {
    // `this[k]` es el valor antes de `toJSON`: un Buffer de Node se convertiría en
    // `{ type: 'Buffer', data: [...] }` y aquí lo queremos como bytes.
    const b = asBytes(this[k])
    if (!b) return v
    blobs.push(b)
    const ref = { [BIN_TAG]: [off, b.byteLength] }
    off += b.byteLength
    return ref
  })
  const head = enc.encode(json)
  const out = new Uint8Array(5 + head.length + off)
  out[0] = PACK_MAGIC
  new DataView(out.buffer).setUint32(1, head.length)
  out.set(head, 5)
  let p = 5 + head.length
  for (const b of blobs) { out.set(b, p); p += b.byteLength }
  return out
}

export const isPacked = (b) => b instanceof Uint8Array && b.length >= 5 && b[0] === PACK_MAGIC

/**
 * Un paquete → el objeto, con sus bytes como `Uint8Array` (vistas sobre `bytes`, sin copiar).
 * Lanza con `code: 'bad-pack'` si no es un paquete o una referencia se sale de él.
 */
export function unpack (bytes) {
  const b = asBytes(bytes)
  if (!isPacked(b)) throw errorWithCode('not a packed message', 'bad-pack')
  const len = new DataView(b.buffer, b.byteOffset, b.byteLength).getUint32(1)
  if (5 + len > b.length) throw errorWithCode('packed message is shorter than its header says', 'bad-pack')
  const area = b.subarray(5 + len)
  let obj
  try { obj = JSON.parse(dec.decode(b.subarray(5, 5 + len))) } catch (_) { throw errorWithCode('packed message header is not JSON', 'bad-pack') }
  const revive = (v) => {
    if (Array.isArray(v)) return v.map(revive)
    if (!v || typeof v !== 'object') return v
    const ref = v[BIN_TAG]
    if (ref !== undefined) {
      if (!Array.isArray(ref) || ref.length !== 2 || !Number.isInteger(ref[0]) || !Number.isInteger(ref[1]) ||
          ref[0] < 0 || ref[1] < 0 || ref[0] + ref[1] > area.length) {
        throw errorWithCode('packed message points outside itself', 'bad-pack')
      }
      return area.subarray(ref[0], ref[0] + ref[1])
    }
    const out = {}
    for (const k of Object.keys(v)) out[k] = revive(v[k])
    return out
  }
  return revive(obj)
}

/** Une varios trozos de bytes en uno. */
export function concatBytes (list) {
  const out = new Uint8Array(list.reduce((a, b) => a + b.byteLength, 0))
  let p = 0
  for (const b of list) { out.set(b, p); p += b.byteLength }
  return out
}

/** La trama binaria del proxio: la cabecera de texto de siempre, y el `message` en crudo. */
export function encodeFrame (header, body) {
  const head = enc.encode(JSON.stringify(header))
  const out = new Uint8Array(5 + head.length + body.byteLength)
  out[0] = FRAME_VERSION
  new DataView(out.buffer).setUint32(1, head.length)
  out.set(head, 5)
  out.set(body, 5 + head.length)
  return out
}

/** El inverso: `{ header, body }`. Lanza con `code: 'bad-frame'` si no es una trama válida. */
export function decodeFrame (data) {
  const b = asBytes(data)
  if (!b || b.length < 5 || b[0] !== FRAME_VERSION) throw errorWithCode('not a binary frame of a known version', 'bad-frame')
  const len = new DataView(b.buffer, b.byteOffset, b.byteLength).getUint32(1)
  if (5 + len > b.length) throw errorWithCode('binary frame is shorter than its header says', 'bad-frame')
  let header
  try { header = JSON.parse(dec.decode(b.subarray(5, 5 + len))) } catch (_) { throw errorWithCode('binary frame header is not JSON', 'bad-frame') }
  if (!header || typeof header !== 'object' || Array.isArray(header)) throw errorWithCode('binary frame header is not an object', 'bad-frame')
  return { header, body: b.subarray(5 + len) }
}
