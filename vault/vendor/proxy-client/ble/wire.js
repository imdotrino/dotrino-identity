/**
 * EL CABLE DEL BLUETOOTH (docs/bluetooth.md). Módulo PURO: sin red, sin Bluetooth, solo
 * WebCrypto. Lo que aquí se decide lo cumplen igual los puertos de `dotrino-native`: si
 * cambia un byte, cambia en los tres.
 */

const BASE = '0be25149-664d-4d28-b496-3ca98a63fb'
export const SERVICE_UUID = BASE + '00'
export const HELLO_UUID = BASE + '01'
export const BEACON_UUID = BASE + '02'
export const RX_UUID = BASE + '03'
export const TX_UUID = BASE + '04'

/** Trama de control por el proxio, hermana de la de WebRTC (`__cc_rtc__`). */
export const BLE_TAG = '__cc_ble__'

export const BID_BYTES = 8
export const BID_ROTATE_MS = 15 * 60 * 1000
export const BEACON_MAX_BYTES = 512
export const RECORD_MAX_BYTES = 1024 * 1024
export const ANSWER_TIMEOUT_MS = 10_000
export const FIND_TIMEOUT_MS = 20_000

export const DIR_TO_PERIPHERAL = 0
export const DIR_TO_CENTRAL = 1

export const TYPE_TEXT = 0
export const TYPE_BINARY = 1
export const TYPE_HELLO = 2

const LAST = 0x01
const enc = new TextEncoder()
const dec = new TextDecoder()

function subtle () {
  const s = globalThis.crypto?.subtle
  if (!s) throw Object.assign(new Error('bluetooth: WebCrypto is not available here'), { code: 'no-webcrypto' })
  return s
}

export function b64u (bytes) {
  let s = ''
  for (const b of bytes) s += String.fromCharCode(b)
  return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
}

export function unb64u (str) {
  const s = String(str).replace(/-/g, '+').replace(/_/g, '/')
  const bin = atob(s + '='.repeat((4 - s.length % 4) % 4))
  const out = new Uint8Array(bin.length)
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i)
  return out
}

export function randomBid () {
  return b64u(globalThis.crypto.getRandomValues(new Uint8Array(BID_BYTES)))
}

// ---------- características de solo lectura ----------

export function encodeHello (bid) { return enc.encode(JSON.stringify({ v: 1, bid })) }

/** El `bid` de un `hello` leído, o null si no es de esta versión. */
export function decodeHello (bytes) {
  try {
    const o = JSON.parse(dec.decode(bytes))
    return o && o.v === 1 && typeof o.bid === 'string' ? o.bid : null
  } catch (_) { return null }
}

export function encodeBeacon (kind, data) {
  if (typeof kind !== 'string' || !kind || typeof data !== 'string') {
    throw Object.assign(new Error('bluetooth: announce needs a kind and a string'), { code: 'bad-beacon' })
  }
  const bytes = enc.encode(JSON.stringify({ kind, data }))
  if (bytes.length > BEACON_MAX_BYTES) {
    throw Object.assign(new Error(`bluetooth: what is announced takes ${bytes.length} bytes; at most ${BEACON_MAX_BYTES}`), { code: 'beacon-too-big' })
  }
  return bytes
}

/** `{kind, data}` de un `beacon` leído, o null si está vacío o no se entiende. */
export function decodeBeacon (bytes) {
  if (!bytes || !bytes.length) return null
  try {
    const o = JSON.parse(dec.decode(bytes))
    return o && typeof o.kind === 'string' && typeof o.data === 'string' ? { kind: o.kind, data: o.data } : null
  } catch (_) { return null }
}

// ---------- llave del canal ----------

export async function makeEphemeral () {
  const kp = await subtle().generateKey({ name: 'ECDH', namedCurve: 'P-256' }, false, ['deriveBits'])
  const raw = new Uint8Array(await subtle().exportKey('raw', kp.publicKey))
  return { privateKey: kp.privateKey, epub: b64u(raw) }
}

/** La llave AES del canal (docs/bluetooth.md §4). El orden de los tokens no depende de quién llama. */
export async function deriveKey (privateKey, theirEpub, tokenA, tokenB) {
  const s = subtle()
  const pub = await s.importKey('raw', unb64u(theirEpub), { name: 'ECDH', namedCurve: 'P-256' }, false, [])
  const secret = await s.deriveBits({ name: 'ECDH', public: pub }, privateKey, 256)
  const ikm = await s.importKey('raw', secret, 'HKDF', false, ['deriveKey'])
  const [lo, hi] = tokenA < tokenB ? [tokenA, tokenB] : [tokenB, tokenA]
  return s.deriveKey(
    { name: 'HKDF', hash: 'SHA-256', salt: enc.encode(lo + '|' + hi), info: enc.encode('dotrino-ble-v1') },
    ikm, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt'])
}

// ---------- registros ----------

function nonce (dir, counter) {
  const n = new Uint8Array(12)
  n[0] = dir
  new DataView(n.buffer).setBigUint64(4, BigInt(counter))
  return n
}

export async function sealRecord (key, dir, counter, type, body) {
  const plain = new Uint8Array(1 + body.length)
  plain[0] = type
  plain.set(body, 1)
  return new Uint8Array(await subtle().encrypt({ name: 'AES-GCM', iv: nonce(dir, counter) }, key, plain))
}

/** `{type, body}`, o lanza si no lo selló esa llave con ese contador. */
export async function openRecord (key, dir, counter, record) {
  const plain = new Uint8Array(await subtle().decrypt({ name: 'AES-GCM', iv: nonce(dir, counter) }, key, record))
  if (!plain.length) throw new Error('bluetooth: empty record')
  return { type: plain[0], body: plain.subarray(1) }
}

export function encodeText (str) { return enc.encode(str) }
export function decodeText (bytes) { return dec.decode(bytes) }

// ---------- trozos ----------

export const TAG_BYTES = 4

/** La etiqueta de los trozos hacia un central: los 4 primeros bytes de su `bid` (docs §5). */
export function tagOf (bid) { return unb64u(bid).subarray(0, TAG_BYTES) }

/** True si el trozo de `tx` lleva esa etiqueta. */
export function hasTag (chunk, tag) {
  if (chunk.length < 1 + TAG_BYTES) return false
  for (let i = 0; i < TAG_BYTES; i++) if (chunk[1 + i] !== tag[i]) return false
  return true
}

/**
 * Parte un registro en trozos de `chunk` bytes de valor GATT, cabecera incluida. Con `tag`
 * (hacia un central, `tx`) la cabecera lleva la etiqueta detrás de las banderas.
 */
export function toChunks (record, chunk, tag = null) {
  const head = 1 + (tag ? TAG_BYTES : 0)
  const room = Math.max(1, chunk - head)
  const out = []
  let i = 0
  do {
    const part = record.subarray(i, i + room)
    i += room
    const c = new Uint8Array(head + part.length)
    c[0] = i >= record.length ? LAST : 0
    if (tag) c.set(tag, 1)
    c.set(part, head)
    out.push(c)
  } while (i < record.length)
  return out
}

/** Rearma registros de trozos que llegan en orden. `push` devuelve el registro entero, o null. */
export class Reassembler {
  /** @param {number} [skip]  bytes de cabecera tras las banderas (la etiqueta, en `tx`) */
  constructor (skip = 0) { this.skip = skip; this.parts = []; this.size = 0 }
  push (chunk) {
    if (!chunk || chunk.length < 1 + this.skip) return null
    const body = chunk.subarray(1 + this.skip)
    this.size += body.length
    if (this.size > RECORD_MAX_BYTES + 64) {
      this.parts = []; this.size = 0
      throw Object.assign(new Error('bluetooth: record larger than 1 MiB'), { code: 'record-too-big' })
    }
    this.parts.push(body)
    if (!(chunk[0] & LAST)) return null
    const out = new Uint8Array(this.size)
    let o = 0
    for (const p of this.parts) { out.set(p, o); o += p.length }
    this.parts = []; this.size = 0
    return out
  }
}
