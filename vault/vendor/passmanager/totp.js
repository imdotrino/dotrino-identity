// Códigos de dos pasos (TOTP, RFC 6238 / HOTP, RFC 4226).
//
// Se guardan como URI `otpauth://`, que es lo que exportan e importan todos los
// demás y lo que lleva un QR. El secreto viaja cifrado con la CEK como cualquier
// otro campo (ver crypto.js); aquí solo se calcula el código.

const B32 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'

export function base32Decode (input) {
  const s = String(input || '').toUpperCase().replace(/=+$/, '').replace(/\s+/g, '')
  let bits = 0
  let value = 0
  const out = []
  for (const ch of s) {
    const idx = B32.indexOf(ch)
    if (idx === -1) throw new Error('base32: carácter inválido')
    value = (value << 5) | idx
    bits += 5
    if (bits >= 8) {
      bits -= 8
      out.push((value >>> bits) & 0xff)
    }
  }
  return new Uint8Array(out)
}

/**
 * Bitwarden (y algún otro) exporta el TOTP como el secreto base32 pelado, sin URI.
 * Se acepta y se envuelve, para que el resto del código vea siempre un `otpauth://`.
 */
export function normalizeOtpauth (input, label = 'dotrino') {
  const s = String(input || '').trim()
  if (!s) return ''
  if (s.toLowerCase().startsWith('otpauth://')) return s
  return `otpauth://totp/${encodeURIComponent(label)}?secret=${encodeURIComponent(s.replace(/\s+/g, ''))}`
}

/** Parsea `otpauth://totp/Emisor:cuenta?secret=...&digits=6&period=30&algorithm=SHA1`. */
export function parseOtpauth (uri) {
  const u = new URL(normalizeOtpauth(uri))
  if (u.protocol !== 'otpauth:') throw new Error('otpauth: esquema inválido')
  const type = u.hostname.toLowerCase()
  if (type !== 'totp' && type !== 'hotp') throw new Error('otpauth: tipo no soportado')
  const q = u.searchParams
  const secret = q.get('secret')
  if (!secret) throw new Error('otpauth: falta secret')

  const label = decodeURIComponent(u.pathname.replace(/^\//, ''))
  const [maybeIssuer, account] = label.includes(':') ? label.split(/:(.+)/) : [null, label]

  return {
    type,
    secret,
    issuer: q.get('issuer') || maybeIssuer || '',
    account: (account || '').trim(),
    digits: clampDigits(q.get('digits')),
    period: clampPeriod(q.get('period')),
    algorithm: (q.get('algorithm') || 'SHA1').toUpperCase(),
    counter: Number(q.get('counter') || 0),
  }
}

function clampDigits (v) {
  const n = Number(v || 6)
  return Number.isInteger(n) && n >= 6 && n <= 10 ? n : 6
}

function clampPeriod (v) {
  const n = Number(v || 30)
  return Number.isInteger(n) && n > 0 && n <= 300 ? n : 30
}

const HASHES = { SHA1: 'SHA-1', SHA256: 'SHA-256', SHA512: 'SHA-512' }

async function hotp (secretBytes, counter, digits, algorithm) {
  const hash = HASHES[algorithm]
  if (!hash) throw new Error('otp: algoritmo no soportado: ' + algorithm)

  const buf = new ArrayBuffer(8)
  const view = new DataView(buf)
  view.setBigUint64(0, BigInt(counter), false)

  const key = await globalThis.crypto.subtle.importKey(
    'raw', secretBytes, { name: 'HMAC', hash }, false, ['sign'])
  const mac = new Uint8Array(await globalThis.crypto.subtle.sign('HMAC', key, buf))

  const offset = mac[mac.length - 1] & 0x0f
  const code = ((mac[offset] & 0x7f) << 24) | (mac[offset + 1] << 16) |
               (mac[offset + 2] << 8) | mac[offset + 3]
  return String(code % 10 ** digits).padStart(digits, '0')
}

/**
 * Código actual y cuántos segundos le quedan.
 * `now` en milisegundos, para poder probarlo con vectores fijos.
 */
export async function totpNow (uri, now = Date.now()) {
  const cfg = parseOtpauth(uri)
  const secret = base32Decode(cfg.secret)
  const seconds = Math.floor(now / 1000)

  if (cfg.type === 'hotp') {
    return { code: await hotp(secret, cfg.counter, cfg.digits, cfg.algorithm), expiresIn: null, cfg }
  }
  const counter = Math.floor(seconds / cfg.period)
  return {
    code: await hotp(secret, counter, cfg.digits, cfg.algorithm),
    expiresIn: cfg.period - (seconds % cfg.period),
    cfg,
  }
}
