/**
 * b64.js — base64url a mano, sin `Buffer` ni `btoa`.
 *
 * Vive aparte porque lo usan piezas que corren en los tres sitios: el binario (Node), la
 * pestaña y la extensión. `Buffer` no existe en el navegador y `btoa` no existe en algunos
 * workers, así que la única forma de tener UNA implementación es esta.
 */

const B64_STD = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'

export function bytesToB64url (bytes) {
  let out = ''
  for (let i = 0; i < bytes.length; i += 3) {
    const a = bytes[i]; const b = bytes[i + 1]; const c = bytes[i + 2]
    out += B64_STD[a >> 2]
    out += B64_STD[((a & 3) << 4) | ((b ?? 0) >> 4)]
    if (b === undefined) break
    out += B64_STD[((b & 15) << 2) | ((c ?? 0) >> 6)]
    if (c === undefined) break
    out += B64_STD[c & 63]
  }
  return out.replace(/\+/g, '-').replace(/\//g, '_')
}

export function b64urlToBytes (s) {
  const clean = String(s).replace(/-/g, '+').replace(/_/g, '/').replace(/[^A-Za-z0-9+/]/g, '')
  const out = []
  let acc = 0; let bits = 0
  for (const ch of clean) {
    const v = B64_STD.indexOf(ch)
    if (v < 0) return null
    acc = (acc << 6) | v; bits += 6
    if (bits >= 8) { bits -= 8; out.push((acc >> bits) & 0xff) }
  }
  return Uint8Array.from(out)
}
