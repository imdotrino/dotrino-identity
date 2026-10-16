/**
 * Sobres SELLADOS para respuestas del vault con contenido sensible (secretos).
 *
 * El proxy transporta pero NUNCA debe ver el contenido. Como la llave de
 * dispositivo `D` es ECDSA (solo firma), el que PIDE genera una llave ECDH
 * EFÍMERA por petición (`ek`) y la manda dentro del sobre firmado por `D`
 * (→ ek queda autenticada por la cadena D←maestra). El vault sella la
 * respuesta a esa ek: ECDH efímero propio + AES-256-GCM. Reproducir una
 * respuesta vieja es inerte: cada petición usa una ek nueva y el replay no
 * se puede descifrar.
 *
 * La AUTENTICIDAD de la respuesta no la da este módulo sino la firma de la
 * maestra sobre el cuerpo (el dispositivo la verifica contra la `iss` pineada).
 *
 * WebCrypto puro (browser y Node ≥20). Cripto alineada al ecosistema:
 * P-256 + AES-GCM, llaves como JWK string.
 */

const subtle = globalThis.crypto.subtle

function b64 (buf) {
  const bytes = new Uint8Array(buf)
  let s = ''
  for (let i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i])
  return btoa(s)
}

function fromB64 (str) {
  const bin = atob(str)
  const out = new Uint8Array(bin.length)
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i)
  return out
}

async function deriveAesKey (privateKey, publicJwkStr) {
  const pub = await subtle.importKey(
    'jwk', JSON.parse(publicJwkStr),
    { name: 'ECDH', namedCurve: 'P-256' }, false, []
  )
  const bits = await subtle.deriveBits({ name: 'ECDH', public: pub }, privateKey, 256)
  return subtle.importKey('raw', bits, { name: 'AES-GCM' }, false, ['encrypt', 'decrypt'])
}

/**
 * Genera la llave ECDH EFÍMERA del solicitante (una por petición).
 * `ek` (JWK string pública) viaja en el sobre firmado; `privateKey` se queda
 * en memoria para abrir la respuesta.
 */
export async function makeEphemeralKey () {
  const kp = await subtle.generateKey({ name: 'ECDH', namedCurve: 'P-256' }, false, ['deriveBits'])
  const jwk = await subtle.exportKey('jwk', kp.publicKey)
  return { ek: JSON.stringify({ kty: jwk.kty, crv: jwk.crv, x: jwk.x, y: jwk.y }), privateKey: kp.privateKey }
}

/**
 * Sella `payload` (cualquier JSON) hacia la ek del solicitante.
 * @returns {Promise<{epk:string, iv:string, ct:string}>}
 */
export async function seal ({ ek, payload }) {
  const eph = await subtle.generateKey({ name: 'ECDH', namedCurve: 'P-256' }, false, ['deriveBits'])
  const key = await deriveAesKey(eph.privateKey, ek)
  const iv = globalThis.crypto.getRandomValues(new Uint8Array(12))
  const pt = new TextEncoder().encode(JSON.stringify(payload))
  const ct = await subtle.encrypt({ name: 'AES-GCM', iv }, key, pt)
  const epkJwk = await subtle.exportKey('jwk', eph.publicKey)
  return {
    epk: JSON.stringify({ kty: epkJwk.kty, crv: epkJwk.crv, x: epkJwk.x, y: epkJwk.y }),
    iv: b64(iv),
    ct: b64(ct)
  }
}

/**
 * Abre un sobre sellado con la privada efímera de `makeEphemeralKey()`.
 * Lanza si el sobre no es para esa llave (AES-GCM autentica el contenido).
 */
export async function openSealed ({ privateKey, enc }) {
  if (!enc || typeof enc.epk !== 'string' || typeof enc.iv !== 'string' || typeof enc.ct !== 'string') {
    throw new Error('invalid sealed envelope')
  }
  const key = await deriveAesKey(privateKey, enc.epk)
  const pt = await subtle.decrypt({ name: 'AES-GCM', iv: fromB64(enc.iv) }, key, fromB64(enc.ct))
  return JSON.parse(new TextDecoder().decode(pt))
}
