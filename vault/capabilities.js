/**
 * Tokens de CAPACIDAD DELEGADOS, firmados por el vault.
 *
 * Problema: un dispositivo (p.ej. el bridge de OwnTracks, un bot, el launcher)
 * necesita actuar EN NOMBRE de una identidad SIN tener su clave maestra. Si le
 * diéramos la clave maestra, robar el dispositivo = robar la identidad.
 *
 * Solución (subkeys / capabilities, estilo certs SSH / OAuth device tokens):
 *   - El dispositivo genera SU PROPIA clave `D` (la maestra nunca la ve).
 *   - El vault firma un CERTIFICADO: «la clave D puede `scope` para la identidad P,
 *     hasta `exp`», con un `nonce` que es el mango de revocación.
 *   - El dispositivo firma cada acción con `D` y adjunta el cert. Cualquiera
 *     verifica la CADENA `D ← P` + scope + expiración + revocación, offline.
 *
 * Garantía: robar el dispositivo solo permite lo del `scope` (p.ej. publicar
 * ubicación), hasta `exp`, y se puede revocar. La clave maestra queda intacta.
 *
 * Cripto IDÉNTICA al resto del ecosistema: ECDSA P-256 + SHA-256 sobre
 * `canonicalStringify`, firma en base64 de los 64 bytes crudos (r||s). Módulo
 * PURO (sin kv/iframe/localStorage) → reusable en el vault, en Node y en el
 * servidor de geo sin cargar el iframe.
 */
import { canonicalStringify, bufToBase64, base64ToBuf } from './core.js'

const ECDSA = { name: 'ECDSA', namedCurve: 'P-256' }
const SIGN = { name: 'ECDSA', hash: { name: 'SHA-256' } }

/** Tope DURO de vida de una delegación (aunque pidan más). */
export const MAX_DELEGATION_MS = 30 * 24 * 60 * 60 * 1000   // 30 días
/** Vida por defecto si no se especifica ttl/exp. */
export const DEFAULT_DELEGATION_MS = 24 * 60 * 60 * 1000    // 24 h

const enc = (s) => new TextEncoder().encode(s)

async function rawSign (privateKey, bytes) {
  return bufToBase64(await crypto.subtle.sign(SIGN, privateKey, bytes))
}
async function rawVerify (publicJwkStr, bytes, sigB64) {
  let pub
  try { pub = await crypto.subtle.importKey('jwk', JSON.parse(publicJwkStr), ECDSA, true, ['verify']) }
  catch (_) { return false }
  try { return await crypto.subtle.verify(SIGN, pub, base64ToBuf(sigB64), bytes) }
  catch (_) { return false }
}

const publicOf = (privateJwk) => ({ kty: privateJwk.kty, crv: privateJwk.crv, x: privateJwk.x, y: privateJwk.y })
const scopeAllows = (scope, expected) => Array.isArray(scope) ? scope.includes(expected) : scope === expected

/** id corto y estable de un pubkey (sha-256 hex de los campos canónicos del JWK). */
export async function pubkeyId (publicJwkStr) {
  const jwk = typeof publicJwkStr === 'string' ? JSON.parse(publicJwkStr) : publicJwkStr
  const h = await crypto.subtle.digest('SHA-256', enc(canonicalStringify({ crv: jwk.crv, kty: jwk.kty, x: jwk.x, y: jwk.y })))
  return [...new Uint8Array(h)].map(b => b.toString(16).padStart(2, '0')).join('')
}

/**
 * Verifica que `signature` (base64) sobre `data` fue hecha por la privada de
 * `publickey` (JWK string). Prueba de POSESION de una sub-clave de dispositivo (no
 * es cadena de delegacion): la usa el vault para confirmar que quien pide enrolar
 * `dpub` realmente tiene su privada (un token robado ya no alcanza para enrolar).
 */
export async function verifyDeviceSig ({ publickey, data, signature }) {
  if (typeof publickey !== 'string' || typeof signature !== 'string') return false
  return rawVerify(publickey, enc(canonicalStringify(data)), signature)
}

/**
 * Short Authentication String: 6 digitos deterministas derivados de (maestra,
 * dispositivo, nonce de sesion). NO es un secreto: su valor esta en COMPARARLO
 * visualmente entre las dos pantallas (PC del vault y dispositivo) al emparejar —
 * eso mata el relay/phishing (un atacante remoto no puede mostrar el SAS correcto
 * en el dispositivo fisico de la victima).
 */
export async function deriveSAS (master, dpub, sn) {
  const h = new Uint8Array(await crypto.subtle.digest('SHA-256', enc(canonicalStringify({ iss: master, sub: dpub, sn }))))
  const n = ((h[0] << 24) | (h[1] << 16) | (h[2] << 8) | h[3]) >>> 0
  return String(n % 1000000).padStart(6, '0')
}

/**
 * Código de emparejamiento ALEATORIO de 6 dígitos. Lo genera el DISPOSITIVO y lo MUESTRA;
 * el usuario lo tipea en el vault. El vault NO lo conoce: el dispositivo solo manda un
 * COMPROMISO (`commitCode`), no el código → el vault lo aprende únicamente cuando vos se lo
 * das, tipeándolo. Así, aprobar exige TENER el dispositivo (de ahí sale el código).
 */
export function makePairingCode () {
  const b = crypto.getRandomValues(new Uint8Array(4))
  const n = (((b[0] << 24) | (b[1] << 16) | (b[2] << 8) | b[3]) >>> 0)
  return String(n % 1000000).padStart(6, '0')
}

/**
 * Compromiso del código: `SHA-256(code ‖ dpub ‖ sn)` en hex. Va en el ENROLL (no el código).
 * Liga el código a ESTE dispositivo y sesión (no reusable para otro). El vault lo guarda y,
 * cuando tipeás el código, recomputa y compara → verifica posesión sin conocer el código antes.
 */
export async function commitCode ({ code, dpub, sn }) {
  const h = await crypto.subtle.digest('SHA-256', enc(canonicalStringify({ code: String(code), sub: dpub, sn })))
  return [...new Uint8Array(h)].map((x) => x.toString(16).padStart(2, '0')).join('')
}

/**
 * Avatar generado (identicon de Dotrino): SVG DETERMINISTA a partir de una semilla
 * (típicamente el pubkey del perfil) → cada perfil/identidad nace con imagen, sin que el
 * usuario tenga que subir nada. Síncrono (hash FNV-1a + xorshift, sin necesidades de
 * seguridad: es solo decorativo) → usable directo en plantillas. Rejilla 5×5 simétrica
 * sobre una "moneda" redondeada, con color derivado del hash.
 */
function _hashSeed (s) {
  let h = 2166136261 >>> 0
  for (let i = 0; i < s.length; i++) { h ^= s.charCodeAt(i); h = Math.imul(h, 16777619) }
  const bytes = []
  let x = (h ^ 0x9e3779b9) >>> 0
  for (let i = 0; i < 16; i++) { x ^= x << 13; x ^= x >>> 17; x ^= x << 5; x >>>= 0; bytes.push(x & 0xff) }
  return { h: h >>> 0, bytes }
}
export function avatarSvg (seed, { size = 80 } = {}) {
  const { h, bytes } = _hashSeed(String(seed || 'dotrino'))
  const hue = h % 360
  const hue2 = (hue + 40) % 360
  const fg = `hsl(${hue} 62% 46%)`
  const bg1 = `hsl(${hue} 48% 95%)`
  const bg2 = `hsl(${hue2} 48% 90%)`
  const cells = 5
  const unit = size / cells
  let rects = ''
  for (let col = 0; col < 3; col++) {
    for (let row = 0; row < cells; row++) {
      if (!(bytes[col * cells + row] & 1)) continue
      for (const c of (col === 2 ? [2] : [col, cells - 1 - col])) {
        rects += `<rect x="${(c * unit).toFixed(2)}" y="${(row * unit).toFixed(2)}" width="${unit.toFixed(2)}" height="${unit.toFixed(2)}"/>`
      }
    }
  }
  const id = 'g' + (h % 100000)
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${size} ${size}" width="${size}" height="${size}">` +
    `<defs><linearGradient id="${id}" x1="0" y1="0" x2="1" y2="1"><stop offset="0" stop-color="${bg1}"/><stop offset="1" stop-color="${bg2}"/></linearGradient></defs>` +
    `<rect width="${size}" height="${size}" rx="${(size * 0.5).toFixed(2)}" fill="url(#${id})"/>` +
    `<g fill="${fg}" transform="translate(${(size * 0.12).toFixed(2)} ${(size * 0.12).toFixed(2)}) scale(0.76)">${rects}</g></svg>`
}
/** El avatar como data-URI listo para `<img src>` o `background-image`. */
export function avatarDataUri (seed, opts) {
  return 'data:image/svg+xml,' + encodeURIComponent(avatarSvg(seed, opts))
}

/** Cuerpo canónico del certificado (lo que se firma): el cert SIN la firma. */
export function delegationBody (cert) {
  return { v: cert.v, iss: cert.iss, sub: cert.sub, scope: cert.scope, iat: cert.iat, exp: cert.exp, nonce: cert.nonce }
}

/**
 * Genera una sub-clave de DISPOSITIVO `D`. Corre EN el dispositivo / bridge; la
 * clave maestra nunca ve la privada. Solo `publickey` (JWK string) sale del device.
 */
export async function makeDeviceKey ({ label = '' } = {}) {
  const pair = await crypto.subtle.generateKey(ECDSA, true, ['sign', 'verify'])
  const privateJwk = await crypto.subtle.exportKey('jwk', pair.privateKey)
  const publicJwk = await crypto.subtle.exportKey('jwk', pair.publicKey)
  const publickey = JSON.stringify(publicJwk)
  return { publickey, privateJwk, publicJwk, label: String(label || ''), createdAt: Date.now(), deviceId: await pubkeyId(publickey) }
}

/**
 * Firma un certificado de delegación con una `privateKey` (CryptoKey) cuyo pubkey
 * es `iss`. Lo usa el handler del vault (con la clave maestra). Devuelve el cert
 * completo `{ v, iss, sub, scope, iat, exp, nonce, sig }`.
 */
export async function signDelegationWith (privateKey, iss, { sub, scope, iat, exp, nonce }) {
  const body = { v: 1, iss, sub, scope, iat, exp, nonce }
  const sig = await rawSign(privateKey, enc(canonicalStringify(body)))
  return { ...body, sig }
}

/**
 * Firma datos con la clave de DISPOSITIVO (formato byte-idéntico a `signData` del
 * vault → lo que el dispositivo/bridge usa para firmar cada pin/acción).
 */
export async function signWithDevice ({ privateJwk, privateKey, publickey, data }) {
  // `privateKey` (CryptoKey, posiblemente NO extractable) tiene prioridad: firma
  // sin tocar bytes de la privada. Con CryptoKey es obligatorio pasar `publickey`.
  if (privateKey) {
    if (!publickey) throw new Error('signWithDevice: con privateKey (CryptoKey) se requiere publickey')
    const signature = await rawSign(privateKey, enc(canonicalStringify(data)))
    return { signature, publickey }
  }
  const priv = await crypto.subtle.importKey('jwk', privateJwk, ECDSA, true, ['sign'])
  const signature = await rawSign(priv, enc(canonicalStringify(data)))
  return { signature, publickey: publickey || JSON.stringify(publicOf(privateJwk)) }
}

/**
 * Verifica un CERTIFICADO de delegación (offline; no requiere la clave maestra):
 *   1) firma de la maestra (`iss`) sobre el cuerpo canónico,
 *   2) ventana temporal `iat ≤ now ≤ exp`,
 *   3) `scope` incluye `expectedScope` (si se pide),
 *   4) `sub` === `expectedSub` (si se pide),
 *   5) `nonce` no revocado (`revoked`: fn(nonce)→bool, Set o mapa).
 * @returns {{ok:boolean, reason?:string, iss?, sub?, scope?, iat?, exp?, nonce?}}
 */
export async function verifyDelegation ({ cert, expectedScope, expectedSub, now = Date.now(), skewMs = 0, revoked } = {}) {
  if (!cert || typeof cert !== 'object') return { ok: false, reason: 'no-cert' }
  const { v, iss, sub, scope, iat, exp, nonce, sig } = cert
  if (v !== 1 || typeof iss !== 'string' || typeof sub !== 'string' || typeof sig !== 'string') return { ok: false, reason: 'shape' }
  if (typeof iat !== 'number' || typeof exp !== 'number' || (typeof scope !== 'string' && !Array.isArray(scope))) return { ok: false, reason: 'shape' }
  if (!(await rawVerify(iss, enc(canonicalStringify(delegationBody(cert))), sig))) return { ok: false, reason: 'bad-signature' }
  // `skewMs` tolera la diferencia de reloj entre el EMISOR (vault) y el VERIFICADOR
  // (p.ej. el bridge de geo, otra máquina). Default 0 = estricto.
  const sk = Math.max(0, skewMs)
  if (now < iat - sk) return { ok: false, reason: 'not-yet-valid' }
  if (now > exp + sk) return { ok: false, reason: 'expired' }
  if (expectedScope != null && !scopeAllows(scope, expectedScope)) return { ok: false, reason: 'scope' }
  if (expectedSub != null && sub !== expectedSub) return { ok: false, reason: 'sub' }
  if (nonce && revoked) {
    const isRev = typeof revoked === 'function' ? revoked(nonce)
      : (revoked instanceof Set ? revoked.has(nonce) : !!revoked[nonce])
    if (isRev) return { ok: false, reason: 'revoked' }
  }
  return { ok: true, iss, sub, scope, iat, exp, nonce }
}

/**
 * Verificación de CADENA de una acción/pin delegado (lo único que llama el bridge):
 *   1) el dispositivo `D` (= `data.publickey`) firmó `data`,
 *   2) el cert delega a ESTE dispositivo (`cert.sub === data.publickey`),
 *   3) el cert es válido (firma de `P`, scope, exp, revocación),
 *   4) opcional: `cert.iss === trustedIssuer` (fija la identidad maestra esperada).
 * @returns {{ok:boolean, reason?:string, issuer?:string, device?:string}}
 */
export async function verifyChain ({ data, signature, cert, expectedScope, expectedIssuer, trustedIssuer, now = Date.now(), skewMs = 0, revoked } = {}) {
  if (!data || typeof data !== 'object' || typeof signature !== 'string') return { ok: false, reason: 'shape' }
  const device = data.publickey
  if (typeof device !== 'string') return { ok: false, reason: 'no-device-pubkey' }
  if (!(await rawVerify(device, enc(canonicalStringify(data)), signature))) return { ok: false, reason: 'bad-action-signature' }
  if (!cert || cert.sub !== device) return { ok: false, reason: 'cert-device-mismatch' }
  const d = await verifyDelegation({ cert, expectedScope, now, skewMs, revoked })
  if (!d.ok) return { ok: false, reason: d.reason }
  const issuer = trustedIssuer != null ? trustedIssuer : expectedIssuer
  if (issuer != null && cert.iss !== issuer) return { ok: false, reason: 'untrusted-issuer' }
  return { ok: true, issuer: cert.iss, device }
}
