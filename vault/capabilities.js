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
export async function signWithDevice ({ privateJwk, data }) {
  const priv = await crypto.subtle.importKey('jwk', privateJwk, ECDSA, true, ['sign'])
  const signature = await rawSign(priv, enc(canonicalStringify(data)))
  return { signature, publickey: JSON.stringify(publicOf(privateJwk)) }
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
