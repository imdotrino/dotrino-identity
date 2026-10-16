// Passkeys: crear una credencial WebAuthn y firmar con ella.
//
// Chrome NO expone API de proveedor de credenciales a las extensiones (Android 14+ e
// iOS 17+ sí). En el escritorio la única vía es la que usan todos: reemplazar
// `navigator.credentials.create/get` en el contexto de la página. Como la llave la
// generamos nosotros y la firma la producimos nosotros, la assertion es válida y el
// sitio no distingue.
//
// Este módulo es la parte que NO toca el DOM: qué se guarda y cómo se firma. El parche
// vive en la extensión.
//
// Referencia: WebAuthn Level 2, §6.3 (authenticatorMakeCredential) y §6.3.3
// (authenticatorGetAssertion). El formato importa hasta el bit: un `authenticatorData`
// mal armado lo rechaza el servidor sin decir por qué.

const subtle = () => globalThis.crypto.subtle
const enc = new TextEncoder()

export const AAGUID = new Uint8Array(16) // ceros: sin atestación, como todo proveedor de software

export function b64urlEncode (bytes) {
  let s = ''
  for (const b of new Uint8Array(bytes)) s += String.fromCharCode(b)
  return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
}

export function b64urlDecode (str) {
  const b64 = String(str).replace(/-/g, '+').replace(/_/g, '/')
  const bin = atob(b64)
  const out = new Uint8Array(bin.length)
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i)
  return out
}

function concat (...arrays) {
  const total = arrays.reduce((n, a) => n + a.length, 0)
  const out = new Uint8Array(total)
  let i = 0
  for (const a of arrays) { out.set(a, i); i += a.length }
  return out
}

async function sha256 (bytes) {
  return new Uint8Array(await subtle().digest('SHA-256', bytes))
}

/** Banderas del authenticatorData. UP = presencia, UV = verificación, AT = trae credencial. */
export const FLAGS = { UP: 0x01, UV: 0x04, AT: 0x40 }

/**
 * `authenticatorData`: hash del rpId + banderas + contador (+ la credencial al crear).
 * El orden y los tamaños son fijos; aquí no hay margen de interpretación.
 */
export async function makeAuthenticatorData ({ rpId, flags, signCount, attested = null }) {
  const rpIdHash = await sha256(enc.encode(rpId))
  const counter = new Uint8Array(4)
  new DataView(counter.buffer).setUint32(0, signCount >>> 0, false) // big-endian
  const header = concat(rpIdHash, new Uint8Array([flags]), counter)
  return attested ? concat(header, attested) : header
}

/** COSE_Key de una pública P-256 (kty 2, alg -7, crv 1). Es lo que el servidor guarda. */
export function coseFromJwk (jwk) {
  const x = b64urlDecode(jwk.x)
  const y = b64urlDecode(jwk.y)
  // CBOR a mano: un mapa de 5 entradas con claves enteras. La alternativa era arrastrar
  // una librería de CBOR entera para escribir 77 bytes de forma fija.
  return concat(
    new Uint8Array([0xa5]),                    // map(5)
    new Uint8Array([0x01, 0x02]),              // 1 (kty): 2 (EC2)
    new Uint8Array([0x03, 0x26]),              // 3 (alg): -7 (ES256)
    new Uint8Array([0x20, 0x01]),              // -1 (crv): 1 (P-256)
    new Uint8Array([0x21, 0x58, 0x20]), x,     // -2 (x): bytes(32)
    new Uint8Array([0x22, 0x58, 0x20]), y,     // -3 (y): bytes(32)
  )
}

/** `attestedCredentialData`: aaguid + size + id + la pública en COSE. */
export function attestedCredentialData (credentialId, coseKey) {
  const size = new Uint8Array(2)
  new DataView(size.buffer).setUint16(0, credentialId.length, false)
  return concat(AAGUID, size, credentialId, coseKey)
}

/**
 * Crea una passkey para un sitio. Devuelve lo que se guarda en la bóveda y lo que hay
 * que devolverle a la página.
 */
export async function createCredential ({ rpId, userHandle, userName = '', origin, challenge }) {
  const pair = await subtle().generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify'])
  const jwkPriv = await subtle().exportKey('jwk', pair.privateKey)
  const jwkPub = await subtle().exportKey('jwk', pair.publicKey)

  const credentialId = globalThis.crypto.getRandomValues(new Uint8Array(32))
  const attested = attestedCredentialData(credentialId, coseFromJwk(jwkPub))
  const authData = await makeAuthenticatorData({
    rpId,
    // UV va puesto porque el usuario abre su bóveda para esto: hay verificación real.
    flags: FLAGS.UP | FLAGS.UV | FLAGS.AT,
    signCount: 0,
    attested,
  })

  const clientDataJSON = enc.encode(JSON.stringify({
    type: 'webauthn.create',
    challenge: typeof challenge === 'string' ? challenge : b64urlEncode(challenge),
    origin,
    crossOrigin: false,
  }))

  return {
    // Lo que se guarda (la privada va cifrada por el modelo, como cualquier secreto).
    entry: {
      credentialId: b64urlEncode(credentialId),
      rpId,
      userHandle: userHandle ? b64urlEncode(userHandle) : '',
      userName,
      privateKey: JSON.stringify(jwkPriv),
      signCount: 0,
    },
    // Lo que se le devuelve a la página, ya en base64url.
    response: {
      id: b64urlEncode(credentialId),
      rawId: b64urlEncode(credentialId),
      type: 'public-key',
      response: {
        clientDataJSON: b64urlEncode(clientDataJSON),
        // `attestationObject` sin atestación: fmt "none", attStmt vacío.
        attestationObject: b64urlEncode(concat(
          new Uint8Array([0xa3]),                                            // map(3)
          new Uint8Array([0x63]), enc.encode('fmt'),                         // "fmt"
          new Uint8Array([0x64]), enc.encode('none'),                        // "none"
          new Uint8Array([0x67]), enc.encode('attStmt'),                     // "attStmt"
          new Uint8Array([0xa0]),                                            // {}
          new Uint8Array([0x68]), enc.encode('authData'),                    // "authData"
          new Uint8Array([0x59]), lengthBytes(authData.length), authData,    // bytes(len)
        )),
        publicKeyAlgorithm: -7,
      },
    },
  }
}

function lengthBytes (n) {
  const b = new Uint8Array(2)
  new DataView(b.buffer).setUint16(0, n, false)
  return b
}

/**
 * Firma un reto con una passkey guardada: `sign(authenticatorData || sha256(clientDataJSON))`.
 * Devuelve también el contador nuevo, que hay que guardar.
 */
export async function signAssertion ({ entry, origin, challenge }) {
  const jwk = JSON.parse(entry.privateKey)
  const key = await subtle().importKey('jwk', jwk, { name: 'ECDSA', namedCurve: 'P-256' }, false, ['sign'])

  const signCount = (entry.signCount || 0) + 1
  const authData = await makeAuthenticatorData({
    rpId: entry.rpId,
    flags: FLAGS.UP | FLAGS.UV,
    signCount,
  })

  const clientDataJSON = enc.encode(JSON.stringify({
    type: 'webauthn.get',
    challenge: typeof challenge === 'string' ? challenge : b64urlEncode(challenge),
    origin,
    crossOrigin: false,
  }))

  const signed = concat(authData, await sha256(clientDataJSON))
  const raw = new Uint8Array(await subtle().sign(
    { name: 'ECDSA', hash: 'SHA-256' }, key, signed))

  return {
    signCount,
    response: {
      id: entry.credentialId,
      rawId: entry.credentialId,
      type: 'public-key',
      response: {
        authenticatorData: b64urlEncode(authData),
        clientDataJSON: b64urlEncode(clientDataJSON),
        // WebAuthn pide la firma en DER, no en el crudo de WebCrypto.
        signature: b64urlEncode(rawSignatureToDer(raw)),
        userHandle: entry.userHandle || null,
      },
    },
  }
}

/**
 * WebCrypto firma ECDSA como `r || s` de 32 bytes cada uno; WebAuthn espera DER
 * (SEQUENCE de dos INTEGER). Sin esta conversión el servidor rechaza la firma sin
 * decir por qué, que es de los fallos más caros de diagnosticar.
 */
export function rawSignatureToDer (raw) {
  const r = derInteger(raw.slice(0, 32))
  const s = derInteger(raw.slice(32, 64))
  return concat(new Uint8Array([0x30, r.length + s.length]), r, s)
}

function derInteger (bytes) {
  let i = 0
  while (i < bytes.length - 1 && bytes[i] === 0) i++   // sin ceros a la izquierda
  let v = bytes.slice(i)
  if (v[0] & 0x80) v = concat(new Uint8Array([0]), v)  // positivo: byte de relleno
  return concat(new Uint8Array([0x02, v.length]), v)
}

/** ¿Sirve esta passkey para el sitio que la pide? */
export function credentialMatches (entry, rpId, allowCredentials) {
  if (!entry?.webauthn) return false
  if (entry.webauthn.rpId !== rpId) return false
  if (!allowCredentials?.length) return true
  return allowCredentials.some(c => {
    const id = typeof c.id === 'string' ? c.id : b64urlEncode(c.id)
    return id === entry.webauthn.credentialId
  })
}
