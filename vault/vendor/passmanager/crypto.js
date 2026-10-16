// Cifrado de las entradas de la bóveda.
//
// Una CEK (AES-GCM 256) por bóveda, con la que se cifra cada entrada por separado.
// Quién tiene la CEK es lo que define la confianza de cada aparato (DISENO §3): al
// vault y a la app nativa se les envuelve; a la extensión, no.
//
// El envoltorio de la CEK a cada miembro NO se hace aquí: eso es `wrapForMember` de
// @dotrino/identity/content, que ya está escrito y probado. Este módulo es solo el
// tramo simétrico.

const enc = new TextEncoder()
const dec = new TextDecoder()

/** WebCrypto del entorno (navegador, service worker o Node ≥ 20). */
function subtle () {
  const c = globalThis.crypto
  if (!c?.subtle) throw new Error('webcrypto unavailable')
  return c.subtle
}

function randomBytes (n) {
  const b = new Uint8Array(n)
  globalThis.crypto.getRandomValues(b)
  return b
}

export function toBase64 (bytes) {
  let s = ''
  for (const b of bytes) s += String.fromCharCode(b)
  return btoa(s)
}

export function fromBase64 (b64) {
  const s = atob(b64)
  const out = new Uint8Array(s.length)
  for (let i = 0; i < s.length; i++) out[i] = s.charCodeAt(i)
  return out
}

/** Genera una CEK nueva. Extraíble: hay que poder envolverla para cada aparato. */
export async function makeVaultKey () {
  return subtle().generateKey({ name: 'AES-GCM', length: 256 }, true, ['encrypt', 'decrypt'])
}

export async function exportVaultKey (key) {
  return new Uint8Array(await subtle().exportKey('raw', key))
}

export async function importVaultKey (raw) {
  return subtle().importKey('raw', raw, { name: 'AES-GCM' }, true, ['encrypt', 'decrypt'])
}

/**
 * Cifra un valor con la CEK. Devuelve `{ iv, ct }` en base64, para que una entrada
 * cifrada siga siendo JSON serializable tal cual.
 *
 * `aad` ata el criptograma a su sitio: se pasa el id de la entrada y el campo, así
 * que un criptograma movido de una entrada a otra (o de `secret` a `totp`) no abre.
 */
export async function sealValue (key, plaintext, aad) {
  const iv = randomBytes(12)
  const params = { name: 'AES-GCM', iv }
  if (aad) params.additionalData = enc.encode(aad)
  const ct = await subtle().encrypt(params, key, enc.encode(plaintext))
  return { iv: toBase64(iv), ct: toBase64(new Uint8Array(ct)) }
}

export async function openValue (key, sealed, aad) {
  if (!sealed || typeof sealed.iv !== 'string' || typeof sealed.ct !== 'string') {
    throw new Error('sealed value malformed')
  }
  const params = { name: 'AES-GCM', iv: fromBase64(sealed.iv) }
  if (aad) params.additionalData = enc.encode(aad)
  const pt = await subtle().decrypt(params, key, fromBase64(sealed.ct))
  return dec.decode(pt)
}

/** Etiqueta AAD de un campo. Un solo sitio para que sellar y abrir no se desalineen. */
export function fieldTag (entryId, field) {
  return `dotrino-passmanager/v1/${entryId}/${field}`
}

// --- Contraseña maestra ------------------------------------------------------
//
// Solo para el caso en que la bóveda vive en el propio aparato y no hay nadie más
// que la custodie (la extensión antes del paso 2, DISENO §8). Cuando responde el
// vault o el teléfono, la CEK llega envuelta y esto no se usa.

const KDF_ITERATIONS = 600_000 // recomendación OWASP para PBKDF2-SHA256

export function makeSalt () {
  return randomBytes(16)
}

/**
 * Deriva la CEK de una contraseña maestra.
 *
 * `extractable` existe por MV3: el service worker de la extensión se duerme, y un
 * `CryptoKey` no sobrevive a `chrome.storage.session` (que serializa a JSON, no
 * clona). Para no pedir la contraseña cada pocos minutos hay que poder exportar la
 * clave y guardarla en memoria de sesión. Es un compromiso consciente y acotado a la
 * extensión: donde no haga falta, se deriva no extraíble.
 */
export async function deriveKeyFromPassword (password, salt, iterations = KDF_ITERATIONS, extractable = false) {
  const material = await subtle().importKey(
    'raw', enc.encode(String(password)), 'PBKDF2', false, ['deriveKey'])
  return subtle().deriveKey(
    { name: 'PBKDF2', salt, iterations, hash: 'SHA-256' },
    material,
    { name: 'AES-GCM', length: 256 },
    extractable,
    ['encrypt', 'decrypt'],
  )
}

/**
 * Verificador de contraseña: un valor sellado con la propia clave derivada. No es un
 * hash de la contraseña — es una prueba de que la clave abre la bóveda, que es lo que
 * de verdad importa.
 */
export async function makeVerifier (key) {
  return sealValue(key, 'dotrino-passmanager', 'verifier')
}

export async function checkVerifier (key, verifier) {
  try {
    return (await openValue(key, verifier, 'verifier')) === 'dotrino-passmanager'
  } catch {
    return false
  }
}

// --- comparar sin abrir -------------------------------------------------------
//
// Para decir «esto que escribiste ya está guardado igual» hace falta comparar con lo
// guardado, y abrir la entrada es una autorización (DISENO §3.3.2). La bóveda manda
// entonces un **resumen** de cada campo: quien pregunta hashea lo que tiene delante y
// compara los resúmenes.
//
// **Un solo método para todos los campos**, públicos y privados (dueño, 2026-08-29):
// dos formas de comparar según qué campo sea son dos comportamientos que se separan y
// acaban diciendo cosas distintas.
//
// El resumen va con un **nonce nuevo en cada respuesta**, así que no es una huella
// estable: no vale para reconocer la misma contraseña entre dos respuestas, ni para
// guardar una tabla y consultarla más tarde. Y el nombre del campo entra en el HMAC, así
// que un resumen tampoco sirve para comparar contra otro campo.

/** Un nonce nuevo, para UNA respuesta. No se guarda en ninguna parte. */
export function makeNonce () {
  return toBase64(randomBytes(16))
}

/**
 * El hasheador de una respuesta. Se importa la llave UNA vez y se hashean todos los
 * campos con ella: importar por campo multiplica el coste de un `find` sin ganar nada.
 */
export async function fieldHasher (nonce) {
  const key = await subtle().importKey(
    'raw', fromBase64(nonce), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign'])
  return async (name, value) => {
    const sig = await subtle().sign('HMAC', key, enc.encode(name + ' ' + value))
    // 128 bits: de sobra para que dos valores distintos no colisionen en la práctica, y
    // la mitad de bytes que mandar el SHA-256 entero.
    return toBase64(new Uint8Array(sig).slice(0, 16))
  }
}
