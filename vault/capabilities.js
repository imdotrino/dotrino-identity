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
 *     mientras el ACTA lo diga», con un `nonce` que es el mango de revocación.
 *   - El dispositivo firma cada acción con `D` y adjunta el cert. Cualquiera
 *     verifica la CADENA `D ← P` + scope + expiración + revocación, offline.
 *
 * Garantía: robar el dispositivo solo permite lo del `scope` (p.ej. publicar
 * ubicación) mientras el acta lo diga, y se puede revocar. La clave maestra queda intacta.
 *
 * Cripto IDÉNTICA al resto del ecosistema: ECDSA P-256 + SHA-256 sobre
 * `canonicalStringify`, firma en base64 de los 64 bytes crudos (r||s). Módulo
 * PURO (sin kv/iframe/localStorage) → reusable en el vault, en Node y en el
 * servidor de geo sin cargar el iframe.
 */
import { canonicalStringify, bufToBase64, base64ToBuf } from './core.js'
import { pubkeyId, keyLabel } from './keyid.js'

const ECDSA = { name: 'ECDSA', namedCurve: 'P-256' }
const ECDH = { name: 'ECDH', namedCurve: 'P-256' }
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

// El id de una llave y su huella legible viven en `./keyid.js`, que no tiene dependencias:
// así una interfaz puede mostrar `AB12-CD34` sin arrastrar todo esto. Una sola implementación.
export { pubkeyId, keyLabel }

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

// El identicon vive en ./avatar.js (función pura, sin dependencias) y se
// re-exporta aquí por compatibilidad: importarlo desde este módulo arrastra
// core.js (55 KB), así que si SOLO quieres el avatar usa el subpath
// '@dotrino/identity/avatar'.
export { avatarSvg, avatarDataUri } from './avatar.js'

/** Cuerpo canónico del certificado (lo que se firma): el cert SIN la firma. */
/**
 * Lo que se firma de un certificado. `seq` en vez de `exp` (dueño, 2026-08-31).
 *
 * EL PAPEL YA NO CADUCA POR RELOJ: caduca cuando cambia el acta. Antes vencía a los 30
 * días, y eso obligaba a que alguien con la maestra estuviera disponible cada mes o los
 * aparatos se quedaban fuera — con una bóveda que pasa casi todo el tiempo cerrada, eso
 * no iba a pasar nunca.
 *
 * Atarlo al `seq` hace las dos cosas de golpe: quitarle un permiso a un aparato surte
 * efecto AL INSTANTE (el acta sube de `seq` y su papel deja de valer, sin esperar a
 * ninguna renovación), y nadie tiene que abrir nada por calendario.
 */
export function delegationBody (cert) {
  return { v: cert.v, iss: cert.iss, sub: cert.sub, scope: cert.scope, iat: cert.iat, seq: cert.seq, nonce: cert.nonce }
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
 * Genera la llave de CIFRADO del dispositivo (ECDH P-256): la hermana de
 * `makeDeviceKey`, que es de FIRMA. Hacen falta las dos y no son intercambiables —
 * con ECDSA no se puede cifrar.
 *
 * Es lo que permite escribirle a un aparato **por adelantado**, sin que esté
 * conectado: su pública va al acta como `encPub` y cualquiera puede envolverle un
 * secreto con `wrapForMember` (ver `./content.js`). La privada no sale de aquí.
 *
 * Sale EXTRAÍBLE porque un servicio headless la persiste en su archivo de identidad
 * (cifrado en reposo). En el navegador la pareja del perfil vive como CryptoKey no
 * extraíble en IndexedDB — eso lo hace `core.js`, no esto.
 */
export async function makeDeviceEncKey () {
  const pair = await crypto.subtle.generateKey(ECDH, true, ['deriveBits'])
  const encPrivateJwk = await crypto.subtle.exportKey('jwk', pair.privateKey)
  const encPublicJwk = await crypto.subtle.exportKey('jwk', pair.publicKey)
  return {
    encPublickey: JSON.stringify({ kty: encPublicJwk.kty, crv: encPublicJwk.crv, x: encPublicJwk.x, y: encPublicJwk.y }),
    encPrivateJwk,
    encPublicJwk,
    createdAt: Date.now()
  }
}

/**
 * Reconstruye la llave privada de cifrado desde su JWK. Es lo que hay que pasarle a
 * `openWrap({ myEncPrivateKey })` para abrir un sobre dirigido a este aparato.
 *
 * Existe para que nadie la importe a mano: `deriveBits` es el ÚNICO uso correcto, y
 * pedir otro (`deriveKey`) hace fallar la importación en Node con un error que no
 * dice nada útil.
 */
export async function importDeviceEncKey (encPrivateJwk) {
  if (!encPrivateJwk || typeof encPrivateJwk !== 'object') throw new Error('importDeviceEncKey: missing private JWK')
  return crypto.subtle.importKey('jwk', encPrivateJwk, ECDH, false, ['deriveBits'])
}

/**
 * Firma un certificado de delegación con una `privateKey` (CryptoKey) cuyo pubkey
 * es `iss`. Lo usa el handler del vault (con la clave maestra). Devuelve el cert
 * completo `{ v, iss, sub, scope, iat, seq, nonce, sig }`.
 */
export async function signDelegationWith (privateKey, iss, { sub, scope, iat, seq, nonce }) {
  const body = { v: 1, iss, sub, scope, iat, seq, nonce }
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
    if (!publickey) throw new Error('signWithDevice: publickey is required when privateKey is a CryptoKey')
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
 *   2) el acta: quien lo emitió puede sellar, y el papel no es de un acta más nueva que la mía,
 *   3) `scope` incluye `expectedScope` (si se pide),
 *   4) `sub` === `expectedSub` (si se pide),
 *   5) `nonce` no revocado (`revoked`: fn(nonce)→bool, Set o mapa).
 * @returns {{ok:boolean, reason?:string, iss?, sub?, scope?, iat?, seq?, nonce?}}
 */
/**
 * MARGEN DE RELOJ ENTRE DOS APARATOS. Sin esto, emparejar es una lotería.
 *
 * La bóveda sella el certificado con SU reloj (`iat`) y el aparato lo valida con el suyo.
 * Con tolerancia cero, un aparato que vaya un pelo por detrás rechaza un certificado
 * perfectamente bueno con `not-yet-valid` — y el usuario no ve un problema de hora, ve un
 * emparejamiento que no funciona. Pasó de verdad (2026-08-31): un teléfono **850 ms** por
 * detrás, medido, no podía enrolarse en ninguna bóveda.
 *
 * Dos minutos es generoso para un reloj a la deriva y no significa nada frente a un
 * certificado que vale 30 días: aceptarlo dos minutos antes de tiempo no le abre la puerta
 * a nadie, porque lo que autoriza es la FIRMA, no la hora.
 *
 * Es para comparar aparatos DISTINTOS. Donde el mismo operador controla los dos relojes
 * —un servicio validando en la máquina que emite— el estricto sigue siendo lo correcto, y
 * por eso el default de `verifyDelegation` no cambia.
 */
export const PEER_SKEW_MS = 120_000

export async function verifyDelegation ({ cert, expectedScope, expectedSub, actaSeq = null, sealers = null, revoked } = {}) {
  if (!cert || typeof cert !== 'object') return { ok: false, reason: 'no-cert' }
  const { v, iss, sub, scope, iat, seq, nonce, sig } = cert
  if (v !== 1 || typeof iss !== 'string' || typeof sub !== 'string' || typeof sig !== 'string') return { ok: false, reason: 'shape' }
  if (typeof iat !== 'number' || typeof seq !== 'number' || (typeof scope !== 'string' && !Array.isArray(scope))) return { ok: false, reason: 'shape' }
  if (!(await rawVerify(iss, enc(canonicalStringify(delegationBody(cert))), sig))) return { ok: false, reason: 'bad-signature' }
  // EL ACTA MANDA, Y NO HAY RELOJ (dueño, 2026-08-31). El papel no vence: dice «una
  // selladora de este perfil, mirando el acta nº `seq`, avaló esta llave». Lo que puede
  // hacer HOY lo dice el acta de hoy, y eso lo cruza cada mostrador (`memberCanScope`).
  //
  // Llegan el `seq` y la LISTA DE SELLADORES, no el acta entera, y no por capricho: este
  // módulo no sabe de actas —`acta.js` importa de aquí, así que mirar para allá sería un
  // ciclo— y la regla de quién sella vive en el acta, en un solo sitio. Quien verifica saca
  // la lista con `sealersOf` y la pasa.
  //
  // Sin esos datos no se puede juzgar, y se dice en vez de contestar «vale» a solas:
  // devolver `ok` sin haber comprobado nada es exactamente cómo un papel viejo seguía
  // entrando.
  if (typeof actaSeq !== 'number' || !Array.isArray(sealers)) return { ok: false, reason: 'no-acta' }
  // SOLO SE RECHAZA EL PAPEL DEL FUTURO. Si el cert nombra un acta MÁS NUEVA que la que
  // tengo, no puedo juzgarlo: mi política está atrasada y decir que sí sería fiarme de algo
  // que no he visto. Al revés no: un papel viejo es normal —el aparato estuvo apagado— y lo
  // que puede hacer ya lo decide mi acta, que es más nueva.
  //
  // La alternativa era exigir `seq === actaSeq`, o sea que cada cambio del acta invalidara
  // TODOS los papeles a la vez. Consigue lo mismo (quitar un permiso surte efecto al
  // instante, porque eso lo hace el cruce con el acta) y además deja tirado al aparato que
  // estaba apagado: vuelve, su papel ya no vale, y renovarlo exige una selladora ABIERTA.
  // O sea que un cambio de acta te obligaría a abrir la bóveda para que tus aparatos
  // volvieran — justo lo que se acaba de quitar de en medio.
  if (seq > actaSeq) return { ok: false, reason: 'acta-vieja' }
  // Y QUIEN LO EMITIÓ TIENE QUE PODER SELLAR. No se compara contra «la maestra»: cualquiera
  // que el acta nombre sellador emite papeles válidos — si no, la segunda bóveda podría
  // invalidar todos los certificados al sellar y luego no poder dar los nuevos.
  if (!sealers.includes(iss)) return { ok: false, reason: 'untrusted-issuer' }
  if (expectedScope != null && !scopeAllows(scope, expectedScope)) return { ok: false, reason: 'scope' }
  if (expectedSub != null && sub !== expectedSub) return { ok: false, reason: 'sub' }
  if (nonce && revoked) {
    const isRev = typeof revoked === 'function' ? revoked(nonce)
      : (revoked instanceof Set ? revoked.has(nonce) : !!revoked[nonce])
    if (isRev) return { ok: false, reason: 'revoked' }
  }
  return { ok: true, iss, sub, scope, iat, seq, nonce }
}

/**
 * Verificación de CADENA de una acción/pin delegado (lo único que llama el bridge):
 *   1) el dispositivo `D` (= `data.publickey`) firmó `data`,
 *   2) el cert delega a ESTE dispositivo (`cert.sub === data.publickey`),
 *   3) el cert es válido (firma de una selladora, scope, revocación),
 *   4) opcional: `cert.iss === trustedIssuer` (fija la identidad maestra esperada).
 * @returns {{ok:boolean, reason?:string, issuer?:string, device?:string}}
 */
export async function verifyChain ({ data, signature, cert, expectedScope, actaSeq = null, sealers = null, revoked } = {}) {
  if (!data || typeof data !== 'object' || typeof signature !== 'string') return { ok: false, reason: 'shape' }
  const device = data.publickey
  if (typeof device !== 'string') return { ok: false, reason: 'no-device-pubkey' }
  if (!(await rawVerify(device, enc(canonicalStringify(data)), signature))) return { ok: false, reason: 'bad-action-signature' }
  if (!cert || cert.sub !== device) return { ok: false, reason: 'cert-device-mismatch' }
  // `actaSeq` + `sealers` sustituyen a `trustedIssuer`: ya no se compara contra UNA llave
  // (la maestra), sino contra lo que el acta dice — quién puede sellar, y cuál es el acta
  // vigente. Ver `verifyDelegation`.
  const d = await verifyDelegation({ cert, expectedScope, actaSeq, sealers, revoked })
  if (!d.ok) return { ok: false, reason: d.reason }
  return { ok: true, issuer: cert.iss, device, scope: cert.scope }
}
