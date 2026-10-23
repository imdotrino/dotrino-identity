/**
 * invite.js — la invitación de emparejamiento: cómo se escribe y cómo se lee.
 *
 * Una invitación viaja de dos maneras —un QR que se escanea y un código que se
 * copia y se pega— y **las dos quieren lo mismo: que sea CORTA**. En un QR cada
 * carácter son módulos, y los módulos son filas y columnas de terminal; en un
 * código pegable, cada carácter es una oportunidad de que alguien lo corte mal.
 *
 * Por eso el formato vigente es **`c` (compacto)**: los datos van en BINARIO y el
 * binario en base64url. Nada de JSON. Un JSON con la llave maestra dentro pesa
 * ~340 caracteres (la llave es una JWK *serializada como string*, con sus comillas
 * escapadas: 182 de esos 340 son ella sola); el mismo contenido en binario son ~75
 * bytes → **~100 caracteres**. Medido en la práctica: el QR pasó de 69 módulos
 * (77×39 en la terminal) a 41 (49×25), y el código pegable de 458 caracteres a 101.
 *
 * De dónde sale el ahorro, en orden de importancia:
 *   · **La llave `iss`** (182 → 44 chars). Una pubkey P-256 son dos coordenadas de
 *     32 bytes; en el QR va el **punto comprimido** de 33 bytes (SEC1: `02`/`03`
 *     según la paridad de `y`, seguido de `x`) y el lector recupera `y` resolviendo
 *     la curva. La JWK se rearma con una PLANTILLA (el índice va en la cabecera)
 *     para que la string vuelva **byte a byte** igual: el proxy direcciona por esa
 *     string exacta, así que una coma de más rompe el enrutamiento.
 *   · **`token` y `sn`** (34+34 → 16+16 bytes): eran hexadecimal, que gasta dos
 *     caracteres por byte.
 *   · **`proxy`** (33 → 0): si es el del ecosistema no viaja; se sobreentiende.
 *   · **`m` y `v`**: dos campos de JSON → dos grupos de bits de la cabecera.
 *
 * SEGURIDAD DEL AHORRO: `encodeInvite` **comprueba el viaje de vuelta** antes de
 * entregar la forma compacta — decodifica lo que acaba de codificar y exige que sea
 * idéntico al original. Si algo no encaja (una JWK con otra forma, un campo nuevo,
 * un `token` que no es hex), devuelve la forma larga en base64. Así una llave rara
 * no rompe un emparejamiento: como mucho lo hace más grande.
 *
 * Formatos que se leen (el primer carácter dice cuál es):
 *   · `c` — compacto binario+base64url. **El que se emite hoy**, para el QR y para
 *           el código pegable: es a la vez el más corto y una sola palabra sin
 *           comillas ni llaves, que sobrevive a un doble clic y a un chat.
 *   · `b` — base64url del JSON. Forma larga, de reserva.
 *   · `j` — JSON crudo. Solo para leer enlaces ya emitidos.
 *   · sin marca — anterior a la marca de formato (base64url, o JSON).
 *
 * GOTCHA que justifica el `decodeURIComponent`: el JSON crudo lleva `{`, `}` y `"`,
 * que **no son legales en una URI**. Al abrir el enlace, el navegador los
 * percent-codifica (`%22`…), así que lo que llega a `location.hash` NO es lo que se
 * emitió. Medido en un navegador real (2026-07-28). El formato compacto no tiene
 * ese problema —base64url ya es seguro en una URL—, pero `j` sigue por ahí.
 */

export const FMT_JSON = 'j'
export const FMT_B64 = 'b'
export const FMT_COMPACT = 'c'
/**
 * `t` — la invitación CORTA: solo la dirección y el nonce de la sesión. La llave
 * maestra ya no viaja; el aparato se la pide a la bóveda por la red presentando el
 * `sn`, y la comprueba con la firma del certificado y con el código de 6 dígitos,
 * que es lo único que de verdad decide. Esconderla no aportaba nada —una pública es
 * pública— y ocupaba 44 de los ~100 caracteres.
 *
 * Lo que lleva NO es la dirección de la bóveda: es una **cita del proxy** —un código
 * de 6 caracteres, de un solo uso y con minutos de vida, cuyos 2 primeros dicen qué
 * proxio la emitió—. El aparato la CANJEA (`redeemPairingCode`) y obtiene la dirección
 * real de la conexión, que hoy son 24 caracteres para poder rutearse entre proxios y no
 * cabría cómoda en un QR. Además, una cita caduca y se quema: no deja una dirección
 * permanente impresa en algo que circula.
 */
export const FMT_SHORT = 't'

/** El proxy del ecosistema: si es este, no viaja en la invitación compacta. */
export const DEFAULT_PROXY = 'wss://proxy.dotrino.com'

/**
 * La base del enlace del QR. Corta a propósito (`/d#v=` en vez de `/vault#vault=`):
 * son caracteres menos dentro del QR, y ahí los caracteres se pagan en módulos.
 *
 * `parseInvite` no mira la ruta, solo el #fragment: por eso un enlace emitido con
 * cualquiera de las formas anteriores sigue emparejando aunque su dirección ya no
 * exista.
 */
export const PAIR_URL = 'https://vault.dotrino.com/d#v='

// ---------------------------------------------------------------------------
// Conversiones (sin dependencias: esto corre en el navegador, en Node y dentro
// del binario SEA). El base64url vive en `b64.js`, porque el paquete de llaves de
// los inicios de sesión usa el mismo.
// ---------------------------------------------------------------------------

import { bytesToB64url, b64urlToBytes } from './b64.js'

const utf8 = (s) => new TextEncoder().encode(s)
const fromUtf8 = (b) => new TextDecoder().decode(b)

/**
 * `token` y `sn` son hexadecimal. Caben en la invitación en dos tamaños —12 o 16
 * bytes— porque el hexadecimal gasta dos caracteres por byte y en un QR eso se
 * paga: 12 bytes (96 bits, lo que emite hoy `startPairing`) son 11 caracteres
 * menos que 16, y esos 11 caracteres son la diferencia entre que quepa un nombre
 * de cuenta normal o que el QR suba una versión entera.
 */
const hexLen = (s) => (typeof s === 'string' && /^[0-9a-f]+$/.test(s) && (s.length === 24 || s.length === 32)) ? s.length / 2 : 0
const hexToBytes = (s) => Uint8Array.from(s.match(/../g).map((h) => parseInt(h, 16)))
const bytesToHex = (b) => [...b].map((x) => x.toString(16).padStart(2, '0')).join('')

const b64urlEncodeStr = (s) => bytesToB64url(utf8(s))
const b64urlDecodeStr = (s) => { const b = b64urlToBytes(s); return b ? fromUtf8(b) : null }

// ---------------------------------------------------------------------------
// La llave maestra: JWK ⇄ punto comprimido de la curva P-256
// ---------------------------------------------------------------------------

/**
 * Las formas de JWK que existen en el ecosistema. `JSON.stringify` de una JWK
 * conserva el orden en que la exportó cada WebCrypto, y **ese orden es parte de la
 * identidad**: el proxy direcciona por la string exacta. Por eso no se «normaliza»
 * la JWK —eso cambiaría la dirección de la bóveda—, se rearma tal cual con la
 * plantilla que le toca. El índice viaja en la cabecera (2 bits, hasta 4 formas).
 */
const JWK_TEMPLATES = [
  // 0 — WebCrypto de Node (el daemon del PC): key_ops, ext, kty, x, y, crv
  (x, y) => `{"key_ops":["verify"],"ext":true,"kty":"EC","x":"${x}","y":"${y}","crv":"P-256"}`,
  // 1 — WebCrypto de navegador (Chrome/Firefox/Safari, alfabético): crv, ext, key_ops, kty, x, y
  (x, y) => `{"crv":"P-256","ext":true,"key_ops":["verify"],"kty":"EC","x":"${x}","y":"${y}"}`,
]

// Parámetros de la curva P-256 (FIPS 186-4). `a` es −3.
const P256_P = 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffffn
const P256_B = 0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604bn

const modPow = (base, exp, m) => {
  let r = 1n; let b = base % m
  while (exp > 0n) { if (exp & 1n) r = (r * b) % m; b = (b * b) % m; exp >>= 1n }
  return r
}

const bytesToBig = (b) => { let n = 0n; for (const x of b) n = (n << 8n) | BigInt(x); return n }
const bigToBytes32 = (n) => { const out = new Uint8Array(32); for (let i = 31; i >= 0; i--) { out[i] = Number(n & 0xffn); n >>= 8n } return out }

/** Coordenada de una JWK: base64url de 32 bytes exactos, o `null`. */
function coordBytes (s) {
  if (typeof s !== 'string' || !/^[A-Za-z0-9_-]{43}$/.test(s)) return null
  const b = b64urlToBytes(s)
  return b && b.length === 32 ? b : null
}

/**
 * `iss` (JWK serializada) → `{ tpl, point }` con el punto comprimido de 33 bytes, o
 * `null` si la llave no tiene una forma conocida (entonces la invitación va larga).
 */
function packPubkey (iss) {
  if (typeof iss !== 'string') return null
  let jwk
  try { jwk = JSON.parse(iss) } catch { return null }
  if (!jwk || jwk.kty !== 'EC' || jwk.crv !== 'P-256') return null
  const xb = coordBytes(jwk.x); const yb = coordBytes(jwk.y)
  if (!xb || !yb) return null

  const tpl = JWK_TEMPLATES.findIndex((f) => f(jwk.x, jwk.y) === iss)
  if (tpl < 0) return null // forma desconocida: no se puede rearmar igual → larga

  const point = new Uint8Array(33)
  point[0] = 2 + (yb[31] & 1) // 02 = y par, 03 = y impar
  point.set(xb, 1)
  return { tpl, point }
}

/** Punto comprimido + plantilla → la `iss` original (o `null` si el punto no es de la curva). */
function unpackPubkey (point, tpl) {
  const template = JWK_TEMPLATES[tpl]
  if (!template || point.length !== 33 || (point[0] !== 2 && point[0] !== 3)) return null

  const x = bytesToBig(point.subarray(1))
  if (x >= P256_P) return null
  // y² = x³ − 3x + b (mod p). Con p ≡ 3 (mod 4) la raíz es y = (y²)^((p+1)/4).
  const y2 = (((x * x) % P256_P) * x - 3n * x + P256_B) % P256_P
  const rhs = (y2 + P256_P) % P256_P
  let y = modPow(rhs, (P256_P + 1n) / 4n, P256_P)
  if ((y * y) % P256_P !== rhs) return null // x no está en la curva
  if ((y & 1n) !== BigInt(point[0] & 1)) y = P256_P - y

  return template(bytesToB64url(point.subarray(1)), bytesToB64url(bigToBytes32(y)))
}

// ---------------------------------------------------------------------------
// El formato compacto
// ---------------------------------------------------------------------------

/**
 * Cabecera (1 byte):
 *   bits 0-2  versión del protocolo (`qr.v`, hoy 2)
 *   bit  3    modo: 0 = `join` · 1 = `adopt`
 *   bits 4-5  plantilla de la JWK (índice en `JWK_TEMPLATES`)
 *   bit  6    lleva proxy propio (si no, el del ecosistema)
 *   bit  7    `token`/`sn` de 12 bytes (si 0, de 16)
 *
 * Cuerpo: punto comprimido (33) ‖ token (n) ‖ sn (n) ‖ len+`acct` ‖ [len+`proxy`]
 */
const MODES = ['join', 'adopt']

function compactEncode (qr) {
  if (!qr || typeof qr !== 'object') return null
  const v = qr.v
  if (!Number.isInteger(v) || v < 0 || v > 7) return null
  const mode = MODES.indexOf(qr.m)
  if (mode < 0) return null
  const n = hexLen(qr.token)
  if (!n || hexLen(qr.sn) !== n) return null

  const pub = packPubkey(qr.iss)
  if (!pub || pub.tpl > 3) return null

  const acct = utf8(String(qr.acct || ''))
  if (acct.length > 255) return null
  const ownProxy = qr.proxy && qr.proxy !== DEFAULT_PROXY
  const proxy = ownProxy ? utf8(String(qr.proxy)) : null
  if (proxy && proxy.length > 255) return null

  // Un campo que no se sepa escribir se perdería en silencio: eso NO se hace.
  const known = new Set(['v', 'iss', 'proxy', 'token', 'sn', 'm', 'acct'])
  if (Object.keys(qr).some((k) => !known.has(k))) return null

  const head = v | (mode << 3) | (pub.tpl << 4) | (ownProxy ? 0x40 : 0) | (n === 12 ? 0x80 : 0)
  const out = [head, ...pub.point, ...hexToBytes(qr.token), ...hexToBytes(qr.sn), acct.length, ...acct]
  if (proxy) out.push(proxy.length, ...proxy)
  return bytesToB64url(Uint8Array.from(out))
}

function compactDecode (text) {
  const b = b64urlToBytes(text)
  const n = (b && (b[0] & 0x80)) ? 12 : 16
  if (!b || b.length < 35 + n * 2) return null
  const head = b[0]

  const iss = unpackPubkey(b.subarray(1, 34), (head >> 4) & 3)
  if (!iss) return null

  let i = 34
  const token = bytesToHex(b.subarray(i, i + n)); i += n
  const sn = bytesToHex(b.subarray(i, i + n)); i += n
  const acctLen = b[i]; i += 1
  if (i + acctLen > b.length) return null
  const acct = acctLen ? fromUtf8(b.subarray(i, i + acctLen)) : ''
  i += acctLen

  let proxy = DEFAULT_PROXY
  if (head & 0x40) {
    if (i >= b.length) return null
    const n = b[i]; i += 1
    if (i + n > b.length) return null
    proxy = fromUtf8(b.subarray(i, i + n)); i += n
  }
  if (i !== b.length) return null // sobran bytes: no es lo que creemos que es

  // Mismo orden de campos que `startPairing`, para que las dos formas serialicen igual.
  return { v: head & 7, iss, proxy, token, sn, m: MODES[(head >> 3) & 1], ...(acct ? { acct } : {}) }
}

// ---------------------------------------------------------------------------
// API
// ---------------------------------------------------------------------------

/**
 * Blob de la forma CORTA (`t`): cabecera(1) ‖ token de conexión(4 ASCII) ‖ sn(8)
 * ‖ [len+proxy].
 *   bits 0-2  versión · bit 3  modo (join/adopt) · bit 4  lleva proxy propio
 *
 * Sin llave y sin nombre de cuenta: eso llega en la respuesta de la bóveda, así que
 * un nombre largo ya no agranda el QR. 13 bytes → 18 caracteres.
 *
 * El PROXY sí viaja cuando no es el del ecosistema, y no es opcional: el token de
 * conexión solo tiene sentido **en el proxy donde se emitió**. Quitarlo hacía que un
 * aparato se conectara al proxy público y le hablara a un token de otro servidor —
 * el mensaje no llegaba a ninguna parte y el emparejamiento se quedaba esperando.
 * Le pasa a cualquiera con proxy propio (y lo cazó el E2E de secretos, que levanta
 * uno local).
 */
// La CITA del proxio: 2 caracteres de prefijo de nodo + 4 = 6. Antes eran 4 (la
// dirección de la conexión). Cambió porque la dirección pasó a ser una instancia
// de 24 caracteres, y lo que se imprime en un QR ahora es una cita de un solo uso.
const CONN_TOKEN_LEN = 6

function shortEncode (qr) {
  if (!qr || qr.v !== 2) return null
  const mode = MODES.indexOf(qr.m)
  if (mode < 0) return null
  const conn = String(qr.conn || '')
  if (conn.length !== CONN_TOKEN_LEN || !/^[\x21-\x7e]+$/.test(conn)) return null
  if (!/^[0-9a-f]{16}$/.test(qr.sn || '')) return null // 8 bytes
  const known = new Set(['v', 'conn', 'sn', 'm', 'proxy'])
  if (Object.keys(qr).some((k) => !known.has(k))) return null
  const ownProxy = qr.proxy && qr.proxy !== DEFAULT_PROXY
  const proxy = ownProxy ? utf8(String(qr.proxy)) : null
  if (proxy && proxy.length > 255) return null
  const out = [qr.v | (mode << 3) | (ownProxy ? 0x10 : 0), ...[...conn].map((c) => c.charCodeAt(0)), ...hexToBytes(qr.sn)]
  if (proxy) out.push(proxy.length, ...proxy)
  return bytesToB64url(Uint8Array.from(out))
}

function shortDecode (text) {
  const b = b64urlToBytes(text)
  if (!b || b.length < 1 + CONN_TOKEN_LEN + 8) return null
  const head = b[0]
  if (head & 0xe0) return null
  let i = 1 + CONN_TOKEN_LEN + 8
  let proxy = DEFAULT_PROXY
  if (head & 0x10) {
    if (i >= b.length) return null
    const n = b[i]; i += 1
    if (i + n !== b.length) return null
    proxy = fromUtf8(b.subarray(i, i + n)); i += n
  } else if (i !== b.length) return null
  const conn = String.fromCharCode(...b.subarray(1, 1 + CONN_TOKEN_LEN))
  return { v: head & 7, conn, sn: bytesToHex(b.subarray(1 + CONN_TOKEN_LEN, 1 + CONN_TOKEN_LEN + 8)), m: MODES[(head >> 3) & 1], proxy }
}

/** Comparación por contenido, sin depender del orden de las claves. */
const canon = (o) => JSON.stringify(Object.keys(o).sort().map((k) => [k, o[k]]))

/**
 * El payload marcado, listo para meter en el `#fragment` o para copiar y pegar.
 *
 * Por defecto **compacto**, que es lo más corto y a la vez pegable. Se cae a la
 * forma larga (`b`) sola, sin avisar, si el compacto no reproduce el original
 * exactamente: más vale un QR grande que uno que no empareja.
 */
export function encodeInvite (qr, fmt = FMT_COMPACT) {
  const json = JSON.stringify(qr)
  // La forma corta se emite cuando el QR trae dirección en vez de llave.
  if (qr && qr.conn) {
    const t = shortEncode(qr)
    if (t) { const back = shortDecode(t); if (back && canon(back) === canon(qr)) return FMT_SHORT + t }
  }
  if (fmt === FMT_JSON) return FMT_JSON + json
  if (fmt === FMT_COMPACT) {
    const c = compactEncode(qr)
    // El viaje de vuelta se comprueba SIEMPRE: es barato (una vez por
    // emparejamiento) y es lo que permite comprimir sin jugarse el enrolamiento.
    if (c) { const back = compactDecode(c); if (back && canon(back) === canon(qr)) return FMT_COMPACT + c }
  }
  return FMT_B64 + b64urlEncodeStr(json)
}

/** El enlace del QR: `https://vault.dotrino.com/d#v=<invitación>`. */
export function inviteUrl (qr) { return PAIR_URL + encodeInvite(qr) }

/**
 * Corta el `#fragment` de una URL. `#vault=` es la forma larga histórica y `#v=` la
 * corta de hoy; se prueba la larga primero porque `#vault=` empieza por `#v`.
 */
const cutFragment = (text) => {
  const long = text.indexOf('#vault=')
  if (long >= 0) return text.slice(long + 7)
  const short = text.indexOf('#v=')
  return short >= 0 ? text.slice(short + 3) : text
}

/**
 * Lee una invitación venga como venga: URL con `#v=`/`#vault=`, el código suelto,
 * con marca de formato o sin ella (formatos viejos). Devuelve el objeto del QR o
 * `null` — nunca lanza, porque del otro lado hay alguien pegando texto a mano.
 */
export function parseInvite (text) {
  if (!text) return null
  const payload = cutFragment(String(text).trim())
  if (!payload) return null

  const parse = (s) => { try { const o = JSON.parse(s); return (o && typeof o === 'object') ? o : null } catch { return null } }
  // El navegador percent-codifica el JSON del fragmento; deshacerlo es un no-op si
  // no lo tocó. Si el texto trae un `%` suelto, `decodeURIComponent` lanza: se usa
  // el original.
  const undoUrl = (s) => { try { return decodeURIComponent(s) } catch { return s } }

  const tag = payload[0]
  const rest = payload.slice(1)
  if (tag === FMT_SHORT) { const o = shortDecode(rest); if (o) return o }
  if (tag === FMT_COMPACT) { const o = compactDecode(rest); if (o) return o }
  if (tag === FMT_JSON) { const o = parse(undoUrl(rest)) || parse(rest); if (o) return o }
  if (tag === FMT_B64) { const s = b64urlDecodeStr(rest); const o = s && parse(s); if (o) return o }

  // --- sin marca: formatos anteriores a la marca de formato (compatibilidad) ---
  const raw = undoUrl(payload)
  if (raw.trimStart().startsWith('{')) return parse(raw)
  const s = b64urlDecodeStr(payload)
  return s ? parse(s) : null
}

export default { encodeInvite, inviteUrl, parseInvite, FMT_JSON, FMT_B64, FMT_COMPACT, FMT_SHORT, PAIR_URL, DEFAULT_PROXY }
