/**
 * advisory.js — EL AVISO A LA RED: «actualiza estos componentes».
 *
 * Punto 3 del dueño (2026-09-04): *«como desarrolladores vemos que una versión falla o es
 * incompatible con otra, tenemos un método de avisar a la red que debe actualizar tales o
 * tales componentes»*.
 *
 * QUIÉN LO FIRMA, y esto es lo que lo ordena todo: **los que desarrollan**. La
 * compatibilidad es política del CÓDIGO, no de la cuenta (decidido el mismo día), así que
 * el ancla de confianza —la pública que valida el aviso— **viaja dentro de la build**. No
 * hay lista de confianza que se pueda cambiar a distancia: para cambiar en quién confías
 * hay que instalar otra versión, que es exactamente lo que significa «política del código».
 *
 * CÓMO VIAJA: por la red que ya existe, de boca en boca. Cada pieza le pasa a la siguiente
 * el aviso más nuevo que tenga. **No hay servidor de avisos ni consulta a Dotrino**: nadie
 * llama a casa, nada depende de que un servicio nuestro esté encendido, y no hay un sitio
 * donde se vea quién tiene qué versión.
 *
 * LO QUE ESTO ES, dicho sin adornos: un aviso firmado por nosotros puede dejar sin trabajar
 * a una versión instalada en la máquina de otro. Es lo que se pidió y es el precio de que
 * un fallo detectado hoy frene hoy. Lo que lo acota:
 *
 *   · **Solo hacia adelante** (`seq`): un aviso viejo no se puede reproducir para deshacer
 *     uno nuevo.
 *   · **Un aviso nuevo REEMPLAZA la lista entera**, así que un aviso equivocado se corrige
 *     con otro aviso. Si solo pudiera sumar, una equivocación sería para siempre.
 *   · **No concede nada.** Lo que la build trae marcado como roto sigue roto aunque el
 *     aviso no lo mencione: quitar por la red lo que el código afirma sería justo el
 *     agujero (`CLAUDE.md`, «nada de repliegues»).
 *   · **Se ve.** El administrador enseña el aviso y su fecha. Un freno que no se explica
 *     es otro silencio, que es de lo que venimos huyendo.
 */

/**
 * Una entrada de la lista de rotas que lleva el aviso.
 * @typedef {object} AdvisoryEntry
 * @property {string} product
 * @property {string[]} versions
 * @property {string} [why]
 * @property {string} [fix]
 */

/**
 * El aviso firmado: «actualiza estos componentes».
 * @typedef {object} Advisory
 * @property {'compat.advisory'} op
 * @property {number} seq        solo hacia adelante
 * @property {number} issued     ms desde epoch
 * @property {AdvisoryEntry[]} broken
 * @property {string} sig        ECDSA P-256 (P1363) en base64
 */

/**
 * JSON canónico (claves ordenadas, recursivo). Es una COPIA deliberada del de
 * `@dotrino/proxy-client`: este paquete no depende de nadie —lo importan las ~30 apps y el
 * proxio— y la firma tiene que dar los mismos bytes en las dos puntas. Si algún día
 * cambian, cambian los dos: hay un test que compara la salida contra la del pilar.
 *
 * @param {unknown} value
 * @returns {string}
 */
export function canonicalStringify (value) {
  if (value === null || typeof value !== 'object') return JSON.stringify(value)
  if (Array.isArray(value)) return '[' + value.map(canonicalStringify).join(',') + ']'
  const o = /** @type {Record<string, unknown>} */ (value)
  const keys = Object.keys(o).sort()
  return '{' + keys.map((k) => JSON.stringify(k) + ':' + canonicalStringify(o[k])).join(',') + '}'
}

/** @param {string} s */
const enc = (s) => new TextEncoder().encode(s)
/** @param {ArrayBuffer} buf */
const b64 = (buf) => {
  const b = new Uint8Array(buf)
  let s = ''
  for (let i = 0; i < b.length; i++) s += String.fromCharCode(b[i])
  return btoa(s)
}
/** @param {string} str */
const fromB64 = (str) => {
  const bin = atob(str)
  const out = new Uint8Array(bin.length)
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i)
  return out
}

/**
 * El cuerpo que se firma: todo menos la firma.
 * @param {Partial<Advisory> | null | undefined} a
 * @returns {Omit<Partial<Advisory>, 'sig'>}
 */
export const advisoryBody = (a) => {
  const { sig, ...body } = a || {}
  return body
}

/**
 * ¿Tiene forma de aviso? No dice si es de fiar, solo si se puede juzgar.
 * @param {any} a   lo que llegó de la red, sin comprobar: esta función es la que lo comprueba
 * @returns {a is Advisory}
 */
export function isAdvisory (a) {
  return !!a && a.op === 'compat.advisory' && Number.isInteger(a.seq) && a.seq >= 0 &&
    typeof a.issued === 'number' && Array.isArray(a.broken) && typeof a.sig === 'string' &&
    a.broken.every((/** @type {any} */ b) => b && typeof b.product === 'string' && Array.isArray(b.versions) &&
      b.versions.every((/** @type {unknown} */ v) => typeof v === 'string'))
}

/**
 * FIRMA un aviso. Lo corre quien publica, no quien lo recibe: aquí está para que el
 * formato lo defina un solo sitio y no dos implementaciones que se separan.
 *
 * @param {{ seq: number, broken: AdvisoryEntry[], privateJwk: JsonWebKey, issued?: number }} args
 * @returns {Promise<Advisory>}
 */
export async function signAdvisory ({ seq, broken, privateJwk, issued = Date.now() }) {
  const body = { op: /** @type {const} */ ('compat.advisory'), seq, issued, broken }
  const key = await globalThis.crypto.subtle.importKey(
    'jwk', privateJwk, { name: 'ECDSA', namedCurve: 'P-256' }, false, ['sign'])
  const sig = await globalThis.crypto.subtle.sign(
    { name: 'ECDSA', hash: 'SHA-256' }, key, enc(canonicalStringify(body)))
  return { ...body, sig: b64(sig) }
}

/**
 * ¿Lo firmó la llave de release que trae MI build? `publickey` es un JWK en texto, igual
 * que en el resto del ecosistema.
 *
 * @param {{ advisory: unknown, publickey: unknown }} args
 * @returns {Promise<boolean>}
 */
export async function verifyAdvisory ({ advisory, publickey }) {
  if (!isAdvisory(advisory) || typeof publickey !== 'string') return false
  try {
    const key = await globalThis.crypto.subtle.importKey(
      'jwk', JSON.parse(publickey), { name: 'ECDSA', namedCurve: 'P-256' }, false, ['verify'])
    return await globalThis.crypto.subtle.verify(
      { name: 'ECDSA', hash: 'SHA-256' }, key, fromB64(advisory.sig),
      enc(canonicalStringify(advisoryBody(advisory))))
  } catch (_) { return false }
}

/**
 * ¿ME QUEDO CON EL QUE LLEGA? Solo hacia adelante y solo si lo firma quien yo digo.
 * Devuelve el aviso vigente (el nuevo o el que ya tenía) y por qué.
 *
 * @param {{ current?: Advisory | null, incoming: unknown, publickey: string }} args
 * @returns {Promise<{ advisory: Advisory | null, adopted: boolean, reason: 'not-an-advisory' | 'not-newer' | 'invalid-signature' | 'newer' | 'first' }>}
 */
export async function adoptAdvisory ({ current, incoming, publickey }) {
  if (!isAdvisory(incoming)) return { advisory: current || null, adopted: false, reason: 'not-an-advisory' }
  if (current && incoming.seq <= current.seq) {
    return { advisory: current, adopted: false, reason: 'not-newer' }
  }
  if (!(await verifyAdvisory({ advisory: incoming, publickey }))) {
    return { advisory: current || null, adopted: false, reason: 'invalid-signature' }
  }
  return { advisory: incoming, adopted: true, reason: current ? 'newer' : 'first' }
}

/**
 * LA LISTA DE ROTAS QUE VALE HOY: la del código MÁS la del aviso.
 *
 * Se suman, no se sustituyen: el aviso puede añadir lo que se descubrió después de esta
 * build, pero **no puede quitar** lo que esta build ya afirma. Que la red pudiera
 * desmarcar algo que el código da por roto sería el repliegue de manual.
 *
 * @param {{ baked?: Array<{ product: string, versions: string | string[], why?: string, fix?: string }>, advisory?: unknown }} [args]
 * @returns {Array<{ product: string, versions: string | string[], why?: string, fix?: string }>}
 */
export function brokenNow ({ baked = [], advisory = null } = {}) {
  return advisory && isAdvisory(advisory) ? [...baked, ...advisory.broken] : [...baked]
}

/**
 * Lo que el administrador enseña del aviso vigente (§14: se ve, no se esconde).
 * @param {unknown} advisory
 * @returns {{ seq: number, issued: number, components: Array<{ product: string, versions: string[], why: string | null, fix: string | null }> } | null}
 */
export function advisorySummary (advisory) {
  if (!isAdvisory(advisory)) return null
  return {
    seq: advisory.seq,
    issued: advisory.issued,
    components: advisory.broken.map((b) => ({
      product: b.product, versions: b.versions, why: b.why || null, fix: b.fix || null
    }))
  }
}

export default { signAdvisory, verifyAdvisory, adoptAdvisory, brokenNow, isAdvisory, advisoryBody, advisorySummary, canonicalStringify }
