/**
 * content.js — la LLAVE DE CONTENIDO del perfil, para que todos tus dispositivos lean lo
 * mismo sin que ninguna llave de identidad se mueva.
 *
 * La distinción que ordena esto (y que conviene decir en voz alta):
 *
 *   · Las llaves de FIRMA son intransferibles. Nacen y mueren en su dispositivo.
 *   · La llave de CONTENIDO se comparte por diseño — si no, dos dispositivos tuyos no
 *     podrían leer el mismo archivo, que es justo lo que se quiere.
 *
 * Cómo: el perfil tiene una clave simétrica (la CEK) que se ENVUELVE hacia la llave de
 * cifrado de cada miembro (ECDH P-256 efímero + AES-GCM, la misma cripto que ya usa el
 * ecosistema para los sobres sellados). Cada miembro abre su envoltura con su propia
 * privada; nadie más puede. Admitir un miembro = envolverle la CEK. Expulsarlo = ROTAR la
 * CEK y envolver la nueva al resto.
 *
 * Lo que esto protege y lo que no: rotar corta el acceso al contenido FUTURO. Lo que el
 * expulsado ya leyó, ya lo leyó — eso no se puede deshacer y no se promete.
 *
 * Módulo PURO (WebCrypto, sin kv/red/disco).
 */

const subtle = globalThis.crypto.subtle
const ECDH = { name: 'ECDH', namedCurve: 'P-256' }

const b64 = (buf) => {
  const bytes = new Uint8Array(buf)
  let s = ''
  for (let i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i])
  return btoa(s)
}
const fromB64 = (str) => {
  const bin = atob(str)
  const out = new Uint8Array(bin.length)
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i)
  return out
}

async function sharedKey (privateKey, peerPubJwkStr) {
  // Llave EXTERNA: el acuerdo ECDH lo hace el chip y devuelve los 32 bytes del secreto
  // (lo mismo que `deriveBits(…, 256)`); la privada no sale de allí.
  const bits = privateKey?.external
    ? await privateKey.deriveBits(peerPubJwkStr)
    : await subtle.deriveBits({ name: 'ECDH', public: await subtle.importKey('jwk', JSON.parse(peerPubJwkStr), ECDH, false, []) }, privateKey, 256)
  return subtle.importKey('raw', bits, { name: 'AES-GCM' }, false, ['encrypt', 'decrypt'])
}

/** Genera una clave de contenido nueva (AES-256-GCM). Devuelve los bytes en base64. */
export async function makeContentKey () {
  const k = await subtle.generateKey({ name: 'AES-GCM', length: 256 }, true, ['encrypt', 'decrypt'])
  return b64(await subtle.exportKey('raw', k))
}

/**
 * Envuelve la CEK hacia la llave de cifrado de un miembro. La envoltura es pública: solo
 * la abre quien tenga la privada de `memberEncPub`, así que puede viajar en el acta.
 * @returns {Promise<{epk:string, iv:string, ct:string}>}
 */
export async function wrapForMember ({ cek, memberEncPub }) {
  if (typeof cek !== 'string' || !cek) throw new Error('wrapForMember: missing content key')
  if (typeof memberEncPub !== 'string' || !memberEncPub) throw new Error('wrapForMember: member has no encryption key')
  const eph = await subtle.generateKey(ECDH, false, ['deriveBits'])
  const key = await sharedKey(eph.privateKey, memberEncPub)
  const iv = globalThis.crypto.getRandomValues(new Uint8Array(12))
  const ct = await subtle.encrypt({ name: 'AES-GCM', iv }, key, new TextEncoder().encode(cek))
  const epk = await subtle.exportKey('jwk', eph.publicKey)
  return {
    epk: JSON.stringify({ kty: epk.kty, crv: epk.crv, x: epk.x, y: epk.y }),
    iv: b64(iv),
    ct: b64(ct)
  }
}

/** Abre la envoltura con la llave de cifrado privada de ESTE miembro. */
export async function openWrap ({ wrap, myEncPrivateKey }) {
  if (!wrap?.epk || !wrap?.iv || !wrap?.ct) throw new Error('invalid wrap')
  const key = await sharedKey(myEncPrivateKey, wrap.epk)
  const pt = await subtle.decrypt({ name: 'AES-GCM', iv: fromB64(wrap.iv) }, key, fromB64(wrap.ct))
  return new TextDecoder().decode(pt)
}

/**
 * Genera la CEK de una generación y la envuelve a TODOS los miembros que tengan llave de
 * cifrado. Un miembro sin `encPub` simplemente no recibe envoltura (y por tanto no lee el
 * contenido): se devuelve la lista para que la consola lo diga en vez de fallar en silencio.
 */
export async function makeGeneration ({ members, gen = 1, cek = null, now = Date.now() }) {
  const key = cek || await makeContentKey()
  const wraps = {}
  const sinLlave = []
  for (const m of members || []) {
    if (!m?.encPub) { sinLlave.push(m?.pub); continue }
    wraps[m.pub] = await wrapForMember({ cek: key, memberEncPub: m.encPub })
  }
  return { generation: { gen, createdAt: now, wraps }, cek: key, sinLlave }
}

/** La CEK vigente para mí, sacada del llavero del acta. `null` si no tengo envoltura. */
export async function myContentKey ({ keyring, myPub, myEncPrivateKey }) {
  const gens = [...(keyring || [])].sort((a, b) => (b.gen || 0) - (a.gen || 0))
  for (const g of gens) {
    const w = g.wraps?.[myPub]
    if (!w) continue
    try { return { gen: g.gen, cek: await openWrap({ wrap: w, myEncPrivateKey }) } } catch (_) {}
  }
  return null
}

/**
 * La marca de un sobre de la llave de la cuenta. La lleva todo sobre de `encryptWithCek`
 * para que quien guarda datos ajenos —la bóveda con el almacén de las apps— lo RECONOZCA
 * dentro de un JSON cualquiera sin adivinar por la forma, y pueda volver a cerrarlo con la
 * generación vigente cuando la llave rota (`resealStale`).
 */
export const CEK_ENVELOPE = 'dotrino-cek'

/** ¿Es un sobre de la llave de la cuenta? */
export const isCekEnvelope = (v) => !!v && typeof v === 'object' && v.t === CEK_ENVELOPE &&
  Number.isInteger(v.gen) && typeof v.iv === 'string' && typeof v.ct === 'string'

/**
 * Cifra con una clave simétrica. Devuelve `{ gen, iv, ct }` (el `gen` dice con cuál).
 *
 * Es GENÉRICA: la usan la llave de la cuenta y también llaves que no son de la cuenta (los
 * cajones de secretos, cada entrada del gestor de contraseñas, el transporte). Por eso NO
 * lleva la marca: la marca dice «esto es de la cuenta» y solo la pone `sealAccount`. En
 * 0.107.0 la ponía aquí, y marcaba como de la cuenta sobres que la cuenta no abre.
 */
export async function encryptWithCek ({ cek, gen, plaintext }) {
  const k = await subtle.importKey('raw', fromB64(cek), { name: 'AES-GCM' }, false, ['encrypt'])
  const iv = globalThis.crypto.getRandomValues(new Uint8Array(12))
  const ct = await subtle.encrypt({ name: 'AES-GCM', iv }, k, new TextEncoder().encode(plaintext))
  return { gen, iv: b64(iv), ct: b64(ct) }
}

/** Cierra con la LLAVE DE LA CUENTA (generación `gen`): el sobre lleva la marca. */
export async function sealAccount ({ cek, gen, plaintext }) {
  if (!Number.isInteger(gen) || gen < 1) throw new Error('sealAccount: the account key generation starts at 1')
  return { t: CEK_ENVELOPE, ...(await encryptWithCek({ cek, gen, plaintext })) }
}

/**
 * Descifra un sobre teniendo YA la CEK. Es el inverso exacto de `encryptWithCek`.
 *
 * Existe para quien administra: tiene la clave a mano (la sacó de donde la guarde) y no
 * necesita el llavero ni ser miembro. El camino normal —el del aparato que solo tiene su
 * propia llave— es `decryptWithKeyring`.
 */
export async function decryptWithCek ({ cek, envelope }) {
  const k = await subtle.importKey('raw', fromB64(cek), { name: 'AES-GCM' }, false, ['decrypt'])
  const pt = await subtle.decrypt({ name: 'AES-GCM', iv: fromB64(envelope.iv) }, k, fromB64(envelope.ct))
  return new TextDecoder().decode(pt)
}

/**
 * Descifra un sobre. Hay que darle el llavero porque el contenido viejo está cifrado con
 * generaciones anteriores: por eso las CEK antiguas se conservan (32 bytes cada una) en vez
 * de re-cifrarlo todo de golpe al rotar.
 */
export async function decryptWithKeyring ({ envelope, keyring, myPub, myEncPrivateKey }) {
  const g = (keyring || []).find((x) => x.gen === envelope?.gen)
  const w = g?.wraps?.[myPub]
  if (!w) throw new Error('this device does not hold the key for that content generation')
  const cek = await openWrap({ wrap: w, myEncPrivateKey })
  const k = await subtle.importKey('raw', fromB64(cek), { name: 'AES-GCM' }, false, ['decrypt'])
  const pt = await subtle.decrypt({ name: 'AES-GCM', iv: fromB64(envelope.iv) }, k, fromB64(envelope.ct))
  return new TextDecoder().decode(pt)
}

/**
 * MIGRACIÓN, con fecha de caducidad: hasta 0.107.0 los sobres de la cuenta salían SIN marca,
 * como `{ gen, iv, ct }` a secas. Hasta esta fecha, `resealStale` también prueba esos: si
 * abren con la llave de la cuenta, los vuelve a cerrar ya marcados; si no abren, no eran de
 * la cuenta y se dejan como están. Pasada la fecha, un sobre sin marca ya no se toca. Se
 * quita el código cuando pase (y su prueba con él).
 */
export const LEGACY_UNMARKED_UNTIL = Date.parse('2027-06-30T00:00:00Z')

/** ¿Tiene la forma EXACTA de un sobre de la cuenta anterior a la marca? */
export const isLegacyCekEnvelope = (v) => !!v && typeof v === 'object' && !Array.isArray(v) &&
  Object.keys(v).length === 3 && Number.isInteger(v.gen) && v.gen >= 1 &&
  typeof v.iv === 'string' && typeof v.ct === 'string'

/**
 * VUELVE A CERRAR con la generación vigente todo sobre de la cuenta de una generación
 * anterior que haya dentro de `value`, a cualquier profundidad. Devuelve una copia (no toca
 * el original) y cuántos sobres cambió.
 *
 * Es lo que hace la bóveda al abrirse y después de una rotación (dueño, 2026-09-30): lo que
 * sirve va SIEMPRE con la llave vigente, así que un aparato que entra después —que solo
 * recibe esa generación— abre todo, y la llave vieja deja de abrir nada porque ya no se le
 * sirve nada cerrado con ella.
 *
 * `reseal(envelope)` abre y vuelve a cerrar un sobre con la llave de la cuenta; lo pone quien
 * la tiene, y debe devolver un sobre MARCADO de la generación `gen`.
 *
 *  · Un sobre MARCADO que no abre PARA todo: es de la cuenta y algo va mal; no se deja a
 *    medias ni se salta en silencio.
 *  · Un sobre SIN MARCA (migración, hasta `LEGACY_UNMARKED_UNTIL`) se prueba aunque ya
 *    tenga la generación vigente —hay que ponerle la marca—; si no abre, se deja y se
 *    cuenta en `skipped`.
 *
 * @param {any} value
 * @param {{ gen: number, reseal: (env: object) => Promise<object>, now?: number }} o
 * @returns {Promise<{ value: any, changed: number, skipped: number }>}
 */
export async function resealStale (value, { gen, reseal, now = Date.now() }) {
  if (!Number.isInteger(gen)) throw new Error('resealStale: the current generation is required')
  const migrar = now < LEGACY_UNMARKED_UNTIL
  let changed = 0; let skipped = 0
  const comprobar = (nuevo) => {
    if (!isCekEnvelope(nuevo) || nuevo.gen !== gen) throw new Error(`resealStale: reseal did not return a marked envelope of generation ${gen}`)
    return nuevo
  }
  const walk = async (v) => {
    if (isCekEnvelope(v)) {
      if (v.gen === gen) return v
      const nuevo = comprobar(await reseal(v))
      changed++
      return nuevo
    }
    if (migrar && isLegacyCekEnvelope(v)) {
      let nuevo
      try { nuevo = await reseal(v) } catch (_) { skipped++; return v }
      changed++
      return comprobar(nuevo)
    }
    if (Array.isArray(v)) {
      const out = []
      for (const x of v) out.push(await walk(x))
      return out
    }
    if (v && typeof v === 'object') {
      const out = {}
      for (const [k, x] of Object.entries(v)) out[k] = await walk(x)
      return out
    }
    return v
  }
  const out = await walk(value)
  return { value: out, changed, skipped }
}

export default {
  makeContentKey, wrapForMember, openWrap, makeGeneration, myContentKey,
  encryptWithCek, sealAccount, decryptWithCek, decryptWithKeyring, CEK_ENVELOPE, isCekEnvelope, isLegacyCekEnvelope, LEGACY_UNMARKED_UNTIL, resealStale
}
