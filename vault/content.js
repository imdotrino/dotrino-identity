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
  const pub = await subtle.importKey('jwk', JSON.parse(peerPubJwkStr), ECDH, false, [])
  const bits = await subtle.deriveBits({ name: 'ECDH', public: pub }, privateKey, 256)
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
  if (typeof cek !== 'string' || !cek) throw new Error('wrapForMember: falta la clave de contenido')
  if (typeof memberEncPub !== 'string' || !memberEncPub) throw new Error('wrapForMember: el miembro no tiene llave de cifrado')
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

/** Cifra con la CEK. Devuelve un sobre `{ gen, iv, ct }` (el `gen` dice con cuál se cifró). */
export async function encryptWithCek ({ cek, gen, plaintext }) {
  const k = await subtle.importKey('raw', fromB64(cek), { name: 'AES-GCM' }, false, ['encrypt'])
  const iv = globalThis.crypto.getRandomValues(new Uint8Array(12))
  const ct = await subtle.encrypt({ name: 'AES-GCM', iv }, k, new TextEncoder().encode(plaintext))
  return { gen, iv: b64(iv), ct: b64(ct) }
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

export default {
  makeContentKey, wrapForMember, openWrap, makeGeneration, myContentKey,
  encryptWithCek, decryptWithKeyring
}
