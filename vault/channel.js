/**
 * channel.js — canal cifrado punto a punto entre el dispositivo enlazado y un agente
 * remoto del ecosistema Dotrino (lo usa `@dotrino/remote-agent`; antes vivía allí). Isomórfico: usa WebCrypto
 * (`globalThis.crypto.subtle`), disponible tanto en el navegador (PWA) como en
 * Node ≥ 18.
 *
 * NO reimplementa la identidad ni la firma del ecosistema: la AUTORIZACIÓN la da
 * el vault (cert de dispositivo verificado con `@dotrino/identity/capabilities`
 * → cadena hasta la maestra). Este módulo solo levanta un secreto de sesión
 * efímero (ECDH P-256 → HKDF → AES-256-GCM) para que el relay de transporte
 * (`proxy.dotrino.com`) vea únicamente texto cifrado. La identidad de las dos
 * puntas ya la garantizan las firmas del vault que envuelven las claves efímeras.
 *
 * Distinto de `content.js` a propósito: aquí la llave es de SESIÓN (se acuerda una vez
 * y cifra muchos mensajes, con HKDF y la pública en raw), allí cada sobre lleva su
 * efímera. El `info` de HKDF conserva su nombre: es parte del cable, y lo hablan también
 * los puertos nativos de `dotrino-native`.
 */

const subtle = () => globalThis.crypto.subtle

const b64 = {
  enc (buf) {
    const b = new Uint8Array(buf)
    let s = ''
    for (let i = 0; i < b.length; i++) s += String.fromCharCode(b[i])
    return btoa(s)
  },
  dec (str) {
    const bin = atob(str)
    const out = new Uint8Array(bin.length)
    for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i)
    return out
  }
}

/** Genera un par ECDH P-256 efímero. Devuelve la pub en raw (base64) + privada. */
export async function makeEphemeral () {
  const kp = await subtle().generateKey({ name: 'ECDH', namedCurve: 'P-256' }, false, ['deriveBits'])
  const raw = await subtle().exportKey('raw', kp.publicKey)
  return { privateKey: kp.privateKey, pub: b64.enc(raw) }
}

/**
 * Deriva la clave AES-256-GCM de la sesión a partir de la privada propia y la
 * pub efímera (base64 raw) del otro extremo. `salt` liga la clave a la sesión.
 */
export async function deriveKey (privateKey, otherPubB64, salt) {
  const otherPub = await subtle().importKey(
    'raw', b64.dec(otherPubB64), { name: 'ECDH', namedCurve: 'P-256' }, false, []
  )
  const bits = await subtle().deriveBits({ name: 'ECDH', public: otherPub }, privateKey, 256)
  const hkdfKey = await subtle().importKey('raw', bits, 'HKDF', false, ['deriveKey'])
  return subtle().deriveKey(
    { name: 'HKDF', hash: 'SHA-256', salt: new TextEncoder().encode(salt), info: new TextEncoder().encode('dotrino-remote-agent-e2e') },
    hkdfKey,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt']
  )
}

/** Cifra un objeto JSON → sobre { iv, ct } (ambos base64). */
export async function seal (key, obj) {
  const iv = globalThis.crypto.getRandomValues(new Uint8Array(12))
  const pt = new TextEncoder().encode(JSON.stringify(obj))
  const ct = await subtle().encrypt({ name: 'AES-GCM', iv }, key, pt)
  return { iv: b64.enc(iv), ct: b64.enc(ct) }
}

/** Descifra un sobre { iv, ct } → objeto JSON. Lanza si el tag GCM no valida. */
export async function open (key, env) {
  const pt = await subtle().decrypt({ name: 'AES-GCM', iv: b64.dec(env.iv) }, key, b64.dec(env.ct))
  return JSON.parse(new TextDecoder().decode(pt))
}

export { b64 }
