/**
 * End-to-end sealing for directed messages.
 *
 * The proxy routes by public key but does NOT encrypt the payload: `sendByPubkey`
 * serializes it and sends it as-is. Anything sensitive that travels this way is
 * readable by whoever runs the proxy — which is exactly what the ecosystem promises
 * does not happen.
 *
 * This is NOT new cryptography. It is `wrapForMember`/`openWrap` from
 * `@dotrino/identity/content`, the same primitives the vault uses for sealed secrets:
 * ephemeral ECDH P-256 against the recipient's encryption public key, plus AES-GCM.
 * Each message carries its own ephemeral key, so there is no shared state to keep.
 *
 * `@dotrino/identity` is a PEER dependency on purpose: bundling it here would ship a
 * second, older copy of a pillar inside every consumer.
 */

const ECDH = { name: 'ECDH', namedCurve: 'P-256' }

/** Un error con `code`: quien llama decide por el código, nunca por la frase. */
function errorCon (mensaje, code) {
  const e = /** @type {Error & { code: string }} */ (new Error(mensaje))
  e.code = code
  return e
}

const VERSION = 1

let primitives = null

async function crypto_ () {
  if (primitives) return primitives
  try {
    primitives = await import('@dotrino/identity/content')
  } catch (e) {
    throw new Error(
      'sealing requires @dotrino/identity (peer dependency) — install it, or pass ' +
      'your own primitives to setSealingPrimitives()')
  }
  return primitives
}

/** Inject the primitives instead of resolving `@dotrino/identity` (bundlers, tests). */
export function setSealingPrimitives (mod) {
  primitives = mod
}

/** A durable encryption keypair for this device. Its public half goes in the pairing code. */
export async function makeEncKeypair () {
  const pair = await globalThis.crypto.subtle.generateKey(ECDH, true, ['deriveBits'])
  const pub = await globalThis.crypto.subtle.exportKey('jwk', pair.publicKey)
  return {
    privateKey: pair.privateKey,
    publicKey: pair.publicKey,
    encPub: JSON.stringify({ kty: pub.kty, crv: pub.crv, x: pub.x, y: pub.y }),
  }
}

export async function importEncPrivate (jwk) {
  return globalThis.crypto.subtle.importKey('jwk', jwk, ECDH, true, ['deriveBits'])
}

export async function exportEncPrivate (privateKey) {
  return globalThis.crypto.subtle.exportKey('jwk', privateKey)
}

/** Seal a message towards a peer's encryption public key. */
export async function seal (message, peerEncPub) {
  if (!peerEncPub) throw new Error('seal: missing peer encryption key')
  const { wrapForMember } = await crypto_()
  const sealed = await wrapForMember({ cek: JSON.stringify(message), memberEncPub: peerEncPub })
  return { v: VERSION, sealed }
}

/** Open a message sealed to me. Throws if it is not mine or was tampered with. */
export async function open (envelope, myEncPrivateKey) {
  if (!isSealed(envelope)) throw new Error('open: not a sealed envelope')
  if (!myEncPrivateKey) throw new Error('open: missing my encryption key')
  const { openWrap } = await crypto_()
  return JSON.parse(await openWrap({ wrap: envelope.sealed, myEncPrivateKey }))
}

export function isSealed (msg) {
  return !!msg && msg.v === VERSION && !!msg.sealed?.ct && !!msg.sealed?.epk
}

/**
 * EL PUENTE DE LA BÓVEDA: sellar y abrir cuando la llave privada NO está aquí.
 *
 * En un aparato headless la privada de cifrado es suya y basta con `myEncPrivateKey`. En
 * el navegador no: la privada vive dentro del iframe de la bóveda y no sale nunca, así
 * que sellar y abrir se le delegan a `@dotrino/identity` (`encrypt` / `decrypt`), que es
 * la MISMA cripto —ECDH P-256 efímero + AES-GCM— y no cripto nueva.
 *
 * Estaba escrito en el gestor de contraseñas, que fue la primera app que selló de verdad,
 * y sube aquí porque son las dos puntas del MISMO sobre: si una cambia de forma, la otra
 * deja de abrirlo, y ese fallo no hace ruido —la petición sale, al otro lado «no es para
 * mí», y desde fuera se ve como que nadie contestó—. Con una sola pieza no hay dos formas.
 *
 * Dos DIALECTOS de identidad, porque no son el mismo objeto y los dos son correctos:
 *   · la clase `Identity` (la que habla con el iframe): `getEncryptionPubkey()` y
 *     `decrypt(remitente, miToken, sobre)` que devuelve `{ plaintext }`
 *   · el núcleo que corre dentro de un service worker: `encryptionPubkey()` y
 *     `decrypt(remitente, sobre)` que devuelve la cadena
 *
 * `app` es la MARCA del sobre: quien recibe lo que no es suyo lo descarta por aquí. Es
 * estable por app y no se cambia a la ligera — cambiarla es dejar de abrir lo de la
 * versión anterior.
 *
 * @param {any} identity cualquiera de los dos dialectos
 * @param {{ app?: string }} [opts]
 * @returns {{ seal:Function, open:Function, isSealed:Function }}
 */
export function identitySealing (identity, { app = 'dotrino' } = {}) {
  // El dialecto se decide UNA vez, por lo que el objeto expone, y no por el resultado de
  // cada llamada: así, si llega un tercero que no es ninguno de los dos, revienta aquí y
  // con nombre, en vez de devolver sobres que nadie abre.
  const iframe = typeof identity?.getEncryptionPubkey === 'function'
  if (!iframe && typeof identity?.encryptionPubkey !== 'function') {
    throw new Error('identitySealing: this identity exposes neither getEncryptionPubkey() nor encryptionPubkey()')
  }
  if (typeof identity?.encrypt !== 'function' || typeof identity?.decrypt !== 'function') {
    throw new Error('identitySealing: this identity does not expose encrypt()/decrypt()')
  }

  const myEncPub = () => (iframe ? identity.getEncryptionPubkey() : identity.encryptionPubkey())
  const openEnvelope = async (from, envelope) => {
    const r = iframe
      ? await identity.decrypt(from, null, envelope)
      : await identity.decrypt(from, envelope)
    // Un dialecto devuelve `{ plaintext }` y el otro la cadena. Nada más se admite: un
    // `?? ''` aquí sería un sobre vacío haciéndose pasar por un mensaje.
    if (typeof r === 'string') return r
    if (typeof r?.plaintext === 'string') return r.plaintext
    throw new Error('identitySealing: decrypt returned neither a string nor { plaintext }')
  }

  return {
    async seal (msg, peerEncPub) {
      if (!peerEncPub) throw errorCon('no encryption key for the other side', 'unsealed')
      // Destinatarios como OBJETOS: `encrypt` expande cada uno a todos los aparatos de
      // esa persona, y una llave suelta se le cae sin envolver nada.
      const sealed = await identity.encrypt([{ encryptionPubkey: peerEncPub }], JSON.stringify(msg))
      // Y SE COMPRUEBA QUE ENVOLVIÓ A ALGUIEN. `encrypt` se salta en silencio al
      // destinatario cuya llave no puede importar, y devuelve un sobre con el llavero
      // VACÍO: cifrado de verdad, y que no abre nadie. Eso no es un sobre, es un mensaje
      // perdido con cara de enviado.
      if (!sealed || !sealed.wrap || Object.keys(sealed.wrap).length === 0) {
        throw errorCon('identitySealing: the vault wrapped the message for nobody', 'unsealed')
      }
      return { app, sealed, from: await myEncPub() }
    },
    async open (env) { return JSON.parse(await openEnvelope(env.from, env.sealed)) },
    isSealed: (m) => !!m && m.app === app && !!m.sealed,
  }
}
