/**
 * El SELLADOR: lo único de los secretos que toca criptografía.
 *
 * `secretsStore.js` guarda la forma y las reglas y no sabe cifrar; le inyecta este
 * puerto y le pide sobres. Así el store se prueba con un sellador falso y este archivo
 * se lee entero de una sentada.
 *
 * QUÉ HACE. Cada cajón (un namespace, o el cajón propio de un aparato) tiene una CEK
 * AES-256-GCM. Las variables privadas se cifran con ella. La CEK viaja de dos formas,
 * y esa dualidad es todo el diseño:
 *
 *   · **hacia los miembros** — envuelta a la llave de cifrado (`encPub`) de cada
 *     aparato que deba leer ese cajón, con ECDH efímero: quien abre solo necesita su
 *     propia privada. Es lo que va en el llavero del archivo y lo que viaja al agente.
 *   · **hacia quien administra** — en la COPIA MAESTRA, cifrada con la llave derivada
 *     de la contraseña del perfil. Es lo que permite sellar una variable nueva o
 *     re-envolver la CEK a un aparato que entra.
 *
 * Y hay una tercera forma que NO existe a propósito: **la CEK nunca se envuelve a la
 * llave de esta bóveda**. Si se hiciera, el daemon podría abrir todo por su cuenta y
 * esto no valdría nada — que es exactamente la situación de la que venimos.
 *
 * La contraseña no está en el disco, así que una copia del disco no abre las privadas.
 * Lo que sí abre es todo lo demás; los límites honestos están en
 * `docs/secretos-sellados.md` §3 y conviene leerlos antes de confiar de más.
 */
import {
  makeContentKey, makeGeneration, encryptWithCek, decryptWithCek, wrapForMember, openWrap
} from '@dotrino/identity/content'

const b64 = (b) => { let s = ''; for (const x of new Uint8Array(b)) s += String.fromCharCode(x); return btoa(s) }
const un64 = (s) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0))
/** AES-256-GCM con WebCrypto: el mismo en Node y en el navegador. */
const aesKey = (raw, uses) => crypto.subtle.importKey('raw', raw, { name: 'AES-GCM' }, false, uses)

/** La copia maestra va cifrada con AES-256-GCM bajo la llave derivada de la contraseña. */
const MASTER_V = 1

/** Se pidió abrir la copia maestra sin llave, o con la equivocada. */
export class WrongPassword extends Error {
  constructor (msg = 'wrong password') {
    super(msg)
    this.code = 'WRONG_PASSWORD'
  }
}

function assertKey (adminKey) {
  if (!(adminKey instanceof Uint8Array) || adminKey.length !== 32) {
    throw new WrongPassword('the derived key is missing or malformed (32 bytes expected)')
  }
}

/**
 * Crea el sellador. No guarda estado ni recuerda la contraseña: cada operación recibe
 * la llave derivada y la suelta. Que no se cachee es la mitad del valor de todo esto —
 * una llave que se queda en memoria para siempre deja el disco protegido y la máquina
 * igual de expuesta que antes.
 */
export function makeSealer () {
  return {
    /**
     * Abre la copia maestra: `{ "ns:<ns>": cek, "dev:<pub>": cek }`. Un `blob` vacío
     * devuelve un mapa vacío — es el primer arranque, no un error.
     */
    async openMaster (blob, adminKey) {
      assertKey(adminKey)
      if (!blob) return {}
      if (blob.v !== MASTER_V) throw new Error(`master copy: unknown format v${blob.v}`)
      try {
        // WebCrypto quiere la etiqueta pegada al final del cifrado; en disco van aparte.
        const ct = un64(blob.ct); const tag = un64(blob.tag)
        const both = new Uint8Array(ct.length + tag.length); both.set(ct); both.set(tag, ct.length)
        const plain = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: un64(blob.iv) }, await aesKey(adminKey, ['decrypt']), both)
        return JSON.parse(new TextDecoder().decode(plain))
      } catch (_) {
        // El tag de AES-GCM ES el verificador: si no cuadra, la contraseña no era.
        // Por eso no hace falta guardar aparte un verificador de la contraseña, que
        // sería un camino más barato para atacarla desde una copia del disco.
        throw new WrongPassword()
      }
    },

    async sealMaster (obj, adminKey) {
      assertKey(adminKey)
      const iv = crypto.getRandomValues(new Uint8Array(12))
      const both = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, await aesKey(adminKey, ['encrypt']), new TextEncoder().encode(JSON.stringify(obj))))
      return { v: MASTER_V, iv: b64(iv), ct: b64(both.subarray(0, both.length - 16)), tag: b64(both.subarray(both.length - 16)) }
    },

    /** La CEK de un cajón, creándola si es la primera variable que entra ahí. */
    async cekFor (master, owner) {
      if (!master[owner]) master[owner] = await makeContentKey()
      return master[owner]
    },

    /** Una CEK NUEVA para el cajón, tirando la anterior. Rotar es esto. */
    async newCek (master, owner) {
      master[owner] = await makeContentKey()
      return master[owner]
    },

    /** Cifra un valor con la CEK del cajón. */
    async encrypt (cek, plaintext, gen = 0) {
      const { iv, ct } = await encryptWithCek({ cek, gen, plaintext })
      return { iv, ct }
    },

    /** Descifra con la CEK que corresponda al cajón. Solo lo usa quien administra. */
    async decrypt (master, envelope, owner) {
      const cek = master[owner]
      if (!cek) throw new Error(`master copy: no key for drawer ${owner}`)
      return decryptWithCek({ cek, envelope })
    },

    /**
     * Una CEK NUEVA, sin llavero de por medio. Es lo que usa cada escritura desde v5: la
     * bóveda no puede reutilizar la de antes porque **no puede abrir ninguna envoltura
     * para recuperarla** — sellar es una capacidad pública, abrir no. Una generación por
     * escritura es la consecuencia, no un capricho (§8.7).
     */
    async newKey () {
      return makeContentKey()
    },

    /**
     * El par de RECUPERACIÓN: su pública se guarda en claro —para poder envolverle sin
     * saber nada— y su privada va sellada bajo la frase. Es la copia que se abre el día
     * que no queda ningún aparato, y la que abre la TUI cuando el dueño pide ver un valor.
     */
    async makeRecoveryPair () {
      const pair = await crypto.subtle.generateKey({ name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveKey', 'deriveBits'])
      return {
        pub: JSON.stringify(await crypto.subtle.exportKey('jwk', pair.publicKey)),
        priv: await crypto.subtle.exportKey('jwk', pair.privateKey)
      }
    },

    /** Envuelve una CEK a UNA pública suelta (la de recuperación, que no es un miembro). */
    async wrapForKey (cek, encPub) {
      return wrapForMember({ cek, memberEncPub: encPub })
    },

    /**
     * Abre una envoltura con una privada ECDH **en JWK**. Lo hace quien PUEDE leer.
     *
     * La privada llega como JWK porque así se guarda (sellada bajo la frase, en un JSON),
     * y `openWrap` quiere una `CryptoKey`: importarla es el puente, y va aquí porque este
     * es el único archivo que toca criptografía.
     */
    async openWrapWith (privJwk, wrap) {
      const key = await crypto.subtle.importKey('jwk', privJwk, { name: 'ECDH', namedCurve: 'P-256' }, false, ['deriveBits'])
      return openWrap({ wrap, myEncPrivateKey: key })
    },

    /** Descifra un sobre con la CEK ya abierta. */
    async openValue (cek, envelope) {
      return decryptWithCek({ cek, envelope })
    },

    /**
     * Envuelve la CEK a cada miembro. Los que no tengan llave de cifrado salen en
     * `sinLlave` en vez de reventar: quien administra tiene que poder VERLO, porque el
     * síntoma sería un servicio arrancando sin configuración y sin decir por qué.
     */
    async wrapFor (cek, members) {
      const { generation, sinLlave: noKey } = await makeGeneration({ members, cek })
      return { wraps: generation.wraps, sinLlave: noKey }
    }
  }
}

export default { makeSealer, WrongPassword }
