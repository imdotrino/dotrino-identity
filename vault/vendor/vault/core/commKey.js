/**
 * commKey.js — LA LLAVE DE COMUNICACIÓN de esta bóveda.
 *
 * La maestra tiene dos trabajos y ninguno más: **sellar el acta y reenvolver los sobres**
 * (dueño, 2026-08-31). Hablar por la red no es suyo. Todo lo demás —identificarse ante el
 * proxio, firmar lo que se sirve— lo hace esta llave, y **su autoridad la dice el acta**,
 * donde entra como un miembro más.
 *
 * Por qué eso importa y no es un rodeo: mientras la maestra fuera la que se identificaba,
 * no podía vivir bajo llave — `identify` firma en cada conexión y en cada reconexión, así
 * que una bóveda cerrada no habría existido en la red. Sacándola de ahí, la maestra solo
 * sale con el perfil abierto y el candado deja de ser una bandera.
 *
 * Tres propiedades, y las tres son a propósito:
 *
 *   · **Firmar no es leer.** No abre ningún valor. Por eso puede vivir cifrada en reposo
 *     con la llave de la máquina y usarse SIN la frase — que es lo que hace que la bóveda
 *     siga sirviendo con el candado echado.
 *   · **ESTABLE.** No rota con cada acta, al revés que la vieja `sealPub`: es un miembro,
 *     y un miembro no cambia de llave cada vez que se toca el acta. Rota cuando se decide,
 *     como cualquier aparato.
 *   · **Acotada por `cn`.** Entra con `cn: 'vault'`, así que el acta la trata como un
 *     SERVICIO: `memberCanSign` sin cajón le dice que no. Puede hablar por la bóveda, no
 *     firmar por la persona. Si alguien se lleva el disco, se lleva eso y nada más.
 */
import { readJson, writeJson } from './disk.js'
import { signWithDevice } from '@dotrino/identity/capabilities'

/** El `cn` con el que entra en el acta. Es un servicio del perfil, no un aparato tuyo. */
export const COMM_CN = 'vault'
/** Lo que puede: firmar (acotado por su `cn`). Nada de leer, guardar ni sellar. */
export const COMM_CAPS = Object.freeze(['sign'])

/** Abre (o estrena) la llave de comunicación del perfil. */
export function openCommKey (disk) {
  const file = 'commkey.json'
  let data = readJson(disk, file, null)
  if (!data || typeof data !== 'object' || !data.pub) data = null

  return {
    /** La pública, o `null` si todavía no se ha estrenado. */
    pub: () => data?.pub || null,

    /**
     * Estrena la llave si no existe y devuelve su pública. Idempotente: llamarla dos veces
     * NO cambia de llave — cambiarla dejaría al acta nombrando una que ya no tenemos y a la
     * bóveda sin poder identificarse hasta el siguiente sellado.
     */
    async ensure () {
      if (data?.pub) return data.pub
      const pair = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify'])
      const pub = JSON.stringify(await crypto.subtle.exportKey('jwk', pair.publicKey))
      const priv = await crypto.subtle.exportKey('jwk', pair.privateKey)
      data = { v: 1, pub, priv, createdAt: Date.now() }
      writeJson(disk, file, data)
      return pub
    },

    /**
     * EL PAR DE CIFRADO DEL TRANSPORTE (ECDH), junto a la llave de comunicación y bajo la misma
     * llave de la máquina: lo que otra bóveda le sella a ESTA llega aunque el perfil esté cerrado
     * (los cajones entre hermanas, `docs/replicas.md` §11.4). Su pública la anuncia el pilar al
     * identificarse, firmada por la llave de comunicación. Se estrena una vez y no cambia.
     * @returns {Promise<{ privateKey: CryptoKey, encPub: string }>}
     */
    async encKeypair () {
      if (!data?.pub) throw new Error('commKey.encKeypair: the communication key does not exist yet')
      if (!data.enc?.priv) {
        const pair = await crypto.subtle.generateKey({ name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveBits'])
        const pub = await crypto.subtle.exportKey('jwk', pair.publicKey)
        data = { ...data, enc: { pub: JSON.stringify({ kty: pub.kty, crv: pub.crv, x: pub.x, y: pub.y }), priv: await crypto.subtle.exportKey('jwk', pair.privateKey) } }
        writeJson(disk, file, data)
      }
      const privateKey = await crypto.subtle.importKey('jwk', data.enc.priv, { name: 'ECDH', namedCurve: 'P-256' }, false, ['deriveBits'])
      return { privateKey, encPub: data.enc.pub }
    },

    /** Firma un cuerpo. `null` si aún no hay llave (no se estrena una al vuelo: ver `ensure`). */
    async sign (body) {
      if (!data?.priv) return null
      const { signature } = await signWithDevice({ privateJwk: data.priv, publickey: data.pub, data: body })
      return signature
    }
  }
}

export default { openCommKey, COMM_CN, COMM_CAPS }
