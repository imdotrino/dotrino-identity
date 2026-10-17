/**
 * Sobres SELLADOS para respuestas del vault con contenido sensible (secretos).
 *
 * El proxy transporta pero NUNCA debe ver el contenido. Como la llave de
 * dispositivo `D` es ECDSA (solo firma), el que PIDE genera una llave ECDH
 * EFÍMERA por petición (`ek`) y la manda dentro del sobre firmado por `D`
 * (→ ek queda autenticada por la cadena D←maestra). El vault sella la
 * respuesta a esa ek: ECDH efímero propio + AES-256-GCM. Reproducir una
 * respuesta vieja es inerte: cada petición usa una ek nueva y el replay no
 * se puede descifrar.
 *
 * La AUTENTICIDAD de la respuesta no la da este módulo sino la firma de la
 * maestra sobre el cuerpo (el dispositivo la verifica contra la `iss` pineada).
 *
 * WebCrypto puro (browser y Node ≥20). Cripto alineada al ecosistema:
 * P-256 + AES-GCM, llaves como JWK string.
 */

import { wrapForMember, openWrap } from '@dotrino/identity/content'

// El sobre es el MISMO que el de las llaves de contenido de identity (ECDH P-256 efímero
// → AES-256-GCM, `epk` en JWK): aquí solo se le mete un JSON en vez de una CEK. Antes
// estaba escrito otra vez en este archivo, byte a byte igual.

const subtle = globalThis.crypto.subtle

/**
 * Genera la llave ECDH EFÍMERA del solicitante (una por petición).
 * `ek` (JWK string pública) viaja en el sobre firmado; `privateKey` se queda
 * en memoria para abrir la respuesta.
 */
export async function makeEphemeralKey () {
  const kp = await subtle.generateKey({ name: 'ECDH', namedCurve: 'P-256' }, false, ['deriveBits'])
  const jwk = await subtle.exportKey('jwk', kp.publicKey)
  return { ek: JSON.stringify({ kty: jwk.kty, crv: jwk.crv, x: jwk.x, y: jwk.y }), privateKey: kp.privateKey }
}

/**
 * Sella `payload` (cualquier JSON) hacia la ek del solicitante.
 * @returns {Promise<{epk:string, iv:string, ct:string}>}
 */
export async function seal ({ ek, payload }) {
  return wrapForMember({ cek: JSON.stringify(payload), memberEncPub: ek })
}

/**
 * Abre un sobre sellado con la privada efímera de `makeEphemeralKey()`.
 * Lanza si el sobre no es para esa llave (AES-GCM autentica el contenido).
 */
export async function openSealed ({ privateKey, enc }) {
  if (!enc || typeof enc.epk !== 'string' || typeof enc.iv !== 'string' || typeof enc.ct !== 'string') {
    throw new Error('invalid sealed envelope')
  }
  return JSON.parse(await openWrap({ wrap: enc, myEncPrivateKey: privateKey }))
}
