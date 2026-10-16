// LA COPIA DE RECUPERACIÓN DE UNA BÓVEDA QUE NO PUEDE LEER LO SUYO.
//
// `SealedStore` exige que toda entrada lleve la envoltura `#recovery` (`store.js`), y con
// razón: sin ella, el día que no quede ningún aparato con `passwords` esas contraseñas no
// las abre nadie — tampoco su dueño. La bóveda publica la PÚBLICA de ese par para que los
// aparatos envuelvan; la privada solo hace falta para repartir de nuevo cuando cambia
// quién puede leer.
//
// De dónde sale esa privada es lo que distingue a cada bóveda, y el dueño lo decidió el
// 2026-09-20: **de una contraseña, en las cuatro**.
//
//   · el binario (`dotrino-vault`) usa la contraseña del PERFIL — ya la tenía;
//   · `dotrino-passmanager serve` usa la contraseña de su bóveda — ya la tenía;
//   · la pestaña (`vault.dotrino.com/vault`) y la bóveda de dentro de la extensión no
//     tenían ninguna, y por eso la piden al convertir.
//
// Lo que esto NO hace, y se dice porque es la mitad del trato: la contraseña **no se puede
// recuperar**. Es la misma promesa que ya hace `passmanager serve` al crear su bóveda, y
// es lo que hace que la copia sirva de algo — una que se pudiera reponer desde el propio
// navegador no sería una copia de recuperación, sería una segunda llave del mismo llavero.
//
// Por qué una pieza y no cuatro: la regla de las tres versiones (`sealed-passwords.md`
// §2.7) dice que lo que escribe una lo abre otra. Si cada una derivara su llave a su
// manera —otro número de vueltas, otra sal, otro formato— el sobre `#recovery` de una no
// lo abriría la de al lado, y eso no falla al escribir: falla el día que hace falta.

import { deriveKeyFromPassword, makeSalt, makeVerifier, checkVerifier, sealValue, openValue, toBase64, fromBase64 } from '../crypto.js'

/** El formato de lo guardado. Sube si cambia la derivación o el sobre. */
export const RECOVERY_VERSION = 1

const subtle = () => {
  const c = globalThis.crypto
  if (!c?.subtle) throw new Error('webcrypto unavailable')
  return c.subtle
}

const err = (code, message) => Object.assign(new Error(message), { code })

/**
 * El par de recuperación. ECDH P-256, como el de los cajones del binario
 * (`dotrino-vault/src/sealer.js`): es la misma curva que espera `wrapForMember`, y usar
 * otra haría que el sobre de una bóveda no lo abriera la de al lado.
 */
async function makePair () {
  const pair = await subtle().generateKey({ name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveKey', 'deriveBits'])
  return {
    pub: JSON.stringify(await subtle().exportKey('jwk', pair.publicKey)),
    priv: await subtle().exportKey('jwk', pair.privateKey)
  }
}

/**
 * CREA la copia de recuperación de esta bóveda a partir de una contraseña.
 *
 * Devuelve lo que hay que GUARDAR (`record`) y la pública, que es lo único que sale de
 * aquí en claro. La privada se va con la función: quien la quiera, que abra con la
 * contraseña.
 *
 * @param {object} o
 *   `password` la contraseña que abrirá la copia. Mínimo 12: quien tenga el archivo puede
 *     probar contraseñas contra el verificador sin límite y sin que nadie se entere, así
 *     que lo único que aguanta es su longitud (mismo criterio que los inicios de sesión).
 */
export async function makeRecovery ({ password, minLength = 12 } = {}) {
  if (typeof password !== 'string' || password.length < minLength) {
    throw err('weak-password', `the recovery password must be at least ${minLength} characters`)
  }
  const salt = makeSalt()
  const key = await deriveKeyFromPassword(password, salt)
  const pair = await makePair()
  return {
    pub: pair.pub,
    record: {
      v: RECOVERY_VERSION,
      salt: toBase64(salt),
      // El verificador prueba que la contraseña ABRE esto, no que coincide con un hash:
      // es lo que deja decir «esa no es» sin tener que intentar descifrar la privada.
      verifier: await makeVerifier(key),
      pub: pair.pub,
      priv: await sealValue(key, JSON.stringify(pair.priv), 'recovery')
    }
  }
}

/** La pública de una copia ya creada. Es lo que la bóveda publica a los aparatos. */
export function recoveryPubOf (record) {
  return record?.pub || null
}

/** ¿Hay copia de recuperación? Lo pregunta quien tiene que crearla al convertir. */
export const hasRecovery = (record) => !!record?.pub && !!record?.priv

/**
 * ABRE la copia con su contraseña y devuelve la privada como `CryptoKey` de ECDH, que es
 * lo que quiere `openWrap`.
 *
 * Se distingue «esa contraseña no es» de «esto está roto», y no es un detalle: la primera
 * se arregla escribiendo bien y la segunda no se arregla de ninguna manera, así que
 * confundirlas manda al usuario a intentarlo cien veces contra un archivo corrupto.
 */
export async function openRecovery ({ record, password } = {}) {
  if (!hasRecovery(record)) throw err('no-recovery', 'this vault has no recovery copy yet')
  const key = await deriveKeyFromPassword(password, fromBase64(record.salt))
  if (!(await checkVerifier(key, record.verifier))) throw err('wrong-password', 'that password does not open the recovery copy')
  let jwk
  try { jwk = JSON.parse(await openValue(key, record.priv, 'recovery')) }
  catch (_) { throw err('bad-recovery', 'the recovery copy is there but cannot be read') }
  // `key_ops` se quita: dice para qué la generó quien la creó, y aquí hace falta además
  // `deriveKey`. Es lo mismo que hace `adoptLogin` al adoptar una llave de cifrado.
  const { key_ops: _o, ext: _e, ...limpio } = jwk
  return subtle().importKey('jwk', limpio, { name: 'ECDH', namedCurve: 'P-256' }, false, ['deriveKey', 'deriveBits'])
}

/**
 * CAMBIA la contraseña de la copia sin tocar el par: los sobres que ya existen siguen
 * valiendo. Hace falta la vieja, porque hay que abrirla para volver a cerrarla.
 */
export async function changeRecoveryPassword ({ record, oldPassword, newPassword, minLength = 12 } = {}) {
  if (typeof newPassword !== 'string' || newPassword.length < minLength) {
    throw err('weak-password', `the recovery password must be at least ${minLength} characters`)
  }
  const vieja = await deriveKeyFromPassword(oldPassword, fromBase64(record.salt))
  if (!(await checkVerifier(vieja, record.verifier))) throw err('wrong-password', 'that password does not open the recovery copy')
  const priv = await openValue(vieja, record.priv, 'recovery')
  const salt = makeSalt()
  const key = await deriveKeyFromPassword(newPassword, salt)
  return {
    ...record,
    salt: toBase64(salt),
    verifier: await makeVerifier(key),
    priv: await sealValue(key, priv, 'recovery')
  }
}

export default { makeRecovery, openRecovery, recoveryPubOf, hasRecovery, changeRecoveryPassword, RECOVERY_VERSION }
