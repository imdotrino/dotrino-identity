// CONVERTIR UNA BÓVEDA AL FORMATO SELLADO (`docs/sealed-passwords.md` §2.7).
//
// Es un acto único y hay que hacerlo en las CUATRO bóvedas —el binario, la pestaña, la de
// dentro de la extensión y `passmanager serve`—, así que vive aquí y no en ninguna de
// ellas. Cuatro copias de esto serían cuatro formas sutilmente distintas de reescribir lo
// mismo, y la que se quedara atrás no fallaría al convertir: fallaría al leerlo otra
// bóveda, meses después.
//
// Durante la conversión —y SOLO durante la conversión— quien convierte ve los valores: hay
// que abrirlos con la llave vieja para volver a cerrarlos uno a uno. Por eso lo último que
// hace es **borrar la llave vieja**: mientras siga ahí, el agujero sigue abierto.
//
// Y por eso no se convierte «en segundo plano»: hace falta la contraseña de la copia de
// recuperación, que es lo único que puede volver a abrir esto el día que no quede ningún
// aparato. Sin ella no se empieza.

import { openEntry } from '../model.js'
import { buildSealedEntry, buildProfileKey } from './device.js'
import { profileKeys } from './keys.js'

/**
 * @param {object} o
 *   `store`      el almacén `{ get(k), set(k, v) }` con las entradas viejas
 *   `sealed`     la `SealedStore` de esta bóveda
 *   `cek`        la llave vieja (`CryptoKey`), o `null` si no hay nada que convertir
 *   `recipients` `{ recoveryPub, main, passkeys }` — a quién se le envuelve
 *   `author`     `{ publickey, sign(body) }` — quien firma lo que se escribe
 *   `dropOldKey` borra la llave vieja. Se llama AL FINAL y solo si salió todo
 *   `legacyKey`  dónde viven las entradas viejas (cada bóveda la guarda en su sitio)
 * @returns {Promise<{already:boolean, entries:number}>}
 */
export async function convertToSealed ({
  store, sealed, cek, recipients, author, dropOldKey,
  legacyKey = 'passmanager/entries/v1', log = () => {}
} = {}) {
  if (!sealed) throw new Error('convertToSealed: missing the sealed store')
  // `recoveryPub: null` vale: se convierte sin copia de recuperación y se añade después
  // (`SealedStore.addRecovery`). Lo que no vale es no haber preguntado.
  if (!recipients || recipients.recoveryPub === undefined) {
    throw new Error('convertToSealed: missing the recipients')
  }
  // Ya convertida: no se vuelve a hacer. Repetirlo estrenaría otra llave de perfil y
  // dejaría las entradas de antes con la anterior — la mitad de la bóveda ilegible.
  if (await sealed.sealed()) return { already: true, entries: 0 }

  const viejas = (await store.get(legacyKey)) || []

  // 1. La llave del perfil, de la que salen el índice de sitios y los resúmenes.
  const pk = await buildProfileKey({ recipients })
  await sealed.setProfile({ envelope: pk.envelope, wraps: pk.wraps })
  const keys = await profileKeys(pk.base)

  // 2. Cada entrada, reescrita: un sobre por campo, la vista sellada, sus huellas.
  let hechas = 0
  for (const vieja of viejas) {
    if (!cek) break
    const abierta = await openEntry(cek, vieja)
    await sealed.putSealed(await buildSealedEntry({ plain: abierta, keys, recipients, author }))
    hechas++
  }

  // 3. Y se va lo viejo: las entradas con la llave que las abría, y la llave misma. Solo
  //    si TODAS pasaron: quedarse a medias y borrar la llave es perder lo que faltaba.
  if (hechas === viejas.length) {
    await store.set(legacyKey, [])
    await dropOldKey?.()
  }
  log(`passwords: ${hechas} entries converted to the sealed format`)
  return { already: false, entries: hechas }
}

export default { convertToSealed }
