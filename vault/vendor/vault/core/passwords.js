/**
 * LA BÓVEDA DE CONTRASEÑAS del dueño, atendida por el vault — Y QUE EL VAULT NO PUEDE LEER.
 *
 * Hasta 0.122 esto tenía una llave propia (`passwordsKey()`) guardada **dentro del mismo
 * archivo que las entradas**, cifrada con la llave de la máquina. O sea: el demonio con el
 * perfil CERRADO seguía descifrando contraseñas, y cualquiera con una copia del disco las
 * leía todas. Era el mismo esquema que tuvo la maestra hasta que se selló.
 *
 * Ahora la bóveda es un cartero también para las contraseñas
 * (`dotrino-passmanager/docs/sealed-passwords.md`): guarda sobres dirigidos a los aparatos
 * y envolturas que no puede abrir. Lo que sí hace, y es lo que sostiene el modelo:
 *
 *   · dice A QUIÉN hay que envolver cada llave —sale del acta, y **la bóveda nunca está en
 *     esa lista**: ni su maestra, ni su llave de comunicación;
 *   · comprueba que quien escribe sea un aparato del acta con `passwords`, por su firma;
 *   · filtra por destinatario al entregar, y decide si hace falta un dedo encima.
 *
 * Lo que SIGUE igual: el protocolo es de a una credencial, `list` no existe en remoto, y la
 * aprobación es la misma del resto del vault (`caps +aprueba`).
 */

import { SealedStore, SealedResponder } from '@dotrino/passmanager'
import { verifyDeviceSig } from '@dotrino/identity/capabilities'

export const PASSWORDS_CAP = 'passwords'

/**
 * @param {object} opts
 *   `client`      cliente del proxio del vault, ya identificado
 *   `store`       `{ get(k), set(k,v) }` donde viven los sobres
 *   `members(kind)`  → `[{ pub, encPub }]` a quién envolverle cada llave (`main`/`passkeys`),
 *                  SIN la bóveda. Lo pone `vault.js`, que es quien lee el acta.
 *   `recoveryPub()`  la pública de la copia de recuperación (la que abre la frase)
 *   `canWrite(pubkey)`  ¿ese aparato puede ESCRIBIR contraseñas? (acta: `passwords`)
 *   `isAllowed(pubkey)` ¿puede pedir? — lo decide el acta, no esto
 *   `encPubOf(pubkey)`  su llave de cifrado, para sellarle la respuesta
 *   `needsApproval(pubkey)`  (async) si ese aparato tiene que pedir aprobación (`unattended`)
 *   `approve({ pubkey, op })`  pide el visto bueno (el teléfono) y espera
 *   `audit(op, info)`  la bitácora del vault
 */
export function createPasswordDesk (opts = {}) {
  const {
    client, store,
    members = () => [],
    recoveryPub = () => null,
    canWrite = () => false,
    isAllowed = () => false,
    encPubOf = () => null,
    needsApproval = () => true,
    approve = async () => false,
    audit = () => {},
    log = () => {},
  } = opts

  const sealed = openSealedPasswords({ store, members, canWrite })

  const responder = new SealedResponder({
    client,
    store: sealed,
    recipients: async () => ({
      recoveryPub: recoveryPub(),
      main: await members('main'),
      passkeys: await members('passkeys'),
    }),
    isAllowed,
    encPubOf,
    // Dos condiciones, y las dos tienen que darse: que ese APARATO esté marcado para
    // aprobar, y que lo que pide sea PRIVADO. Rellenar un nombre no es sacar un secreto, y
    // pedir permiso para todo enseña a decir que sí sin mirar.
    needsApproval: async (pubkey) => await needsApproval(pubkey),
    approve,
    onRequest: (r) => {
      // La bitácora NO lleva qué credencial se pidió: eso es contenido del usuario.
      audit('passwords', { op: r.op, outcome: r.outcome, device: (r.from || '').slice(0, 24) })
      if (r.outcome !== 'ok') log(`[vault] passwords: ${r.op} ${r.outcome}`)
    },
  })

  return {
    start () { responder.start(); return this },
    stop () { responder.stop() },
    /**
     * EL CANDADO DEL PERFIL YA NO PINTA NADA AQUÍ, y eso es la noticia: esta bóveda no
     * tiene ninguna llave que cerrar. Se conserva el método porque quien lo llama no tiene
     * por qué saberlo, y porque decirlo en la bitácora ayuda a entender el cambio.
     */
    lock () { audit('passwords.lock', { sealed: true }) },
    unlock () {},
    /** Para la consola local y las pruebas. Aquí tampoco se abre nada. */
    sealed,
    responder,
  }
}

/**
 * EL ALMACÉN SELLADO DE LAS CONTRASEÑAS, sin el mostrador. Lo usa el mostrador y lo usa el
 * respaldo (`backup.js`): el respaldo tiene que poder leer y escribir aunque ningún aparato
 * tenga todavía `passwords` y el mostrador no se haya levantado. Una sola pieza, para que
 * la regla de quién puede escribir no se escriba dos veces.
 */
/**
 * @param {{ store?: any, members?: (kind: string) => any[], canWrite?: (pub: string) => boolean }} [o]
 */
export function openSealedPasswords ({ store, members = () => [], canWrite = () => false } = {}) {
  return new SealedStore(store, {
    recipients: (kind) => members(kind),
    /**
     * ¿LA FIRMÓ QUIEN DICE, Y PUEDE ESCRIBIR? Es lo único que la bóveda puede comprobar
     * sobre una entrada cuyo contenido no ve. Las dos mitades importan: la firma ata el
     * sobre a una llave, y el acta dice si esa llave tiene algo que hacer aquí.
     */
    verifyAuthor: async ({ body, author }) => {
      if (!canWrite(author?.pub)) return false
      return verifyDeviceSig({ publickey: author.pub, data: body, signature: author.sig })
    },
  })
}

/**
 * CONVERTIR LO QUE HAY (§2.7). Es un acto único y es **segundo trabajo de la maestra**: se
 * hace al ABRIR la bóveda, que es cuando la frase está a mano y hay con qué reescribirlo
 * todo.
 *
 * El trabajo está en `@dotrino/passmanager/sealed` y no aquí, porque lo hacen las CUATRO
 * bóvedas: esta, la pestaña, la de dentro de la extensión y `passmanager serve`. Cuatro
 * copias serían cuatro formas sutilmente distintas de reescribir lo mismo, y la que se
 * quedara atrás no fallaría al convertir — fallaría al leerlo otra bóveda, meses después.
 *
 * Lo que sí es de aquí: `dropOldKey`, porque dónde vive la llave vieja lo sabe cada una.
 */
export async function convertPasswords ({ store, sealed, cek, recipients, author, dropOldKey, log = () => {} } = {}) {
  const { convertToSealed } = await import('@dotrino/passmanager/sealed')
  return convertToSealed({
    store, sealed, cek, recipients, author, dropOldKey,
    log: (m) => log('[vault] ' + m)
  })
}

/**
 * LAS CONTRASEÑAS DEL RESPALDO, abiertas con la copia de recuperación (`backup.js`).
 *
 * Es lectura, así que pide lo mismo que ver una variable: `openRecovery(wrap)` → la CEK, que
 * solo funciona con la bóveda abierta. Cada entrada sale entera, con la forma de siempre
 * (`newEntry`), para poder volver a sellarla en OTRA bóveda con sus propias llaves.
 *
 * Lo que no abre la copia de recuperación no se calla: `unreadable` cuenta las entradas sin
 * envoltura `#recovery` (guardadas antes de que existiera), y `withheld` los campos sueltos
 * que tampoco la tienen. Un respaldo que se deja cosas tiene que decirlo.
 */
export async function exportPasswordEntries ({ sealed, openRecovery }) {
  const { RECOVERY, openSealedEntry } = await import('@dotrino/passmanager/sealed')
  const { decryptWithCek } = await import('@dotrino/identity/content')
  const stats = await sealed.stats()
  if (!stats.sealed) return { entries: [], unreadable: stats.entries, withheld: 0 }
  const openSealed = async ({ wrap, envelope }) => decryptWithCek({ cek: await openRecovery(wrap), envelope })
  const views = await sealed.views({ pub: RECOVERY })
  const entries = []
  let withheld = 0
  for (const v of views) {
    const got = await sealed.get(v.id, { pub: RECOVERY })
    const { withheld: lost = [], ...plain } = await openSealedEntry({ got, openSealed })
    withheld += lost.length
    entries.push(plain)
  }
  return { entries, unreadable: stats.entries - views.length, withheld }
}

/**
 * VUELVE A SELLAR entradas de un respaldo en ESTA bóveda: a los aparatos de su acta y a su
 * copia de recuperación, con la llave del perfil de aquí (la que hace las huellas de sitio).
 *
 * Si esta bóveda todavía no tiene llave de perfil (nunca guardó una contraseña), se estrena
 * aquí: es lo mismo que haría al convertir, y sin ella no hay dónde guardar.
 *
 * `writes`: `[{ entry, replaces }]` de `writesOf`. `replaces` es el id de la entrada de aquí
 * que se pisa; la entrada nueva toma ese id, así que el almacén la reemplaza en su sitio.
 * `author` firma cada entrada (`{ publickey, sign }`), como cualquier aparato que escribe.
 */
export async function importPasswordEntries ({ sealed, openRecovery, recipients, author, writes = [] }) {
  if (!writes.length) return { written: 0 }
  const { RECOVERY, profileKeys, buildSealedEntry, buildProfileKey } = await import('@dotrino/passmanager/sealed')
  const { decryptWithCek } = await import('@dotrino/identity/content')
  let base
  if ((await sealed.stats()).sealed) {
    const p = await sealed.profile({ pub: RECOVERY })
    base = await decryptWithCek({ cek: await openRecovery(p.wrap), envelope: p.envelope })
  } else {
    const k = await buildProfileKey({ recipients })
    await sealed.setProfile({ envelope: k.envelope, wraps: k.wraps })
    base = k.base
  }
  const keys = await profileKeys(base)
  let written = 0
  for (const { entry, replaces } of writes) {
    const built = await buildSealedEntry({ plain: { ...entry, id: replaces || entry.id }, keys, recipients, author })
    await sealed.putSealed({ ...built, by: author.publickey })
    written++
  }
  return { written }
}
