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
export const PASSKEYS_CAP = 'passkeys'

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

  const sealed = new SealedStore(store, {
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
