// LA BÓVEDA SELLADA CUANDO QUIEN GUARDA Y QUIEN LEE SON EL MISMO PROCESO.
//
// `SealedVault` es el aparato hablando con una bóveda que está al otro lado de un
// transporte. Esto es el otro caso, y existe de verdad en dos sitios del ecosistema:
//
//   · **`dotrino-passmanager serve`** — el mismo proceso atiende por el proxio y es
//     también la línea de comandos con la que el dueño mira lo suyo;
//   · **la bóveda de dentro de la extensión** — no hay nadie más a quien preguntar.
//
// En los dos, quien lee lo hace con UNA envoltura: la de `#recovery` (el dueño con su
// contraseña) o la del propio aparato. Se le dice cuál al construirla y no se adivina:
// adivinarlo sería leer con la que hubiera, y entonces «no puedo abrir esto» y «esto no es
// para mí» se verían igual.
//
// Cumple el contrato de siempre (`./interface.js`) para que nada de lo que hay encima
// tenga que aprender otra forma de pedir las cosas.

import { VaultError, CODES } from './errors.js'
import { findForUrl } from '../match.js'
import { siteIndex, fieldIndex, valueDigest } from '../sealed/keys.js'
import { buildSealedEntry, openSealedEntry, openSealedView } from '../sealed/device.js'
import { mergePatch } from '../model.js'

/** Los nombres FIJOS, que viajan tal cual: vocabulario cerrado e igual para todos. */
const FIXED = ['name', 'username', 'secret', 'totp', 'notes']

export class SealedLocalVault {
  /**
   * @param {SealedStore} sealed  el almacén de sobres
   * @param {object} opts
   *   `readerPub`   con qué envoltura se lee: `RECOVERY` o la pública de este aparato
   *   `openSealed({ wrap, envelope })` abre un sobre. La privada no sale de donde viva.
   *   `author`      `{ publickey, sign(body) }` quien firma lo que se escribe
   *   `recipients()` → `{ recoveryPub, main, passkeys }` a quién se le envuelve
   *   `keys()`      → las llaves del perfil (`profileKeys`), para huellas y resúmenes
   */
  constructor (sealed, { readerPub, openSealed, author, recipients, keys } = {}) {
    if (!sealed) throw new Error('SealedLocalVault: missing the sealed store')
    if (!readerPub) throw new Error('SealedLocalVault: say which wrap this one reads with')
    for (const n of ['openSealed', 'author', 'recipients', 'keys']) {
      if (!arguments[1]?.[n]) throw new Error(`SealedLocalVault: missing ${n}`)
    }
    this.sealed = sealed
    this.readerPub = readerPub
    this.openSealed = openSealed
    this.author = author
    this.recipients = recipients
    this.keys = keys
  }

  get capabilities () {
    // `canList` es `true` y aquí sí es verdad: quien pregunta es el dueño en su propia
    // máquina, no un aparato pidiendo por el proxio. Lo que no existe en remoto sigue sin
    // existir — esto no se asoma por ningún transporte.
    return { canWrite: true, canList: true, needsApproval: false, sealed: true }
  }

  /** De la clave que usa la interfaz a la que guarda la bóveda. La misma que `SealedVault`. */
  async #sealedKey (k) {
    if (FIXED.includes(k) || k.startsWith('wa.')) return k
    const { kidx } = await this.keys()
    return 'f:' + await fieldIndex(kidx, k)
  }

  /** Las vistas, abiertas. Es lo que se enseña en una lista: sin valores privados. */
  async list () {
    const vistas = await this.sealed.views({ pub: this.readerPub })
    const out = []
    for (const v of vistas) {
      const abierta = await openSealedView({ ...v, openSealed: this.openSealed })
      // `fieldHashes` con el nombre que ya usa la interfaz para comparar sin abrir nada.
      // Los resúmenes están GUARDADOS y su clave viaja por huella, así que aquí se
      // traducen de vuelta — la vista sí lleva los nombres de verdad, porque va sellada.
      // Sin esto, «¿ya está guardado igual?» se contesta que no siempre, y el aviso de
      // guardar sale en cada formulario que ya tenías.
      const fieldHashes = {}
      for (const k of [...(abierta.fieldKeys || []), 'notes']) {
        const clave = await this.#sealedKey(k)
        if (abierta.digests?.[clave] !== undefined) fieldHashes[k] = abierta.digests[clave]
      }
      out.push({ ...abierta, fieldHashes })
    }
    return out
  }

  /**
   * El resumen de un valor, para decir si ya está guardado igual **sin abrir nada** (§2.6).
   * No hay nonce que compartir: el `id` de la entrada va dentro, que es lo que impide que
   * un valor repetido en dos entradas se note.
   */
  async digest (id, key, value) {
    const { kcmp } = await this.keys()
    return valueDigest(kcmp, id, key, String(value))
  }

  /**
   * Lo que hay para una URL, ya ORDENADO por lo bien que casa: las entradas, no los pares
   * `{entry, match}` de `findForUrl`. Es la misma forma que devuelve `SealedVault.find`,
   * y tiene que serlo — quien llama no debería notar de qué bóveda le están contestando.
   */
  async find (url) {
    return findForUrl(await this.list(), url).map((x) => x.entry)
  }

  /**
   * EN QUÉ SITIOS HAY ALGO, y cuánto en cada uno. Misma forma que `LocalVault.sites()`
   * —`[{ site, count }]`— porque es lo que pinta el gestor: devolver una lista de cadenas
   * dejaba la fila de dominios vacía sin un solo error.
   *
   * El sitio vacío es «sirve en cualquier parte» y va al final, que es donde se busca.
   */
  async sites () {
    const cuenta = new Map()
    for (const e of await this.list()) {
      for (const s of (e.sites?.length ? e.sites : [''])) cuenta.set(s, (cuenta.get(s) || 0) + 1)
    }
    return [...cuenta.entries()]
      .map(([site, count]) => ({ site, count }))
      .sort((a, b) => (a.site === '' ? 1 : b.site === '' ? -1 : a.site.localeCompare(b.site)))
  }

  /**
   * BUSCAR por texto. Se mira lo mismo que mira `SealedVault`: el nombre, el SITIO y la
   * **pista** —el usuario tapado que la vista lleva—, que es por lo que la gente busca de
   * verdad («ana@…»). Dejarla fuera hacía que buscar la cuenta de otro dominio no
   * encontrara nada, sin un solo error.
   *
   * Se busca sobre las VISTAS, no sobre los valores: aquí no se abre ninguna contraseña
   * para contestar a un buscador.
   */
  async search (texto, { limit = 20 } = {}) {
    const q = String(texto || '').trim().toLowerCase()
    if (!q) return []
    const out = []
    for (const v of await this.list()) {
      if (out.length >= limit) break
      if ([v.title, v.hint, ...(v.sites || [])].filter(Boolean).join(' ').toLowerCase().includes(q)) out.push(v)
    }
    return out
  }

  /** Una entrada ENTERA, o solo los campos que se pidan. */
  async get (id, { keys = null } = {}) {
    let got
    try { got = await this.sealed.get(id, { pub: this.readerPub, keys }) }
    catch (e) {
      if (e?.code === 'not-found') throw new VaultError(CODES.NOT_FOUND, 'no hay ninguna entrada con ese id')
      // «no me la envolvieron a mí» no es «no existe», y confundirlas manda a buscar el
      // problema al sitio equivocado.
      if (e?.code === 'not-yours') throw new VaultError(CODES.NOT_ALLOWED, 'esta punta no tiene llave para esa entrada')
      throw e
    }
    return openSealedEntry({ got, openSealed: this.openSealed })
  }

  /**
   * GUARDAR. Se cierra aquí y sale cerrado: la entrada se cifra, su llave se envuelve a
   * los destinatarios que diga el acta AHORA y el conjunto va firmado.
   *
   * Los destinatarios se piden en cada escritura y no se cachean: un aparato que acaba de
   * entrar tiene que poder leer lo siguiente que se guarde.
   */
  async put (entry) {
    const sobre = await buildSealedEntry({
      plain: entry,
      keys: await this.keys(),
      recipients: await this.recipients(),
      author: this.author
    })
    await this.sealed.putSealed(sobre)
    // La VISTA, como devuelve `LocalVault.put`: quien llama enseña el nombre de lo que
    // acaba de guardar. Devolver solo el id dejaba un «Guardada: undefined» en la CLI.
    return { id: sobre.entry.id, title: entry.title || '', sites: entry.sites || [] }
  }

  /**
   * Cambiar unos campos. Se hace leyendo y volviendo a escribir porque aquí quien lee y
   * quien escribe son el mismo: no hay nada que ahorrar ocultándose un valor a sí mismo.
   * (En remoto SÍ lo hay, y por eso allí existe `patchSealed`.)
   *
   * La fusión la hace `mergePatch`, la MISMA que `LocalVault` — y tiene que ser la misma,
   * porque no es un `{...a, ...b}`: un campo sin `value` dice «déjale el que tenga», no
   * «bórralo». Marcar uno como privado llega así, y fusionarlo a lo bruto le borraba el
   * valor. Costó encontrarlo porque no falla: guarda, y el campo ya no está.
   */
  async patch (id, changes = {}) {
    return this.put(mergePatch(await this.get(id), changes))
  }

  async remove (id) { return this.sealed.remove(id) }

  /** La huella de un sitio, por si quien llama quiere preguntar por ella directamente. */
  async siteIndexOf (site) {
    const { kidx } = await this.keys()
    return siteIndex(kidx, site)
  }
}

export default { SealedLocalVault }
