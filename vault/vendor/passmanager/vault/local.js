// Bóveda local: la que corre donde SÍ está la CEK — el vault del PC, la app nativa,
// y la caché opt-in de solo lectura de la extensión (DISENO §3).
//
// El almacén se inyecta para no atar la librería a nada: en la app es
// `@dotrino/store`, en la extensión `chrome.storage.local`, en las pruebas un Map.
// Solo tiene que cumplir `{ get(k), set(k, v) }`.

import { openEntry, sealEntry, mergePatch, publicView, entryWho, normalizeSites } from '../model.js'
import { entryDigestValues, fieldKey, normalizeFields, KINDS } from '../fields.js'
import { makeNonce, fieldHasher } from '../crypto.js'
import { findForUrl } from '../match.js'
import { VaultError, CODES } from './errors.js'

const KEY = 'passmanager/entries/v1'

export class LocalVault {
  /**
   * @param {object} store almacén `{ get(k), set(k, v) }`
   * @param {object} opts  `{ readOnly }` — la caché de la extensión va en `true`
   */
  constructor (store, opts = {}) {
    this.store = store
    this.readOnly = !!opts.readOnly
    this.key = null
  }

  get capabilities () {
    return { canWrite: !this.readOnly, canList: true, needsApproval: false }
  }

  /** Entrega la CEK. Sin esto, todo lo demás falla con `locked`. */
  unlock (cek) {
    this.key = cek
  }

  lock () {
    this.key = null
  }

  #requireKey () {
    if (!this.key) throw new VaultError(CODES.LOCKED, 'la bóveda está cerrada')
  }

  async #all () {
    return (await this.store.get(KEY)) || []
  }

  /**
   * Los RESÚMENES de los campos de una entrada, para que quien pregunta pueda comparar
   * sin abrir nada (§4.0.2). Un nonce por respuesta, no por entrada: así dos entradas de
   * la misma respuesta se pueden comparar contra lo mismo, y entre dos respuestas no hay
   * nada que correlacionar.
   */
  async #digest (nonce, hash, open) {
    const fields = {}
    for (const f of entryDigestValues(open)) fields[f.key] = await hash(f.key, f.value)
    return { nonce, fields }
  }

  async find (url) {
    this.#requireKey()
    const hits = findForUrl(await this.#all(), url)
    const nonce = makeNonce()
    const hash = await fieldHasher(nonce)
    // El nombre visible obliga a abrir la entrada: por eso lo calcula quien tiene la CEK,
    // y no quien pregunta. Lo mismo los resúmenes.
    return Promise.all(hits.map(async ({ entry }) => {
      const open = await openEntry(this.key, entry)
      return publicView(entry, entryWho(open), open, await this.#digest(nonce, hash, open))
    }))
  }

  async get (id) {
    this.#requireKey()
    const entry = (await this.#all()).find(e => e.id === id)
    if (!entry) throw new VaultError(CODES.NOT_FOUND, 'no hay ninguna entrada con ese id')
    return openEntry(this.key, entry)
  }

  async put (plain) {
    this.#requireKey()
    if (this.readOnly) throw new VaultError(CODES.READ_ONLY, 'esta copia solo puede leer')
    const sealed = await sealEntry(this.key, plain)
    const all = await this.#all()
    const i = all.findIndex(e => e.id === sealed.id)
    if (i >= 0) {
      sealed.createdAt = all[i].createdAt
      all[i] = sealed
    } else {
      all.push(sealed)
    }
    await this.store.set(KEY, all)
    return publicView(sealed)
  }

  /**
   * CAMBIAR unos campos de una entrada, dejando el resto como estaba.
   *
   * Existe para que quien guarda **no tenga que leerla antes**. Antes el aparato hacía
   * `get` + fusionar + `put`, y eso tenía dos costes que no se veían: sacaba de la bóveda
   * la entrada entera —contraseña incluida— para escribir un teléfono, y si esa lectura
   * fallaba, el `put` que venía detrás escribía la entrada **sin lo que no pudo leer**.
   * Eso no es un fallo raro: es perder datos por una autorización denegada.
   *
   * Aquí la fusión ocurre donde vive el dato. Lo que no venga en `changes` no se toca, y
   * si la entrada no existe no se crea nada — para crear está `put`.
   *
   * `changes`:
   *   `name`, `title`, `username`, `secret`, `totp`, `notes`  cada uno, si viene, reemplaza
   *   `fields`  lista `{ label, value, kind, private }`; se casan por su clave (§4.2),
   *             los que no aparecen se quedan. **`value` sin poner no toca el valor**:
   *             sirve para cambiar solo la marca de privado, que es lo único que se puede
   *             hacer desde el gestor con un campo cuyo valor no se tiene delante
   *   `removeFields`  claves que se van. Un campo libre desaparece; uno de los de siempre
   *             (`username`, `secret`, `totp`, `notes`) se queda vacío, que es lo mismo
   *   `sites`   la lista ENTERA, tal cual queda. Es lo que manda el gestor, que la edita
   *             a mano; vacía significa «sirve en cualquier sitio», que es lo que la
   *             ausencia de sitios ha significado siempre. Si viene, `addSite` se ignora
   *   `addSite` suma este sitio **solo si la entrada ya tenía alguno**: una entrada sin
   *             sitios sirve en cualquier parte, y atarla al primer formulario donde se
   *             usó sería quitarle eso sin que nadie lo pidiera
   */
  async patch (id, changes = {}) {
    this.#requireKey()
    if (this.readOnly) throw new VaultError(CODES.READ_ONLY, 'esta copia solo puede leer')
    const all = await this.#all()
    const i = all.findIndex(e => e.id === id)
    if (i < 0) throw new VaultError(CODES.NOT_FOUND, 'no hay ninguna entrada con ese id')

    const base = await openEntry(this.key, all[i])
    // La fusión vive en `model.js` y la comparten esta bóveda y la sellada: no es un
    // `{...a, ...b}` —un campo sin `value` dice «déjale el que tenga»— y dos copias de esa
    // sutileza son una que se queda atrás.
    const sealed = await sealEntry(this.key, mergePatch(base, changes))
    all[i] = sealed
    await this.store.set(KEY, all)
    return publicView(sealed)
  }

  /**
   * EN QUÉ SITIOS HAY ALGO GUARDADO, y cuánto en cada uno.
   *
   * Es lo que le permite al gestor abrir con la lista de dominios en vez de con un
   * buscador en blanco (dueño, 2026-08-29). **No es `list`**, y la diferencia no es de
   * grado: de aquí no sale ni un id, ni un nombre, ni qué campos lleva nadie, ni un
   * resumen con el que comparar. Sale el dominio, que **ya viaja en claro** —`sites` no
   * se cifra, porque hace falta para emparejar con la página sin tener la CEK (§5)— y
   * cuántas entradas hay en él.
   *
   * Lo que sí concede, y conviene decirlo: hoy hay que preguntar sitio por sitio para
   * saber dónde tienes cuenta, y esto lo contesta de una vez. Es la razón de que el
   * dueño lo decidiera a propósito y no se colara como un detalle.
   *
   * `site: ''` son las entradas SIN sitio, que sirven en cualquier parte.
   */
  async sites () {
    this.#requireKey()
    const cuenta = new Map()
    for (const e of await this.#all()) {
      const suyos = e.sites?.length ? e.sites : ['']
      for (const s of suyos) cuenta.set(s, (cuenta.get(s) || 0) + 1)
    }
    return [...cuenta.entries()]
      .map(([site, count]) => ({ site, count }))
      .sort((a, b) => (a.site === '' ? 1 : b.site === '' ? -1 : a.site.localeCompare(b.site)))
  }

  /**
   * BUSCAR por texto en toda la bóveda. Devuelve lo público, y como mucho `limit`.
   *
   * No es `list` con otro nombre, y la diferencia importa (DISENO §2): `list` lo puede
   * pedir el código en cualquier momento y devuelve todo; esto exige un término que
   * **escribe una persona** y devuelve un puñado. Existe porque a veces la cuenta que
   * sirve está guardada en otro dominio —el subdominio cambió y la clave es la misma— y
   * sin buscarla no hay forma de llegar a ella.
   *
   * Se busca en lo que identifica a la entrada: su título, sus sitios y su nombre
   * visible. **Nunca en los valores de los campos**: buscar «1700» y que aparezca tu
   * documento es exactamente lo que no puede pasar.
   */
  async search (q, { limit = 20 } = {}) {
    this.#requireKey()
    const texto = String(q || '').trim().toLowerCase()
    if (texto.length < 2) return []
    const nonce = makeNonce()
    const hash = await fieldHasher(nonce)
    const out = []
    for (const entry of await this.#all()) {
      if (out.length >= limit) break
      const open = await openEntry(this.key, entry)
      const quien = entryWho(open)
      const heno = [entry.title, quien, ...(entry.sites || [])].filter(Boolean).join(' ').toLowerCase()
      if (heno.includes(texto)) {
        out.push(publicView(entry, quien, open, await this.#digest(nonce, hash, open)))
      }
    }
    return out
  }

  async remove (id) {
    this.#requireKey()
    if (this.readOnly) throw new VaultError(CODES.READ_ONLY, 'esta copia solo puede leer')
    const all = await this.#all()
    const rest = all.filter(e => e.id !== id)
    if (rest.length === all.length) throw new VaultError(CODES.NOT_FOUND, 'no hay ninguna entrada con ese id')
    await this.store.set(KEY, rest)
  }

  async list () {
    this.#requireKey()
    return (await this.#all()).map(e => publicView(e))
  }
}
