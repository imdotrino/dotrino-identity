// LA BÓVEDA SELLADA, VISTA DESDE EL APARATO.
//
// Cumple el MISMO contrato que `RemoteVault` (`./interface.js`: find/get/put/patch/search/
// sites/remove) para que la interfaz no tenga que aprender nada nuevo. Lo que cambia está
// debajo: al otro lado ya no hay una bóveda que abre entradas, hay una que guarda sobres.
// Así que todo lo que antes hacía ella lo hace esto, aquí:
//
//   · **buscar por sitio** — se calculan las huellas de la URL que hay delante y la bóveda
//     compara cadenas. El emparejamiento de verdad (subdominios, comodines) se rehace aquí
//     con `match.js` sobre las vistas ya abiertas, así que la regla no cambia;
//   · **abrir** — cada sobre con la envoltura de este aparato;
//   · **escribir** — cifrar, envolver a los destinatarios que dice el acta y firmar;
//   · **buscar por texto** — la bóveda no ve ningún texto: se piden las vistas y se busca
//     aquí (§2.2). Son vistas, no valores.
//
// Lo que este aparato no puede abrir se dice en `withheld` en vez de aparecer vacío.

import { SEALED_OPS } from '../transport/protocol.js'
import { VaultError, CODES } from './errors.js'
import { hostOf, registrableDomain, findForUrl } from '../match.js'
import { profileKeys, siteIndex, fieldIndex, passkeyIndex, valueDigest } from '../sealed/keys.js'
import { buildSealedEntry, buildSealedPatch, buildProfileKey, openSealedEntry, makeOpener } from '../sealed/device.js'
import { openView, PASSKEY_FIELD } from '../sealed/entry.js'
import { fieldKey, normalizeFields } from '../fields.js'

/** Las claves de campo de la interfaz, tal como las pide `get(id, { keys })`. */
const FIXED = ['name', 'username', 'secret', 'totp', 'notes']

/**
 * DE LA CLAVE QUE USA LA INTERFAZ A LA QUE GUARDA LA BÓVEDA.
 *
 * Las fijas viajan por su nombre —vocabulario cerrado, igual para todo el mundo— y las
 * libres por HUELLA: «cédula» es del usuario y la bóveda no tiene por qué leerlo. La
 * traducción vive aquí y en un solo sitio; si quien guarda y quien pide la hicieran
 * distinta, el sobre no se encontraría y no habría forma de verlo.
 */
const esFija = (k) => FIXED.includes(k) || k.startsWith('wa.')

export class SealedVault {
  /**
   * @param {object} transport `{ request(op, payload) }` — el mismo de `RemoteVault`
   * @param {object} opts
   *   `identity` `{ publickey, sign(body), openSealed({ wrap, envelope }) }`. La privada de
   *     cifrado no sale de donde viva: aquí solo se pide abrir.
   *   `needsApproval` si lo privado exige un dedo encima al otro lado (solo informativo)
   */
  constructor (transport, { identity, needsApproval = true } = {}) {
    if (!transport?.request) throw new Error('SealedVault: missing transport')
    if (typeof identity?.sign !== 'function' || typeof identity?.openSealed !== 'function') {
      throw new Error('SealedVault: identity needs { publickey, sign(body), openSealed({wrap,envelope}) }')
    }
    this.transport = transport
    this.identity = identity
    this.needsApproval = needsApproval
    this._keys = null
    this._recipients = null
  }

  get capabilities () {
    return { canWrite: true, canList: false, needsApproval: this.needsApproval, sealed: true }
  }

  /** Lo que se cachea muere al dormirse el worker, que es justo cuando hay que releerlo. */
  forget () { this._keys = null; this._recipients = null }

  async #request (op, payload) {
    if (!SEALED_OPS.includes(op)) throw new VaultError(CODES.NOT_ALLOWED, 'operación desconocida: ' + op)
    try {
      return await this.transport.request(op, payload)
    } catch (e) {
      if (e instanceof VaultError) throw e
      throw new VaultError(e?.code || CODES.UNREACHABLE, e?.message || 'no hay bóveda al otro lado')
    }
  }

  /**
   * LAS LLAVES DEL PERFIL. Sin ellas no se puede ni buscar (el índice va con huella) ni
   * comparar, así que es lo primero que pide este aparato al despertar.
   */
  async keys () {
    if (this._keys) return this._keys
    const { envelope, wrap } = await this.#request('pm2.profile', {})
    const base = await this.identity.openSealed({ wrap, envelope })
    this._keys = await profileKeys(base)
    return this._keys
  }

  /** A quién hay que envolverle cada llave. La lista sale del acta y la sabe la bóveda. */
  async recipients () {
    if (this._recipients) return this._recipients
    this._recipients = await this.#request('pm2.recipients', {})
    return this._recipients
  }

  async #sealedKey (k) {
    if (esFija(k)) return k
    const { kidx } = await this.keys()
    return 'f:' + await fieldIndex(kidx, k)
  }

  #opener (wraps) {
    return makeOpener({ wraps, openSealed: (x) => this.identity.openSealed(x) })
  }

  async #openView (v) {
    const abierta = await openView(
      { id: v.id, updatedAt: v.updatedAt, view: v.view, digests: v.digests },
      this.#opener({ [v.view.gen]: v.wrap })
    )
    // `fieldHashes` conserva el nombre que ya usa la interfaz para comparar. Dos cosas
    // cambian debajo: los resúmenes están GUARDADOS (antes era un HMAC con un nonce de la
    // respuesta), y su clave viaja por huella — así que aquí se traducen de vuelta a los
    // nombres de verdad, que la vista sí lleva porque va sellada.
    const fieldHashes = {}
    for (const k of [...abierta.fieldKeys, 'notes']) {
      const clave = await this.#sealedKey(k)
      if (abierta.digests[clave] !== undefined) fieldHashes[k] = abierta.digests[clave]
    }
    return { ...abierta, fieldHashes }
  }

  /**
   * LAS HUELLAS DE LA URL QUE HAY DELANTE. El sitio guardado puede ser el dominio y la URL
   * un subdominio suyo (`empresa.com` vale en `login.empresa.com`), así que se calculan las
   * huellas de CADA variante: el host, sus padres hasta el dominio registrable, y las de
   * comodín. La bóveda solo compara cadenas.
   */
  async #hashesFor (url) {
    const { kidx } = await this.keys()
    const host = hostOf(url)
    if (!host) return []
    const base = registrableDomain(host)
    const variantes = new Set([host])
    let actual = host
    while (actual.includes('.') && actual !== base) {
      actual = actual.slice(actual.indexOf('.') + 1)
      variantes.add(actual)
    }
    const out = []
    for (const v of variantes) {
      out.push(await siteIndex(kidx, v))
      out.push(await siteIndex(kidx, '*.' + v))
    }
    return out
  }

  /**
   * QUÉ HAY PARA ESTE SITIO. Las huellas son un filtro previo; el emparejamiento de verdad
   * —el que decide si `empresa.com` vale aquí— se rehace con `match.js` sobre las vistas ya
   * abiertas, para que la regla siga siendo UNA y no dos que se desincronizan.
   */
  async find (url) {
    const hits = await this.#request('pm2.find', { idx: await this.#hashesFor(url) })
    const vistas = []
    for (const v of hits) vistas.push(await this.#openView(v))
    return findForUrl(vistas, url).map((x) => x.entry)
  }

  /** La passkey que este sitio pide, o la que tiene ese id de credencial. */
  async findPasskey ({ rpId = null, credentialId = null } = {}) {
    const { kidx } = await this.keys()
    const hits = await this.#request('pm2.passkey', {
      ...(rpId ? { rp: await passkeyIndex(kidx, 'rp', rpId) } : {}),
      ...(credentialId ? { cred: await passkeyIndex(kidx, 'cred', credentialId) } : {})
    })
    const out = []
    for (const v of hits) out.push(await this.#openView(v))
    return out
  }

  /** UNA credencial, y solo los campos pedidos. */
  async get (id, opts = {}) {
    const keys = Array.isArray(opts.keys) ? await Promise.all(opts.keys.map((k) => this.#sealedKey(k))) : null
    const got = await this.#request('pm2.get', { id, ...(keys ? { keys } : {}) })
    return openSealedEntry({ got, openSealed: (x) => this.identity.openSealed(x) })
  }

  async put (plain) {
    const [keys, recipients] = await Promise.all([this.keys(), this.recipients()])
    const sobre = await buildSealedEntry({ plain, keys, recipients, author: this.#author() })
    await this.#request('pm2.put', sobre)
    // La vista se devuelve ARMADA AQUÍ: quien guardó ya la tiene en claro, y pedírsela a la
    // bóveda sería un viaje para que nos devuelva lo que acabamos de sellar.
    return this.#viewOf(plain)
  }

  /**
   * CAMBIAR unos campos sin leer los demás (§2.4).
   *
   * La vista se rehace aquí con lo que ya se sabe: los NOMBRES de los campos y cuáles son
   * privados viven en ella, no en los sobres, así que marcar un teléfono como privado no
   * saca el teléfono de la bóveda.
   */
  async patch (id, changes = {}) {
    const [keys, recipients] = await Promise.all([this.keys(), this.recipients()])
    const actual = await this.#viewById(id)
    if (!actual) throw new VaultError(CODES.NOT_FOUND, 'no hay ninguna entrada con ese id')

    const values = {}
    const drop = []
    for (const k of FIXED) if (typeof changes[k] === 'string') values[k] = { name: k, value: changes[k] }
    if (typeof changes.title === 'string') actual.title = changes.title

    const campos = normalizeFields(Array.isArray(changes.fields) ? changes.fields : [])
    for (const f of campos) {
      const k = fieldKey(f)
      // LA MARCA VA DENTRO DEL SOBRE, así que cambiarla es reescribir el campo — y para eso
      // hay que tener su valor. Quien edita lo tiene: si solo trae la marca, hay que leerlo
      // primero. Leer uno PÚBLICO no cuesta aprobación; quitarle la marca a uno privado sí,
      // y está bien, porque vas a exponerlo.
      let valor = f.value
      if (typeof valor !== 'string' || !valor) {
        if (f.private === undefined) continue
        const leido = await this.get(id, { keys: [k] })
        valor = (JSON.parse(leido.fields || '[]').find((x) => fieldKey(x) === k) || {}).value || ''
        if (!valor) continue
      }
      values[await this.#sealedKey(k)] = {
        name: k,
        value: JSON.stringify({ label: f.label, value: valor, kind: f.kind, ...(f.private ? { private: true } : {}) })
      }
      const privados = new Set(actual.privateKeys)
      if (f.private) privados.add(k); else if (f.private === false) privados.delete(k)
      actual.privateKeys = [...privados]
      if (!actual.fieldKeys.includes(k)) actual.fieldKeys.push(k)
    }
    for (const k of (changes.removeFields || [])) {
      drop.push(await this.#sealedKey(k))
      actual.fieldKeys = actual.fieldKeys.filter((x) => x !== k)
      actual.privateKeys = actual.privateKeys.filter((x) => x !== k)
    }
    for (const k of FIXED) {
      if (typeof changes[k] !== 'string') continue
      if (changes[k]) { if (!actual.fieldKeys.includes(k) && k !== 'name') actual.fieldKeys.push(k) } else {
        drop.push(k)
        actual.fieldKeys = actual.fieldKeys.filter((x) => x !== k)
      }
    }
    // Los sitios: la lista entera manda, y `addSite` solo suma si ya tenía alguno — una
    // entrada sin sitios sirve en cualquier parte y atarla al primer formulario donde se
    // usó sería cambiarle el sentido.
    let sites = null
    if (Array.isArray(changes.sites)) sites = changes.sites
    else if (changes.addSite && actual.sites.length) sites = [...new Set([...actual.sites, changes.addSite])]
    if (sites) actual.sites = sites

    if (typeof changes.name === 'string' || typeof changes.username === 'string') {
      actual.hint = changes.name || actual.hint
    }

    const vista = {
      type: actual.type,
      title: actual.title,
      sites: actual.sites,
      hint: actual.hint,
      fieldKeys: actual.fieldKeys,
      privateKeys: actual.privateKeys,
      has: {
        secret: drop.includes('secret') ? false : (actual.hasSecret || !!values.secret),
        totp: drop.includes('totp') ? false : (actual.hasTotp || !!values.totp),
        notes: drop.includes('notes') ? false : (actual.hasNotes || !!values.notes),
        fields: actual.fieldKeys.some((k) => !FIXED.includes(k)),
        webauthn: actual.hasWebauthn
      },
      ...(actual.webauthn ? { webauthn: actual.webauthn } : {})
    }
    const idx = sites ? await Promise.all(sites.map((s) => siteIndex(keys.kidx, s))) : null
    const parche = await buildSealedPatch({
      id, view: vista, values, drop,
      priv: await Promise.all(vista.privateKeys.map((k) => this.#sealedKey(k))),
      ...(idx ? { idx } : {}), keys, recipients, author: this.#author()
    })
    await this.#request('pm2.patch', parche)
    return { id, ...vista, updatedAt: Date.now() }
  }

  /** Buscar por texto: la bóveda no ve ninguno, así que se busca aquí sobre las vistas. */
  async search (q, opts = {}) {
    const termino = String(q || '').trim().toLowerCase()
    if (!termino) return []
    const limite = Number(opts.limit) > 0 ? Number(opts.limit) : 20
    const out = []
    for (const v of await this.#views()) {
      const texto = [v.title, v.hint, ...(v.sites || [])].join(' ').toLowerCase()
      if (texto.includes(termino)) out.push(v)
      if (out.length >= limite) break
    }
    return out
  }

  /** En qué sitios hay algo. Los nombres salen de abrir las vistas, no de la bóveda. */
  async sites () {
    const cuenta = new Map()
    for (const v of await this.#views()) {
      for (const s of v.sites || []) cuenta.set(s, (cuenta.get(s) || 0) + 1)
    }
    return [...cuenta].map(([site, count]) => ({ site, count })).sort((a, b) => a.site.localeCompare(b.site))
  }

  async remove (id) {
    await this.#request('pm2.remove', { id })
  }

  /**
   * LA BÓVEDA ENTERA, ABIERTA AQUÍ. No es `list` de la bóveda: son las VISTAS, que no
   * llevan ningún valor, y las abre este aparato con su llave. Es lo que sustituye a
   * buscar dentro de la bóveda (§2.2), y por eso existe donde antes no podía existir.
   */
  async list () {
    return this.#views()
  }

  /** El resumen de un valor, para decir si ya está guardado igual sin abrir nada (§2.6). */
  async digest (id, key, value) {
    const { kcmp } = await this.keys()
    return valueDigest(kcmp, id, key, String(value))
  }

  async #views () {
    const crudas = await this.#request('pm2.views', {})
    const out = []
    for (const v of crudas) out.push(await this.#openView(v))
    return out
  }

  async #viewById (id) {
    return (await this.#views()).find((v) => v.id === id) || null
  }

  #author () {
    return { publickey: this.identity.publickey, sign: (body) => this.identity.sign(body) }
  }

  /** La vista de lo que se acaba de guardar, con la forma que espera la interfaz. */
  #viewOf (plain) {
    const campos = normalizeFields(Array.isArray(plain.fields) ? plain.fields : [])
    return {
      id: plain.id,
      type: plain.type || 'login',
      title: plain.title || '',
      sites: plain.sites || [],
      hasSecret: !!plain.secret,
      hasTotp: !!plain.totp,
      hasNotes: !!plain.notes,
      hasFields: campos.length > 0,
      hasWebauthn: !!plain.webauthn,
      updatedAt: Date.now()
    }
  }

  /** Estrenar la llave del perfil. Solo al convertir: después ya está y se pide. */
  async initProfileKey () {
    const recipients = await this.recipients()
    const pk = await buildProfileKey({ recipients })
    await this.#request('pm2.profile', { set: { envelope: pk.envelope, wraps: pk.wraps } })
    this._keys = await profileKeys(pk.base)
    return this._keys
  }
}

export { PASSKEY_FIELD }
export default SealedVault
