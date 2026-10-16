// LA BÓVEDA DE CONTRASEÑAS QUE NO PUEDE LEERLAS (`sealed-passwords.md`).
//
// Guarda sobres dirigidos a los aparatos y las envolturas de sus llaves, y **no tiene
// ninguna llave propia con la que abrir nada** — ni abierta ni cerrada. Es el mismo modelo
// que los cajones de secretos del vault (`dotrino-vault/src/secretsStore.js`), y se parece
// a propósito: quien lea uno entiende el otro.
//
// Lo que sí hace, porque no necesita la llave para hacerlo:
//
//   · **comprobar los destinatarios**. Es LA comprobación que sostiene el modelo: un
//     aparato no puede guardar una entrada que solo él pueda abrir, ni dejar fuera la copia
//     de recuperación, ni meter la privada de una passkey en el sobre de las contraseñas;
//   · **filtrar por destinatario** al entregar: a cada aparato, lo suyo;
//   · **numerar las generaciones** y barrer las que ya no usa nadie.
//
// El almacén se inyecta (`{ get(k), set(k, v) }`), como en `../vault/local.js`: en el
// demonio es un archivo, en la pestaña IndexedDB, en las pruebas un Map. Una sola pieza
// para las tres bóvedas y el `serve`, que es lo que la regla de las tres versiones exige.

import { wrapForMember } from '@dotrino/identity/content'
import { PASSKEY_FIELD } from './entry.js'
import { entryAuthorBody, patchAuthorBody } from './device.js'

export const KEY = 'passmanager/sealed/v2'
/** La envoltura que abre la frase del perfil. Sin ella, una entrada nace ilegible. */
export const RECOVERY = '#recovery'

const isEnv = (e) => !!e && typeof e.iv === 'string' && typeof e.ct === 'string'
const sorted = (a) => [...a].sort()
const same = (a, b) => a.length === b.length && sorted(a).every((x, i) => x === sorted(b)[i])

export class SealedError extends Error {
  constructor (code, message) { super(message); this.code = code; this.name = 'SealedError' }
}

export class SealedStore {
  /**
   * @param {object} store  `{ get(k), set(k, v) }`
   * @param {object} opts
   *   `recipients(kind)` → `[{ pub, encPub }]` quién DEBE tener envoltura. `kind` es
   *     `'main'` (los aparatos con `passwords`) o `'passkeys'` (los que además tienen
   *     `passkeys`). Lo pone quien conoce el acta: esta pieza no la lee.
   *   `verifyAuthor({ body, author })` → ¿la firmó quien dice, y puede escribir? Lo
   *     contesta quien tiene el acta. **No es opcional**: sin ella, cualquiera que llegue
   *     al almacén podría dejar una entrada a nombre de otro, y la bóveda no puede mirar
   *     dentro para notarlo.
   *   `recovery()` → ¿la cuenta YA tiene copia de recuperación? Si la tiene, toda envoltura
   *     lleva la suya (`#recovery`). Si todavía no, la bóveda funciona igual, sellada solo a
   *     los aparatos del acta, y la copia se añade después con `addRecovery`. Por defecto
   *     contesta que sí: lo estricto es el valor por omisión, no el permisivo.
   *   `now()` el reloj, para poder probar sin esperar.
   */
  constructor (store, { recipients, verifyAuthor, recovery = async () => true, now = () => Date.now() } = {}) {
    if (!store) throw new Error('SealedStore: missing store')
    if (typeof recipients !== 'function') throw new Error('SealedStore: missing recipients(kind)')
    if (typeof verifyAuthor !== 'function') throw new Error('SealedStore: missing verifyAuthor({ body, author })')
    this.store = store
    this.recipients = recipients
    this.verifyAuthor = verifyAuthor
    this.recovery = recovery
    this.now = now
  }

  async #state () {
    const s = await this.store.get(KEY)
    if (s && typeof s === 'object') return s
    return { v: 2, keyring: [], profile: null, entries: [] }
  }

  async #save (s) { await this.store.set(KEY, s) }

  /** ¿Hay algo guardado en el formato sellado? Lo pregunta quien tiene que convertir. */
  async sealed () {
    const s = await this.#state()
    return !!s.profile
  }

  #gen (s, gen) { return (s.keyring || []).find((g) => g.gen === gen) || null }

  /** La envoltura de ESTE aparato para esa generación, o `null` si no le tocaba. */
  #wrapFor (s, gen, pub) { return this.#gen(s, gen)?.wraps?.[pub] || null }

  /**
   * ¿SON EXACTAMENTE LOS DESTINATARIOS QUE MANDA EL ACTA? Ni de más ni de menos, más la
   * copia de recuperación.
   *
   * Ni de menos, porque un aparato podría guardar algo que los demás no pueden abrir —y la
   * pérdida no se nota hasta que hace falta—. Ni de más, porque entonces cualquiera podría
   * darle acceso a una llave que el acta no reconoce. Y la de recuperación siempre que la
   * cuenta tenga copia: sin ella, ni el dueño con su frase puede volver a repartir esa
   * entrada. Una cuenta que aún no la creó guarda igual, y la pantalla lo avisa.
   */
  async #checkWraps (kind, wraps) {
    if (!wraps || typeof wraps !== 'object') throw new SealedError('wraps-missing', 'the envelope wraps are missing')
    if (!wraps[RECOVERY] && await this.recovery()) {
      throw new SealedError('recovery-missing',
        'the wraps must include the recovery one (#recovery), or this entry could never be handed out again')
    }
    const deben = (await this.recipients(kind)).filter((m) => m?.encPub).map((m) => m.pub)
    // NADIE A QUIEN ENVOLVÉRSELA NO ES «CERO DESTINATARIOS», ES UN ERROR. Guardar una
    // passkey que ningún aparato puede abrir la deja viva solo para la frase del perfil: no
    // se pierde, pero no sirve, y el usuario se entera el día que la necesita. Se dice
    // ahora, con un código que explica qué falta.
    if (kind === 'passkeys' && !deben.length) {
      throw new SealedError('no-passkeys-device',
        'no device in the account record can open passkeys: grant `passkeys` to one (`dotrino-vault caps <ID> +passkeys`) before saving it')
    }
    const hay = Object.keys(wraps).filter((k) => k !== RECOVERY)
    if (!same(deben, hay)) {
      throw new SealedError('wrong-recipients',
        `the wraps do not match the account record: it expects [${sorted(deben).join(', ')}] and got [${sorted(hay).join(', ')}]`)
    }
  }

  /** La forma de una entrada sellada, antes de tocar el disco. */
  #checkEntry (entry, tienePasskeys) {
    if (!entry || typeof entry.id !== 'string' || !entry.id) throw new SealedError('bad-entry', 'the entry has no id')
    if (!isEnv(entry.view)) throw new SealedError('bad-entry', 'the entry has no sealed public view')
    if (!entry.fields || typeof entry.fields !== 'object') throw new SealedError('bad-entry', 'the entry has no fields')
    for (const [k, e] of Object.entries(entry.fields)) {
      if (!isEnv(e)) throw new SealedError('bad-entry', `field «${k}» is not a sealed envelope`)
    }
    if (!Array.isArray(entry.idx)) throw new SealedError('bad-entry', 'the entry has no site index')
    const llevaPasskey = !!entry.fields[PASSKEY_FIELD]
    // Una passkey en el sobre de las contraseñas la abriría un aparato sin el permiso, que
    // es exactamente lo que §2.8 separa. Y al revés: una generación de passkeys sin passkey
    // reparte una llave que nadie va a usar.
    if (llevaPasskey && !tienePasskeys) {
      throw new SealedError('passkeys-generation-missing',
        'this entry carries a passkey: it needs its own wraps, only for devices with `passkeys`')
    }
    if (!llevaPasskey && tienePasskeys) {
      throw new SealedError('passkeys-generation-unused', 'there is no passkey in this entry to wrap')
    }
  }

  /**
   * GUARDAR. Llega todo cerrado: la bóveda no ve ni un valor, tampoco al escribir.
   *
   * La GENERACIÓN la pone el almacén y no quien escribe —igual que en los cajones—: es lo
   * que ordena el llavero, y dejar elegirla permitiría pisar una anterior.
   *
   * @param {object} o
   *   `entry`     la entrada de `sealEntry`, con los sobres SIN `gen`
   *   `main`      `{ wraps }` de la llave con la que se cerró todo menos la passkey
   *   `passkeys`  `{ wraps }` de la llave de la passkey, si la entrada lleva una
   *   `by`        el aparato que escribe (para la bitácora; quién PUEDE lo decide quien llama)
   */
  async putSealed ({ entry, main, passkeys = null, by = null } = {}) {
    this.#checkEntry(entry, !!passkeys)
    await this.#checkWraps('main', main?.wraps)
    if (passkeys) await this.#checkWraps('passkeys', passkeys.wraps)
    // LA FIRMA DEL AUTOR, sobre lo que de verdad se guarda. Es lo que ata cada entrada a un
    // aparato del acta: la bóveda no ve los valores, así que esto es lo único que puede
    // comprobar sobre su procedencia.
    if (!entry.author?.pub || !entry.author?.sig) throw new SealedError('unsigned', 'the entry is not signed by its author')
    const ok = await this.verifyAuthor({ body: entryAuthorBody(entry, entry.author.ts), author: entry.author })
    if (!ok) throw new SealedError('bad-author', 'that entry was not signed by a device allowed to write passwords')

    const s = await this.#state()
    const t = this.now()
    const siguiente = () => (s.keyring.reduce((max, g) => Math.max(max, g.gen || 0), 0) + 1)

    const genMain = siguiente()
    s.keyring.push({ gen: genMain, kind: 'main', createdAt: t, wraps: main.wraps })
    let genPk = null
    if (passkeys) {
      genPk = siguiente()
      s.keyring.push({ gen: genPk, kind: 'passkeys', createdAt: t, wraps: passkeys.wraps })
    }

    const fields = {}
    for (const [k, e] of Object.entries(entry.fields)) {
      fields[k] = { ...e, gen: k === PASSKEY_FIELD ? genPk : genMain }
    }
    const guardada = {
      id: entry.id,
      createdAt: entry.createdAt || t,
      updatedAt: t,
      by: by || entry.author.pub,
      author: entry.author,
      idx: [...entry.idx],
      wa: entry.wa || null,
      view: { ...entry.view, gen: genMain },
      fields,
      digests: { ...(entry.digests || {}) },
      priv: [...(entry.priv || [])]
    }
    const i = s.entries.findIndex((e) => e.id === guardada.id)
    if (i >= 0) { guardada.createdAt = s.entries[i].createdAt || guardada.createdAt; s.entries[i] = guardada }
    else s.entries.push(guardada)

    this.#gc(s)
    await this.#save(s)
    return { id: guardada.id, gen: genMain, updatedAt: guardada.updatedAt }
  }

  /**
   * CAMBIAR UNOS CAMPOS SIN LEER LA ENTRADA (§2.4).
   *
   * Es la razón de que exista `patch` y no se haya caído con el formato nuevo: antes, para
   * escribir un teléfono había que sacar la entrada ENTERA de la bóveda —contraseña
   * incluida—, y si esa lectura fallaba, lo que se escribía detrás perdía lo que no se pudo
   * leer. Perder datos por una autorización denegada no es un fallo raro.
   *
   * Aquí los campos que no vienen **se quedan con su sobre y su generación**: ni se abren
   * ni se reescriben. Lo único que hay que rehacer siempre es la VISTA, porque dice qué
   * campos lleva la entrada — y eso lo sabe quien la cambia, sin abrir ningún valor.
   *
   * @param {object} o
   *   `id`      la entrada
   *   `view`    la vista nueva (sobre), obligatoria: cambia con cualquier campo
   *   `fields`  solo los campos que cambian `{ clave: sobre }`
   *   `drop`    las claves que se van
   *   `digests` los resúmenes de lo que cambió (los de `drop` se quitan)
   *   `idx`/`wa` si cambian los sitios o la passkey
   *   `main` / `passkeys`  `{ wraps }` de las llaves nuevas
   */
  async patchSealed ({ id, view, fields = {}, drop = [], digests = {}, priv = null, idx = null, wa, main, passkeys = null, author = null, by = null } = {}) {
    if (!isEnv(view)) throw new SealedError('bad-entry', 'a patch has to bring the public view again')
    for (const [k, e] of Object.entries(fields)) {
      if (!isEnv(e)) throw new SealedError('bad-entry', `field «${k}» is not a sealed envelope`)
    }
    await this.#checkWraps('main', main?.wraps)
    if (passkeys) await this.#checkWraps('passkeys', passkeys.wraps)
    if (fields[PASSKEY_FIELD] && !passkeys) {
      throw new SealedError('passkeys-generation-missing',
        'that patch carries a passkey: it needs its own wraps, only for devices with `passkeys`')
    }

    const s = await this.#state()
    const e = s.entries.find((x) => x.id === id)
    if (!e) throw new SealedError('not-found', 'there is no entry with that id')

    if (!author?.pub || !author?.sig) throw new SealedError('unsigned', 'the patch is not signed by its author')
    const body = patchAuthorBody({ id, view, fields, drop, digests, priv, idx, wa }, author.ts)
    if (!(await this.verifyAuthor({ body, author }))) {
      throw new SealedError('bad-author', 'that patch was not signed by a device allowed to write passwords')
    }

    const t = this.now()
    const siguiente = () => (s.keyring.reduce((max, g) => Math.max(max, g.gen || 0), 0) + 1)
    const genMain = siguiente()
    s.keyring.push({ gen: genMain, kind: 'main', createdAt: t, wraps: main.wraps })
    let genPk = null
    if (passkeys) {
      genPk = siguiente()
      s.keyring.push({ gen: genPk, kind: 'passkeys', createdAt: t, wraps: passkeys.wraps })
    }

    for (const k of drop) { delete e.fields[k]; delete e.digests[k] }
    for (const [k, env] of Object.entries(fields)) {
      e.fields[k] = { ...env, gen: k === PASSKEY_FIELD ? genPk : genMain }
    }
    for (const [k, d] of Object.entries(digests)) e.digests[k] = d
    e.view = { ...view, gen: genMain }
    if (Array.isArray(priv)) e.priv = [...priv]
    if (Array.isArray(idx)) e.idx = [...idx]
    if (wa !== undefined) e.wa = wa
    e.updatedAt = t
    e.by = by || author.pub
    e.author = author

    this.#gc(s)
    await this.#save(s)
    return { id: e.id, gen: genMain, updatedAt: e.updatedAt }
  }

  /**
   * LAS VISTAS que este aparato puede abrir. Es lo que sustituye a `list`, `search` y
   * `sites`: la bóveda ya no puede buscar por texto —no ve ninguno— así que entrega las
   * vistas selladas y busca quien las abre (§2.2).
   *
   * **Vistas, no valores**: de aquí no sale ninguna contraseña. Y solo las que este aparato
   * puede abrir: a quien lleva una selección de entradas no se le dice ni que existen las
   * demás (§2.6).
   */
  async views ({ pub } = {}) {
    const s = await this.#state()
    const out = []
    for (const e of s.entries) {
      const wrap = this.#wrapFor(s, e.view.gen, pub)
      if (!wrap) continue
      out.push({ id: e.id, updatedAt: e.updatedAt, idx: e.idx, wa: e.wa, view: e.view, wrap, digests: e.digests, author: e.author })
    }
    return out
  }

  /**
   * QUÉ HAY PARA ESTE SITIO. `idx` son las huellas que calculó el aparato con la llave del
   * perfil: la bóveda compara cadenas, sin saber de qué sitio se habla.
   *
   * `anySite` trae además las entradas SIN sitios, que son las que sirven en cualquier
   * parte — es lo que ha significado siempre no tener sitios.
   */
  async find ({ pub, idx = [], anySite = true } = {}) {
    const busca = new Set(idx)
    return (await this.views({ pub })).filter((v) =>
      v.idx.some((h) => busca.has(h)) || (anySite && v.idx.length === 0))
  }

  /** Lo mismo para una passkey: por el sitio que la pide o por el id de la credencial. */
  async findPasskey ({ pub, rp = null, cred = null } = {}) {
    return (await this.views({ pub })).filter((v) =>
      v.wa && ((rp && v.wa.rp === rp) || (cred && v.wa.cred === cred)))
  }

  /**
   * LOS SOBRES DE LOS CAMPOS PEDIDOS, con la envoltura de quien pregunta.
   *
   * Lo que este aparato no puede abrir no se manda y **se dice** (`withheld`): una passkey
   * para un aparato sin el permiso se queda aquí, y la pantalla lo explica en vez de
   * enseñar un hueco.
   */
  async get (id, { pub, keys = null } = {}) {
    const s = await this.#state()
    const e = s.entries.find((x) => x.id === id)
    if (!e) throw new SealedError('not-found', 'there is no entry with that id')
    const quiere = Array.isArray(keys) ? new Set(keys) : null
    const envelopes = {}
    const wraps = {}
    const withheld = []
    const vista = this.#wrapFor(s, e.view.gen, pub)
    if (!vista) throw new SealedError('not-yours', 'this device has no key for that entry')
    for (const [k, env] of Object.entries(e.fields)) {
      if (quiere && !quiere.has(k)) continue
      const w = this.#wrapFor(s, env.gen, pub)
      if (!w) { withheld.push(k); continue }
      envelopes[k] = env
      wraps[env.gen] = w
    }
    wraps[e.view.gen] = vista
    return { id: e.id, view: e.view, envelopes, wraps, withheld, updatedAt: e.updatedAt, digests: e.digests }
  }

  /**
   * QUÉ CLAVES DE ESA ENTRADA SON PRIVADAS. Es lo único de la vista que la bóveda ve, y lo
   * ve porque la aprobación es suya: sin esto no podría distinguir «rellena mi nombre» de
   * «dame la contraseña» (ver la nota en `entry.js`).
   */
  async privateKeysOf (id) {
    const s = await this.#state()
    return s.entries.find((e) => e.id === id)?.priv || []
  }

  async remove (id) {
    const s = await this.#state()
    const antes = s.entries.length
    s.entries = s.entries.filter((e) => e.id !== id)
    if (s.entries.length === antes) return { ok: false }
    this.#gc(s)
    await this.#save(s)
    return { ok: true }
  }

  /**
   * LA LLAVE DEL PERFIL (de la que salen el índice y los resúmenes), sellada como un valor
   * más. Se escribe una vez y se vuelve a repartir cuando cambia quién puede leer.
   */
  async profile ({ pub } = {}) {
    const s = await this.#state()
    if (!s.profile) throw new SealedError('not-sealed', 'this vault has no sealed password key yet: open it to convert')
    const wrap = this.#wrapFor(s, s.profile.gen, pub)
    if (!wrap) throw new SealedError('not-yours', 'this device has no key for the profile password key')
    return { envelope: s.profile, wrap }
  }

  async setProfile ({ envelope, wraps } = {}) {
    if (!isEnv(envelope)) throw new SealedError('bad-entry', 'the profile key is not a sealed envelope')
    await this.#checkWraps('main', wraps)
    const s = await this.#state()
    const gen = s.keyring.reduce((max, g) => Math.max(max, g.gen || 0), 0) + 1
    s.keyring.push({ gen, kind: 'main', createdAt: this.now(), wraps })
    s.profile = { ...envelope, gen }
    this.#gc(s)
    await this.#save(s)
    return { gen }
  }

  /**
   * LAS GENERACIONES QUE YA NO ABRE NADA se van. Cada escritura estrena una, así que sin
   * este barrido el llavero crece para siempre (§2.4).
   */
  #gc (s) {
    const vivas = new Set()
    if (s.profile?.gen) vivas.add(s.profile.gen)
    for (const e of s.entries) {
      vivas.add(e.view.gen)
      for (const env of Object.values(e.fields)) vivas.add(env.gen)
    }
    s.keyring = s.keyring.filter((g) => vivas.has(g.gen))
  }

  /**
   * PAGAR LA DEUDA: reenvolver cada generación para exactamente quien dice el acta AHORA.
   *
   * Lo hace quien puede abrir la copia de RECUPERACIÓN, o sea la bóveda con la frase del
   * perfil delante — al abrirla, que es cuando la tiene (§2.5). Sin esto, un aparato que
   * entra después de escrita una entrada no puede abrirla nunca: nadie más tiene con qué
   * envolvérsela.
   *
   * Y de paso se va lo que sobra: la envoltura de quien ya no está en la lista. Ni se
   * descifra ni se reescribe ningún valor — solo cambian las envolturas de las llaves.
   *
   * **O lo hace un MIEMBRO que ya tiene su envoltura** (`holder`). Es el caso de la bóveda de
   * dentro de la extensión: ella misma está entre los destinatarios de todo, así que puede
   * completar a un aparato que entró después sin pedirle a nadie la frase. No regala nada:
   * quien hace esto ya podía leerlo, y a quien se lo entrega lo reconoce el acta. La llave
   * tampoco sale de él — `rewrapFor` es de `@dotrino/identity`, que abre y vuelve a
   * envolver sin devolverla.
   *
   * @param {object} o  hace falta uno de los dos, y si están los dos manda `holder`
   * @param {(wrap:object) => Promise<string>} [o.openRecovery] abre la envoltura `#recovery`
   * @param {{ pub:string, rewrapFor:({wrap, encPub}) => Promise<object> }} [o.holder]
   *   un miembro con envoltura propia: su pública y cómo re-envuelve la llave que ya abre
   */
  async rewrapAll ({ openRecovery, holder } = {}) {
    const conHolder = !!holder?.pub && typeof holder.rewrapFor === 'function'
    if (typeof openRecovery !== 'function' && !conHolder) {
      throw new Error('rewrapAll: missing openRecovery(wrap) or holder { pub, rewrapFor }')
    }
    const s = await this.#state()
    const out = { generations: 0, wrapped: 0, dropped: 0, failed: [] }
    for (const g of s.keyring) {
      const kind = g.kind || 'main'
      const deben = (await this.recipients(kind)).filter((m) => m?.encPub)
      const antes = Object.keys(g.wraps).filter((k) => k !== RECOVERY)
      const faltan = deben.filter((m) => !g.wraps[m.pub])
      const sobran = antes.filter((p) => !deben.some((m) => m.pub === p))
      if (!faltan.length && !sobran.length) continue
      try {
        if (faltan.length) {
          const suya = conHolder ? g.wraps[holder.pub] : null
          if (suya) {
            for (const m of faltan) { g.wraps[m.pub] = await holder.rewrapFor({ wrap: suya, encPub: m.encPub }); out.wrapped++ }
          } else if (typeof openRecovery === 'function') {
            const cek = await openRecovery(g.wraps[RECOVERY])
            for (const m of faltan) { g.wraps[m.pub] = await wrapForMember({ cek, memberEncPub: m.encPub }); out.wrapped++ }
          } else {
            // Ni envoltura propia en esta generación ni la frase: no hay con qué, y se dice.
            throw new SealedError('no-opener', 'this generation is not wrapped for the holder and no recovery was given')
          }
        }
        for (const p of sobran) { delete g.wraps[p]; out.dropped++ }
        out.generations++
      } catch (e) {
        out.failed.push({ gen: g.gen, error: e?.message || String(e) })
      }
    }
    if (out.wrapped || out.dropped) await this.#save(s)
    return out
  }

  /**
   * LA COPIA DE RECUPERACIÓN LLEGA DESPUÉS. Lo guardado antes de crearla solo lo abren los
   * aparatos del acta; esto le añade a cada generación la envoltura `#recovery`, con la
   * llave de un miembro que ya la abre (`holder`, como en `rewrapAll`). La llave no sale
   * de él: `rewrapFor` abre y vuelve a envolver sin devolverla.
   *
   * Lo que no se pudo envolver se devuelve en `failed`, no se calla.
   */
  async addRecovery ({ recoveryPub, holder } = {}) {
    if (!recoveryPub) throw new Error('addRecovery: missing recoveryPub')
    if (!holder?.pub || typeof holder.rewrapFor !== 'function') throw new Error('addRecovery: missing holder { pub, rewrapFor }')
    const s = await this.#state()
    const out = { wrapped: 0, failed: [] }
    for (const g of s.keyring) {
      if (g.wraps?.[RECOVERY]) continue
      const suya = g.wraps?.[holder.pub]
      if (!suya) { out.failed.push({ gen: g.gen, error: 'this generation is not wrapped for the holder' }); continue }
      try {
        g.wraps[RECOVERY] = await holder.rewrapFor({ wrap: suya, encPub: recoveryPub })
        out.wrapped++
      } catch (e) {
        out.failed.push({ gen: g.gen, error: e?.message || String(e) })
      }
    }
    if (out.wrapped) await this.#save(s)
    return out
  }

  /**
   * QUIÉN SE QUEDÓ SIN ENVOLTURA, para que la consola lo diga en vez de que un aparato se
   * encuentre con que no puede abrir nada (§2.5). No hace falta ninguna llave: se mira
   * quién debería estar en cada generación y quién está.
   */
  async incompleteMembers () {
    const s = await this.#state()
    const faltan = new Map()
    for (const kind of ['main', 'passkeys']) {
      const deben = (await this.recipients(kind)).filter((m) => m?.encPub).map((m) => m.pub)
      for (const g of s.keyring.filter((x) => (x.kind || 'main') === kind)) {
        for (const pub of deben) {
          if (!g.wraps?.[pub]) faltan.set(pub, (faltan.get(pub) || 0) + 1)
        }
      }
    }
    return [...faltan].map(([pub, generations]) => ({ pub, generations }))
  }

  /** Cuántas entradas y cuántas generaciones. Diagnóstico: no abre nada. */
  async stats () {
    const s = await this.#state()
    return { entries: s.entries.length, generations: s.keyring.length, sealed: !!s.profile }
  }
}

export default { SealedStore, SealedError, KEY, RECOVERY }
