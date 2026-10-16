/**
 * Sub-store de HILOS + APERTURAS del vault (Fase 3: store centralizado).
 *
 * Espeja el modelo de datos de `@dotrino/store` (store.dotrino.com):
 *   threads: { [threadKey]: Entry[] }   (Entry tiene `id` + `ts`, opaco para el store)
 *   opens:   { [appId]: { count, ts } } (contador de "recientes" del hub)
 * para que un dispositivo emparejado pueda guardar su contenido EN el vault del
 * usuario (su propio servidor) en vez de —o además de— el IndexedDB del navegador.
 *
 * File-backed (`threads.json`), síncrono y simple (sin cuota/IndexedDB). Es el
 * backend autoritativo; el navegador usa su IndexedDB como caché y sincroniza.
 * **Cifrado en reposo** con la clave ligada a la máquina (`atrest.js`): aquí
 * vive el contenido de las apps y el perfil del usuario, que es exactamente lo
 * que el ecosistema promete que no queda en claro en ningún disco.
 */
import * as core from '@dotrino/store/core'
import { resealStale } from '@dotrino/identity/content'
import { readJson, writeJson } from './disk.js'

// El MISMO tope que acepta la página del almacén. Era 1000: una app que guarda más en un
// hilo (los compradores de facturero, por ejemplo) perdía aquí lo más viejo sin decir nada,
// y el navegador lo volvía a subir en cada sincronización.
const MAX_PER_THREAD = core.MAX_PER_THREAD_LIMIT

// DATOS SENSIBLES (F4): topes para que un dispositivo con `vault:store` no pueda
// llenar el disco de la bóveda. Son generosos para el uso real (unas contraseñas,
// notas, un documento corto) y ridículos para un abuso.
// LO QUE SE VUELVE A CERRAR AL ROTAR NO SE BORRA: la versión anterior de cada sobre se
// guarda como respaldo AL MENOS UN AÑO (política del dueño, 2026-09-30). No se sirve por
// ningún método; solo está por si volver a cerrar sale mal.
export const RESEALED_KEEP_MS = 366 * 24 * 60 * 60 * 1000

const MAX_SECURE_ITEMS = 2000
const MAX_SECURE_BLOB = 64 * 1024   // por campo sellado (meta y valor)

export function openThreadStore (disk) {
  const file = 'threads.json'
  let data = readJson(disk, file, null)
  if (!data || typeof data !== 'object') data = { v: 1, threads: {}, opens: {} }
  if (!data.threads) data.threads = {}
  if (!data.opens) data.opens = {}
  if (!data.secure) data.secure = {}
  // Lápidas de lo borrado (`@dotrino/store/core`): sin ellas un borrado vuelve desde el
  // primer aparato que todavía tenga la entrada.
  if (!data.tombs) data.tombs = {}
  core.pruneTombs(data.tombs, Date.now())
  const save = () => writeJson(disk, file, data)
  save() // reescribe al abrir: cifra lo que venía en claro
  const budget = (n) => Math.min(Math.max(Number(n) || core.PAGE_BYTES, 1024), core.PAGE_BYTES)
  const needKeys = (keys) => {
    if (!Array.isArray(keys) || !keys.every((k) => typeof k === 'string')) throw new Error('keys must be a list of thread keys')
    return keys
  }
  const needMap = (value, what) => {
    if (value == null) return {}
    if (typeof value !== 'object' || Array.isArray(value)) throw new Error(`${what} must be an object`)
    return value
  }

  const methods = {
    appendMessage ({ threadKey, entry }) {
      core.writeEntry(data.threads, data.tombs, threadKey, entry, { max: MAX_PER_THREAD, now: Date.now(), newId: () => crypto.randomUUID() })
      save(); return entry
    },
    listThread ({ threadKey, limit, before }) {
      if (!core.validKey(threadKey) || !Object.hasOwn(data.threads, threadKey)) return []
      let arr = data.threads[threadKey]
      if (typeof before === 'number') arr = arr.filter((e) => (e.ts || 0) < before)
      if (typeof limit === 'number' && limit > 0) arr = arr.slice(-limit)
      return arr
    },
    listThreadKeys () { return Object.keys(data.threads) },
    getThreadSummaries () {
      const out = {}
      for (const [k, arr] of Object.entries(data.threads)) out[k] = { lastEntry: arr.length ? arr[arr.length - 1] : null, count: arr.length }
      return out
    },
    removeThread ({ threadKey }) {
      const removed = core.removeWholeThread(data.threads, data.tombs, threadKey, Date.now())
      if (removed) save()
      return { removed }
    },
    removeMessage ({ threadKey, id }) {
      const removed = core.removeEntry(data.threads, data.tombs, threadKey, id, Date.now())
      if (removed) save()
      return { removed }
    },
    recordOpen ({ appId }) {
      if (!appId || typeof appId !== 'string') throw new Error('appId required')
      const prev = data.opens[appId]
      data.opens[appId] = { count: (prev?.count || 0) + 1, ts: Date.now() }
      save(); return data.opens[appId]
    },
    getOpens () { return { ...data.opens } },
    clearOpens () { data.opens = {}; save(); return { ok: true } },
    /** Mezcla el contador de un aparato (el mayor de cada lado) y devuelve el resultado. */
    mergeOpens ({ opens }) {
      if (core.mergeOpens(data.opens, needMap(opens, 'opens'))) save()
      return { ...data.opens }
    },
    exportThreads () { return { threads: data.threads } },
    // ----- SINCRONIZAR POR PARTES (@dotrino/store ≥ 0.11) -----
    // `exportThreads`/`importThreads` a secas mueven TODO en un mensaje, y el proxio corta
    // los frames en 1 MB: con unos cientos de KB de datos la sincronización dejaba de caber.
    // Con esto el aparato pregunta qué hilos difieren (una huella por hilo), baja su índice
    // (id y ts) y pide solo las entradas que le faltan, todo por páginas con tope de bytes.
    // Las reglas —huella, mezcla, lápidas— son las de `@dotrino/store/core`, las mismas que
    // aplica el navegador: si cada lado llevara las suyas, las huellas no coincidirían nunca.
    getThreadDigests ({ keys } = {}) {
      return core.digestsOf(data.threads, keys == null ? undefined : needKeys(keys))
    },
    getThreadIndexes ({ keys, cursor, maxBytes }) {
      return core.indexPage(data.threads, data.tombs, needKeys(keys), cursor || null, budget(maxBytes))
    },
    getEntries ({ refs, maxBytes }) {
      return core.entriesPage(data.threads, needMap(refs, 'refs'), budget(maxBytes))
    },
    importThreads ({ threads, tombs, mode = 'merge' }) {
      if (!threads || typeof threads !== 'object') throw new Error('threads required')
      if (mode === 'replace') { data.threads = threads; save(); return { mode, count: Object.keys(threads).length } }
      if (mode !== 'merge' && mode !== 'upsert') throw new Error(`unknown import mode: ${mode}`)
      const now = Date.now()
      const buried = core.applyTombs(data.threads, data.tombs, needMap(tombs, 'tombs'), now)
      const merged = core.mergeEntries(data.threads, data.tombs, threads, { mode, max: MAX_PER_THREAD })
      core.pruneTombs(data.tombs, now)
      if (buried.tombsChanged || buried.changed.size || merged.size) save()
      return { mode, count: Object.keys(data.threads).length, changed: [...new Set([...buried.changed, ...merged])] }
    },
    // ----- PERFIL del usuario (me): el vault es la copia AUTORITATIVA -----
    // Cada dispositivo emparejado lo empuja al editarlo y lo jala al arrancar →
    // el mismo perfil (apodo/avatar/datos) en todos los dispositivos.
    profileSet ({ me }) {
      if (!me || typeof me !== 'object') throw new Error('me required')
      // nunca guardar llaves de dispositivo (son por-dispositivo)
      const { publickey, encryptionPubkey, ...content } = me
      data.profile = { ...content, updatedAt: content.updatedAt || Date.now() }
      save(); return { ok: true, updatedAt: data.profile.updatedAt }
    },
    profileGet () { return { me: data.profile || null } },

    // LOS DATOS DEL PERFIL EN SOBRES (`docs/datos-del-perfil.md`). Están aquí solo para
    // que el filtro de métodos los reconozca: los atiende `handleProfile` en `vault.js`,
    // antes de llegar a este store, porque su puerta es otra —`firma` y sin candado—.
    // Si alguna vez alguien los llamara por este camino, contestan que no en vez de
    // hacer algo a medias.
    profilePut () { throw new Error('profilePut is handled before the store: see handleProfile') },
    profileBundle () { throw new Error('profileBundle is handled before the store: see handleProfile') },
    profilePublic () { throw new Error('profilePublic is handled before the store: see handleProfile') },
    profileRecipients () { throw new Error('profileRecipients is handled before the store: see handleProfile') },

    // ----- DATOS SENSIBLES del usuario (F4, docs/consola-remota.md §6) -----
    //
    // Contraseñas, notas, documentos: van al contenido del perfil, cifrados con la
    // CEK de la cuenta y accesibles con `vault:store` — el mismo camino que hilos y
    // perfil. NO tocan `secrets.json`: ese es el cajón de los SERVICIOS (proxy, geo),
    // acotado por CN y con clave ligada a la máquina. Mismo nombre coloquial, distinto
    // dueño.
    //
    // La bóveda guarda DOS SOBRES OPACOS por ficha y no abre ninguno:
    //   `meta` — lo que hace falta para pintar la lista (nombre, tipo, carpeta)
    //   `enc`  — el valor en sí, que solo viaja cuando abres la ficha
    // Los sella el dispositivo con la clave de contenido (`identity.sealContent`). Que
    // sean dos y no uno es lo que permite listar sin bajar todas las contraseñas, y que
    // el nombre («Banco») tampoco quede legible aquí.
    //
    // Alcance: esto es el ALMACÉN. Una app de contraseñas con generador y
    // autocompletado es otra cosa y no vive aquí.
    'secure.list' () {
      return Object.values(data.secure)
        .map(({ enc, ...rest }) => rest)   // el valor NO viaja al listar
        .sort((a, b) => (b.updatedAt || 0) - (a.updatedAt || 0))
    },
    'secure.get' ({ id }) {
      if (!id || typeof id !== 'string') throw new Error('id required')
      return data.secure[id] || null
    },
    'secure.put' ({ id, meta, enc }) {
      if (typeof enc !== 'string' || !enc) throw new Error('enc required (sealed value)')
      if (meta != null && typeof meta !== 'string') throw new Error('meta must be a sealed string')
      // Se comprueba el TAMAÑO, nunca el contenido: son sobres cerrados.
      if (enc.length > MAX_SECURE_BLOB || (meta || '').length > MAX_SECURE_BLOB) throw new Error('secure: item too large')
      const prev = id ? data.secure[id] : null
      if (!prev && Object.keys(data.secure).length >= MAX_SECURE_ITEMS) throw new Error('secure: too many items')
      const rec = {
        id: prev?.id || id || crypto.randomUUID(),
        ts: prev?.ts || Date.now(),
        updatedAt: Date.now(),
        meta: meta ?? prev?.meta ?? null,
        enc
      }
      data.secure[rec.id] = rec
      save()
      return { id: rec.id, updatedAt: rec.updatedAt }
    },
    'secure.del' ({ id }) {
      if (!id || typeof id !== 'string') throw new Error('id required')
      const had = !!data.secure[id]
      delete data.secure[id]
      if (had) save()
      return { removed: had ? 1 : 0 }
    },

    getStats () {
      const threads = {}
      for (const [k, arr] of Object.entries(data.threads)) threads[k] = { count: arr.length }
      return { threadCount: Object.keys(data.threads).length, threads, opensCount: Object.keys(data.opens).length, secureCount: Object.keys(data.secure).length }
    }
  }
  /**
   * VUELVE A CERRAR CON LA LLAVE VIGENTE todo sobre de la cuenta (`t: 'dotrino-cek'`) de
   * una generación anterior que haya en lo guardado. Lo llama la BÓVEDA al abrirse y
   * después de quitar un aparato —que es cuando la llave rota—; NO está en `methods`, así
   * que ningún aparato puede dispararlo.
   *
   * Lo que sirve la bóveda va así siempre con la generación vigente: un aparato que entra
   * después, que solo recibe esa, abre todo; y la vieja deja de abrir nada porque ya no se
   * sirve nada cerrado con ella (dueño, 2026-09-30). Cada entrada que cambia estrena `ts`,
   * para que los aparatos la bajen en su siguiente sincronización.
   *
   * También MIGRA los sobres de la cuenta anteriores a la marca (`{ gen, iv, ct }` a secas,
   * identity < 0.107): si abren con la llave de la cuenta se vuelven a cerrar marcados; si no,
   * no eran de la cuenta y se cuentan en `skipped` sin tocarlos.
   *
   * La versión anterior NO se tira: queda en `resealed` con la fecha, por si algo sale mal
   * (lo pidió el dueño: «podría retenerlos… pero no los envía»), y se guarda AL MENOS un
   * año (`RESEALED_KEEP_MS`). No se sirve por ningún método.
   *
   * @param {{ gen: number, reseal: (env: object) => Promise<object> }} o
   * @returns {Promise<{ changed: number, entries: number, skipped: number }>}
   */
  async function resealStaleEnvelopes ({ gen, reseal }) {
    let changed = 0; let entries = 0; let skipped = 0
    const now = Date.now()
    if (!data.resealed) data.resealed = []
    // Solo sale lo que ya cumplió su año de respaldo.
    const antes = data.resealed.length
    data.resealed = data.resealed.filter((x) => now - (x.at || 0) < RESEALED_KEEP_MS)
    const podados = antes - data.resealed.length
    for (const [key, arr] of Object.entries(data.threads)) {
      for (let i = 0; i < arr.length; i++) {
        const r = await resealStale(arr[i], { gen, reseal })
        skipped += r.skipped || 0
        if (!r.changed) continue
        data.resealed.push({ threadKey: key, at: now, gen, before: arr[i] })
        arr[i] = { ...r.value, ts: Math.max(now, (arr[i].ts || 0) + 1) }
        changed += r.changed; entries++
      }
    }
    if (entries || podados) save()
    return { changed, entries, skipped }
  }

  return { methods, raw: () => data, resealStaleEnvelopes }
}

/**
 * Métodos del store que son de SOLO LECTURA (para decidir el scope necesario).
 *
 * `secure.list`/`secure.get` NO están aquí a propósito, aunque sean lecturas: los datos
 * sensibles piden `vault:store` (doc §6), que es MÁS estricto que `vault:read`. Un
 * dispositivo al que solo le diste «leer» no lee tus contraseñas.
 */
export const STORE_READ_METHODS = new Set([
  'listThread', 'listThreadKeys', 'getThreadSummaries', 'getOpens', 'exportThreads', 'getStats', 'profileGet',
  'getThreadDigests', 'getThreadIndexes', 'getEntries'
])

/**
 * Métodos que EDITAN el perfil del usuario (quién es: apodo, avatar, campos).
 * Son los únicos que el candado por contraseña bloquea (`vault.js`): el resto del
 * store —contenido de las apps— sigue disponible con el perfil bloqueado.
 */
export const PROFILE_EDIT_METHODS = new Set(['profileSet'])
