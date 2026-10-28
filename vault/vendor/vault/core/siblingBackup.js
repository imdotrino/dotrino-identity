/**
 * EL RESPALDO DE LAS APPS SE COPIA ENTRE LAS BÓVEDAS DE LA CUENTA, solo (dueño, 2026-10-28:
 * «las bóvedas siempre se sincronizan automáticamente»). Antes cada navegador respaldaba en la
 * bóveda que le dio su papel y nada más: si el disco del PC se perdía, se perdía el respaldo.
 *
 * Mismo camino que los cajones: mensajes sellados a la hermana y CALLADOS, que no despiertan a
 * la Nube (cada despertar cuesta). Los recibe cuando despierta, y al arrancar anuncia lo suyo.
 *
 * Por partes, porque son hasta 25 MB y el proxio corta en 1 MB. Cuatro mensajes:
 *
 *   state    huella por hilo y suelos           → la otra, si difiere, manda su índice
 *   index    ids y ts de los hilos que difieren → la otra manda lo que le falta a esta y pide lo suyo
 *   want     ids que me faltan                  → la otra los manda
 *   entries  entradas, lápidas, dueños y suelos → se mezclan con las reglas de @dotrino/store/core
 *
 * Termina solo: cuando las huellas coinciden nadie manda nada. Y el tope es determinista, así
 * que dos bóvedas con lo mismo borran lo mismo y no se persiguen la cola.
 */
import * as core from '@dotrino/store/core'

const ANNOUNCE_DEBOUNCE_MS = 2 * 60_000

/** Qué mandar y qué pedir de un hilo, comparando mi índice con el de la otra. */
export function planSibling (mine, theirs) {
  const M = new Map((mine?.items || []).map(([id, ts]) => [String(id), ts]))
  const T = new Map((theirs?.items || []).map(([id, ts]) => [String(id), ts]))
  const send = []; const want = []
  for (const [id, ts] of M) { const t = T.get(id); if (t === undefined || ts > t) send.push(id) }
  for (const [id, ts] of T) { const m = M.get(id); if (m === undefined || ts > m) want.push(id) }
  return { send, want }
}

/**
 * @param {{
 *   threads: { methods: object, raw: () => object },
 *   siblings: () => Promise<string[]>,          // llaves de comunicación de las hermanas
 *   send: (to: string, body: object) => Promise<void>,
 *   onChange?: () => void,                       // lo mezclado cambió lo guardado
 *   log: (msg: string) => void
 * }} o
 */
export function createSiblingBackup ({ threads, siblings, send, onChange = () => {}, log }) {
  const partial = new Map()   // quién → { indexes } mientras llegan las páginas de su índice
  let timer = null

  async function announce (reason) {
    const to = await siblings()
    if (!to.length) return
    const { digests, floors } = await threads.methods.getBackupState()
    let n = 0
    for (const pub of to) {
      try { await send(pub, { op: 'state', digests, floors }); n++ }
      catch (e) { log(`[vault] could not send the app backup state to a sibling vault (${e.code || 'error'}): ${e.message}`) }
    }
    if (n) log(`[vault] sent the app backup state to ${n} sibling vault(s) on ${reason}`)
  }

  function schedule () {
    if (timer) return
    timer = setTimeout(() => { timer = null; announce('change').catch((e) => log('[vault] could not announce the app backup: ' + e.message)) }, ANNOUNCE_DEBOUNCE_MS)
    timer.unref?.()
  }

  async function sendIndex (to, keys) {
    const data = threads.raw()
    const { floors } = await threads.methods.getBackupState()
    let cursor = null
    do {
      const page = core.indexPage(data.threads, data.tombs, keys, cursor, core.PAGE_BYTES)
      cursor = page.next
      await send(to, { op: 'index', keys, indexes: page.indexes, floors, last: !cursor })
    } while (cursor)
  }

  async function sendEntries (to, refs, keys) {
    const data = threads.raw()
    const { floors } = await threads.methods.getBackupState()
    const tombs = core.pickTombs(data.tombs, refs, keys)
    let rest = refs
    let first = true
    while (rest || first) {
      const page = threads.methods.getEntries({ refs: rest || {}, maxBytes: core.PAGE_BYTES })
      await send(to, { op: 'entries', threads: page.threads, owners: page.owners, tombs: first ? tombs : {}, floors })
      rest = page.rest
      first = false
    }
  }

  async function merge (body) {
    const r = threads.methods.importThreads({ threads: body.threads || {}, tombs: body.tombs || {}, owners: body.owners || {}, floors: body.floors || {}, mode: 'merge' })
    if (r.changed.length) { onChange(); schedule() }
    return r
  }

  /** Un mensaje de una hermana ya comprobada (sellado, del acta, para mí). */
  async function handle (from, body) {
    if (body.op === 'state') {
      if (body.floors) await merge({ floors: body.floors })
      const mine = await threads.methods.getBackupState()
      const theirs = body.digests || {}
      const keys = [...new Set([...Object.keys(mine.digests), ...Object.keys(theirs)])]
        .filter((k) => mine.digests[k]?.digest !== theirs[k]?.digest)
      if (keys.length) await sendIndex(from, keys)
      return
    }
    if (body.op === 'index') {
      const acc = partial.get(from) || { indexes: {} }
      for (const [k, idx] of Object.entries(body.indexes || {})) {
        const a = acc.indexes[k] || (acc.indexes[k] = { items: [], tombs: [] })
        a.items.push(...(idx.items || [])); a.tombs.push(...(idx.tombs || []))
      }
      partial.set(from, acc)
      if (!body.last) return
      partial.delete(from)
      const keys = Array.isArray(body.keys) ? body.keys.filter(core.validKey) : []
      // Sus lápidas y sus suelos primero: lo borrado allí no se manda de vuelta.
      const tombs = Object.fromEntries(Object.entries(acc.indexes).map(([k, idx]) => [k, idx.tombs]))
      await merge({ tombs, floors: body.floors })
      const data = threads.raw()
      const mine = core.indexPage(data.threads, data.tombs, keys, null, Infinity).indexes
      const send_ = {}; const want = {}
      for (const k of keys) {
        const p = planSibling(mine[k], acc.indexes[k])
        if (p.send.length) send_[k] = p.send
        if (p.want.length) want[k] = p.want
      }
      if (Object.keys(send_).length) await sendEntries(from, send_, keys)
      if (Object.keys(want).length) await send(from, { op: 'want', refs: want })
      return
    }
    if (body.op === 'want') return sendEntries(from, body.refs || {}, Object.keys(body.refs || {}))
    if (body.op === 'entries') {
      const r = await merge(body)
      if (r.changed.length || r.evicted) log(`[vault] merged the app backup of a sibling vault: ${r.changed.length} thread(s) changed${r.evicted ? `, ${r.evicted} old entr${r.evicted === 1 ? 'y' : 'ies'} out by the 25 MB cap` : ''}`)
    }
  }

  return { announce, schedule, handle }
}
