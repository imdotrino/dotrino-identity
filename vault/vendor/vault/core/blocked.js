/**
 * LOS APARATOS BLOQUEADOS: la lista que un aprobador decide y solo la bóveda deshace.
 *
 * Un agente (la terminal, por ahora) reporta un INCIDENTE cuando un aparato de la cuenta se
 * equivoca de clave tres veces seguidas. El aprobador lo ve en su teléfono y elige: bloquear
 * o ignorar. Bloquear NO es revocar: el aparato sigue en el acta —no hace falta la maestra, y
 * la bóveda vive cerrada—, pero la bóveda deja de atenderle y los agentes, que reciben esta
 * lista con el acta, le cierran la puerta. Se deshace aquí (`dotrino-vault unblock <ID>`) o
 * desde la consola de administración; un aprobador solo bloquea.
 *
 * Va en el disco cifrado en reposo como las contraseñas: es parte del mapa de la cuenta.
 * Se carga UNA vez: un archivo que existe y no se puede leer NO es «nadie bloqueado» — se
 * lanza, y la bóveda no arranca con una lista que no puede saber.
 */

export const BLOCKED_FILE = 'blocked.json'

const fail = (code, message) => Object.assign(new Error(message), { code })

/**
 * @param {{ disk: object, now?: () => number }} opts
 */
export function openBlocked ({ disk, now = Date.now }) {
  const file = BLOCKED_FILE
  const atRest = disk.atRest
  /** pub → { deviceId, label, since, by, reason } */
  let items = load()

  function load () {
    let raw
    try { raw = disk.read(file) } catch (e) {
      throw fail('blocked-unreadable', `cannot read ${BLOCKED_FILE}: ${e.message}`)
    }
    if (raw == null) return new Map()
    let d
    try { d = JSON.parse(atRest.decrypt(raw)) } catch (e) { throw fail('blocked-unreadable', `${BLOCKED_FILE} cannot be opened: ${e.message}`) }
    if (d?.v !== 1 || !d.items || typeof d.items !== 'object') throw fail('blocked-unreadable', `${BLOCKED_FILE} has an unknown shape`)
    return new Map(Object.entries(d.items))
  }

  function save () {
    disk.write(file, atRest.encrypt(JSON.stringify({ v: 1, items: Object.fromEntries(items) })))
  }

  const publicOf = (pub, b) => ({ pub, deviceId: b.deviceId || null, label: b.label || '', since: b.since, by: b.by || null, reason: b.reason || null })

  return {
    has: (pub) => items.has(pub),
    pubs: () => [...items.keys()],
    list: () => [...items].map(([pub, b]) => publicOf(pub, b)),
    /** Bloquea. Devuelve la entrada; si ya estaba, la que había (no se pisa el «desde cuándo»). */
    block ({ pub, deviceId = null, label = '', by = null, reason = null }) {
      if (typeof pub !== 'string' || !pub) throw fail('bad-pub', 'block: a device key is required')
      if (items.has(pub)) return publicOf(pub, items.get(pub))
      const b = { deviceId, label, since: now(), by, reason }
      items.set(pub, b)
      save()
      return publicOf(pub, b)
    },
    /** Desbloquea. `true` si estaba. */
    unblock (pub) {
      if (!items.has(pub)) return false
      items.delete(pub)
      save()
      return true
    }
  }
}
