/**
 * QUÉ APROBADORES PUEDEN RECIBIR UN AVISO: lo dice cada uno, y caduca.
 *
 * Un aparato con `approve` que no recibe avisos es un aprobador solo en el papel: el pedido
 * no le suena y solo lo ve si abre la app por su cuenta.
 *
 * Así que el aprobador lo declara: al pedir su lista de pedidos (`op: 'approvals'`, que ya
 * manda firmado cada vez que se abre) dice `notify: true` si tiene los avisos encendidos.
 * Aquí se apunta CUÁNDO lo dijo por última vez, y vale `NOTIFIABLE_TTL_MS`: una app que se
 * desinstala deja de renovarlo.
 *
 * NO DECIDE NADA: SE ENSEÑA (dueño, 2026-10-08). Un día decidió si la bóveda pedía permiso
 * para actualizarse —sin nadie que lo hubiera dicho, se actualizaba sola— y se quitó: era
 * una condición más, y el silencio de un aprobador abría la puerta. Quién aprueba lo dice
 * el acta y nada más; los avisos salen a todos los que tienen `approve`, lo hayan dicho o
 * no. Esto sirve para VER a cuál no le está sonando el pedido (`members`, `status`, la
 * consola).
 *
 * Y NO SE LE PREGUNTA AL PROXIO, que es quien guarda las suscripciones: es la pieza de la
 * que el diseño no se fía, y creerle sería dejarle decidir cuándo no hace falta permiso.
 *
 * Cifrado en reposo como lo demás. Un archivo que existe y no se puede leer NO es «nadie
 * puede recibir avisos»: se lanza.
 */

export const NOTIFIABLE_FILE = 'notifiable.json'
/** Cuánto vale un «puedo recibir avisos» sin renovarse. */
export const NOTIFIABLE_TTL_MS = 30 * 24 * 60 * 60 * 1000

const fail = (code, message) => Object.assign(new Error(message), { code })

/**
 * @param {{ disk: object, now?: () => number }} opts
 */
export function openNotifiable ({ disk, now = Date.now }) {
  const file = NOTIFIABLE_FILE
  const atRest = disk.atRest
  /** pub → ms de la última vez que dijo que sí */
  const items = load()

  function load () {
    let raw
    try { raw = disk.read(file) } catch (e) {
      throw fail('notifiable-unreadable', `cannot read ${NOTIFIABLE_FILE}: ${e.message}`)
    }
    if (raw == null) return new Map()
    let d
    try { d = JSON.parse(atRest.decrypt(raw)) } catch (e) { throw fail('notifiable-unreadable', `${NOTIFIABLE_FILE} cannot be opened: ${e.message}`) }
    if (d?.v !== 1 || !d.items || typeof d.items !== 'object') throw fail('notifiable-unreadable', `${NOTIFIABLE_FILE} has an unknown shape`)
    return new Map(Object.entries(d.items))
  }

  function save () {
    disk.write(file, atRest.encrypt(JSON.stringify({ v: 1, items: Object.fromEntries(items) })))
  }

  return {
    /**
     * Lo que acaba de decir un aprobador. `true` lo apunta (o lo renueva); `false` lo quita
     * ya, sin esperar a que caduque. Cualquier otra cosa no dice nada y no cambia nada: un
     * cliente viejo, que no manda el campo, no borra lo que dijo uno nuevo.
     */
    declare (pub, canNotify) {
      if (typeof pub !== 'string' || !pub) throw fail('bad-pub', 'declare: a device key is required')
      if (canNotify === true) { items.set(pub, now()); save() } else if (canNotify === false && items.delete(pub)) save()
    },
    /** Cuándo lo dijo por última vez, o `null` si nunca o si ya caducó. */
    since (pub) {
      const t = items.get(pub)
      return typeof t === 'number' && now() - t < NOTIFIABLE_TTL_MS ? t : null
    }
  }
}
