/**
 * DÓNDE CORRE CADA APARATO, según lo último que dijo (`@dotrino/identity/machine`).
 *
 * El acta guarda lo que el aparato dijo AL EMPAREJARSE, y eso no cambia sin una firma de la
 * maestra. Aquí va lo que dice en cada pedido firmado: así un aparato que entró antes de que
 * existiera el campo aparece con su máquina en cuanto se actualiza y habla, y uno que cambió
 * de sistema sale al día. La lista enseña esto primero y, si no hay, lo del acta.
 *
 * NO DECIDE NADA: se enseña. Lo dice el propio aparato, dentro de lo que firma; nadie más lo
 * puede escribir por él, pero tampoco prueba nada.
 *
 * Cifrado en reposo como lo demás. Un archivo que existe y no se puede leer se lanza.
 */
import { cleanMachine, sameMachine } from '@dotrino/identity/machine'

export const MACHINES_FILE = 'machines.json'

const fail = (code, message) => Object.assign(new Error(message), { code })

/**
 * @param {{ disk: object, now?: () => number }} opts
 */
export function openMachines ({ disk, now = Date.now }) {
  const file = MACHINES_FILE
  const atRest = disk.atRest
  /** pub → { kind, os, name, at } */
  const items = load()

  function load () {
    let raw
    try { raw = disk.read(file) } catch (e) {
      throw fail('machines-unreadable', `cannot read ${MACHINES_FILE}: ${e.message}`)
    }
    if (raw == null) return new Map()
    let d
    try { d = JSON.parse(atRest.decrypt(raw)) } catch (e) { throw fail('machines-unreadable', `${MACHINES_FILE} cannot be opened: ${e.message}`) }
    if (d?.v !== 1 || !d.items || typeof d.items !== 'object') throw fail('machines-unreadable', `${MACHINES_FILE} has an unknown shape`)
    return new Map(Object.entries(d.items))
  }

  function save () {
    disk.write(file, atRest.encrypt(JSON.stringify({ v: 1, items: Object.fromEntries(items) })))
  }

  return {
    /**
     * Lo que acaba de decir un aparato. Solo se escribe si cambió: casi todos los pedidos
     * repiten lo de siempre, y reescribir el archivo en cada uno sería disco para nada.
     * Lo que no tiene forma de máquina no borra lo que ya había.
     */
    note (pub, raw) {
      if (typeof pub !== 'string' || !pub) throw fail('bad-pub', 'note: a device key is required')
      const m = cleanMachine(raw)
      if (!m) return false
      if (sameMachine(items.get(pub), m)) return false
      items.set(pub, { ...m, at: now() })
      save()
      return true
    },
    /** Lo último que dijo, o `null` si nunca dijo nada. */
    of (pub) {
      const m = items.get(pub)
      return m ? { ...m } : null
    }
  }
}
