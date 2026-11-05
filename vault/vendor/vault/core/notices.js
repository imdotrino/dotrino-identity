/**
 * LO QUE LA BÓVEDA TIENE QUE CONTARLE A QUIEN APRUEBA, y que no es un pedido.
 *
 * Lo que se cuenta: «me actualicé», «hay versión nueva y necesita permisos de administrador»,
 * un incidente de emparejamiento, el ancla de la bitácora, lo entregado sin aprobación y los
 * pedidos que se cerraron (`answered`). Los dos primeros, de la bóveda o de uno de sus aparatos: «me actualicé» y «hay versión nueva y
 * necesita permisos de administrador: instálala a mano» (`update-needs-root`). (`ev: 'updated'`, dueño 2026-10-08: «las actualizaciones, que se
 * envíe una notificación de que ocurrieron a los aprobadores»). Sale como aviso por el
 * proxio, pero el timbre de una app nativa llega VACÍO —lo leen Google y Apple—, así que la
 * app pregunta por su lista (`op: 'approvals'`) y lo lee de aquí, en `notices`.
 *
 * Caduca a las 24 h: es una noticia, no un registro (eso es la bitácora).
 *
 * Cifrado en reposo como lo demás. Un archivo que existe y no se puede leer se LANZA: callar
 * sería decir «no pasó nada» de algo que sí pasó.
 */

export const NOTICES_FILE = 'notices.json'
/** Cuánto se sigue contando un aviso. */
export const NOTICE_TTL_MS = 24 * 60 * 60 * 1000
/**
 * Los avisos que existen. El tercero, `pairing-contested`, es un INCIDENTE: dos aparatos
 * respondieron a la misma invitación de emparejar y la sesión se canceló
 * (`docs/pairing-protocol.md` §1.7). No pide nada: no hay a quién bloquear, porque ninguno
 * entró. Lo cuenta, con el ID y la máquina de los dos.
 */
export const NOTICE_EVS = ['updated', 'update-needs-root', 'pairing-contested', 'log-anchor', 'delivered', 'answered']
/**
 * `answered`: un pedido que se cerró —aprobado, denegado, bloqueado, ignorado, retirado o
 * caducado—, con quién lo contestó (`by`, el ID del aparato) si fue alguien (dueño, 2026-11-05:
 * «las notificaciones llegan pero al abrirlas en la app no hay restos de nada; el vault debe
 * mostrarme en la pantalla de aprobaciones el movimiento de las últimas 24 horas»). Un pedido
 * contestado salía de la lista y no quedaba nada que enseñar junto al aviso que ya había sonado.
 */
export const ANSWER_OUTCOMES = ['approved', 'denied', 'blocked', 'ignored', 'withdrawn', 'expired']
/**
 * `delivered`: un aparato con `unattended` se llevó claves de un cajón (`kind: 'secrets'`) o
 * una contraseña (`kind: 'passwords'`) sin que nadie aprobara, porque no le hacía falta (dueño,
 * 2026-11-04: «equipos unattended no deben pedir aprobación, quizás sí notificar que han
 * entregado contraseñas»). No pide nada: lo cuenta. Lleva `ns`, `deviceId` y `label`.
 */
const DELIVERED_KINDS = ['secrets', 'passwords']

const newId = () => [...crypto.getRandomValues(new Uint8Array(8))].map((b) => b.toString(16).padStart(2, '0')).join('')

const fail = (code, message) => Object.assign(new Error(message), { code })

/**
 * @param {{ disk: object, now?: () => number }} opts
 */
export function openNotices ({ disk, now = Date.now }) {
  const file = NOTICES_FILE
  const atRest = disk.atRest
  let items = load()

  function load () {
    if (!disk.exists(file)) return []
    try {
      const d = JSON.parse(atRest.decrypt(disk.read(file)))
      if (!d || !Array.isArray(d.items)) throw new Error('not a list')
      return d.items.filter((n) => n && typeof n.id === 'string' && typeof n.ts === 'number')
    } catch (e) { throw fail('notices-unreadable', `${NOTICES_FILE} cannot be read: ${e.message}`) }
  }

  function save () {
    disk.write(file, atRest.encrypt(JSON.stringify({ v: 1, items })))
  }

  const alive = (n) => now() - n.ts < NOTICE_TTL_MS

  return {
    /**
     * Apunta un aviso y lo devuelve tal como viaja. `ev`: `updated` (se actualizó) o
     * `update-needs-root` (hay versión nueva y hay que instalarla a mano, con permisos de
     * administrador). `product`: qué (`@dotrino/vaultd` es la propia bóveda);
     * `deviceId`/`label`: el aparato, si fue uno.
     */
    add (ev, { version, from = null, product = '@dotrino/vaultd', deviceId = null, label = null, devices = null, logSeq = null, head = null, tsa = null, ns = null, kind = null, outcome = null, by = null, byLabel = null, request = null }) {
      if (!NOTICE_EVS.includes(ev)) throw fail('bad-notice', `unknown notice: ${ev}`)
      if (ev === 'delivered') {
        if (!DELIVERED_KINDS.includes(kind)) throw fail('bad-notice', `${ev}: kind must be one of ${DELIVERED_KINDS.join(', ')}`)
        if (typeof ns !== 'string' || !ns) throw fail('bad-notice', `${ev}: the drawer (ns) is required`)
        if (typeof deviceId !== 'string' || !deviceId) throw fail('bad-notice', `${ev}: the device is required`)
        const n = { id: newId(), ev, kind, ns, deviceId, label: typeof label === 'string' ? label : '', ts: now() }
        items = [...items.filter(alive), n]
        save()
        return n
      }
      // EL ANCLA DE LA BITÁCORA (`logAnchor.js`): la cabeza sellada por el signer, para que el
      // aprobador la guarde. Solo se queda la última: la anterior ya no dice nada que esta no diga.
      if (ev === 'log-anchor') {
        if (typeof logSeq !== 'number' || typeof head !== 'string' || !tsa || typeof tsa.signature !== 'string') {
          throw fail('bad-notice', `${ev}: logSeq, head and the signer receipt are required`)
        }
        const n = { id: newId(), ev, logSeq, head, tsa, ts: now() }
        items = [...items.filter(alive).filter((x) => x.ev !== 'log-anchor'), n]
        save()
        return n
      }
      if (ev === 'answered') {
        if (!ANSWER_OUTCOMES.includes(outcome)) throw fail('bad-notice', `${ev}: outcome must be one of ${ANSWER_OUTCOMES.join(', ')}`)
        if (typeof kind !== 'string' || !kind) throw fail('bad-notice', `${ev}: the kind of request is required`)
        const n = {
          id: newId(), ev, outcome, kind,
          ns: typeof ns === 'string' ? ns : null,
          deviceId: typeof deviceId === 'string' ? deviceId : null,
          label: typeof label === 'string' ? label : '',
          by: typeof by === 'string' && by ? by : null,
          byLabel: typeof byLabel === 'string' ? byLabel : '',
          request: typeof request === 'string' ? request : null,
          ts: now()
        }
        items = [...items.filter(alive), n]
        save()
        return n
      }
      if (ev === 'pairing-contested') {
        if (!Array.isArray(devices) || devices.length < 2) throw fail('bad-notice', `${ev}: the devices that answered are required`)
        const n = {
          id: newId(), ev,
          devices: devices.slice(0, 8).map((d) => ({ deviceId: String(d?.deviceId || ''), machine: d?.machine || null })),
          ts: now()
        }
        items = [...items.filter(alive), n]
        save()
        return n
      }
      if (typeof version !== 'string' || !version) throw fail('bad-notice', `${ev}: a version is required`)
      if (typeof product !== 'string' || !product) throw fail('bad-notice', `${ev}: a product is required`)
      const n = {
        id: newId(), ev, product, version, from: typeof from === 'string' ? from : null,
        ...(typeof deviceId === 'string' && deviceId ? { deviceId, label: typeof label === 'string' ? label : '' } : {}),
        ts: now()
      }
      items = [...items.filter(alive), n]
      save()
      return n
    },
    updated (o) { return this.add('updated', o) },
    /** Los avisos vivos, del más viejo al más nuevo. */
    list () { return items.filter(alive).map((n) => ({ ...n })) }
  }
}
