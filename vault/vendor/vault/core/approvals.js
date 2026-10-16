/**
 * PEDIDOS DE APROBACIÓN Y CONCESIONES (puro: sin red ni disco).
 *
 * Un aparato marcado con `approval on` no recibe claves privadas solo por tener el cert: el
 * vault apunta el pedido, avisa a los aparatos con `approve` (el teléfono), y solo su firma
 * libera los secretos. Lo que nadie aprueba vence solo a los 5 min.
 *
 * Lo que se guarda de cada pedido es lo justo para contestar después: el cajón, quién pide,
 * su llave efímera `ek` (a la que se sella la respuesta) y **qué comando está corriendo y
 * desde dónde**. Nunca un valor.
 *
 * LA CONCESIÓN POR COMANDO (dueño, 2026-09-11). Antes no había ventana: cada petición era un
 * pedido, y para un servicio bien hecho eso era una por arranque. Dejó de alcanzar en cuanto
 * los pedidos empezaron a decir QUÉ comando piden: si el dueño ya dijo que sí a ese comando
 * exacto desde esa carpeta exacta, volver a timbrarle por lo mismo es ruido. Así que aprobar
 * concede **una hora, contada desde el último uso** — o sea que un servicio que sigue
 * pidiendo la mantiene viva indefinidamente, que es lo que se pidió. Lo que la corta: que
 * cambie el comando o la carpeta (otra huella, otro pedido), una hora entera sin usarla,
 * revocarla a mano, o reiniciar la bóveda (viven en memoria y no se escriben en ningún
 * sitio: un permiso que sobrevive a un reinicio es un permiso que nadie recuerda haber dado).
 *
 * SIN COMANDO NO HAY CONCESIÓN. Un pedido que no dice qué está corriendo —porque vino de
 * otra máquina por el proxio, donde mandarlo en claro filtraría las rutas del dueño— no
 * tiene huella con la que emparejarse, y entonces se pide aprobación cada vez. No se
 * inventa una huella «vacía» que valdría para todo: eso sería exactamente un repliegue.
 *
 * Y PARA EL GESTOR DE CONTRASEÑAS ESO ES LO QUE SE QUIERE, no una carencia que arreglar
 * (dueño, 2026-09-11: «para el gestor de contraseñas es perfecto»). La extensión es un
 * navegador hablando por el proxio, no un proceso con línea de comandos, así que nunca va a
 * traer huella — y así cada acceso a una credencial vuelve a pasar por tu mano, que es la
 * protección por la que esto existe. No se le busque un sustituto del comando para que
 * entre en la ventana.
 */
import { commandFingerprint } from '../procContext.js'

const rnd = () => [...crypto.getRandomValues(new Uint8Array(8))].map((b) => b.toString(16).padStart(2, '0')).join('')

/** Separador de la llave compuesta. Es un byte que no puede aparecer en un cajón ni en una pubkey. */
const SEP = String.fromCharCode(0)

/**
 * LO QUE DURA UN PEDIDO SIN CONTESTAR, y por qué son dos números y no uno.
 *
 * CINCO MINUTOS es lo correcto para un COMANDO: hay un proceso bloqueado esperando, y
 * aprobar media hora más tarde entregaría claves a algo cuyo contexto ya cambió — la
 * carpeta, el comando o la máquina pueden ser otros. Que caduque rápido es la protección.
 *
 * UNA ACTUALIZACIÓN no se parece en nada (dueño, 2026-09-20): no hay nadie esperando, y
 * caducar no protege de nada — solo significa que mañana se vuelve a pedir y se vuelve a
 * perder, porque mirar el teléfono puede tardar horas. Un pedido que nunca llega a tiempo
 * es una función que no existe.
 *
 * Por eso el plazo es DEL PEDIDO y no de la mesa. Quien pide dice cuánto aguanta lo suyo.
 */
export const PENDING_TTL_MS = 5 * 60 * 1000
/**
 * Y el de una actualización: un día. Cuadra con que la bóveda mire una vez al día — pedir
 * otra vez reemplaza el pedido anterior del mismo cajón y aparato, así que siempre hay
 * exactamente uno vivo, en vez de una cola de avisos caducados.
 */
export const UPDATE_TTL_MS = 24 * 60 * 60 * 1000
/** Lo que dura una concesión SIN USARSE. Cada uso la vuelve a poner en una hora. */
export const GRANT_TTL_MS = 60 * 60 * 1000

export function createApprovals ({ now = Date.now, pendingTtlMs = PENDING_TTL_MS } = {}) {
  /** id → { id, ns, device, deviceId, label, ek, ctx, ts, exp, from } */
  const pending = new Map()
  /**
   * EL CONTEXTO VA EN LA LISTA, Y QUIEN LA SACA POR LA RED LO ENVUELVE.
   *
   * `ctx` es el comando y el path del dueño: por el mostrador local y en la consola de su
   * propia máquina se enseña tal cual, pero al teléfono viaja por el proxio y ahí va dentro
   * de un sobre (`handleApproval`). Si mañana aparece otro sitio que publique esta lista,
   * esto es lo que hay que recordar.
   */
  // `kind` dice QUÉ se pide: `read` (llevarse las claves, lo de siempre) o `write` (guardar
  // variables). La pantalla del teléfono no puede decir «pide tus claves» a una escritura.
  const publicOf = (p) => ({ id: p.id, ns: p.ns, kind: p.kind, deviceId: p.deviceId, label: p.label, ts: p.ts, exp: p.exp, ctx: p.ctx || null })

  return {
    /** Apunta un pedido. Uno por cajón y aparato: pedir otra vez reemplaza al anterior. */
    /**
     * `from` es POR DÓNDE ENTRÓ la pregunta. La respuesta llega más tarde —cuando alguien
     * apruebe— y tiene que volver por el mismo sitio: desde que la bóveda atiende también
     * por un socket local, mandarla siempre por el proxio la dejaba en el vacío.
     */
    request ({ ns, device, deviceId, label = '', ek, ctx = null, from = null, ttlMs = null, kind = 'read' }) {
      // Pedir las claves otra vez reemplaza al pedido anterior: es la misma pregunta. Una
      // ESCRITURA no: cada una lleva su propio valor, y reemplazarla tiraría la anterior
      // sin que nadie dijera que no.
      if (kind !== 'write') for (const [id, p] of pending) if (p.kind !== 'write' && p.ns === ns && p.device === device) pending.delete(id)
      const ts = now()
      // `ttlMs` lo pone quien pide: una actualización aguanta un día y un comando cinco
      // minutos, y la mesa no tiene por qué saber cuál es cuál (ver `PENDING_TTL_MS`).
      const p = { id: rnd(), ns, kind, device, deviceId, label, ek, ctx, ts, exp: ts + (ttlMs || pendingTtlMs), from }
      pending.set(p.id, p)
      return publicOf(p)
    },
    /** Los pedidos vivos, sin la `ek` (no hace falta fuera de aquí). */
    list () { this.sweep(); return [...pending.values()].map(publicOf) },
    /** Saca un pedido para resolverlo (aprobar o denegar). `null` si no existe o venció. */
    take (id) {
      this.sweep()
      const p = pending.get(id)
      if (p) pending.delete(id)
      return p || null
    },
    /** Tira lo vencido; devuelve los pedidos que vencieron, para anotarlos. */
    sweep () {
      const t = now(); const gone = []
      for (const [id, p] of pending) if (p.exp <= t) { pending.delete(id); gone.push(publicOf(p)) }
      return gone
    }
  }
}

/**
 * LAS CONCESIONES VIVAS: «este comando, desde esta carpeta, ya está aprobado».
 *
 * La llave es cajón + aparato + huella del comando. Nada de esto se escribe en disco.
 */
export function createGrants ({ now = Date.now, ttlMs = GRANT_TTL_MS } = {}) {
  /** key → { id, ns, device, deviceId, fp, ctx, by, grantedAt, lastAt, exp, uses } */
  const grants = new Map()
  const keyOf = (ns, device, fp) => ns + SEP + device + SEP + fp
  const publicOf = (g) => ({
    id: g.id, ns: g.ns, deviceId: g.deviceId, fp: g.fp, ctx: g.ctx,
    by: g.by, grantedAt: g.grantedAt, lastAt: g.lastAt, exp: g.exp, uses: g.uses
  })

  const api = {
    /**
     * Anota que este comando quedó aprobado. Devuelve la concesión, o `null` si el pedido no
     * traía comando: sin huella no hay nada que recordar, y el próximo pedido volverá a
     * timbrar. Que eso se diga en el log es cosa de quien llama.
     */
    grant ({ ns, device, deviceId = null, ctx = null, by = null }) {
      const fp = commandFingerprint(ctx)
      if (!fp) return null
      const t = now()
      const g = { id: rnd(), ns, device, deviceId, fp, ctx, by, grantedAt: t, lastAt: t, exp: t + ttlMs, uses: 0 }
      grants.set(keyOf(ns, device, fp), g)
      return publicOf(g)
    },
    /**
     * ¿Está este comando ya aprobado? Si lo está, **la concesión se estira**: la hora cuenta
     * desde el último uso, no desde que se dio. Devuelve la concesión (ya refrescada) o `null`.
     */
    allows ({ ns, device, ctx }) {
      api.sweep()
      const fp = commandFingerprint(ctx)
      if (!fp) return null
      const g = grants.get(keyOf(ns, device, fp))
      if (!g) return null
      const t = now()
      g.lastAt = t
      g.exp = t + ttlMs
      g.uses += 1
      return publicOf(g)
    },
    /** Las concesiones vivas. */
    list () { api.sweep(); return [...grants.values()].map(publicOf) },
    /** Corta una por su id. `true` si existía. */
    revoke (id) {
      for (const [k, g] of grants) if (g.id === id) { grants.delete(k); return true }
      return false
    },
    /** Corta todas, o las de un cajón / un aparato. Devuelve cuántas se fueron. */
    revokeAll ({ ns = null, device = null } = {}) {
      let n = 0
      for (const [k, g] of grants) {
        if (ns && g.ns !== ns) continue
        if (device && g.device !== device) continue
        grants.delete(k); n++
      }
      return n
    },
    /** Tira lo vencido; devuelve lo que se fue, para anotarlo. */
    sweep () {
      const t = now(); const gone = []
      for (const [k, g] of grants) if (g.exp <= t) { grants.delete(k); gone.push(publicOf(g)) }
      return gone
    }
  }
  return api
}

/**
 * ¿SE LLEVÓ UNA LIMPIEZA AL ÚLTIMO QUE APROBABA? Devuelve los aprobadores que se fueron si
 * antes había alguno y ahora no queda ninguno; si no, una lista vacía.
 *
 * Una cuenta SIN aprobadores puede ser legítima (todo desatendido, se actualiza sola), así
 * que el aviso no es «no hay aprobadores»: es «LOS HABÍA y acabas de perder el último».
 *
 * @param {string[]} before  llaves con `approve` antes
 * @param {string[]} after   llaves con `approve` después
 * @param {string[]} removed llaves que salieron del acta
 */
export function lastApproverGone (before, after, removed) {
  if (!before.length || after.length) return []
  return removed.filter((pub) => before.includes(pub))
}

export default { createApprovals, createGrants, lastApproverGone, PENDING_TTL_MS, UPDATE_TTL_MS, GRANT_TTL_MS }
