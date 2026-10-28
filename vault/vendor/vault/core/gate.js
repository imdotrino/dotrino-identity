/**
 * gate.js — LA PUERTA DE LA BÓVEDA: solo atiende al acta (dueño, 2026-10-22).
 *
 * Una bóveda solo acepta mensajes de llaves que están en su acta. Hay dos excepciones, y
 * ninguna más:
 *
 *   · **Entrar con contraseña** (`LOGIN_*`): quien entra todavía no es nadie. Pasa solo eso,
 *     con freno por conexión y freno global, antes de cualquier trabajo.
 *   · **El alta de un aparato** (`HELLO`, `ENROLL`, `ACTA_SEALED`): solo mientras hay un
 *     emparejamiento abierto y el mensaje es de ESE emparejamiento. Fuera de eso, nada.
 *   · **Los que salieron** (`CHECK`): un aparato de las actas de la ventana que ya no está pasa
 *     solo a preguntar si sigue dentro, con su firma y con freno. Se le contesta con su aviso
 *     de expulsión ya firmado (`exNotices.js`), para que se borre.
 *
 * Lo demás se descarta EN SILENCIO: sin respuesta, sin firma, sin línea en la bitácora y sin
 * tocar el disco. Antes un desconocido conseguía que la bóveda le contestara con el acta
 * entera, que la maestra le firmara cosas y que la bitácora rotara hasta perder lo viejo; todo
 * eso pasaba ANTES de mirar quién preguntaba. Lo descartado se cuenta en memoria (`stats`),
 * para que `status` lo pueda enseñar.
 *
 * La firma del miembro se comprueba aquí y otra vez en el manejador, que además mira el papel
 * y los permisos: esta puerta no autoriza nada, solo decide si se escucha.
 */
import { verifyDeviceSig } from '@dotrino/identity/capabilities'

/** Freno por conexión y global, en memoria. Ventana fija: simple y suficiente. */
export function makeLimiter ({ perKey = 10, global = 120, windowMs = 60_000, maxKeys = 10_000, now = Date.now } = {}) {
  let start = now()
  let total = 0
  let byKey = new Map()
  return {
    /** `true` si cabe; `false` si se pasó (de la conexión o del total). */
    take (key) {
      const t = now()
      if (t - start >= windowMs) { start = t; total = 0; byKey = new Map() }
      if (total >= global) return false
      const n = byKey.get(key) || 0
      if (n >= perKey) return false
      // Un desconocido que abre miles de conexiones no puede llenar la memoria: al tope, ya
      // no entra nadie nuevo hasta la siguiente ventana.
      if (!byKey.has(key) && byKey.size >= maxKeys) return false
      byKey.set(key, n + 1)
      total++
      return true
    },
    /** Cuánto falta para la siguiente ventana. */
    waitMs: () => Math.max(0, windowMs - (now() - start))
  }
}

/**
 * QUIÉN DICE SER el que manda cada mensaje, y con qué lo prueba. `null` si el tipo no es de los
 * que se atienden a un miembro. La llave tiene que estar en el acta y la firma ser suya.
 */
export function claimOf (MSG, p) {
  switch (p?.type) {
    case MSG.SIGN: case MSG.GET: case MSG.STORE: case MSG.CHECK: case MSG.DEVICES:
    case MSG.RENEW: case MSG.SECRETS: case MSG.ADMIN: case MSG.INCIDENT:
      return { pub: p.data?.publickey, data: p.data, signature: p.signature }
    case MSG.REWRAP_OK:
      return { pub: p.cert?.sub, data: p.data, signature: p.signature }
    case MSG.REPLICA_ACK:
      return { pub: p.body?.publickey, data: p.body, signature: p.signature }
    // Los cajones de una hermana, y el respaldo de las apps: los firma su llave de comunicación
    // (`body.by`), que es miembro.
    case MSG.SIBLING_DRAWERS: case MSG.SIBLING_BACKUP:
      return { pub: p.body?.by, data: p.body, signature: p.signature }
    // La renuncia la firma el propio miembro dentro del registro; la comprueba el manejador.
    case MSG.RENOUNCE: {
      const r = p.data?.record || p.record
      return { pub: r?.member, data: null, signature: null }
    }
    // El aviso de otra bóveda no va firmado: lo que se autentica es el acta, sellada. Aquí se
    // exige que la haya sellado un miembro de la nuestra; `adoptActa` comprueba el sello.
    case MSG.ADMIN_EVENT:
      return { pub: p.acta?.sealedBy, data: null, signature: null }
    default:
      return null
  }
}

/**
 * @param {object} o
 * @param {object} o.MSG            los tipos del protocolo
 * @param {() => Promise<object|null>} o.acta   el acta vigente de esta bóveda
 * @param {(type: string, p: object, from: string) => boolean} o.pairing  ¿es de un emparejamiento abierto?
 * @param {(pub: string) => boolean} [o.former]  ¿estuvo en el acta (y tiene su aviso)?
 * @param {ReturnType<typeof makeLimiter>} [o.limiter]
 */
export function createGate ({ MSG, acta, pairing, former = () => false, limiter = makeLimiter(), verify = verifyDeviceSig }) {
  const LOGIN = new Set([MSG.LOGIN_START, MSG.LOGIN_FINISH, MSG.LOGIN_CLOSE])
  const PAIRING = new Set([MSG.HELLO, MSG.ENROLL, MSG.ACTA_SEALED])
  const stats = { dropped: 0, throttled: 0, since: Date.now() }

  async function admit (from, p) {
    const type = p?.type
    if (LOGIN.has(type)) {
      if (limiter.take(String(from))) return { ok: true }
      stats.throttled++
      return { ok: false, throttled: true, waitMs: limiter.waitMs() }
    }
    if (PAIRING.has(type)) {
      if (pairing(type, p, from)) return { ok: true }
      stats.dropped++
      return { ok: false }
    }
    const claim = claimOf(MSG, p)
    if (!claim || typeof claim.pub !== 'string' || !claim.pub) { stats.dropped++; return { ok: false } }
    // NADA QUE DECIDIR SIN ACTA: se para (no hay a quién atender), no se deja pasar.
    const record = await acta()
    if (!record) { stats.dropped++; return { ok: false } }
    const member = (record.members || []).some((m) => m?.pub === claim.pub)
    // Un ex-miembro, solo a preguntar si sigue dentro, y con freno.
    const leaving = !member && type === MSG.CHECK && former(claim.pub)
    if (!member && !leaving) { stats.dropped++; return { ok: false } }
    if (leaving && !limiter.take('check:' + from)) { stats.throttled++; return { ok: false } }
    if (claim.signature !== null) {
      const ok = typeof claim.signature === 'string' && claim.data &&
        await verify({ publickey: claim.pub, data: claim.data, signature: claim.signature }).catch(() => false)
      if (!ok) { stats.dropped++; return { ok: false } }
    }
    return { ok: true, pub: claim.pub }
  }

  return { admit, stats: () => ({ ...stats }) }
}

export default { createGate, makeLimiter, claimOf }
