/**
 * enroll.js — núcleo del LADO BÓVEDA del emparejamiento endurecido.
 *
 * Fuente ÚNICA del flujo `vault.enroll` → `vault.enroll.challenge` → `vault.enrolled`
 * y de la revocación firmada. Lo consumen los tres sitios que hacen de bóveda:
 *   · el daemon del PC            (`dotrino-vault/src/vault.js`)
 *   · «este dispositivo es bóveda» (`lib/src/index.js#startDeviceVault`)
 *   · la copia vendorizada del iframe de identidad (`dotrino-identity/vault/vendor/vault/`)
 *
 * Módulo PURO: sin `node:*`, sin red, sin disco. Recibe la identidad (que firma), un
 * transporte (`send`/`sendByPubkey`) y callbacks de log/auditoría. Así el binario Node
 * lo embebe al compilar (SEA), el navegador lo importa y el iframe lo vendoriza sin
 * bundler.
 *
 * EL CÓDIGO DE APROBACIÓN, en detalle (esto es lo que hace seguro el emparejamiento):
 *   1. El DISPOSITIVO genera un código aleatorio de 6 dígitos, lo MUESTRA en su pantalla
 *      y manda solo su COMPROMISO `SHA-256(code‖dpub‖sn)` dentro del `data` firmado.
 *      El código en sí NUNCA viaja.
 *   2. La bóveda no conoce el código: lo aprende cuando un humano lo TIPEA al aprobar.
 *   3. Al aprobar, la bóveda RECOMPUTA el compromiso con el código tipeado y solo firma
 *      el cert si coincide → aprobar exige haber ido a leer el código del dispositivo.
 *   4. La bóveda ECHA el código junto al cert; el dispositivo lo acepta solo si es el
 *      suyo → una bóveda falsa (que nunca vio el código) no puede enrolarlo.
 *
 * Qué cierra y qué NO (sin exagerar): cierra que se emita un cert sin que quien aprueba
 * tenga el código del dispositivo — antes se firmaba igual y la defensa vivía solo en el
 * cliente honesto, así que un cliente malicioso se quedaba con un cert válido. NO cierra
 * el phishing en el que alguien le DICTA el código al dueño por otro canal: contra eso
 * está la copy de advertencia y que el dueño reconozca el `deviceId` (residual A1/A2 de
 * `docs/pairing-protocol.md`).
 */
import { verifyDeviceSig, pubkeyId, commitCode } from '@dotrino/identity/capabilities'

/** Un token de emparejamiento vale 5 min. */
export const PAIRING_TTL_MS = 5 * 60 * 1000
/** Ventana anti-replay del ENROLL (±5 min), mismo criterio que el identify del proxy. */
export const FRESH_WINDOW_MS = 5 * 60 * 1000
/** Vida por defecto del cert de un dispositivo (tope duro de `MAX_DELEGATION_MS`). */
export const DEVICE_TTL_MS = 30 * 24 * 60 * 60 * 1000

export const MSG_ENROLL = 'vault.enroll'
export const MSG_ENROLL_CHALLENGE = 'vault.enroll.challenge'
export const MSG_ENROLLED = 'vault.enrolled'
export const MSG_REVOKED = 'vault.revoked'
export const MSG_ERROR = 'vault.error'

/** Token aleatorio de 128 bits en hex. */
export function randToken () {
  const b = crypto.getRandomValues(new Uint8Array(16))
  return [...b].map((x) => x.toString(16).padStart(2, '0')).join('')
}

/** deviceId legible (p. ej. `C440-AC0E`) a partir de una pubkey JWK. */
export async function deviceIdOf (pub) {
  const id = (await pubkeyId(pub)).slice(0, 8).toUpperCase()
  return id.slice(0, 4) + '-' + id.slice(4, 8)
}

/**
 * Crea el «mostrador» de emparejamiento de una bóveda.
 *
 * @param {Object} opts
 * @param {Object} opts.identity        firma: `signData`, `signDelegation`, `listDelegations`, `revokeDelegation`.
 * @param {string} opts.iss             pubkey de la maestra de ESTA bóveda (va en el QR).
 * @param {string} opts.proxy           URL del proxy (va en el QR).
 * @param {(to:string, obj:object)=>void} opts.send            responder por el token de la conexión.
 * @param {(pub:string, obj:object)=>void} opts.sendByPubkey   dirigir por pubkey (cola offline 24 h).
 * @param {(op:string, info?:object)=>void} [opts.audit]
 * @param {(...a:any[])=>void} [opts.log]
 * @param {(c:{deviceId:string, scope:any, label:string})=>void} [opts.onChallenge]  un dispositivo espera aprobación.
 * @param {()=>void} [opts.onPendingChange]
 * @param {string[]} [opts.defaultScope]
 * @param {number} [opts.defaultTtlMs]
 */
export function createEnrollDesk ({
  identity, iss, proxy, send, sendByPubkey,
  audit = () => {}, log = () => {},
  onChallenge = () => {}, onPendingChange = () => {},
  defaultScope = ['vault:sign'], defaultTtlMs = DEVICE_TTL_MS
} = {}) {
  if (!identity) throw new Error('createEnrollDesk: falta identity')
  if (!iss) throw new Error('createEnrollDesk: falta iss (pubkey de la maestra)')

  // token -> { token, exp, scope, ttlMs, label, sn, state, dpub?, deviceId?, commit?, from? }
  // state: 'AWAITING_ENROLL' -> 'PENDING_CONFIRM'
  const pending = new Map()

  const fire = (fn, arg) => { try { fn(arg) } catch (_) {} }
  const reply = (to, obj) => { try { send(to, obj) } catch (e) { log('[vault] no se pudo responder:', e.message) } }
  const isFresh = (d) => typeof d?.ts === 'number' && Math.abs(Date.now() - d.ts) <= FRESH_WINDOW_MS

  /** Inicia un emparejamiento: token + nonce de sesión. NO firma nada todavía. */
  function startPairing ({ scope = defaultScope, ttlMs = defaultTtlMs, label = '' } = {}) {
    pending.clear() // uno a la vez: una sesión nueva supersede a la anterior
    const token = randToken()
    const sn = randToken()
    pending.set(token, { token, exp: Date.now() + PAIRING_TTL_MS, scope, ttlMs, label, sn, state: 'AWAITING_ENROLL' })
    return { token, qr: { v: 2, iss, proxy, token, sn }, expiresInMs: PAIRING_TTL_MS }
  }

  function stopPairing (token) { pending.delete(token) }

  function listPending () {
    return [...pending.values()]
      .filter((p) => p.state === 'PENDING_CONFIRM')
      .map((p) => ({ deviceId: p.deviceId, label: p.label || '', scope: p.scope }))
  }

  function findPending (deviceId) {
    for (const p of pending.values()) {
      if (p.state === 'PENDING_CONFIRM' && p.deviceId === deviceId) return p
    }
    return null
  }

  /**
   * ENROLL: el dispositivo prueba posesión de `D` firmando el sobre y deja el
   * COMPROMISO de su código. Todavía NO se firma ningún cert.
   */
  async function handleEnroll (from, p) {
    const d = p?.data
    if (!d || typeof d.dpub !== 'string' || typeof p.signature !== 'string') {
      return reply(from, { type: MSG_ERROR, error: 'enroll inválido' })
    }
    const pend = pending.get(d.token)
    if (!pend || pend.state === 'DONE' || Date.now() > pend.exp) {
      return reply(from, { type: MSG_ERROR, error: 'token de emparejamiento inválido o expirado' })
    }
    if (d.sn !== pend.sn) return reply(from, { type: MSG_ERROR, error: 'sesión inválida' })
    if (!isFresh(d)) {
      audit('rejected', { what: 'enroll', reason: 'stale' })
      return reply(from, { type: MSG_ERROR, error: 'petición vencida: ts fuera de la ventana ±5 min (posible replay, o el reloj del dispositivo está desfasado)' })
    }
    // PRUEBA DE POSESIÓN: la firma de `data` debe verificar contra `dpub`.
    if (!(await verifyDeviceSig({ publickey: d.dpub, data: d, signature: p.signature }))) {
      audit('rejected', { what: 'enroll', reason: 'bad-device-signature' })
      return reply(from, { type: MSG_ERROR, error: 'firma de dispositivo inválida' })
    }
    // El COMPROMISO del código es obligatorio: sin él no se puede comprobar al aprobar
    // y volveríamos a emitir certs a ciegas. Un cliente viejo cae acá con un mensaje claro.
    if (typeof d.commit !== 'string' || !/^[0-9a-f]{64}$/.test(d.commit)) {
      audit('rejected', { what: 'enroll', reason: 'no-commit' })
      return reply(from, { type: MSG_ERROR, error: 'este dispositivo usa una versión antigua del emparejamiento (no envía el compromiso del código). Actualízalo y vuelve a intentarlo.' })
    }
    // Un solo dispositivo a la vez esperando su código (así aprobar no es ambiguo).
    if (pend.state === 'PENDING_CONFIRM' && pend.dpub && pend.dpub !== d.dpub) {
      return reply(from, { type: MSG_ERROR, error: 'ya hay un dispositivo usando este emparejamiento' })
    }

    const deviceId = await deviceIdOf(d.dpub)
    pend.state = 'PENDING_CONFIRM'
    pend.dpub = d.dpub
    pend.deviceId = deviceId
    pend.commit = d.commit
    pend.from = from // la bóveda NO conoce el código: lo aprende cuando lo tipeas
    if (d.label) pend.label = String(d.label).slice(0, 60)

    reply(from, { type: MSG_ENROLL_CHALLENGE, deviceId })
    fire(onChallenge, { deviceId, scope: pend.scope, label: pend.label || '' })
    fire(onPendingChange)
    return { deviceId }
  }

  /**
   * Aprueba TIPEANDO el código que muestra el dispositivo. Recompone el compromiso
   * `SHA-256(code‖dpub‖sn)` y solo firma el cert si coincide con el que llegó en el
   * ENROLL — es decir, solo si de verdad fuiste a leer el código del dispositivo.
   *
   * @param {string} code
   * @param {{deviceId?: string}} [opts]  cuál aprobar cuando hay varios pendientes.
   */
  async function approve (code, { deviceId } = {}) {
    code = String(code || '').trim()
    if (!code) throw new Error('falta el código (los dígitos que muestra el dispositivo)')

    let pend
    if (deviceId) {
      pend = findPending(deviceId)
      if (!pend) throw new Error('no hay ninguna máquina esperando aprobación con ese identificador')
    } else {
      const waiting = [...pending.values()].filter((p) => p.state === 'PENDING_CONFIRM' && p.dpub)
      if (waiting.length === 0) throw new Error('no hay ningún dispositivo esperando aprobación')
      if (waiting.length > 1) throw new Error('hay más de un emparejamiento en curso; reinícialo con dotrino-vault pair')
      pend = waiting[0]
    }

    // COMPROBACIÓN DEL CÓDIGO — antes de firmar nada.
    const expected = await commitCode({ code, dpub: pend.dpub, sn: pend.sn })
    if (expected !== pend.commit) {
      audit('rejected', { what: 'approve', device: pend.deviceId, reason: 'bad-code' })
      log('[vault] código incorrecto para %s: no se emitió ningún certificado', pend.deviceId)
      throw new Error('el código no coincide con el que muestra el dispositivo: no se emitió ningún certificado. Vuelve a mirarlo y prueba otra vez.')
    }

    const { cert } = await identity.signDelegation(pend.dpub, pend.scope, { ttlMs: pend.ttlMs, label: pend.label })
    audit('enroll', { device: pend.deviceId, label: pend.label || '', scope: pend.scope })
    // Echamos el código tipeado junto al cert: el DISPOSITIVO acepta solo si coincide
    // con el que generó → una bóveda falsa (que no lo conoce) no puede enrolarlo.
    reply(pend.from, { type: MSG_ENROLLED, code, cert, iss })
    pend.state = 'DONE'
    pending.delete(pend.token)
    fire(onPendingChange)
    log('[vault] dispositivo aprobado: %s', pend.deviceId)
    return { ok: true, deviceId: pend.deviceId, cert }
  }

  /** Rechaza un enrolamiento pendiente. */
  function reject (deviceId) {
    const pend = deviceId
      ? findPending(deviceId)
      : [...pending.values()].find((p) => p.state === 'PENDING_CONFIRM')
    if (!pend) return { ok: false }
    reply(pend.from, { type: MSG_ERROR, error: 'emparejamiento rechazado' })
    pending.delete(pend.token)
    audit('reject', { device: pend.deviceId })
    fire(onPendingChange)
    log('[vault] dispositivo rechazado: %s', pend.deviceId)
    return { ok: true, deviceId: pend.deviceId }
  }

  /**
   * Emite un REVOKED FIRMADO por la maestra para que el dispositivo se autoborre. El
   * borrado remoto SOLO se dispara con esta firma (nunca con un error cualquiera →
   * cierra el wipe-DoS). Va por `sendByPubkey`: si está apagado, el proxy lo encola 24 h.
   */
  async function emitRevoke (dpub, nonce) {
    const body = { op: 'revoke', sub: dpub, nonce, iat: Date.now(), exp: Date.now() + DEVICE_TTL_MS }
    const { signature } = await identity.signData(body)
    try { sendByPubkey(dpub, { type: MSG_REVOKED, body, signature }) }
    catch (e) { log('[vault] no se pudo emitir revoke:', e.message) }
  }

  /** Revoca una delegación por `nonce` y avisa al dispositivo para que se autoborre. */
  async function revoke (nonce) {
    audit('revoke', { nonce })
    const { issued } = await identity.listDelegations()
    const dele = (issued || []).find((d) => d.nonce === nonce)
    const res = await identity.revokeDelegation(nonce)
    if (dele?.sub) await emitRevoke(dele.sub, nonce)
    return res
  }

  return {
    startPairing, stopPairing, handleEnroll, approve, reject,
    listPending, findPending, emitRevoke, revoke,
    get pendingCount () { return pending.size }
  }
}

export default { createEnrollDesk, deviceIdOf, randToken }
