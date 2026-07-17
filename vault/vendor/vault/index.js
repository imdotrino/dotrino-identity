/**
 * @dotrino/vault — "este dispositivo es una bóveda" (lado SERVIDOR, browser+node).
 *
 * Convierte la identidad de ESTE dispositivo (`@dotrino/identity`, la clave P) en una
 * bóveda/CA: atiende el MISMO protocolo de enrolamiento endurecido que el daemon
 * `dotrino-vault` (`vault.enroll` → `vault.enroll.challenge` → `vault.enrolled`) por el
 * proxy del ecosistema, firma certificados de delegación `D ← P` al aprobar, y responde
 * consultas de revocación (`vault.devices`). Así CUALQUIER app (no solo la terminal)
 * puede dejar que el usuario use su dispositivo como bóveda, sin un PC con el daemon.
 *
 * Modelo de aprobación SEGURO (idéntico al daemon `dotrino-vault#approveDevice`):
 *   - El DISPOSITIVO que se enrola (p. ej. `@dotrino/identity#enrollDevice`) genera un
 *     código ALEATORIO (`makePairingCode`) y lo MUESTRA; NO lo envía por la red.
 *   - Esta bóveda NO conoce el código: un humano lo LEE del dispositivo y lo TIPEA aquí.
 *   - Al aprobar, la bóveda firma el cert y ECHA el código tipeado de vuelta.
 *   - El dispositivo acepta el cert SOLO si el código echado coincide con el que generó.
 *     → una bóveda falsa (que nunca vio el código) no puede enrolar el dispositivo, y
 *     aprobar "a ciegas" (sin ir a leer el código del dispositivo) tampoco enrola nada.
 *
 * Cripto 100% de `@dotrino/identity/capabilities` (verifyDeviceSig/verifyChain/pubkeyId)
 * + firma con la identidad P (`identity.signDelegation`). Transporte: `@dotrino/proxy-client`
 * (import perezoso). No reimplementa nada del ecosistema.
 */
import { verifyDeviceSig, verifyChain, pubkeyId } from '@dotrino/identity/capabilities'

const SIGN_SCOPE = 'vault:sign'
const PAIRING_TTL_MS = 5 * 60 * 1000           // un emparejamiento (token) vale 5 min
const DEVICE_TTL_MS = 30 * 24 * 60 * 60 * 1000 // vida de un cert de dispositivo (30 días)
const SELFCERT_TTL_MS = 24 * 60 * 60 * 1000    // el self-cert P←P se regenera cada 24 h
const FRESH_WINDOW_MS = 5 * 60 * 1000          // ventana anti-replay del enroll (±5 min)

const MSG = {
  ENROLL: 'vault.enroll',
  ENROLL_CHALLENGE: 'vault.enroll.challenge',
  ENROLLED: 'vault.enrolled',
  DEVICES: 'vault.devices',
  DEVICES_RESULT: 'vault.devices.result',
  REVOKED: 'vault.revoked',
  ERROR: 'vault.error'
}

function randToken () {
  const b = crypto.getRandomValues(new Uint8Array(16))
  return [...b].map((x) => x.toString(16).padStart(2, '0')).join('')
}

/** deviceId legible (p. ej. `C440-AC0E`) desde una pubkey JWK. */
export function deviceIdOf (pub) {
  return pubkeyId(pub).then((id) => id.slice(0, 8).toUpperCase().replace(/(.{4})(.{4})/, '$1-$2'))
}

/**
 * Levanta la bóveda de este dispositivo: se conecta al proxy identificado como P y
 * atiende enrolamientos + consultas de revocación de los dispositivos que se enrolan.
 *
 * @param {object} identity  instancia de `@dotrino/identity` (P): expone
 *   `me.publickey`, `signData`, `signDelegation`, `listDelegations`, `revokeDelegation`.
 * @param {object} [opts]
 * @param {string} [opts.proxyUrl='wss://proxy.dotrino.com']
 * @returns {Promise<object>} handle: { iss, proxy, client, startPairing, approve, reject,
 *   listPending, listMachines, revoke, getSelfCert, onPendingChange, close }
 */
export async function startDeviceVault (identity, { proxyUrl } = {}) {
  const iss = identity.me?.publickey
  if (!iss) throw new Error('sin identidad: crea/desbloquea tu identidad antes de usar el dispositivo como bóveda')
  const proxy = proxyUrl || 'wss://proxy.dotrino.com'

  // ----- self-cert P ← P (para que este dispositivo pueda además actuar de cliente
  // de sus propias máquinas: lo firma la propia P y verifyChain lo acepta) -----
  let _selfCert = null
  const getSelfCert = async () => {
    if (_selfCert && _selfCert.exp > Date.now() + 60_000) return _selfCert
    const { cert } = await identity.signDelegation(iss, SIGN_SCOPE, { ttlMs: SELFCERT_TTL_MS })
    _selfCert = cert
    return cert
  }

  const { WebSocketProxyClient } = await import('@dotrino/proxy-client')
  const client = new WebSocketProxyClient({
    url: proxy, enableWebRTC: false, autoReconnect: true,
    maxReconnectAttempts: 100000, reconnectDelay: 4000
  })
  await client.connect()

  const selfCert = await getSelfCert()
  const identify = async () => {
    if (!client.token) return
    const data = { op: 'identify', publickey: iss, token: client.token, ts: Date.now() }
    const { signature } = await identity.signData(data)
    await client.identify({ data, signature, cert: selfCert })
  }
  await identify()
  client.on('token', () => identify().catch(() => {}))

  const send = (to, obj) => { try { client.send(to, obj) } catch (_) {} }

  // token -> { exp, sn, scope, ttlMs, label, state, dpub?, deviceId?, from? }
  const pending = new Map()
  let _onPendingChange = () => {}

  async function handleEnroll (from, p) {
    const d = p?.data
    if (!d || typeof d.dpub !== 'string' || typeof p.signature !== 'string') {
      return send(from, { type: MSG.ERROR, error: 'enroll inválido' })
    }
    const pend = pending.get(d.token)
    if (!pend || Date.now() > pend.exp) {
      return send(from, { type: MSG.ERROR, error: 'token de emparejamiento inválido o expirado' })
    }
    if (d.sn !== pend.sn) return send(from, { type: MSG.ERROR, error: 'sesión inválida' })
    if (typeof d.ts !== 'number' || Math.abs(Date.now() - d.ts) > FRESH_WINDOW_MS) {
      return send(from, { type: MSG.ERROR, error: 'enroll vencido (posible replay, o el reloj desfasado)' })
    }
    // PRUEBA DE POSESIÓN: la firma de `data` debe verificar contra `dpub`.
    const ok = await verifyDeviceSig({ publickey: d.dpub, data: d, signature: p.signature })
    if (!ok) return send(from, { type: MSG.ERROR, error: 'firma de dispositivo inválida' })
    // Un solo dispositivo a la vez esperando su código (así `approve` no es ambiguo).
    if (pend.state === 'PENDING_CONFIRM' && pend.dpub && pend.dpub !== d.dpub) {
      return send(from, { type: MSG.ERROR, error: 'ya hay un dispositivo usando este emparejamiento' })
    }
    const deviceId = await deviceIdOf(d.dpub)
    pend.state = 'PENDING_CONFIRM'
    pend.dpub = d.dpub
    pend.deviceId = deviceId
    pend.from = from // esta bóveda NO conoce el código (no viaja): el dispositivo lo MUESTRA
    if (d.label) pend.label = String(d.label).slice(0, 60)
    _onPendingChange()
    send(from, { type: MSG.ENROLL_CHALLENGE, deviceId })
  }

  // Emite un REVOKED FIRMADO por la maestra a la máquina revocada para que se
  // auto-borre. Va por `sendByPubkey` → si está offline, el proxy lo encola 24 h; y
  // si reaparece más tarde, `handleDevices` lo re-emite en su siguiente consulta.
  // El auto-borrado remoto SOLO se dispara con esta firma (no con un error cualquiera).
  async function emitRevoke (dpub, nonce) {
    const body = { op: 'revoke', sub: dpub, nonce, iat: Date.now(), exp: Date.now() + DEVICE_TTL_MS }
    const { signature } = await identity.signData(body)
    try { client.sendByPubkey(dpub, { type: MSG.REVOKED, body, signature }) } catch (_) {}
  }

  // Consulta de revocaciones (igual que `vault.devices` del daemon): responde la lista
  // de dispositivos enrolados + revocados para que el dispositivo refresque su set. Y si
  // QUIEN consulta es una máquina ya revocada (reapareció), le re-emite el REVOKED firmado.
  async function handleDevices (from, p) {
    const d = p?.data
    if (!d || !p.signature || !p.cert) return send(from, { type: MSG.ERROR, error: 'petición inválida' })
    if (typeof d.ts !== 'number' || Math.abs(Date.now() - d.ts) > FRESH_WINDOW_MS) return
    const chk = await verifyChain({ data: d, signature: p.signature, cert: p.cert, trustedIssuer: iss })
    if (!chk.ok) return send(from, { type: MSG.ERROR, error: 'no autorizado: ' + chk.reason })
    const { issued, revoked } = await identity.listDelegations()
    const devices = await Promise.all((issued || []).map(async (x) => ({
      deviceId: x.sub ? await deviceIdOf(x.sub) : null, sub: x.sub || null,
      label: x.label || '', scope: x.scope, exp: x.exp, nonce: x.nonce
    })))
    send(from, { type: MSG.DEVICES_RESULT, devices, revoked: (revoked || []).map((r) => r.nonce || r) })
    // ¿el que consulta es una máquina revocada que reapareció? → re-emite el REVOKED firmado.
    const mine = (issued || []).find((x) => x.sub === chk.device && x.revokedAt)
    if (mine) emitRevoke(chk.device, mine.nonce)
  }

  client.on('message', (_from, p) => {
    if (!p || typeof p !== 'object') return
    if (p.type === MSG.ENROLL) handleEnroll(_from, p).catch(() => {})
    else if (p.type === MSG.DEVICES) handleDevices(_from, p).catch(() => {})
  })

  /**
   * Abre un emparejamiento: devuelve el QR/JSON v2 que el dispositivo consume para
   * enrolarse. `scope`/`ttlMs`/`label` fijan lo que otorgará el cert al aprobar.
   */
  function startPairing ({ scope = [SIGN_SCOPE], ttlMs = DEVICE_TTL_MS, label = '' } = {}) {
    pending.clear()
    const token = randToken()
    const sn = randToken()
    pending.set(token, { token, exp: Date.now() + PAIRING_TTL_MS, sn, scope, ttlMs, label, state: 'AWAITING_ENROLL' })
    return { qr: { v: 2, iss, proxy, token, sn }, expiresInMs: PAIRING_TTL_MS }
  }

  function listPending () {
    return [...pending.values()]
      .filter((p) => p.state === 'PENDING_CONFIRM')
      .map((p) => ({ deviceId: p.deviceId, label: p.label }))
  }
  function findPending (deviceId) {
    for (const [, p] of pending) if (p.state === 'PENDING_CONFIRM' && p.deviceId === deviceId) return p
    return null
  }

  /**
   * Aprueba una máquina pendiente TIPEANDO el código que ella muestra. Esta bóveda NO
   * conoce/valida el código: firma el cert y ECHA el código tipeado; la máquina lo acepta
   * solo si coincide con el que generó. (Modelo `dotrino-vault#approveDevice`.)
   */
  async function approve (deviceId, code) {
    const pend = findPending(deviceId)
    if (!pend || !pend.dpub) throw new Error('no hay ninguna máquina esperando aprobación')
    code = String(code || '').trim()
    if (!code) throw new Error('escribe el código que muestra la máquina')
    const { cert } = await identity.signDelegation(pend.dpub, pend.scope, { ttlMs: pend.ttlMs, label: pend.label })
    send(pend.from, { type: MSG.ENROLLED, code, cert, iss })
    pending.delete(pend.token)
    _onPendingChange()
    return { ok: true, deviceId }
  }

  function reject (deviceId) {
    const pend = findPending(deviceId)
    if (!pend) return
    send(pend.from, { type: MSG.ERROR, error: 'emparejamiento rechazado' })
    pending.delete(pend.token)
    _onPendingChange()
  }

  /**
   * Máquinas enroladas bajo esta identidad (P), vigentes, con scope de firma y label
   * propio (excluye navegadores enrolados con label 'cli', que no atienden peticiones).
   */
  async function listMachines () {
    const { issued } = await identity.listDelegations()
    const now = Date.now()
    const bySub = new Map()
    for (const x of (issued || [])) {
      if (!x.sub || x.revokedAt || (x.exp && x.exp <= now)) continue // revocada = fuera de la lista
      if (!Array.isArray(x.scope) || !x.scope.includes(SIGN_SCOPE)) continue
      if (!x.label || x.label === 'cli') continue
      if (!bySub.has(x.sub) || (x.exp || 0) > (bySub.get(x.sub).exp || 0)) bySub.set(x.sub, x)
    }
    return Promise.all([...bySub.values()].map(async (x) => ({ ...x, deviceId: await deviceIdOf(x.sub) })))
  }

  async function revoke (nonce) {
    // Deja el registro persistente (revokedAt en la delegación) y AVISA a la máquina
    // con un REVOKED firmado para que se auto-borre (ahora si está online, o al
    // reaparecer vía handleDevices). Ver emitRevoke.
    const { issued } = await identity.listDelegations()
    const dele = (issued || []).find((d) => d.nonce === nonce)
    const res = await identity.revokeDelegation(nonce)
    if (dele?.sub) await emitRevoke(dele.sub, nonce)
    return res
  }

  return {
    iss, proxy, client,
    startPairing, approve, reject, listPending, listMachines, revoke,
    getSelfCert,
    onPendingChange (fn) { _onPendingChange = fn || (() => {}) },
    close () { try { client.close() } catch (_) {} }
  }
}

export default { startDeviceVault, deviceIdOf }
