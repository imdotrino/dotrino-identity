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
 * El flujo de enrolamiento en sí (incluida la comprobación del código antes de firmar) vive
 * en `./enroll.js`, COMPARTIDO con el daemon del PC y con la copia vendorizada del iframe:
 * un solo sitio donde se decide a quién se le emite un certificado.
 *
 * Cripto 100% de `@dotrino/identity/capabilities`; firma con la identidad P
 * (`identity.signDelegation`). Transporte: `@dotrino/proxy-client` (import perezoso).
 * No reimplementa nada del ecosistema.
 */
import { verifyChain } from '@dotrino/identity/capabilities'
import { createEnrollDesk, deviceIdOf, DEVICE_TTL_MS, FRESH_WINDOW_MS } from './enroll.js'
// Las constantes del protocolo salen del MISMO módulo que usa el daemon: si la lista
// local se queda corta, el dispositivo deja de atender mensajes sin que nadie lo note.
import { MSG, SCOPE } from './protocol.js'

const SIGN_SCOPE = SCOPE.SIGN
const SELFCERT_TTL_MS = 24 * 60 * 60 * 1000    // el self-cert P←P se regenera cada 24 h
const RENEW_TTL_MS = DEVICE_TTL_MS             // la renovación extiende la misma ventana (30 días)

/** deviceId legible (p. ej. `C440-AC0E`) desde una pubkey JWK. */
export { deviceIdOf }

/**
 * Levanta la bóveda de este dispositivo: se conecta al proxy identificado como P y
 * atiende enrolamientos + consultas de revocación de los dispositivos que se enrolan.
 *
 * @param {object} identity  instancia de `@dotrino/identity` (P): expone
 *   `me.publickey`, `signData`, `signDelegation`, `listDelegations`, `revokeDelegation`.
 * @param {object} [opts]
 * @param {string} [opts.proxyUrl='wss://proxy.dotrino.com']
 * @returns {Promise<object>} handle: { iss, proxy, client, startPairing, stopPairing,
 *   approve, reject, listPending, listMachines, revoke, getSelfCert, onPendingChange,
 *   onAdopted, close }
 */
export async function startDeviceVault (identity, { proxyUrl, client: injectedClient } = {}) {
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

  // `client` inyectado: solo para las pruebas (transporte de mentira). En producción se
  // levanta el del ecosistema — no hay otro transporte.
  const client = injectedClient || await (async () => {
    const { WebSocketProxyClient } = await import('@dotrino/proxy-client')
    const c = new WebSocketProxyClient({
      url: proxy, enableWebRTC: false, autoReconnect: true,
      maxReconnectAttempts: 100000, reconnectDelay: 4000
    })
    await c.connect()
    return c
  })()

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

  let _onPendingChange = () => {}
  let _onAdopted = () => {}

  // ENROLL / aprobación / revocación: núcleo COMPARTIDO con el daemon del PC y con la
  // copia vendorizada del iframe (`lib/src/enroll.js`). Un solo sitio donde vive el
  // flujo → y por lo tanto un solo sitio donde se comprueba el código antes de firmar.
  const desk = createEnrollDesk({
    identity,
    iss,
    proxy,
    send,
    sendByPubkey: (pub, obj) => { try { client.sendByPubkey(pub, obj) } catch (_) {} },
    defaultScope: [SIGN_SCOPE],
    defaultTtlMs: DEVICE_TTL_MS,
    // Camino A (la cuenta del aparato pasa a vivir aquí): sin la llave de cifrado, esta
    // bóveda entraría mandando una cuenta cuyo contenido no puede abrir.
    encPub: identity.me?.encryptionPubkey || null,
    vaultLabel: 'bóveda',
    // Cita del proxio para la invitación corta (QR). Si el proxio es viejo y no las
    // conoce, el desk se cae solo a la invitación larga.
    connToken: async () => {
      try { return (await client.requestPairingCode())?.code || null }
      catch (_) { return null }
    },
    onAdopted: (info) => { try { _onAdopted(info) } catch (_) {} },
    onPendingChange: () => _onPendingChange()
  })

  /** Nonces revocados, para que un cert revocado no pase ningún `verifyChain`. */
  async function revocationSet () {
    const { revoked } = await identity.listDelegations()
    return new Set((revoked || []).map((r) => r.nonce || r))
  }

  /**
   * RENOVACIÓN automática (igual que `dotrino-vault#handleRenew`): un dispositivo con
   * cert VIGENTE y no revocado pide uno fresco —misma sub-clave y scope— sin QR ni
   * aprobación: sigue siendo el mismo dispositivo, solo extiende la ventana. Un cert
   * vencido o revocado NO se renueva (ahí toca re-emparejar con aprobación).
   *
   * Sin esto, toda máquina enrolada contra un dispositivo-bóveda caduca a los 30 días.
   */
  async function handleRenew (from, p) {
    const d = p?.data
    if (!d || !p.signature || !p.cert) return send(from, { type: MSG.ERROR, error: 'petición inválida' })
    if (typeof d.ts !== 'number' || Math.abs(Date.now() - d.ts) > FRESH_WINDOW_MS) {
      return send(from, { type: MSG.ERROR, error: 'stale request: ts outside the ±5 min window (possible replay, or the device clock is off)' })
    }
    const chk = await verifyChain({ data: d, signature: p.signature, cert: p.cert, trustedIssuer: iss, revoked: await revocationSet() })
    if (!chk.ok) return send(from, { type: MSG.ERROR, error: 'unauthorized: ' + chk.reason })
    // Reusar el label del cert original (si sigue registrado en delegations).
    const { issued } = await identity.listDelegations()
    const prev = (issued || []).find((x) => x.nonce === p.cert.nonce)
    const { cert } = await identity.signDelegation(p.cert.sub, p.cert.scope, { ttlMs: RENEW_TTL_MS, label: prev?.label || '' })
    send(from, { type: MSG.RENEWED, cert })
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
    if (mine) desk.emitRevoke(chk.device, mine.nonce)
  }

  client.on('message', (_from, p) => {
    if (!p || typeof p !== 'object') return
    // El QR corto no lleva la llave: el aparato la pide con un HELLO presentando el `sn`.
    if (p.type === MSG.HELLO) Promise.resolve(desk.handleHello(_from, p)).catch(() => {})
    else if (p.type === MSG.ENROLL) desk.handleEnroll(_from, p).catch(() => {})
    // Camino A: el aparato devuelve su acta sellada admitiendo a esta bóveda.
    else if (p.type === MSG.ACTA_SEALED) Promise.resolve(desk.handleActaSealed(_from, p)).catch(() => {})
    else if (p.type === MSG.RENEW) handleRenew(_from, p).catch(() => {})
    else if (p.type === MSG.DEVICES) handleDevices(_from, p).catch(() => {})
  })

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

  return {
    iss, proxy, client,
    startPairing: desk.startPairing,
    stopPairing: desk.stopPairing,
    // Aprueba TIPEANDO el código que muestra la máquina: el núcleo compartido recompone
    // el compromiso `SHA-256(code‖dpub‖sn)` y solo firma el cert si coincide.
    approve: (deviceId, code) => desk.approve(code, { deviceId }),
    reject: (deviceId) => desk.reject(deviceId),
    listPending: desk.listPending,
    listMachines,
    // Revoca y AVISA a la máquina con un REVOKED firmado para que se auto-borre (ahora si
    // está online, o al reaparecer vía handleDevices).
    revoke: (nonce) => desk.revoke(nonce),
    getSelfCert,
    onPendingChange (fn) { _onPendingChange = fn || (() => {}) },
    /** Camino A: la cuenta del aparato quedó adoptada por esta bóveda. */
    onAdopted (fn) { _onAdopted = fn || (() => {}) },
    close () { try { client.close() } catch (_) {} }
  }
}

export default { startDeviceVault, deviceIdOf }
