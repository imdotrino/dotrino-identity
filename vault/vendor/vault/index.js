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

const SIGN_SCOPE = 'vault:sign'
const SELFCERT_TTL_MS = 24 * 60 * 60 * 1000    // el self-cert P←P se regenera cada 24 h

const MSG = {
  ENROLL: 'vault.enroll',
  DEVICES: 'vault.devices',
  DEVICES_RESULT: 'vault.devices.result',
  ERROR: 'vault.error'
}

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

  let _onPendingChange = () => {}

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
    onPendingChange: () => _onPendingChange()
  })

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
    if (p.type === MSG.ENROLL) desk.handleEnroll(_from, p).catch(() => {})
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
    close () { try { client.close() } catch (_) {} }
  }
}

export default { startDeviceVault, deviceIdOf }
