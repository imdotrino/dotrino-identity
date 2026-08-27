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
import { verifyChain, verifyDeviceSig } from '@dotrino/identity/capabilities'
import { createEnrollDesk, deviceIdOf, DEVICE_TTL_MS, FRESH_WINDOW_MS } from './enroll.js'
// Las constantes del protocolo salen del MISMO módulo que usa el daemon: si la lista
// local se queda corta, el dispositivo deja de handle mensajes sin que nadie lo note.
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
  if (!iss) throw new Error('no identity: create/unlock your identity before using this device as a vault')
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
    if (!d || !p.signature || !p.cert) return send(from, { type: MSG.ERROR, error: 'invalid request' })
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
    if (!d || !p.signature || !p.cert) return send(from, { type: MSG.ERROR, error: 'invalid request' })
    if (typeof d.ts !== 'number' || Math.abs(Date.now() - d.ts) > FRESH_WINDOW_MS) return
    const chk = await verifyChain({ data: d, signature: p.signature, cert: p.cert, trustedIssuer: iss })
    if (!chk.ok) return send(from, { type: MSG.ERROR, error: 'unauthorized: ' + chk.reason })
    const { issued, revoked, revokedCerts } = await identity.listDelegations()
    const devices = await Promise.all((issued || []).map(async (x) => ({
      deviceId: x.sub ? await deviceIdOf(x.sub) : null, sub: x.sub || null,
      label: x.label || '', scope: x.scope, exp: x.exp, nonce: x.nonce
    })))
    send(from, { type: MSG.DEVICES_RESULT, devices, revoked: (revoked || []).map((r) => r.nonce || r) })
    // ¿el que consulta es una máquina revocada que reapareció? → re-emite el REVOKED firmado.
    // Se busca en `revokedCerts`: desde que `issued` solo trae lo vigente, los retirados
    // ya no están ahí y este aviso dejaba de dispararse (se caía en silencio).
    const mine = (revokedCerts || issued || []).find((x) => x.sub === chk.device && x.revokedAt)
    if (mine) desk.emitRevoke(chk.device, mine.nonce)
  }

  /**
   * Lo que el daemon comprueba antes de cualquier operación firmada, en un solo sitio:
   * frescura (anti-replay), cadena de certs, scope esperado y revocaciones.
   *
   * Estaba repetido en `handleRenew` y `handleDevices` con matices distintos; al añadir
   * el resto de operaciones eso habría sido cuatro copias divergiendo.
   */
  async function authorise (from, p, expectedScope) {
    const d = p?.data
    if (!d || !p.signature || !p.cert) {
      send(from, { type: MSG.ERROR, error: 'invalid request' })
      return null
    }
    if (typeof d.ts !== 'number' || Math.abs(Date.now() - d.ts) > FRESH_WINDOW_MS) {
      send(from, { type: MSG.ERROR, error: 'stale request: ts outside the ±5 min window (possible replay, or a clock out of sync)' })
      return null
    }
    const chk = await verifyChain({
      data: d, signature: p.signature, cert: p.cert,
      ...(expectedScope ? { expectedScope } : {}),
      trustedIssuer: iss, revoked: await revocationSet(),
    })
    if (!chk.ok) {
      send(from, { type: MSG.ERROR, error: 'unauthorized: ' + chk.reason })
      return null
    }
    return chk
  }

  /**
   * FIRMAR en name de la identidad. Es la razón de ser de una bóveda, y faltaba: un
   * aparato enrolado contra este dispositivo podía renovar su cert y listar aparatos,
   * pero no pedir la única cosa para la que se enroló.
   */
  async function handleSign (from, p) {
    const chk = await authorise(from, p, SCOPE.SIGN)
    if (!chk) return
    const toSign = p.data?.payload
    if (toSign == null) return send(from, { type: MSG.ERROR, error: 'data.payload required' })
    const { signature, publickey } = await identity.signData(toSign)
    send(from, { type: MSG.SIGNED, signature, publickey, device: chk.device })
  }

  /** Leer del almacén del perfil. Mismo scope que en el daemon: `read`. */
  async function handleGet (from, p) {
    const chk = await authorise(from, p, SCOPE.READ)
    if (!chk) return
    const id = p.data?.id || 'root'
    try {
      const node = await identity.getNode?.(id)
      send(from, { type: MSG.DATA, id, node: node ?? null })
    } catch (e) {
      send(from, { type: MSG.ERROR, error: 'get: ' + e.message })
    }
  }

  /**
   * Escribir en el almacén. Se pasa por `vaultStore`, que es el mismo camino que usa
   * un aparato contra el daemon — no se reimplementa el store aquí.
   */
  async function handleStore (from, p) {
    const d = p?.data
    if (!d || typeof d.method !== 'string') {
      return send(from, { type: MSG.ERROR, error: 'store: invalid method' })
    }
    const chk = await authorise(from, p, SCOPE.STORE)
    if (!chk) return
    try {
      const result = await identity.vaultStore?.(d.method, d.args || [])
      send(from, { type: MSG.DATA, id: d.method, node: result ?? null })
    } catch (e) {
      send(from, { type: MSG.ERROR, error: 'store: ' + e.message })
    }
  }

  /**
   * ¿Sigue este aparato dentro del acta? Lo pregunta un aparato al arrancar, y por eso
   * NO va firmado con cert: va firmado con su propia llave. Un aparato revocado tiene
   * que poder enterarse de que lo está.
   */
  async function handleCheck (from, p) {
    const d = p?.data
    if (!d || typeof d.ts !== 'number' || Math.abs(Date.now() - d.ts) > FRESH_WINDOW_MS) return
    const pub = d.publickey
    if (typeof pub !== 'string') return send(from, { type: MSG.ERROR, error: 'unauthorized: shape' })
    if (!(await verifyDeviceSig({ publickey: pub, data: d, signature: p.signature }))) {
      return send(from, { type: MSG.ERROR, error: 'unauthorized: bad-signature' })
    }
    const record = (await identity.profileActa?.().catch(() => null))?.acta || null
    const inside = (record?.members || []).some((m) => m?.pub === pub)
    if (inside) return send(from, { type: MSG.CHECKED, in: true })

    // Fuera del acta: se le dice, y además se le re-emite el aviso firmado si consta
    // revocado — para que se apague solo en vez de quedarse creyendo que sigue dentro.
    const { revokedCerts, issued } = await identity.listDelegations()
    const mine = (revokedCerts || issued || []).find((x) => x.sub === pub && x.revokedAt)
    if (mine) desk.emitRevoke(pub, mine.nonce)
    send(from, { type: MSG.CHECKED, in: false })
  }

  /**
   * Un fallo dentro de un handler NO se traga.
   *
   * El router llevaba `.catch(() => {})` en cada rama: si algo reventaba, el aparato del
   * otro lado se quedaba esperando para siempre y aquí no quedaba rastro. Ahora se
   * contesta el error — que es lo que permite depurarlo desde el lado que pregunta.
   */
  const handle = (name, promise, from) => Promise.resolve(promise).catch((e) => {
    send(from, { type: MSG.ERROR, error: `${name}: ${e?.message || e}` })
  })

  client.on('message', (_from, p) => {
    if (!p || typeof p !== 'object') return
    // El QR corto no lleva la llave: el aparato la pide con un HELLO presentando el `sn`.
    if (p.type === MSG.HELLO) handle('hello', desk.handleHello(_from, p), _from)
    else if (p.type === MSG.ENROLL) handle('enroll', desk.handleEnroll(_from, p), _from)
    // Camino A: el aparato devuelve su acta sellada admitiendo a esta bóveda.
    else if (p.type === MSG.ACTA_SEALED) handle('acta', desk.handleActaSealed(_from, p), _from)
    else if (p.type === MSG.RENEW) handle('renew', handleRenew(_from, p), _from)
    else if (p.type === MSG.DEVICES) handle('devices', handleDevices(_from, p), _from)
    // Lo que faltaba para que un aparato enrolado aquí pueda hacer lo mismo que contra
    // el daemon del PC: firmar, leer, guardar y comprobar que sigue dentro.
    else if (p.type === MSG.SIGN) handle('sign', handleSign(_from, p), _from)
    else if (p.type === MSG.GET) handle('get', handleGet(_from, p), _from)
    else if (p.type === MSG.STORE) handle('store', handleStore(_from, p), _from)
    else if (p.type === MSG.CHECK) handle('check', handleCheck(_from, p), _from)
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
    // QUITA LA MÁQUINA entera (por su llave): fuera del acta y sin ningún certificado
    // vigente, que son las dos caras del mismo acto. Y AVISA con un REVOKED firmado para
    // que se auto-borre (ahora si está online, o al reaparecer vía handleDevices).
    revokeDevice: (sub) => desk.revokeDevice(sub),
    // Retira UN certificado. No es quitar la máquina: sigue siendo miembro del acta, y
    // quien queda así ya no recibe el aviso de expulsión (mientras siga en el acta, un
    // papel retirado significa «renueva»). Usar `revokeDevice` salvo que quieras
    // exactamente esto.
    revoke: (nonce) => desk.revoke(nonce),
    getSelfCert,
    onPendingChange (fn) { _onPendingChange = fn || (() => {}) },
    /** Camino A: la cuenta del aparato quedó adoptada por esta bóveda. */
    onAdopted (fn) { _onAdopted = fn || (() => {}) },
    close () { try { client.close() } catch (_) {} }
  }
}

export default { startDeviceVault, deviceIdOf }
