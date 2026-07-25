/**
 * Enrolamiento de ESTE dispositivo contra el vault del usuario (lado dispositivo).
 *
 * Corre dentro del iframe de identidad (o headless en Node): genera la sub-clave `D`
 * —cuya privada NUNCA sale de la identidad—, hace el emparejamiento ENDURECIDO por el
 * proxy (ver dotrino-vault/docs/pairing-protocol.md) y devuelve el cert ya validado.
 *
 * Flujo: genera un código de 6 dígitos, lo MUESTRA y manda solo su COMPROMISO dentro del
 * ENROLL firmado con D (prueba de posesión) → el dueño tipea el código en la bóveda, que
 * lo comprueba contra el compromiso y solo entonces firma → el dispositivo acepta el cert
 * si le ECHAN su código y lo valida (firmado por la maestra que vio en el QR, y para SU clave).
 *
 * No reimplementa cripto: usa `@dotrino/identity/capabilities`. Transporte:
 * `@dotrino/proxy-client` (importado perezosamente; solo se carga al emparejar).
 */
import { makeDeviceKey, signWithDevice, verifyDelegation, verifyDeviceSig, makePairingCode, commitCode, pubkeyId } from './capabilities.js'

const MSG = {
  ENROLL: 'vault.enroll',
  ENROLL_CHALLENGE: 'vault.enroll.challenge',
  ENROLLED: 'vault.enrolled',
  REVOKED: 'vault.revoked',
  ERROR: 'vault.error'
}

/**
 * ¿Es AUTÉNTICO este `vault.revoked`? Solo lo es si va firmado por la maestra PINEADA al
 * emparejar, es para ESTE dispositivo y no ha caducado. Es la única puerta al autoborrado:
 * un `vault.error` con la palabra «revocado» no borra nada (cierra el wipe-DoS, ver
 * `dotrino-vault/docs/pairing-protocol.md §2.3`).
 */
export async function isAuthenticRevoke ({ body, signature, master, devicePubkey }) {
  if (!body || body.op !== 'revoke' || typeof signature !== 'string') return false
  if (body.sub !== devicePubkey) return false
  if (typeof body.exp === 'number' && Date.now() > body.exp) return false
  return verifyDeviceSig({ publickey: master, data: body, signature })
}

/**
 * Identifica la conexión bajo la pubkey de este dispositivo. Además de hacerlo
 * direccionable, es lo que hace que el proxy le entregue lo que tenía ENCOLADO (24 h) —
 * entre otras cosas, un `vault.revoked` emitido mientras estaba apagado.
 */
async function identifyAsDevice (client, device) {
  if (!client.token) return
  const data = { op: 'identify', publickey: device.publickey, token: client.token, ts: Date.now() }
  const { signature } = await signWithDevice({ privateJwk: device.privateJwk, privateKey: device.privateKey, publickey: device.publickey, data })
  await client.identify({ data, signature })
}

/**
 * @param {Object} opts
 * @param {{v:number, iss:string, proxy:string, token:string, sn:string}} opts.qr  QR v2 del vault.
 * @param {(c:{deviceId:string, code:string})=>void} [opts.onChallenge]  Para mostrar el código a tipear en el PC.
 * @param {string} [opts.label]
 * @param {number} [opts.approveTimeoutMs]  Espera de la aprobación humana (def 3 min).
 * @returns {Promise<{device, cert, master:string, proxy:string, deviceId:string}>}
 */
export async function enrollDevice ({ qr, device, onChallenge, label = '', continuity = null, approveTimeoutMs = 180000 } = {}) {
  if (!qr?.iss || !qr?.proxy || !qr?.token || !qr?.sn) throw new Error('qr inválido (v2): faltan iss/proxy/token/sn')
  const { WebSocketProxyClient } = await import('@dotrino/proxy-client')
  const client = new WebSocketProxyClient({ url: qr.proxy, enableWebRTC: false, autoReconnect: false })
  await client.connect()
  try {
    // Por defecto genera una sub-clave nueva; pero el iframe pasa SU PROPIA llave de
    // identidad (P) como `device` → el cert delega tu identidad y hay UNA sola (signData/
    // identify/cert son la misma P).
    const dev = device || await makeDeviceKey({ label })
    const deviceId = (await pubkeyId(dev.publickey)).slice(0, 8).toUpperCase().replace(/(.{4})(.{4})/, '$1-$2')
    // El DISPOSITIVO genera el código y manda solo su COMPROMISO (no el código). El vault
    // aprende el código únicamente cuando vos lo tipeás en el PC → aprobar exige tener el dispositivo.
    const code = makePairingCode()
    // Se manda el COMPROMISO del código, nunca el código. El vault lo aprende solo cuando lo
    // tipeas, recompone el compromiso y únicamente entonces firma el cert → aprobar exige
    // haber leído el código de ESTA pantalla. Y al ECHARLO de vuelta, el dispositivo confía:
    // una bóveda falsa no conoce el código y no puede enrolarlo.
    const commit = await commitCode({ code, dpub: dev.publickey, sn: qr.sn })
    // `continuity`: si esta identidad ya existía, va firmada por ella misma para que lo
    // que hizo antes se pueda seguir atribuyendo a la misma persona (ver acta.js).
    const data = { op: 'enroll', dpub: dev.publickey, token: qr.token, sn: qr.sn, commit, label, ts: Date.now(), ...(continuity ? { continuity } : {}) }
    const { signature } = await signWithDevice({ privateJwk: dev.privateJwk, privateKey: dev.privateKey, publickey: dev.publickey, data })

    const enrolled = new Promise((resolve, reject) => {
      const off = client.on('message', (_from, p) => {
        if (!p || typeof p !== 'object') return
        if (p.type === MSG.ENROLL_CHALLENGE) { try { onChallenge?.({ deviceId, code }) } catch (_) {} }
        // El vault ECHA el código que tipeaste; aceptamos SOLO si coincide con el que generamos.
        // (Un código distinto = un vault que no lo conoce → lo ignoramos y seguimos esperando.)
        else if (p.type === MSG.ENROLLED) { if (p.code === code) { cleanup(); resolve(p) } }
        else if (p.type === MSG.ERROR) { cleanup(); reject(new Error(p.error)) }
      })
      const t = setTimeout(() => { cleanup(); reject(new Error('timeout esperando la aprobación en el vault')) }, approveTimeoutMs)
      const cleanup = () => { off(); clearTimeout(t) }
    })
    client.sendByPubkey(qr.iss, { type: MSG.ENROLL, data, signature })
    const res = await enrolled

    // Validación estricta antes de guardar (cierra inyección de cert / sustitución de maestra).
    const v = await verifyDelegation({ cert: res.cert, expectedSub: dev.publickey })
    if (!v.ok) throw new Error('cert inválido: ' + v.reason)
    if (res.cert.iss !== qr.iss) throw new Error('cert firmado por una maestra distinta a la que viste')
    if (res.cert.sub !== dev.publickey) throw new Error('cert emitido para otro dispositivo')
    return { device: dev, cert: res.cert, master: qr.iss, proxy: qr.proxy, deviceId, acta: res.acta || null }
  } finally { try { client.close() } catch (_) {} }
}

/**
 * Pide a la MAESTRA (en el vault del PC) que firme `payload`, adjuntando el cert de
 * delegación de este dispositivo. La maestra nunca sale del vault: vuelve solo la
 * firma. Requiere que el vault esté online.
 * @returns {Promise<{ signature:string, publickey:string }>}  publickey = la maestra.
 */
export async function requestSign ({ master, proxy, device, cert, payload, onRevoked, timeoutMs = 15000 } = {}) {
  const res = await vaultRpc({
    master, proxy, device, cert, onRevoked, timeoutMs,
    sendType: 'vault.sign', okType: 'vault.signed', data: { op: 'sign', payload }
  })
  return { signature: res.signature, publickey: res.publickey }
}

/**
 * Helper genérico: una RPC al vault firmada por D + cert, esperando `okType`.
 *
 * Se identifica al conectar para que el proxy entregue lo ENCOLADO: si mientras el
 * dispositivo estaba apagado la bóveda emitió un `vault.revoked` firmado, llega aquí y se
 * ejecuta el autoborrado (`onRevoked`) tras verificar la firma contra la maestra pineada.
 */
async function vaultRpc ({ master, proxy, device, cert, sendType, okType, data, onRevoked, timeoutMs = 15000 }) {
  if (!master || !proxy || !(device?.privateJwk || device?.privateKey) || !cert) throw new Error('faltan datos de emparejamiento')
  const { WebSocketProxyClient } = await import('@dotrino/proxy-client')
  const client = new WebSocketProxyClient({ url: proxy, enableWebRTC: false, autoReconnect: false })
  await client.connect()
  try {
    try { await identifyAsDevice(client, device) } catch (_) { /* sin identify seguimos: solo perdemos la cola */ }
    const signed = { ...data, publickey: device.publickey, ts: Date.now() }
    const { signature } = await signWithDevice({ privateJwk: device.privateJwk, privateKey: device.privateKey, publickey: device.publickey, data: signed })
    const pending = new Promise((resolve, reject) => {
      const off = client.on('message', (_f, p) => {
        if (!p || typeof p !== 'object') return
        if (p.type === MSG.REVOKED) {
          isAuthenticRevoke({ body: p.body, signature: p.signature, master, devicePubkey: device.publickey })
            .then((ok) => { if (ok) { try { onRevoked?.() } catch (_) {} } })
            .catch(() => {})
          return
        }
        if (p.type === okType) { cleanup(); resolve(p) }
        else if (p.type === 'vault.error') { cleanup(); reject(new Error(p.error)) }
      })
      const t = setTimeout(() => { cleanup(); reject(new Error('el vault no respondió (¿está encendido?)')) }, timeoutMs)
      const cleanup = () => { off(); clearTimeout(t) }
    })
    client.sendByPubkey(master, { type: sendType, data: signed, signature, cert })
    return await pending
  } finally { try { client.close() } catch (_) {} }
}

/** Lee/escribe el store de hilos+aperturas EN el vault (con el cert del dispositivo). */
export async function requestStore ({ master, proxy, device, cert, method, args, onRevoked } = {}) {
  const res = await vaultRpc({ master, proxy, device, cert, onRevoked, sendType: 'vault.store', okType: 'vault.store.result', data: { op: 'store', method, args: args || {} } })
  return res.result
}

/** Lista (solo lectura) los dispositivos enrolados en tu vault. */
export async function requestDevices ({ master, proxy, device, cert, onRevoked } = {}) {
  const res = await vaultRpc({ master, proxy, device, cert, onRevoked, sendType: 'vault.devices', okType: 'vault.devices.result', data: { op: 'devices' } })
  return { devices: res.devices || [], revoked: res.revoked || [], acta: res.acta || null }
}

/**
 * RENUEVA el cert de este dispositivo (requiere el cert aún VIGENTE y no revocado):
 * el vault firma uno fresco para la misma sub-clave y scope, sin QR ni aprobación.
 * @returns {Promise<{ cert: object }>}
 */
export async function requestRenew ({ master, proxy, device, cert, onRevoked } = {}) {
  const res = await vaultRpc({ master, proxy, device, cert, onRevoked, sendType: 'vault.renew', okType: 'vault.renewed', data: { op: 'renew' } })
  if (!res.cert || res.cert.sub !== device.publickey || res.cert.iss !== master) throw new Error('cert renovado inválido')
  return { cert: res.cert }
}
