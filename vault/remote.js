/**
 * Enrolamiento de ESTE dispositivo contra el vault del usuario (lado dispositivo).
 *
 * Corre dentro del iframe de identidad (o headless en Node): genera la sub-clave `D`
 * —cuya privada NUNCA sale de la identidad—, hace el emparejamiento ENDURECIDO por el
 * proxy (ver dotrino-vault/docs/pairing-protocol.md) y devuelve el cert ya validado.
 *
 * Flujo: firma el ENROLL con D (prueba de posesión) → recibe el reto y computa SU
 * propio SAS (que el usuario compara con el del PC) → al ser aprobado en el PC, recibe
 * el cert y lo valida (firmado por la maestra que vio en el QR, y para SU clave).
 *
 * No reimplementa cripto: usa `@dotrino/identity/capabilities`. Transporte:
 * `@dotrino/proxy-client` (importado perezosamente; solo se carga al emparejar).
 */
import { makeDeviceKey, signWithDevice, verifyDelegation, deriveSAS, pubkeyId } from './capabilities.js'

const MSG = {
  ENROLL: 'vault.enroll',
  ENROLL_CHALLENGE: 'vault.enroll.challenge',
  ENROLLED: 'vault.enrolled',
  ERROR: 'vault.error'
}

/**
 * @param {Object} opts
 * @param {{v:number, iss:string, proxy:string, token:string, sn:string}} opts.qr  QR v2 del vault.
 * @param {(c:{deviceId:string, sas:string})=>void} [opts.onChallenge]  Para mostrar el SAS a comparar.
 * @param {string} [opts.label]
 * @param {number} [opts.approveTimeoutMs]  Espera de la aprobación humana (def 3 min).
 * @returns {Promise<{device, cert, master:string, proxy:string, deviceId:string}>}
 */
export async function enrollDevice ({ qr, device, onChallenge, label = '', approveTimeoutMs = 180000 } = {}) {
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
    const sas = await deriveSAS(qr.iss, dev.publickey, qr.sn)
    const data = { op: 'enroll', dpub: dev.publickey, token: qr.token, sn: qr.sn, label, ts: Date.now() }
    const { signature } = await signWithDevice({ privateJwk: dev.privateJwk, data })

    const enrolled = new Promise((resolve, reject) => {
      const off = client.on('message', (_from, p) => {
        if (!p || typeof p !== 'object') return
        if (p.type === MSG.ENROLL_CHALLENGE) { try { onChallenge?.({ deviceId, sas }) } catch (_) {} }
        else if (p.type === MSG.ENROLLED) { cleanup(); resolve(p) }
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
    return { device: dev, cert: res.cert, master: qr.iss, proxy: qr.proxy, deviceId }
  } finally { try { client.close() } catch (_) {} }
}

/**
 * Pide a la MAESTRA (en el vault del PC) que firme `payload`, adjuntando el cert de
 * delegación de este dispositivo. La maestra nunca sale del vault: vuelve solo la
 * firma. Requiere que el vault esté online.
 * @returns {Promise<{ signature:string, publickey:string }>}  publickey = la maestra.
 */
export async function requestSign ({ master, proxy, device, cert, payload, timeoutMs = 15000 } = {}) {
  if (!master || !proxy || !device?.privateJwk || !cert) throw new Error('faltan datos de emparejamiento')
  const { WebSocketProxyClient } = await import('@dotrino/proxy-client')
  const client = new WebSocketProxyClient({ url: proxy, enableWebRTC: false, autoReconnect: false })
  await client.connect()
  try {
    const data = { op: 'sign', payload, publickey: device.publickey, ts: Date.now() }
    const { signature } = await signWithDevice({ privateJwk: device.privateJwk, data })
    const pending = new Promise((resolve, reject) => {
      const off = client.on('message', (_f, p) => {
        if (!p || typeof p !== 'object') return
        if (p.type === 'vault.signed') { cleanup(); resolve(p) }
        else if (p.type === 'vault.error') { cleanup(); reject(new Error(p.error)) }
      })
      const t = setTimeout(() => { cleanup(); reject(new Error('el vault no respondió (¿está encendido?)')) }, timeoutMs)
      const cleanup = () => { off(); clearTimeout(t) }
    })
    client.sendByPubkey(master, { type: 'vault.sign', data, signature, cert })
    const res = await pending
    return { signature: res.signature, publickey: res.publickey }
  } finally { try { client.close() } catch (_) {} }
}

/** Helper genérico: una RPC al vault firmada por D + cert, esperando `okType`. */
async function vaultRpc ({ master, proxy, device, cert, sendType, okType, data, timeoutMs = 15000 }) {
  if (!master || !proxy || !device?.privateJwk || !cert) throw new Error('faltan datos de emparejamiento')
  const { WebSocketProxyClient } = await import('@dotrino/proxy-client')
  const client = new WebSocketProxyClient({ url: proxy, enableWebRTC: false, autoReconnect: false })
  await client.connect()
  try {
    const signed = { ...data, publickey: device.publickey, ts: Date.now() }
    const { signature } = await signWithDevice({ privateJwk: device.privateJwk, data: signed })
    const pending = new Promise((resolve, reject) => {
      const off = client.on('message', (_f, p) => {
        if (!p || typeof p !== 'object') return
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
export async function requestStore ({ master, proxy, device, cert, method, args } = {}) {
  const res = await vaultRpc({ master, proxy, device, cert, sendType: 'vault.store', okType: 'vault.store.result', data: { op: 'store', method, args: args || {} } })
  return res.result
}

/** Lista (solo lectura) los dispositivos enrolados en tu vault. */
export async function requestDevices ({ master, proxy, device, cert } = {}) {
  const res = await vaultRpc({ master, proxy, device, cert, sendType: 'vault.devices', okType: 'vault.devices.result', data: { op: 'devices' } })
  return { devices: res.devices || [], revoked: res.revoked || [] }
}
