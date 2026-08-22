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
  HELLO: 'vault.hello',
  HELLO_OK: 'vault.hello.ok',
  ENROLL: 'vault.enroll',
  ENROLL_CHALLENGE: 'vault.enroll.challenge',
  ENROLLED: 'vault.enrolled',
  // --- camino A (la cuenta del aparato pasa a vivir en la bóveda) ---
  // La bóveda, en vez del cert, manda QUIÉN es ella para que el aparato la meta en su
  // acta; el aparato responde con el acta sellada y la bóveda devuelve la definitiva.
  ENROLL_ADOPT: 'vault.enroll.adopt',
  ACTA_SEALED: 'vault.acta.sealed',
  ACTA_ADOPTED: 'vault.acta.adopted',
  REVOKED: 'vault.revoked',
  // «¿sigo siendo de esta casa?»: la única pregunta que la bóveda atiende SIN certificado.
  CHECK: 'vault.check',
  CHECKED: 'vault.checked',
  // Consola remota: administrar el perfil desde un dispositivo (scope `vault:admin`).
  ADMIN: 'vault.admin',
  ADMIN_RESULT: 'vault.admin.result',
  ADMIN_EVENT: 'vault.admin.event',
  // Renuncia: el miembro se quita capacidades a sí mismo y la bóveda la sella en el acta.
  RENOUNCE: 'vault.renounce',
  RENOUNCE_RESULT: 'vault.renounce.result',
  // Pedidos de aprobación y llaves SSH del teléfono: van por el canal de secretos
  // (`op: approvals | approve | deny | ssh.keys | ssh.key.add | ssh.key.rm`).
  SECRETS: 'vault.secrets',
  SECRETS_RESULT: 'vault.secrets.result',
  ERROR: 'vault.error'
}
export { MSG as VAULT_MSG }

/**
 * ¿Es AUTÉNTICO este `vault.revoked`? Solo lo es si va firmado por la maestra PINEADA al
 * emparejar, es para ESTE dispositivo y no ha caducado. Es la única puerta al autoborrado:
 * un `vault.error` con la palabra «revocado» no borra nada (cierra el wipe-DoS, ver
 * `dotrino-vault/docs/pairing-protocol.md §2.3`).
 */
export async function isAuthenticRevoke ({ body, signature, master, devicePubkey, currentNonce = null }) {
  if (!body || body.op !== 'revoke' || typeof signature !== 'string') return false
  if (body.sub !== devicePubkey) return false
  if (typeof body.exp === 'number' && Date.now() > body.exp) return false
  // Y tiene que hablar del certificado que este aparato usa AHORA. Un certificado se
  // retira también cuando NO pasa nada malo: renovar retira el anterior, y cambiar
  // permisos obliga a renovar. Sin esta comprobación, el aviso de «tu papel viejo ya no
  // vale» borraba el enlace con la bóveda entero: dabas «administra» a un aparato y el
  // aparato desaparecía solo, como si lo hubieran echado. El proxy encola 24 h, así que
  // el aviso puede llegar mucho después de haber renovado.
  if (currentNonce && typeof body.nonce === 'string' && body.nonce !== currentNonce) return false
  return verifyDeviceSig({ publickey: master, data: body, signature })
}

/**
 * Identifica la conexión bajo la pubkey de este dispositivo. Además de hacerlo
 * direccionable, es lo que hace que el proxy le entregue lo que tenía ENCOLADO (24 h) —
 * entre otras cosas, un `vault.revoked` emitido mientras estaba apagado.
 */
async function identifyAsDevice (client, device, { cert = null, acta = null } = {}) {
  if (!client.token) return
  const data = { op: 'identify', publickey: device.publickey, token: client.token, ts: Date.now() }
  const { signature } = await signWithDevice({ privateJwk: device.privateJwk, privateKey: device.privateKey, publickey: device.publickey, data })
  // cert → el proxy enruta lo dirigido a la maestra; acta → lo dirigido a la PERSONA.
  await client.identify({ data, signature, cert, acta })
}


/**
 * La respuesta al `hello` va firmada y con el `sn` DENTRO de lo firmado. Comprobarlo
 * ata la respuesta a ESTA sesión: no vale la de otro emparejamiento ni la de otra
 * bóveda. Ojo con lo que NO prueba: cualquiera puede firmar con una llave suya, así
 * que esto no dice que sea TU bóveda — eso lo dice el código de 6 dígitos, que solo
 * aprende la bóveda donde tú lo tecleas.
 */
async function verificarHola (p, sn) {
  const b = p?.body
  if (!b?.iss || b.sn !== sn) throw new Error('the vault answered a different pairing')
  if (!(await verifyDeviceSig({ publickey: b.iss, data: b, signature: p.signature }))) {
    throw new Error('the vault reply is not properly signed')
  }
  return b
}


/**
 * Canjea la CITA del QR: devuelve la dirección real de la conexión de la bóveda. El
 * código se quema al usarse, así que esto va una sola vez por emparejamiento.
 */
async function canjearCita (client, code) {
  const r = await client.redeemPairingCode(code)
  if (!r?.ok || !r.instance) throw new Error(r?.error || 'that pairing code is no longer valid')
  return r.instance
}

/** «¿Quién eres?» del QR corto: devuelve `{ iss, proxy, acct, m }` de la bóveda. */
async function askVault (client, qr) {
  const destino = await canjearCita(client, qr.conn)
  return new Promise((resolve, reject) => {
    const off = client.on('message', (_from, p) => {
      if (p?.type === MSG.HELLO_OK) { fin(); verificarHola(p, qr.sn).then((b) => resolve({ iss: b.iss, proxy: b.proxy || qr.proxy, acct: b.acct || '', m: b.m || qr.m }), reject) }
      else if (p?.type === MSG.ERROR) { fin(); reject(new Error(p.error)) }
    })
    const t = setTimeout(() => { fin(); reject(new Error('the vault did not answer: that code may have expired')) }, 15000)
    const fin = () => { off(); clearTimeout(t) }
    try { client.send(destino, { type: MSG.HELLO, sn: qr.sn }) } catch (e) { fin(); reject(e) }
  })
}

/**
 * @param {Object} opts
 * @param {{v:number, iss:string, proxy:string, token:string, sn:string}} opts.qr  QR v2 del vault.
 * @param {(c:{deviceId:string, code:string})=>void} [opts.onChallenge]  Para mostrar el código a tipear en el PC.
 * @param {string} [opts.label]
 * @param {number} [opts.approveTimeoutMs]  Espera de la aprobación humana (def 3 min).
 * @returns {Promise<{device, cert, master:string, proxy:string, deviceId:string}>}
 */
export async function enrollDevice ({ qr, device, onChallenge, label = '', continuity = null, encPub = null, approveTimeoutMs = 180000, intent = 'join', profileId = null, onAdopt = null } = {}) {
  if (!qr?.sn || !(qr.iss || qr.conn)) throw new Error('invalid qr: missing vault or nonce')
  const { WebSocketProxyClient } = await import('@dotrino/proxy-client')
  const client = new WebSocketProxyClient({ url: qr.proxy || 'wss://proxy.dotrino.com', enableWebRTC: false, autoReconnect: false })
  await client.connect()
  try {
    // QR CORTO: no trae la llave, solo la dirección de la bóveda en el proxy. Se le
    // pregunta quién es, punto a punto, presentando el `sn`; solo contesta si esa sesión
    // de emparejamiento sigue abierta. Lo que acredita la llave no es el QR: es la firma
    // del certificado y el código de 6 dígitos, que solo aprende la bóveda donde lo tecleas.
    if (!qr.iss) qr = { ...qr, ...(await askVault(client, qr)) }
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
    // `encPub`: la llave de CIFRADO de este dispositivo. Sin ella la bóveda no puede
    // envolverle la clave de contenido del perfil, y entraría sin poder leer nada.
    // `intent` (V7 de `vinculacion-de-cuentas.md`): va DENTRO de lo firmado, y la bóveda
    // rechaza el que no coincida con el modo con el que ella abrió el emparejamiento. Así
    // ninguno de los dos puede hacer, a mitad de camino, algo distinto de lo que el humano
    // vio anunciado en las dos pantallas.
    const adoptar = intent === 'adopt'
    if (adoptar && typeof onAdopt !== 'function') throw new Error('enrollDevice(adopt): falta onAdopt')
    const data = {
      op: 'enroll', dpub: dev.publickey, token: qr.token || qr.sn, sn: qr.sn, commit, label, ts: Date.now(), intent,
      ...(adoptar && profileId ? { profileId } : {}),
      ...(continuity ? { continuity } : {}), ...(encPub ? { encPub } : {})
    }
    const { signature } = await signWithDevice({ privateJwk: dev.privateJwk, privateKey: dev.privateKey, publickey: dev.publickey, data })

    const enrolled = new Promise((resolve, reject) => {
      let sellando = false
      const off = client.on('message', (_from, p) => {
        if (!p || typeof p !== 'object') return
        if (p.type === MSG.ENROLL_CHALLENGE) { try { onChallenge?.({ deviceId, code }) } catch (_) {} }
        // El vault ECHA el código que tipeaste; aceptamos SOLO si coincide con el que generamos.
        // (Un código distinto = un vault que no lo conoce → lo ignoramos y seguimos esperando.)
        else if (p.type === MSG.ENROLLED) { if (p.code === code) { cleanup(); resolve(p) } }
        // CAMINO A · la bóveda dice quién es (con el código de vuelta, misma defensa que el
        // ENROLLED): este aparato la admite en SU acta, le envuelve la clave de contenido y
        // le traspasa el mando, todo en un solo `seq`, y le manda el acta sellada.
        else if (p.type === MSG.ENROLL_ADOPT && adoptar) {
          if (p.code !== code || sellando) return
          sellando = true
          Promise.resolve(onAdopt({ pub: p.pub, encPub: p.encPub || null, label: p.label || '' }))
            .then((acta) => { client.sendByPubkey(qr.iss, { type: MSG.ACTA_SEALED, acta, code }) })
            .catch((e) => { cleanup(); reject(e) })
        }
        // La bóveda ya se vio como sellador y devuelve el acta definitiva (con los certs
        // re-emitidos, §D9). Es la que este aparato adopta.
        else if (p.type === MSG.ACTA_ADOPTED && adoptar) { cleanup(); resolve(p) }
        else if (p.type === MSG.ERROR) { cleanup(); reject(new Error(p.error)) }
      })
      const t = setTimeout(() => { cleanup(); reject(new Error('timeout waiting for approval at the vault')) }, approveTimeoutMs)
      const cleanup = () => { off(); clearTimeout(t) }
    })
    client.sendByPubkey(qr.iss, { type: MSG.ENROLL, data, signature })
    const res = await enrolled

    // Camino A: aquí no hay cert que validar — este aparato NO delega su identidad, sigue
    // siendo la cuenta. Lo que vuelve es el acta ya sellada por la bóveda.
    if (adoptar) {
      if (!res.acta) throw new Error('the vault did not return the adopted record')
      if (res.acta.sealer !== qr.iss) throw new Error('the record is sealed by a vault other than the one you saw')
      return { device: dev, cert: null, master: qr.iss, proxy: qr.proxy, deviceId, acta: res.acta, adopted: true }
    }

    // Validación estricta antes de guardar (cierra inyección de cert / sustitución de maestra).
    const v = await verifyDelegation({ cert: res.cert, expectedSub: dev.publickey })
    if (!v.ok) throw new Error('invalid cert: ' + v.reason)
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
 * Cuánto se espera el aviso FIRMADO de expulsión después de que la bóveda conteste
 * «revoked». Corto a propósito: es el tiempo de un mensaje que ya viene en camino, no una
 * espera de verdad.
 */
const REVOKE_GRACE_MS = 1500

/**
 * Helper genérico: una RPC al vault firmada por D + cert, esperando `okType`.
 *
 * Se identifica al conectar para que el proxy entregue lo ENCOLADO: si mientras el
 * dispositivo estaba apagado la bóveda emitió un `vault.revoked` firmado, llega aquí y se
 * ejecuta el autoborrado (`onRevoked`) tras verificar la firma contra la maestra pineada.
 */
async function vaultRpc ({ master, proxy, device, cert, acta = null, sendType, okType, data, onRevoked, timeoutMs = 15000 }) {
  if (!master || !proxy || !(device?.privateJwk || device?.privateKey) || !cert) throw new Error('faltan datos de emparejamiento')
  const { WebSocketProxyClient } = await import('@dotrino/proxy-client')
  const client = new WebSocketProxyClient({ url: proxy, enableWebRTC: false, autoReconnect: false })
  await client.connect()
  try {
    try { await identifyAsDevice(client, device, { cert, acta }) } catch (_) { /* sin identify seguimos: solo perdemos la cola */ }
    const signed = { ...data, publickey: device.publickey, ts: Date.now() }
    const { signature } = await signWithDevice({ privateJwk: device.privateJwk, privateKey: device.privateKey, publickey: device.publickey, data: signed })
    const pending = new Promise((resolve, reject) => {
      let graceTimer = null
      const off = client.on('message', (_f, p) => {
        if (!p || typeof p !== 'object') return
        if (p.type === MSG.REVOKED) {
          isAuthenticRevoke({ body: p.body, signature: p.signature, master, devicePubkey: device.publickey, currentNonce: cert?.nonce || null })
            .then((ok) => { if (ok) { try { onRevoked?.() } catch (_) {} } })
            .catch(() => {})
          return
        }
        if (p.type === okType) { cleanup(); resolve(p) }
        else if (p.type === 'vault.error') {
          // «Te echaron» llega en DOS mensajes: este error (que no va firmado, así que no
          // puede borrar nada — wipe-DoS) y el `vault.revoked` FIRMADO, que es el único que
          // sí. Cerrar el socket al recibir el primero era llegar a cerrar la puerta justo
          // antes que el segundo, y entonces el aparato se quedaba con la cuenta puesta
          // hasta vaya a saber cuándo. Se le da un respiro corto para recogerlo.
          if (/\brevoked\b/.test(p.error || '') && !graceTimer) {
            graceTimer = setTimeout(() => { cleanup(); reject(new Error(p.error)) }, REVOKE_GRACE_MS)
            return
          }
          cleanup(); reject(new Error(p.error))
        }
      })
      const t = setTimeout(() => { cleanup(); reject(new Error('the vault did not reply (is it running?)')) }, timeoutMs)
      const cleanup = () => { off(); clearTimeout(t); clearTimeout(graceTimer) }
    })
    client.sendByPubkey(master, { type: sendType, data: signed, signature, cert })
    return await pending
  } finally { try { client.close() } catch (_) {} }
}

/**
 * PREGUNTA SIN CERTIFICADO: «¿sigo estando en el acta?».
 *
 * Es el único camino que le queda al aparato que perdió su papel — sin cert no puede
 * firmar, ni leer, ni renovar, así que tampoco podía enterarse de que lo habían echado y se
 * quedaba enseñando una cuenta que ya no era suya. Va firmada con SU llave, que es lo que
 * el acta nombra.
 *
 * La bóveda contesta sí o no, y nada más. Si el no viene acompañado del aviso FIRMADO de
 * expulsión, ESE es el que borra la cuenta aquí (`onRevoked`); el «no» pelado no borra
 * nada, como cualquier otro mensaje sin firma.
 */
export async function checkMembership ({ master, proxy, device, onRevoked, timeoutMs = 12000 } = {}) {
  if (!master || !proxy || !(device?.privateJwk || device?.privateKey)) throw new Error('faltan datos del dispositivo')
  const { WebSocketProxyClient } = await import('@dotrino/proxy-client')
  const client = new WebSocketProxyClient({ url: proxy, enableWebRTC: false, autoReconnect: false })
  await client.connect()
  try {
    // Identificarse hace además que el proxy entregue lo ENCOLADO (un aviso de cuando
    // estaba apagado, si todavía está dentro de las 24 h).
    try { await identifyAsDevice(client, device) } catch (_) {}
    const data = { op: 'check', publickey: device.publickey, ts: Date.now() }
    const { signature } = await signWithDevice({ privateJwk: device.privateJwk, privateKey: device.privateKey, publickey: device.publickey, data })
    const res = await new Promise((resolve) => {
      let hecho = false
      const fin = (v) => { if (!hecho) { hecho = true; cleanup(); resolve(v) } }
      const off = client.on('message', (_f, p) => {
        if (!p || typeof p !== 'object') return
        if (p.type === MSG.REVOKED) {
          isAuthenticRevoke({ body: p.body, signature: p.signature, master, devicePubkey: device.publickey, currentNonce: null })
            .then((ok) => { if (ok) { try { onRevoked?.() } catch (_) {} ; fin({ in: false, wiped: true }) } })
            .catch(() => {})
          return
        }
        if (p.type === MSG.CHECKED) fin({ in: !!p.in })
        else if (p.type === MSG.ERROR) fin({ error: p.error })
      })
      const t = setTimeout(() => fin({ error: 'the vault did not reply' }), timeoutMs)
      const cleanup = () => { off(); clearTimeout(t) }
      client.sendByPubkey(master, { type: MSG.CHECK, data, signature })
    })
    return res
  } finally { try { client.close() } catch (_) {} }
}

/** Lee/escribe el store de hilos+aperturas EN el vault (con el cert del dispositivo). */
export async function requestStore ({ master, proxy, device, cert, method, args, enc, onRevoked } = {}) {
  // `enc`: argumentos cifrados con la clave de contenido del perfil (el proxy no los ve).
  const data = enc ? { op: 'store', method, enc } : { op: 'store', method, args: args || {} }
  const res = await vaultRpc({ master, proxy, device, cert, onRevoked, sendType: 'vault.store', okType: 'vault.store.result', data })
  return res.result
}

/** Lista (solo lectura) los dispositivos enrolados en tu vault. */
export async function requestDevices ({ master, proxy, device, cert, sinceSeq, onRevoked } = {}) {
  const data = typeof sinceSeq === 'number' ? { op: 'devices', sinceSeq } : { op: 'devices' }
  const res = await vaultRpc({ master, proxy, device, cert, onRevoked, sendType: 'vault.devices', okType: 'vault.devices.result', data })
  return { devices: res.devices || [], revoked: res.revoked || [], acta: res.acta || null, chain: res.chain || null }
}

/**
 * RENUEVA el cert de este dispositivo (requiere el cert aún VIGENTE y no revocado):
 * el vault firma uno fresco para la misma sub-clave y scope, sin QR ni aprobación.
 * @returns {Promise<{ cert: object }>}
 */
export async function requestRenew ({ master, proxy, device, cert, onRevoked } = {}) {
  const res = await vaultRpc({ master, proxy, device, cert, onRevoked, sendType: 'vault.renew', okType: 'vault.renewed', data: { op: 'renew' } })
  if (!res.cert || res.cert.sub !== device.publickey || res.cert.iss !== master) throw new Error('invalid renewed cert')
  return { cert: res.cert }
}

/**
 * Manda a la bóveda la RENUNCIA de este dispositivo para que la selle en el acta.
 *
 * Sin esto, renunciar solo valía en el propio aparato: la bóveda seguía teniendo escrito
 * que podía firmar, le seguía aceptando peticiones, y cualquiera que mirara el acta lo
 * seguía viendo como firmante. Una renuncia que no llega al acta no es oponible a nadie —
 * y en el caso que la justifica (te robaron el aparato) su registro local no vale nada,
 * porque lo borra quien lo tenga en la mano.
 *
 * El `record` va FIRMADO por el propio miembro y solo puede QUITAR, así que la bóveda no
 * necesita comprobar ningún certificado para honrarlo: le basta la firma.
 */
export async function requestRenounce ({ master, proxy, device, cert, record, onRevoked } = {}) {
  const res = await vaultRpc({
    master, proxy, device, cert, onRevoked,
    sendType: MSG.RENOUNCE, okType: MSG.RENOUNCE_RESULT, data: { op: 'renounce', record }
  })
  return { ok: !!res.ok, seq: res.seq ?? null }
}

/**
 * CONSOLA REMOTA (`dotrino-vault/docs/consola-remota.md`): administrar el perfil desde
 * este dispositivo, sin ir al PC. Requiere un cert con scope `vault:admin`, que **no se
 * recibe al emparejar** — se concede a mano en la bóveda.
 *
 * `op`: `pending` · `pair` · `approve` · `reject` · `revoke` · `audit`. Lo que NO existe
 * aquí es tan importante como lo que sí: cambiar permisos, traspasar el mando y los
 * secretos de servicios no se administran a distancia.
 *
 * El `nonce` de un solo uso va en cada petición porque `approve` y `revoke` cambian
 * estado, y para eso la ventana de frescura de ±5 min no alcanza.
 */
export async function requestAdmin ({ master, proxy, device, cert, op, onRevoked, ...rest } = {}) {
  const nonce = [...crypto.getRandomValues(new Uint8Array(16))]
    .map((b) => b.toString(16).padStart(2, '0')).join('')
  const res = await vaultRpc({
    master, proxy, device, cert, onRevoked,
    sendType: MSG.ADMIN, okType: MSG.ADMIN_RESULT,
    data: { op, ...rest, nonce }
  })
  return res.result
}

/**
 * PEDIDOS DE APROBACIÓN (cajones con `approval`): `approvals` (listar) · `approve` ·
 * `deny`. Van por `vault.secrets`, firmados por un aparato cuyo cert lleve
 * `vault:approve` — que, como `admin`, no se recibe al emparejar: se concede a mano.
 * La bóveda contesta un cuerpo firmado por la maestra (`{ op, items | ok }`).
 */
export async function requestApproval ({ master, proxy, device, cert, op, id, onRevoked } = {}) {
  const res = await vaultRpc({
    master, proxy, device, cert, onRevoked,
    sendType: MSG.SECRETS, okType: MSG.SECRETS_RESULT,
    data: id ? { op, id } : { op }
  })
  return res.body
}

/**
 * ¿Es AUTÉNTICO este `vault.admin.event` (entró o salió alguien del perfil)? Solo si va
 * firmado por la maestra PINEADA. Un aviso sin firma no se muestra: si no, cualquiera
 * podría llenar de alarmas falsas los dispositivos del usuario.
 */
export async function isAuthenticAdminEvent ({ body, signature, master }) {
  if (!body || typeof body.ev !== 'string') return false
  return verifyDeviceSig({ publickey: master, data: body, signature })
}
