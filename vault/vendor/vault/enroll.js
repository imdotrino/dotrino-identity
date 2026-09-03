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
import { verifyContinuity, canSeal } from '@dotrino/identity/acta'

/** Un token de emparejamiento vale 5 min. */
export const PAIRING_TTL_MS = 5 * 60 * 1000
/** Ventana anti-replay del ENROLL (±5 min), mismo criterio que el identify del proxy. */
export const FRESH_WINDOW_MS = 5 * 60 * 1000
/** Vida por defecto del cert de un dispositivo (tope duro de `MAX_DELEGATION_MS`). */
export const DEVICE_TTL_MS = 30 * 24 * 60 * 60 * 1000

export const MSG_HELLO = 'vault.hello'
export const MSG_HELLO_OK = 'vault.hello.ok'
export const MSG_ENROLL = 'vault.enroll'
export const MSG_ENROLL_CHALLENGE = 'vault.enroll.challenge'
export const MSG_ENROLLED = 'vault.enrolled'
// --- camino A: la cuenta del aparato pasa a vivir en la bóveda ---
export const MSG_ENROLL_ADOPT = 'vault.enroll.adopt'
export const MSG_ACTA_SEALED = 'vault.acta.sealed'
export const MSG_ACTA_ADOPTED = 'vault.acta.adopted'
export const MSG_REVOKED = 'vault.revoked'
export const MSG_ERROR = 'vault.error'

/** Los scopes del cert se corresponden 1:1 con las capacidades del acta (§D7). */
const SCOPE_TO_CAP = {
  'vault:sign': 'sign',
  'vault:store': 'store',
  'vault:read': 'read',
  'vault:admin': 'admin',
  'vault:passwords': 'passwords',
  // `replica` SÍ se empareja, al revés que `sealer` y `admin`. La razón es la misma que
  // hace estrecho al permiso: un replicador reparte sobres que no puede abrir y no cambia
  // nada. Y se despliega sin teclado —un contenedor, una máquina ajena—, que es justo
  // donde obligar a un segundo paso a mano es el paso que nadie da.
  'vault:replica': 'replica'
}
export const scopeToCaps = (scope) =>
  (Array.isArray(scope) ? scope : [scope]).map((s) => SCOPE_TO_CAP[s]).filter(Boolean)

/**
 * El CN de un servicio sale de su scope: `vault:secrets:proxy` ⇒ CN `proxy`. Con CN, el
 * miembro entra al acta como SERVICIO —solo abre su propio cajón— en vez de como un
 * dispositivo del usuario. Es la frontera, y vive en el acta para que se pueda comprobar.
 */
export function scopeToCn (scope) {
  for (const s of (Array.isArray(scope) ? scope : [scope])) {
    const m = /^vault:secrets:([a-z0-9-]{1,32})$/.exec(String(s || ''))
    if (m) return m[1]
  }
  return null
}

/**
 * Token aleatorio en hex (16 bytes = 128 bits por defecto).
 *
 * El emparejamiento pide 12 (96 bits): son de un solo uso, valen 5 minutos y hay
 * UNA sesión viva a la vez, así que adivinarlo es 2^95 intentos contra una bóveda
 * que además exige el código de 6 dígitos. A cambio, cada byte de menos son ~1,4
 * caracteres menos en el QR — y el QR se mide en filas de terminal.
 */
export function randToken (bytes = 16) {
  const b = crypto.getRandomValues(new Uint8Array(bytes))
  return [...b].map((x) => x.toString(16).padStart(2, '0')).join('')
}

/** Tamaño del token/nonce de una sesión de emparejamiento (ver `randToken`). */
const PAIR_TOKEN_BYTES = 12

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
 * @param {(sub:string)=>void} [opts.onDeviceRemoved]  se quitó un aparato (fuera del acta y sin papeles):
 *   para que quien guarde algo indexado por esa llave lo suelte. Se avisa desde AQUÍ y no desde
 *   quien llama porque a `revokeDevice` se entra por dos puertas (el PC y la consola remota).
 * @param {string[]} [opts.defaultScope]
 * @param {number} [opts.defaultTtlMs]
 */
export function createEnrollDesk ({
  identity, iss, proxy, send, sendByPubkey,
  audit = () => {}, log = () => {},
  onChallenge = () => {}, onPendingChange = () => {}, onAdopted = () => {}, onDeviceRemoved = () => {},
  defaultScope = ['vault:sign'], defaultTtlMs = DEVICE_TTL_MS,
  // Camino A: lo que ESTA bóveda le manda al aparato para que la meta en su acta. `encPub`
  // es su llave de CIFRADO — sin ella entra mandando pero sin poder leer el contenido.
  encPub = null, vaultLabel = '',
  // Token de CONEXIÓN de esta bóveda en el proxy (4 chars): su dirección. Es lo
  // único que necesita el QR corto para que el aparato le hable punto a punto.
  connToken = null
} = {}) {
  if (!identity) throw new Error('createEnrollDesk: missing identity')
  if (!iss) throw new Error('createEnrollDesk: missing iss (master pubkey)')

  // token -> { token, exp, scope, ttlMs, label, sn, state, dpub?, deviceId?, commit?, from? }
  // state: 'AWAITING_ENROLL' -> 'PENDING_CONFIRM'
  const pending = new Map()

  const fire = (fn, arg) => { try { fn(arg) } catch (_) {} }
  const reply = (to, obj) => { try { send(to, obj) } catch (e) { log('[vault] could not reply:', e.message) } }
  const isFresh = (d) => typeof d?.ts === 'number' && Math.abs(Date.now() - d.ts) <= FRESH_WINDOW_MS

  /**
   * Inicia un emparejamiento: token + nonce de sesión. NO firma nada todavía.
   *
   * `mode` y `account` son LO QUE LA BÓVEDA DECLARA que va a pasar, y viajan en el QR
   * para que el aparato pueda **decirlo antes de hacerlo** en vez de emparejar a
   * ciegas (decisión V9 de `docs/vinculacion-de-cuentas.md`: pregunta el vault, el
   * dispositivo muestra el proceso y sus consecuencias):
   *
   *   · `mode: 'join'`  → el dispositivo estrena una cuenta suya y entra a la de la
   *                       bóveda. Es lo único que existe hoy.
   *   · `mode: 'adopt'` → la bóveda se quedaría con la cuenta que trae el aparato
   *                       (camino A). Reservado: todavía no hay protocolo.
   *   · `account`       → cómo se llama la cuenta de la bóveda, para nombrarla en el
   *                       aviso. Es ORIENTATIVO (un nombre que puso su dueño); la
   *                       identidad de verdad de la cuenta es `iss`.
   */
  async function startPairing ({ scope = defaultScope, ttlMs = defaultTtlMs, label = '', mode = 'join', account = '' } = {}) {
    pending.clear() // uno a la vez: una sesión nueva supersede a la anterior
    const acct = String(account || '').slice(0, 40)
    // INVITACIÓN CORTA: si sabemos cómo alcanzarnos, el QR lleva solo eso y el
    // nonce de la sesión. La llave, el proxy y el nombre de la cuenta los pide el
    // aparato por la red presentando el `sn`. El nonce hace de identificador de
    // sesión: no hace falta un token de emparejamiento aparte.
    //
    // `conn` es una CITA del proxio (6 caracteres, un solo uso, caduca en
    // minutos), no la dirección de la conexión: esa pasó a ser una instancia de
    // 24 caracteres, que ni entra cómoda en un QR ni tiene por qué quedar impresa
    // en algo que circula. Por eso se pide una nueva por emparejamiento, y por
    // eso esto es asíncrono.
    const conn = typeof connToken === 'function' ? await connToken() : connToken
    if (conn) {
      const sn = randToken(8)
      pending.set(sn, { token: sn, exp: Date.now() + PAIRING_TTL_MS, scope, ttlMs, label, sn, mode, account: acct, state: 'AWAITING_ENROLL' })
      return { token: sn, qr: { v: 2, conn, sn, m: mode, proxy }, expiresInMs: PAIRING_TTL_MS }
    }
    const token = randToken(PAIR_TOKEN_BYTES)
    const sn = randToken(PAIR_TOKEN_BYTES)
    pending.set(token, { token, exp: Date.now() + PAIRING_TTL_MS, scope, ttlMs, label, sn, mode, account: acct, state: 'AWAITING_ENROLL' })
    return { token, qr: { v: 2, iss, proxy, token, sn, m: mode, ...(acct ? { acct } : {}) }, expiresInMs: PAIRING_TTL_MS }
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
   * «¿Quién eres?» — la respuesta al QR corto. Solo se contesta a quien presente el
   * `sn` de una sesión VIVA: el token de conexión son 4 caracteres y se puede acertar
   * a ciegas, el `sn` no. Fuera de un emparejamiento no hay ninguna sesión y por lo
   * tanto no hay respuesta: la puerta solo está abierta mientras dura el `pair`.
   */
  async function handleHello (from, p) {
    const pend = pending.get(String(p?.sn || ''))
    if (!pend || Date.now() > pend.exp) {
      audit('rejected', { what: 'hello', reason: 'sin-sesion' })
      return reply(from, { type: MSG_ERROR, error: 'no pairing session open for that code' })
    }
    // La respuesta va FIRMADA por la maestra y el `sn` va dentro de lo firmado. Eso ata
    // la respuesta a ESTA sesión: no se puede reutilizar la de otro emparejamiento ni la
    // de otra bóveda. Lo que NO hace es demostrar que sea TU bóveda —cualquiera puede
    // firmar con una llave suya—; eso solo lo demuestra el código de 6 dígitos.
    const body = { op: 'hello', sn: pend.sn, iss, proxy, acct: pend.account || '', m: pend.mode || 'join', ts: Date.now() }
    const { signature } = await identity.signData(body)
    reply(from, { type: MSG_HELLO_OK, body, signature })
    return { ok: true }
  }

  /**
   * ENROLL: el dispositivo prueba posesión de `D` firmando el sobre y deja el
   * COMPROMISO de su código. Todavía NO se firma ningún cert.
   */
  async function handleEnroll (from, p) {
    const d = p?.data
    if (!d || typeof d.dpub !== 'string' || typeof p.signature !== 'string') {
      return reply(from, { type: MSG_ERROR, error: 'invalid enroll' })
    }
    const pend = pending.get(d.token)
    if (!pend || pend.state === 'DONE' || Date.now() > pend.exp) {
      return reply(from, { type: MSG_ERROR, error: 'invalid or expired pairing token' })
    }
    if (d.sn !== pend.sn) return reply(from, { type: MSG_ERROR, error: 'invalid session' })
    // V7 · la INTENCIÓN viaja firmada y tiene que coincidir con el modo con el que ESTA
    // bóveda abrió el emparejamiento. Es lo que garantiza que lo que pasa es lo que el
    // humano vio anunciado en las dos pantallas, y no algo que se decidió a mitad de camino.
    const intent = d.intent || 'join'
    if (intent !== 'join' && intent !== 'adopt') {
      return reply(from, { type: MSG_ERROR, error: 'unknown intent: ' + intent })
    }
    if (intent !== (pend.mode || 'join')) {
      audit('rejected', { what: 'enroll', reason: 'intent-mismatch' })
      return reply(from, { type: MSG_ERROR, error: `this pairing was opened for "${pend.mode || 'join'}" and the device asked for "${intent}"` })
    }
    if (!isFresh(d)) {
      audit('rejected', { what: 'enroll', reason: 'stale' })
      return reply(from, { type: MSG_ERROR, error: 'stale request: ts outside the ±5 min window (possible replay, or the device clock is off)' })
    }
    // PRUEBA DE POSESIÓN: la firma de `data` debe verificar contra `dpub`.
    if (!(await verifyDeviceSig({ publickey: d.dpub, data: d, signature: p.signature }))) {
      audit('rejected', { what: 'enroll', reason: 'bad-device-signature' })
      return reply(from, { type: MSG_ERROR, error: 'invalid device signature' })
    }
    // El COMPROMISO del código es obligatorio: sin él no se puede comprobar al aprobar
    // y volveríamos a emitir certs a ciegas. Un cliente viejo cae acá con un mensaje claro.
    if (typeof d.commit !== 'string' || !/^[0-9a-f]{64}$/.test(d.commit)) {
      audit('rejected', { what: 'enroll', reason: 'no-commit' })
      return reply(from, { type: MSG_ERROR, error: 'this device speaks an old pairing version (no code commitment). Update it and try again.' })
    }
    // Un solo dispositivo a la vez esperando su código (así aprobar no es ambiguo).
    if (pend.state === 'PENDING_CONFIRM' && pend.dpub && pend.dpub !== d.dpub) {
      return reply(from, { type: MSG_ERROR, error: 'another device is already using this pairing session' })
    }

    const deviceId = await deviceIdOf(d.dpub)
    pend.state = 'PENDING_CONFIRM'
    pend.dpub = d.dpub
    pend.deviceId = deviceId
    pend.commit = d.commit
    // Llave de CIFRADO del dispositivo: con ella se le envuelve la clave del cajón al
    // admitirlo. Un SERVICIO sin ella entraría al acta y no podría leer NUNCA ninguna
    // variable —las privadas van selladas a esta llave—, así que se corta aquí en vez
    // de admitirlo y dejar que falle más tarde y en otro sitio. Un dispositivo de
    // persona sí puede entrar sin ella: no lee variables de servicio.
    if (typeof d.encPub === 'string') pend.encPub = d.encPub
    if (!pend.encPub && scopeToCn(pend.scope)) {
      return reply(from, { type: MSG_ERROR, error: 'a service must send its encryption key (update @dotrino/vault on the service)' })
    }
    // Certificado de continuidad (opcional): lo firma la identidad que se une, con su
    // propia llave. Se comprueba aquí y se guarda con el miembro al aprobar.
    if (d.continuity) {
      const okC = await verifyContinuity(d.continuity)
      pend.continuity = (okC && d.continuity.member === d.dpub) ? d.continuity : null
    }
    pend.from = from // la bóveda NO conoce el código: lo aprende cuando lo tipeas
    // EL NOMBRE QUE PUSISTE AQUÍ MANDA. El aparato manda el suyo al enrolarse, y hasta
    // ahora pisaba siempre al de la bóveda — como el aparato usa por defecto el apodo del
    // PERFIL, acababas con varios dispositivos llamados igual que tú y sin forma de saber
    // cuál era cuál. Si en `pair` le diste un nombre, ese es el nombre; el del aparato
    // sigue valiendo como propuesta cuando no dijiste nada.
    if (d.label && !pend.label) pend.label = String(d.label).slice(0, 60)
    // Camino A: de qué cuenta estamos hablando. Se guarda para poder comprobar, cuando
    // llegue el acta sellada, que es la que este dispositivo dijo que iba a entregar.
    if (intent === 'adopt' && typeof d.profileId === 'string') pend.profileId = d.profileId

    reply(from, { type: MSG_ENROLL_CHALLENGE, deviceId })
    fire(onChallenge, { deviceId, scope: pend.scope, label: pend.label || '', mode: pend.mode || 'join' })
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
    if (!code) throw new Error('missing code (the digits shown by the device)')

    let pend
    if (deviceId) {
      pend = findPending(deviceId)
      if (!pend) throw new Error('no device awaiting approval with that id')
    } else {
      const waiting = [...pending.values()].filter((p) => p.state === 'PENDING_CONFIRM' && p.dpub)
      if (waiting.length === 0) throw new Error('no device awaiting approval')
      if (waiting.length > 1) throw new Error('more than one pairing in flight; restart it with dotrino-vault pair')
      pend = waiting[0]
    }

    // COMPROBACIÓN DEL CÓDIGO — antes de firmar nada.
    const expected = await commitCode({ code, dpub: pend.dpub, sn: pend.sn })
    if (expected !== pend.commit) {
      audit('rejected', { what: 'approve', device: pend.deviceId, reason: 'bad-code' })
      log('[vault] wrong code for %s: no certificate was issued', pend.deviceId)
      throw new Error('code does not match the one shown by the device: no certificate was issued. Check it and try again.')
    }

    // CAMINO A · aquí la bóveda no entrega un cert: entrega SU IDENTIDAD para que el
    // aparato la meta en el acta de la cuenta que le está pasando. El código de vuelta es
    // la misma defensa de siempre, en el otro sentido: el aparato solo hace caso a una
    // bóveda que demuestre que un humano la aprobó.
    if ((pend.mode || 'join') === 'adopt') {
      audit('adopt-approve', { device: pend.deviceId, profile: pend.profileId || null })
      pend.state = 'AWAITING_ACTA'
      pend.approvedAt = Date.now()
      reply(pend.from, { type: MSG_ENROLL_ADOPT, code, pub: iss, encPub: encPub || null, label: vaultLabel || '' })
      log('[vault] adoption approved for %s: waiting for the sealed record', pend.deviceId)
      fire(onPendingChange)
      return { ok: true, deviceId: pend.deviceId, adopting: true }
    }

    const { cert } = await identity.signDelegation(pend.dpub, pend.scope, { ttlMs: pend.ttlMs, label: pend.label })

    // Aprobar un emparejamiento ES admitir al dispositivo en el perfil: el cert es la
    // credencial y el acta es la política, y no tiene sentido emitir una sin la otra.
    // Las capacidades salen del scope que se pidió al emparejar (cert ∩ acta, §2.3).
    let record = null
    try {
      if (typeof identity.admitMember === 'function') {
        // PERMISOS, no tipos (2026-08-22): las capacidades son las del scope ENTERO. Un
        // cajón (`secrets:<ns>`) suma `secrets` y fija el CN; no borra lo demás — un bot
        // con `sign,secrets:eco` firma como aparato del acta Y lee solo su cajón.
        const cn = scopeToCn(pend.scope)
        const caps = [...new Set([...scopeToCaps(pend.scope), ...(cn ? ['secrets'] : [])])]
        if (caps.length) await identity.admitMember({ pub: pend.dpub, encPub: pend.encPub || null, label: pend.label || '', cn, caps, cert, continuity: pend.continuity || null })
      }
      record = (await identity.profileActa?.())?.acta || null
    } catch (e) { log('[vault] could not admit into the record:', e.message) }

    audit('enroll', { device: pend.deviceId, label: pend.label || '', scope: pend.scope })
    // Echamos el código tipeado junto al cert: el DISPOSITIVO acepta solo si coincide
    // con el que generó → una bóveda falsa (que no lo conoce) no puede enrolarlo.
    // El acta viaja con el cert: el dispositivo ya sabe de quién es el perfil al que entra.
    reply(pend.from, { type: MSG_ENROLLED, code, cert, iss, acta: record })
    pend.state = 'DONE'
    pending.delete(pend.token)
    fire(onPendingChange)
    log(`[vault] device approved: ${pend.deviceId}`)
    return { ok: true, deviceId: pend.deviceId, cert }
  }

  /**
   * CAMINO A · paso 6: llega el acta que el aparato acaba de sellar, con la bóveda dentro
   * como miembro, la clave de contenido envuelta para ella y el mando ya traspasado.
   *
   * Lo que se comprueba antes de guardar nada (y por qué):
   *   · que el sellador sea ESTA bóveda — si no, no es un traspaso, es un acta ajena;
   *   · que la selle el aparato que estaba en este emparejamiento — cierra que un tercero
   *     que vea pasar el mensaje cuele la suya;
   *   · que sea la cuenta que ese aparato declaró al enrolarse (`profileId`) — cierra el
   *     cambiazo de cuenta entre el anuncio que leyó el humano y lo que llega después.
   *
   * Adoptar la cuenta de otro solo procede sobre un perfil que **nació para eso** (la marca
   * de `prepareForAdoption`). Es la misma regla del navegador: sin la marca, adoptar sería
   * pisar una cuenta con datos, y eso no puede pasar por accidente.
   */
  async function handleActaSealed (from, p) {
    const record = p?.acta
    const pend = [...pending.values()].find((x) => x.state === 'AWAITING_ACTA' && (x.from === from || x.dpub))
    if (!pend) return reply(from, { type: MSG_ERROR, error: 'no adoption awaiting a record' })
    if (!record || typeof record !== 'object') return reply(from, { type: MSG_ERROR, error: 'record missing or unreadable' })
    // Ya no hay campo `sealer`: se le pregunta al PERMISO. Es la misma comprobación —«¿me
    // nombra a mí la que me mandan?»— dicha en el idioma nuevo, y con varios selladores la
    // respuesta puede ser que sí para más de uno, que es lo correcto.
    if (!canSeal(record, iss)) {
      audit('rejected', { what: 'adopt', reason: 'not-sealer' })
      return reply(from, { type: MSG_ERROR, error: 'that record does not let this vault seal it' })
    }
    if (record.sealedBy !== pend.dpub) {
      audit('rejected', { what: 'adopt', reason: 'sealed-by-other' })
      return reply(from, { type: MSG_ERROR, error: 'that record was not sealed by the device of this pairing' })
    }
    if (pend.profileId && record.profileId !== pend.profileId) {
      audit('rejected', { what: 'adopt', reason: 'other-profile' })
      return reply(from, { type: MSG_ERROR, error: 'that record belongs to an account other than the one the device announced' })
    }

    try {
      const r = await identity.joinProfile(record)
      if (!r?.joined) throw new Error(r?.reason || 'could not adopt')
      audit('adopt', { device: pend.deviceId, profile: record.profileId, seq: record.seq })
      // El acta que vuelve es la que la bóveda tiene guardada: el aparato la adopta y los
      // dos quedan en la misma versión.
      const mine = (await identity.profileActa?.())?.acta || record
      reply(pend.from, { type: MSG_ACTA_ADOPTED, code: p.code, acta: mine })
      pend.state = 'DONE'
      pending.delete(pend.token)
      fire(onPendingChange)
      fire(onAdopted, { deviceId: pend.deviceId, profileId: record.profileId, seq: mine.seq })
      log('[vault] account adopted from device %s (profile %s)', pend.deviceId, record.profileId?.slice(0, 12))
      return { ok: true, adopted: true, profileId: record.profileId, seq: mine.seq }
    } catch (e) {
      log('[vault] could not adopt the account: %s', e.message)
      reply(pend.from, { type: MSG_ERROR, error: 'the vault could not adopt the account: ' + e.message })
      return { ok: false, error: e.message }
    }
  }

  /** Rechaza un enrolamiento pendiente. */
  function reject (deviceId) {
    const pend = deviceId
      ? findPending(deviceId)
      : [...pending.values()].find((p) => p.state === 'PENDING_CONFIRM')
    if (!pend) return { ok: false }
    reply(pend.from, { type: MSG_ERROR, error: 'pairing rejected' })
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
    catch (e) { log('[vault] could not emit revoke:', e.message) }
  }

  /** Revoca una delegación por `nonce` y avisa al dispositivo para que se autoborre. */
  async function revoke (nonce) {
    audit('revoke', { nonce })
    const { issued } = await identity.listDelegations()
    const delegation = (issued || []).find((d) => d.nonce === nonce)
    const res = await identity.revokeDelegation(nonce)
    if (delegation?.sub) await emitRevoke(delegation.sub, nonce)
    return res
  }

  /**
   * QUITA EL DISPOSITIVO entero: retira TODOS sus certificados vigentes y le manda una
   * sola orden de autoborrado. `revoke(nonce)` retira un papel, y un aparato puede tener
   * varios (una renovación dejaba vivo el anterior): quitarle uno no lo echaba, y podía
   * quedarse dentro justo con el que llevaba `vault:admin`.
   */
  async function revokeDevice (sub) {
    if (!sub) throw new Error('sub (device pubkey) required')
    const { issued } = await identity.listDelegations()
    const mine = (issued || []).filter((d) => d.sub === sub)
    audit('revoke-device', { certs: mine.length })
    // Si el núcleo no trae `revokeDevice` (bóveda vieja), se cae a retirarlos uno a uno.
    const res = identity.revokeDevice
      ? await identity.revokeDevice(sub)
      : { ok: true, nonces: await (async () => {
          const done = []
          for (const d of mine) { await identity.revokeDelegation(d.nonce); done.push(d.nonce) }
          return done
        })() }
    await emitRevoke(sub, mine[0]?.nonce || null)
    fire(onDeviceRemoved, sub)
    return res
  }

  return {
    startPairing, stopPairing, handleEnroll, handleActaSealed, handleHello, approve, reject,
    listPending, findPending, emitRevoke, revoke, revokeDevice,
    get pendingCount () { return pending.size }
  }
}

export default { createEnrollDesk, deviceIdOf, randToken }
