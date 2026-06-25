import { buildSignedChannel, getPublicKeyJwk, signData } from './signature.js'
import { WebRTCManager, RTC_TAG } from './webrtc.js'

/**
 * Dotrino WebSocket proxy client.
 * Minimal API: connection + token + messages + channels (publish/list/count/disconnect)
 * with ECDSA P-256 signed envelopes.
 *
 * Events emitted:
 *   - 'connect'           ()                          : socket open
 *   - 'token'             (token)                     : token assigned by proxy
 *   - 'disconnect'        ({code, reason})            : socket closed
 *   - 'error'             (errorObj)                  : transport or server error
 *   - 'message'           (from, payload, raw)        : incoming peer message
 *   - 'channel_joined'    (channel, token)            : new peer joined the channel
 *   - 'channel_left'      (channel, token)            : peer unpublished
 *   - 'peer_disconnected' (token, channel?)           : peer dropped (with channel if it was published there)
 *   - 'reconnecting'      (attempt, max)
 *   - 'reconnect_failed'  (attempts)
 */
export class WebSocketProxyClient {
  constructor (options = {}) {
    this.url = options.url || 'wss://proxy.dotrino.com'
    this.autoReconnect = options.autoReconnect !== false
    this.maxReconnectAttempts = options.maxReconnectAttempts ?? 5
    this.reconnectDelay = options.reconnectDelay ?? 3000
    this.enableWebRTC = options.enableWebRTC !== false
    this.iceServers = options.iceServers || null

    // Heartbeat de aplicación: el WebSocket del browser NO expone ping/pong de
    // protocolo, así que mandamos `{type:'ping'}` y esperamos cualquier tráfico
    // de vuelta (el server responde `pong`). Si no hay respuesta en
    // `heartbeatTimeout`, la conexión está "half-open" (TCP muerto sin FIN) y
    // forzamos la reconexión. Sin esto, una caída silenciosa pasa inadvertida y
    // los `send` se pierden en el vacío.
    this.enableHeartbeat = options.enableHeartbeat !== false
    this.heartbeatInterval = options.heartbeatInterval ?? 20000
    this.heartbeatTimeout = options.heartbeatTimeout ?? 8000
    this._hbTimer = null
    this._hbDeadTimer = null

    this.ws = null
    this.token = null
    this._connected = false
    this._reconnectAttempts = 0
    this._reconnectTimer = null
    this._handlers = new Map()
    this._pending = new Map() // messageId -> { resolve, reject, timer }
    this._nextId = 1

    this._rtc = this.enableWebRTC ? new WebRTCManager({
      getSelfToken: () => this.token,
      signalSend: (to, payload) => this._proxySendOne(to, payload),
      deliverMessage: (from, parsed, meta) => this._emit('message', from, parsed, meta),
      emit: (event, ...args) => this._emit(event, ...args),
      config: this.iceServers ? { iceServers: this.iceServers } : null
    }) : null
  }

  // ---------- public API ----------

  get isConnected () { return this._connected }

  connect () {
    return new Promise((resolve, reject) => {
      if (this._connected) return resolve(this.token)
      this._connectResolve = resolve
      this._connectReject = reject
      this._open()
    })
  }

  close () {
    this.autoReconnect = false
    if (this._reconnectTimer) {
      clearTimeout(this._reconnectTimer)
      this._reconnectTimer = null
    }
    if (this._rtc) this._rtc.closeAll()
    if (this.ws) {
      try { this.ws.close(1000) } catch (_) {}
    }
  }

  /** Alias for close() to ease migration from older clients. */
  disconnect () { return this.close() }

  /** Update connection options before (re)connecting. */
  updateConfig (options = {}) {
    if (options.url) this.url = options.url
    if (typeof options.autoReconnect === 'boolean') this.autoReconnect = options.autoReconnect
    if (typeof options.maxReconnectAttempts === 'number') this.maxReconnectAttempts = options.maxReconnectAttempts
    if (typeof options.reconnectDelay === 'number') this.reconnectDelay = options.reconnectDelay
  }

  on (event, handler) {
    if (!this._handlers.has(event)) this._handlers.set(event, new Set())
    this._handlers.get(event).add(handler)
    return () => this.off(event, handler)
  }

  off (event, handler) {
    const set = this._handlers.get(event)
    if (set) set.delete(handler)
  }

  /**
   * Send a payload to one or many peer tokens.
   * The payload is JSON-stringified into the envelope's `message` field.
   */
  send (to, payload) {
    const tokens = Array.isArray(to) ? to : [to]
    const messageStr = typeof payload === 'string' ? payload : JSON.stringify(payload)
    if (!this._rtc) {
      this._sendRaw({ to: tokens, message: messageStr })
      return
    }
    const proxyTokens = []
    for (const t of tokens) {
      if (!this._rtc.trySend(t, messageStr)) proxyTokens.push(t)
    }
    if (proxyTokens.length) {
      this._sendRaw({ to: proxyTokens, message: messageStr })
    }
  }

  /**
   * Force opening (or reusing) a WebRTC DataChannel to a peer.
   * Resolves once the channel is open. Rejects on failure.
   */
  connectWebRTC (token) {
    if (!this._rtc) return Promise.reject(new Error('WebRTC disabled'))
    return this._rtc.connect(token)
  }

  /** True if there is an open DataChannel to the given peer. */
  isWebRTCOpen (token) {
    return !!(this._rtc && this._rtc.isOpen(token))
  }

  _proxySendOne (to, payload) {
    if (!this.ws || this.ws.readyState !== WebSocket.OPEN) return
    this._sendRaw({
      to: [to],
      message: typeof payload === 'string' ? payload : JSON.stringify(payload)
    })
  }

  /**
   * Publish self into a public channel.
   * @param {string} channelName
   * @param {Object} [extraData] Extra fields baked into channel.data and signed.
   */
  async publish (channelName, extraData = {}) {
    const channel = await buildSignedChannel(channelName, extraData)
    return this._request({ type: 'publish', channel }, 'published', 'channel')
  }

  /** Unpublish self from a public channel. */
  async unpublish (channelName) {
    const channel = await buildSignedChannel(channelName)
    return this._request({ type: 'unpublish', channel }, 'unpublished', 'channel')
  }

  /** List the tokens currently in a channel. */
  async list (channelName) {
    const channel = await buildSignedChannel(channelName)
    const res = await this._request({ type: 'list', channel }, 'channel_list', 'channel')
    return res.tokens || []
  }

  /** Alias for list() to ease migration from older clients. */
  listChannel (channelName) { return this.list(channelName) }

  /**
   * Watch a channel read-only: receive its `channel_joined`/`channel_left`/
   * `peer_disconnected` events live WITHOUT being listed as a member (you won't
   * appear in others' list()). Ideal for a lobby that shows rooms in real time
   * without publishing itself as a phantom room. Resolves with the current tokens.
   */
  async watch (channelName) {
    const channel = await buildSignedChannel(channelName)
    const res = await this._request({ type: 'watch', channel }, 'watched', 'channel')
    return res.tokens || []
  }

  /** Stop watching a channel. */
  async unwatch (channelName) {
    const channel = await buildSignedChannel(channelName)
    return this._request({ type: 'unwatch', channel }, 'unwatched', 'channel')
  }

  /** List public channel names (optionally filtered by prefix). */
  async listChannels (options = {}) {
    const msg = { type: 'list_channels' }
    if (typeof options.prefix === 'string') msg.prefix = options.prefix
    const res = await this._request(msg, 'channels_list')
    return res.channels || []
  }

  /** How many tokens are in a channel right now (no listing). */
  async channelCount (channelName) {
    const res = await this._request(
      { type: 'channel_count', channel: channelName },
      'channel_count', 'channel'
    )
    return res.count || 0
  }

  /**
   * Direccionar uno o varios mensajes por **publickey** (con cola offline en
   * el proxy hasta 24h). El destinatario debe haber llamado previamente a
   * `identify` para que el proxy sepa qué token tiene asignado en cada momento.
   *
   * Si el destinatario está conectado, se entrega de inmediato; si no, queda
   * en cola y se entrega cuando se reconecte e identifique. Los WebRTC peers
   * NO se usan para esta ruta (el proxy debe ser el broker).
   *
   * @param {string|string[]} toPubkeys publickey JWK string o array
   * @param {any} payload
   */
  sendByPubkey (toPubkeys, payload) {
    const list = Array.isArray(toPubkeys) ? toPubkeys : [toPubkeys]
    this._sendRaw({
      to_publickey: list,
      message: typeof payload === 'string' ? payload : JSON.stringify(payload)
    })
  }

  /**
   * Registrar la conexión actual bajo una publickey estable. Se requiere un
   * sobre `{data:{op,publickey,token,ts}, signature}` firmado externamente
   * (típicamente por el identity vault). Devuelve la respuesta del proxy con
   * `queued_delivered` (mensajes offline despachados al instante).
   */
  identify ({ data, signature }) {
    if (!data || !signature) throw new Error('identify requires {data, signature}')
    return this._request({ type: 'identify', data, signature }, 'identified')
  }

  /**
   * Consultar la config de Web Push del proxy.
   * @returns {Promise<{enabled:boolean, vapidPublicKey:string|null}>}
   */
  async getPushConfig () {
    const res = await this._request({ type: 'push-config' }, 'push-config')
    return { enabled: !!res.enabled, vapidPublicKey: res.vapidPublicKey || null }
  }

  /**
   * Activar Web Push ("timbre" para mensajes offline). Registra el Service
   * Worker, crea la PushSubscription (VAPID) y la registra en el proxy bajo la
   * MISMA publickey usada en `identify` (la del vault), con un sobre firmado por
   * el vault — igual patrón que identify.
   *
   * No usa el SDK de Firebase: solo Web Push estándar. El push no transporta
   * contenido de usuario; despierta al SW para que reconecte y baje la cola.
   *
   * Resolución del Service Worker (en orden):
   *   - `registration`: usa esa ServiceWorkerRegistration directamente.
   *   - `swPath`: registra ese archivo (apps sin SW propio).
   *   - ninguno: usa el SW ya registrado por la app (`navigator.serviceWorker.ready`).
   * Esto último es lo correcto para PWAs que ya tienen su propio SW (p.ej. con
   * vite-plugin-pwa/Workbox): inyectá los handlers de push en ese SW con
   * `importScripts` y llamá enablePush() sin swPath para no clobbear el scope.
   *
   * @param {Object} opts
   * @param {string} opts.publicKey  Pubkey JWK string del vault (la de identify).
   * @param {(data:any)=>Promise<string|{signature:string}>} opts.sign  Firma del vault (id.signData).
   * @param {string} [opts.vapidPublicKey]  VAPID pública; si falta se pide al proxy.
   * @param {ServiceWorkerRegistration} [opts.registration]  SW ya registrado a reutilizar.
   * @param {string} [opts.swPath]  Ruta de un SW a registrar (apps sin SW propio).
   * @param {string} [opts.swScope]  Scope del SW (solo con swPath).
   * @returns {Promise<PushSubscription>}
   */
  async enablePush ({ publicKey, sign, vapidPublicKey, registration, swPath, swScope } = {}) {
    if (typeof navigator === 'undefined' || !('serviceWorker' in navigator)) {
      throw new Error('Service Worker no soportado en este entorno')
    }
    if (typeof PushManager === 'undefined') {
      throw new Error('Push API no soportada en este navegador')
    }
    if (!publicKey || typeof sign !== 'function') {
      throw new Error('enablePush requires { publicKey, sign }')
    }
    if (!vapidPublicKey) {
      const cfg = await this.getPushConfig()
      if (!cfg.enabled || !cfg.vapidPublicKey) throw new Error('El proxy no tiene Web Push habilitado')
      vapidPublicKey = cfg.vapidPublicKey
    }
    let reg
    if (registration) {
      reg = registration
    } else if (swPath) {
      await navigator.serviceWorker.register(swPath, swScope ? { scope: swScope } : undefined)
      reg = await navigator.serviceWorker.ready
    } else {
      // PWA con SW propio: reutilizar el registrado por la app.
      reg = await navigator.serviceWorker.ready
    }
    let sub = await reg.pushManager.getSubscription()
    if (!sub) {
      sub = await reg.pushManager.subscribe({
        userVisibleOnly: true,
        applicationServerKey: urlBase64ToUint8Array(vapidPublicKey)
      })
    }
    const subJson = typeof sub.toJSON === 'function' ? sub.toJSON() : sub
    const data = { op: 'push-subscribe', publickey: publicKey, subscription: JSON.stringify(subJson), ts: Date.now() }
    const signature = await normalizeSignature(sign, data)
    await this._request({ type: 'push-subscribe', data, signature }, 'push-subscribed')
    return sub
  }

  /**
   * Desactivar Web Push: cancela la PushSubscription local y la borra del proxy.
   * @param {Object} opts
   * @param {string} opts.publicKey  Pubkey JWK string del vault.
   * @param {(data:any)=>Promise<string|{signature:string}>} opts.sign  Firma del vault.
   * @param {ServiceWorkerRegistration} [opts.registration]  SW a usar (default: el activo).
   * @param {string} [opts.swPath]  Ruta del SW si se registró uno propio.
   */
  async disablePush ({ publicKey, sign, registration, swPath } = {}) {
    if (typeof navigator !== 'undefined' && 'serviceWorker' in navigator) {
      try {
        const reg = registration ||
          (swPath ? await navigator.serviceWorker.getRegistration(swPath)
                  : await navigator.serviceWorker.ready)
        const sub = reg && await reg.pushManager.getSubscription()
        if (sub) await sub.unsubscribe()
      } catch (_) { /* best-effort local */ }
    }
    if (publicKey && typeof sign === 'function') {
      const data = { op: 'push-unsubscribe', publickey: publicKey, ts: Date.now() }
      const signature = await normalizeSignature(sign, data)
      await this._request({ type: 'push-unsubscribe', data, signature }, 'push-unsubscribed')
    }
  }

  /**
   * Programar un push a la PROPIA pubkey (auto-recordatorio). El proxy lo
   * dispara a la hora indicada, aunque la app esté cerrada (vía el SW). Es
   * self-only: el target es siempre la pubkey que firma (no se puede programar
   * a terceros). One-shot (`when`) o recurrente (`cron` + `tz`).
   *
   * @param {Object} opts
   * @param {string} opts.publicKey  Pubkey JWK string del vault.
   * @param {(data:any)=>Promise<string|{signature:string}>} opts.sign  Firma del vault.
   * @param {Date|number} [opts.when]  One-shot: instante futuro (Date o epoch ms).
   * @param {string} [opts.cron]  Recurrente: expresión cron (5 campos).
   * @param {string} [opts.tz]    Timezone IANA para el cron (ej. 'America/Argentina/Buenos_Aires').
   * @param {object} [opts.payload]  Datos extra opcionales para la notificación (ej. { title }).
   * @returns {Promise<{ jobId:number, nextFire:number }>}
   */
  async schedulePush ({ publicKey, sign, when, cron, tz, payload } = {}) {
    if (!publicKey || typeof sign !== 'function') throw new Error('schedulePush requires { publicKey, sign }')
    const spec = {}
    if (cron) {
      spec.cron = cron
      if (tz) spec.tz = tz
    } else {
      const fireAt = when instanceof Date ? when.getTime() : Number(when)
      if (!Number.isFinite(fireAt)) throw new Error('schedulePush requires { when } (Date|ms) or { cron }')
      spec.fireAt = fireAt
    }
    if (payload) spec.payload = payload
    const data = { op: 'schedule-push', publickey: publicKey, spec: JSON.stringify(spec), ts: Date.now() }
    const signature = await normalizeSignature(sign, data)
    const res = await this._request({ type: 'schedule-push', data, signature }, 'push-scheduled')
    return { jobId: res.jobId, nextFire: res.nextFire }
  }

  /**
   * Cancelar un push programado propio.
   * @param {Object} opts
   * @param {string} opts.publicKey
   * @param {(data:any)=>Promise<string|{signature:string}>} opts.sign
   * @param {number} opts.jobId
   */
  async cancelScheduledPush ({ publicKey, sign, jobId } = {}) {
    if (!publicKey || typeof sign !== 'function') throw new Error('cancelScheduledPush requires { publicKey, sign }')
    const data = { op: 'cancel-push', publickey: publicKey, jobId, ts: Date.now() }
    const signature = await normalizeSignature(sign, data)
    const res = await this._request({ type: 'cancel-push', data, signature }, 'push-canceled')
    return res.jobId
  }

  /**
   * Listar los push programados propios.
   * @returns {Promise<Array<{ jobId:number, nextFire:number, cron:string|null, tz:string|null, payload:object|null }>>}
   */
  async listScheduledPushes ({ publicKey, sign } = {}) {
    if (!publicKey || typeof sign !== 'function') throw new Error('listScheduledPushes requires { publicKey, sign }')
    const data = { op: 'list-pushes', publickey: publicKey, ts: Date.now() }
    const signature = await normalizeSignature(sign, data)
    const res = await this._request({ type: 'list-pushes', data, signature }, 'push-list')
    return res.jobs || []
  }

  /** Tear down the logical pair with a peer (both sides get notified). */
  async disconnectFrom (targetToken) {
    return this._request(
      { type: 'disconnect', target: targetToken },
      'disconnect_confirmation', 'target'
    )
  }

  /** Public key in JWK string form, useful as a stable identity. */
  getPublicKey () {
    return getPublicKeyJwk()
  }

  /** Sign arbitrary data with the local private key (base64 signature). */
  sign (data) {
    return signData(data)
  }

  // ---------- internals ----------

  _open () {
    const ws = new WebSocket(this.url)
    this.ws = ws
    // `ws !== this.ws` ⇒ es un socket que ya abandonamos (p.ej. por heartbeat
    // muerto). Ignoramos sus eventos tardíos para no disparar reconexiones dobles.
    ws.addEventListener('open', () => {
      if (ws !== this.ws) return
      this._connected = true
      this._reconnectAttempts = 0
      this._emit('connect')
      this._startHeartbeat()
    })
    ws.addEventListener('message', (ev) => {
      if (ws !== this.ws) return
      this._noteActivity()           // cualquier frame entrante prueba que está vivo
      this._handleFrame(ev.data)
    })
    ws.addEventListener('error', (err) => {
      if (ws !== this.ws) return
      this._emit('error', { type: 'transport', error: err })
      if (this._connectReject) {
        this._connectReject(err)
        this._connectResolve = null
        this._connectReject = null
      }
    })
    ws.addEventListener('close', (ev) => {
      if (ws !== this.ws) return
      this._stopHeartbeat()
      const wasConnected = this._connected
      this._connected = false
      this._emit('disconnect', { code: ev.code, reason: ev.reason })
      if (wasConnected && this.autoReconnect && ev.code !== 1000) {
        this._scheduleReconnect()
      }
    })
  }

  // ---------- heartbeat ----------

  _startHeartbeat () {
    if (!this.enableHeartbeat) return
    this._stopHeartbeat()
    this._hbTimer = setInterval(() => this._heartbeatTick(), this.heartbeatInterval)
  }

  _stopHeartbeat () {
    if (this._hbTimer) { clearInterval(this._hbTimer); this._hbTimer = null }
    if (this._hbDeadTimer) { clearTimeout(this._hbDeadTimer); this._hbDeadTimer = null }
  }

  // Llamado en cada frame entrante: si estábamos esperando un pong, llegó algo ⇒ vivo.
  _noteActivity () {
    if (this._hbDeadTimer) { clearTimeout(this._hbDeadTimer); this._hbDeadTimer = null }
  }

  _heartbeatTick () {
    if (!this._connected || !this.ws) return
    if (this._hbDeadTimer) return // ya hay un ping en vuelo esperando respuesta
    try { this.ws.send(JSON.stringify({ type: 'ping' })) }
    catch (_) { this._onHeartbeatDead(); return }
    this._hbDeadTimer = setTimeout(() => this._onHeartbeatDead(), this.heartbeatTimeout)
  }

  // No llegó respuesta al ping ⇒ conexión half-open. Abandonamos el socket y
  // forzamos la reconexión sin esperar el `close` (que en half-open puede no llegar).
  _onHeartbeatDead () {
    this._stopHeartbeat()
    const dead = this.ws
    this.ws = null  // a partir de acá, los eventos tardíos de `dead` se ignoran
    const wasConnected = this._connected
    this._connected = false
    this._emit('error', { type: 'heartbeat_timeout' })
    this._emit('disconnect', { code: 4000, reason: 'heartbeat timeout' })
    try { if (dead) dead.close() } catch (_) {}
    if (wasConnected && this.autoReconnect) this._scheduleReconnect()
  }

  _scheduleReconnect () {
    if (this._reconnectAttempts >= this.maxReconnectAttempts) {
      this._emit('reconnect_failed', this._reconnectAttempts)
      return
    }
    this._reconnectAttempts++
    this._emit('reconnecting', this._reconnectAttempts, this.maxReconnectAttempts)
    this._reconnectTimer = setTimeout(() => this._open(), this.reconnectDelay)
  }

  _handleFrame (raw) {
    let data
    try { data = JSON.parse(raw) } catch (e) {
      this._emit('error', { type: 'parse_error', error: e })
      return
    }
    const { type } = data
    switch (type) {
      case 'connected':
        this.token = data.token
        this._emit('token', this.token)
        if (this._connectResolve) {
          this._connectResolve(this.token)
          this._connectResolve = null
          this._connectReject = null
        }
        break
      case 'message': {
        const { from, message, timestamp, from_publickey, queued, queued_at } = data
        let parsed = null
        if (typeof message === 'string') {
          try { parsed = JSON.parse(message) } catch (_) { parsed = null }
        }
        if (this._rtc && parsed && parsed.t === RTC_TAG) {
          this._rtc.handleIncoming(from, parsed)
          break
        }
        this._emit('message', from, parsed ?? message, {
          raw: message, timestamp, via: 'proxy',
          fromPubkey: from_publickey || null,
          queued: !!queued,
          queuedAt: queued_at || null
        })
        break
      }
      case 'disconnected':
        this._emit('peer_disconnected', data.token, data.channel || null)
        if (this._rtc && data.token) this._rtc.closePeer(data.token)
        this._resolvePending(data, 'token')
        break
      case 'joined':
        this._emit('channel_joined', data.channel, data.token)
        break
      case 'left':
        this._emit('channel_left', data.channel, data.token)
        break
      case 'published':
      case 'unpublished':
      case 'watched':
      case 'unwatched':
      case 'channel_list':
      case 'channels_list':
      case 'channel_count':
      case 'disconnect_confirmation':
      case 'identified':
      case 'message_sent':
      case 'push-config':
      case 'push-subscribed':
      case 'push-unsubscribed':
      case 'push-scheduled':
      case 'push-canceled':
      case 'push-list':
        this._resolvePending(data, type)
        break
      case 'error':
        this._emit('error', {
          type: 'server',
          error: data.error,
          id: data.id,
          messageId: data.messageId,
          limit_level: data.limit_level,
          limit_type: data.limit_type,
          retry_after_ms: data.retry_after_ms,
          operation: data.operation
        })
        this._rejectPending(data)
        break
      case 'abuse_notice':
        this._emit('abuse_notice', {
          from: data.from,
          operation: data.operation,
          severity: data.severity,
          timestamp: data.timestamp
        })
        break
      case 'pong':
        // keepalive: la actividad ya se registró en _noteActivity; nada más que hacer.
        break
      default:
        this._emit('unknown', data)
    }
  }

  _sendRaw (frame) {
    if (!this.ws || this.ws.readyState !== WebSocket.OPEN) {
      throw new Error('WebSocket not connected')
    }
    this.ws.send(JSON.stringify(frame))
  }

  _request (frame, expectedType, channelKey) {
    return new Promise((resolve, reject) => {
      const id = `req_${this._nextId++}`
      const out = { ...frame, id }
      const timer = setTimeout(() => {
        this._pending.delete(id)
        reject(new Error(`Timeout waiting for ${expectedType}`))
      }, 10000)
      this._pending.set(id, { resolve, reject, timer, expectedType, channelKey })
      try {
        this._sendRaw(out)
      } catch (e) {
        clearTimeout(timer)
        this._pending.delete(id)
        reject(e)
      }
    })
  }

  _resolvePending (data, actualType) {
    const id = data.id
    if (!id || !this._pending.has(id)) return
    const entry = this._pending.get(id)
    if (entry.expectedType && entry.expectedType !== actualType) return
    clearTimeout(entry.timer)
    this._pending.delete(id)
    entry.resolve(data)
  }

  _rejectPending (data) {
    const id = data.id
    if (!id || !this._pending.has(id)) return
    const entry = this._pending.get(id)
    clearTimeout(entry.timer)
    this._pending.delete(id)
    entry.reject(new Error(data.error || 'Server error'))
  }

  _emit (event, ...args) {
    const set = this._handlers.get(event)
    if (!set) return
    for (const h of set) {
      try { h(...args) } catch (e) { console.error('handler error', e) }
    }
  }
}

// El callback de firma del vault devuelve `string` o `{ signature }` (id.signData
// devuelve un objeto). Normalizamos a string base64.
async function normalizeSignature (sign, data) {
  const out = await sign(data)
  const sig = typeof out === 'string' ? out : (out && out.signature)
  if (!sig) throw new Error('sign() debe devolver una firma base64 (string o {signature})')
  return sig
}

// Convierte la VAPID pública (base64url) al Uint8Array que espera
// pushManager.subscribe({ applicationServerKey }).
function urlBase64ToUint8Array (base64String) {
  const padding = '='.repeat((4 - (base64String.length % 4)) % 4)
  const base64 = (base64String + padding).replace(/-/g, '+').replace(/_/g, '/')
  const raw = atob(base64)
  const output = new Uint8Array(raw.length)
  for (let i = 0; i < raw.length; i++) output[i] = raw.charCodeAt(i)
  return output
}
