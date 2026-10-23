import { buildSignedChannel, getPublicKeyJwk, signData, samePubkey } from './signature.js'
import { seal, open, isSealed, isBinSealed, BIN_SEALED, makeMessageKey, encryptBytes, decryptBytes } from './sealing.js'
import { buildEncPubStatement, readEncPubStatement, isEncPub } from './encpub.js'
import { WebRTCManager, RTC_TAG, DEFAULT_ICE_SERVERS, loadNodePeerConnection, resolvePeerConnection, pinTurnToIPv4 } from './webrtc.js'
import { BluetoothManager } from './ble/manager.js'
import { BLE_TAG } from './ble/wire.js'
import { TrafficStats, utf8Length, registerTransport, unregisterTransport } from './stats.js'
import { splitParts, splitBinParts, isPart, Reassembler, DIRECT_PART_CHARS, PROXY_PART_CHARS, QUEUE_MAX_CHARS, RELAY_MAX_CHARS, DIRECT_PART_BYTES, PROXY_PART_BYTES, QUEUE_MAX_BYTES, RELAY_MAX_BYTES } from './parts.js'
import { pack, unpack, hasBinary, encodeFrame, decodeFrame } from './binpack.js'
import { errorWithCode } from './errors.js'

/**
 * EL SALUDO: «este token es de esta identidad».
 *
 * Es una trama de CONTROL del transporte, como la señalización de WebRTC, y por eso va
 * en claro y no la para `requireSealed`: lo único que lleva es una llave PÚBLICA que el
 * proxio ya tiene atada a esta conexión desde `identify`. Nada del usuario viaja aquí.
 */
const HELLO_TAG = '__cc_hello__'
/**
 * Lo que este cliente entiende, y lo dice en el saludo (0.36.0). Hoy una cosa: `binary`, las
 * tramas con bytes (binpack.js). Quien saluda sin decirlo es anterior y no las entiende, así
 * que no se le mandan: se lanza `peer-no-binary` y la app lo enseña. La idea del dueño es que
 * todo pase a binario con el tiempo, y esta lista es por donde se sabrá quién ya puede.
 */
const SPEAKS = ['binary']

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
 *   - 'peer_identity'     (token, publickey)          : that token said whose it is (helloTo)
 *   - 'reconnecting'      (attempt, max)
 *   - 'reconnect_failed'  (attempts)
 */
const APP_RE = /^[a-z0-9][a-z0-9-]{0,31}$/

/**
 * Valida un nombre de app (`messenger`, `vault`…). Lo que no tiene forma LANZA: un nombre mal
 * escrito haría que el timbre no sonara nunca en esa app, y eso no se ve.
 */
function checkApp (app) {
  if (app == null) return null
  if (typeof app !== 'string' || !APP_RE.test(app)) {
    throw errorWithCode(`app: "${app}" is not a valid app name (a-z, 0-9, -; up to 32)`, 'bad-app')
  }
  return app
}

export class WebSocketProxyClient {
  constructor (options = {}) {
    this.url = options.url || 'wss://proxy.dotrino.com'
    this.autoReconnect = options.autoReconnect !== false
    this.maxReconnectAttempts = options.maxReconnectAttempts ?? 5
    this.reconnectDelay = options.reconnectDelay ?? 3000
    // UN SOCKET QUE NO ABRE NI FALLA. El WebSocket de Node (y el del navegador) no tiene
    // tope para el saludo: si el TCP entra y nadie contesta el upgrade, se queda en
    // CONNECTING sin disparar `open`, `error` ni `close`. Como el siguiente reintento solo
    // se programa desde esos eventos, la cadena de reconexión se paraba ahí, en silencio.
    // Se abandona el intento pasado este tiempo y cuenta como un fallo más.
    this.connectTimeout = options.connectTimeout ?? 15000
    this.enableWebRTC = options.enableWebRTC !== false
    this.iceServers = options.iceServers || null

    /**
     * Refuse to send or accept directed messages in the clear.
     *
     * The proxy does not encrypt payloads, so anything sensitive sent with
     * `sendByPubkey` is readable by whoever runs the proxy. With this on:
     *   · `sendSealed()` is the only way out — plain `sendByPubkey` throws
     *   · unsealed directed messages are dropped and reported as 'unsealed'
     *
     * Off by default so existing apps keep working; public channels are unaffected
     * either way, since they are public by design.
     */
    this.requireSealed = options.requireSealed === true
    this.myEncPrivateKey = options.myEncPrivateKey || null

    /**
     * QUÉ APP ES ESTA (websocket-proxy ≥ 1.4.0). En un teléfono varias apps hablan con la
     * MISMA llave (el perfil del teléfono), y el proxio necesita saber a cuál despertar y a
     * cuál entregarle la cola: sin esto, la última en suscribirse se llevaba todos los
     * timbres y la primera en conectarse, los mensajes de todas. Es ruteo, no contenido.
     *
     * Se dice al identificarse (solo baja lo suyo de la cola), al suscribirse al timbre (solo
     * suena con lo suyo) y quien le escribe lo marca con `sendByPubkey(…, { app })`.
     * Sin `app`, como antes: recibe todo.
     */
    this.app = checkApp(options.app)

    /**
     * MI llave de cifrado, la pública. Con ella puesta, `identify` anuncia al proxio
     * —firmado— que esta identidad se abre por aquí, y cualquiera que sepa mi pubkey puede
     * averiguarla y sellarme sin habernos emparejado nunca. Sin ella, los demás no tienen
     * de dónde sacarla y `sendSealed` hacia mí no sale: falla en vez de ir en claro.
     *
     * En un aparato headless es `(await makeEncKeypair()).encPub`; en el navegador,
     * `await identity.getEncryptionPubkey()` — ahí la privada vive en la bóveda y no se
     * pasa, se delega en `sealing`.
     */
    this.myEncPub = options.myEncPub || null

    /**
     * Llaves de cifrado ajenas YA VERIFICADAS (pubkey → encpub). Solo entra aquí lo que
     * pasó por `readEncPubStatement`, así que lo de dentro está atado a su identidad.
     * No se cachean los fallos: «hoy no la tengo» no es un hecho, es un momento.
     */
    this._encPubs = new Map()
    this._encPubInflight = new Map()

    /**
     * QUIÉN ESTÁ AL OTRO LADO DE CADA TOKEN (token → publickey), aprendido del saludo.
     *
     * Un token es una dirección del proxio y no dice de quién es. Hasta que alguien lo
     * diga, a ese token no se le puede sellar nada: no se sabe a qué identidad, y por lo
     * tanto tampoco a qué llave de cifrado. Es el hueco por el que una sala de
     * desconocidos seguía hablando en claro aunque el sellado ya existiera.
     *
     * Se vacía al reconectar: los tokens se reparten por conexión y los de antes ya no
     * son de nadie.
     */
    this._tokenPubkeys = new Map()
    // Lo que dijo entender cada token en su saludo, y cada identidad (para lo que va por
    // pubkey). Sin saludo no se sabe, y entonces no se frena nada.
    this._tokenSpeaks = new Map()
    this._pubkeySpeaks = new Map()
    this._helloSent = new Set()

    /** Mi propia identidad en el cable, la que `identify` dejó atada a este token. */
    this.myPublickey = null

    /**
     * QUIEN YA SABE LA RESPUESTA, QUE NO PREGUNTE. Los aparatos de un mismo dueño llevan su
     * llave de cifrado escrita en el ACTA (`memberEncPub` de `@dotrino/identity`), firmada
     * por el master: eso es más fuerte que el anuncio y no hace falta ir al proxio a por
     * ello. Una app con acta enchufa aquí
     * `encPubResolver: (pub) => memberEncPub(acta, pub)`.
     *
     * Devolver `null` significa «yo no sé», y entonces se pregunta al proxio. No es un
     * repliegue: si no lo sabe nadie, no se manda nada — se sigue fallando cerrado.
     *
     * @type {((publickey:string)=>Promise<string|null>|string|null)|null}
     */
    this.encPubResolver = typeof options.encPubResolver === 'function' ? options.encPubResolver : null

    /**
     * Who does the sealing. Two worlds, and only one of them holds the key:
     *
     *   · headless devices (a CLI, an agent) have their own encryption private key,
     *     so `myEncPrivateKey` is enough
     *   · browser apps do NOT: the private key lives in the vault, and they delegate
     *     with `identity.encrypt` / `identity.decrypt`
     *
     * Pass `sealing: { seal(msg, peerEncPub), open(envelope), isSealed(msg) }` to
     * plug the second case in. Without it, the built-in sealing is used.
     */
    this.sealing = options.sealing || null

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
    this._tokenWatch = new Map() // messageId -> { token, sobre, peerPubkey, timer, queueFallback }
    // Mensajes grandes que llegan en partes (parts.js). Uno que se queda a medias se DICE:
    // con él se pierde el mensaje entero, y eso no puede pasar callado.
    this._parts = new Reassembler({
      onExpire: (info) => this._emit('error', { type: 'parts_incomplete', code: 'parts-incomplete', ...info })
    })
    // Las CEK de los mensajes con bytes ya abiertas, por su sobre: todas las partes de un
    // mensaje traen la misma, y abrirla es una vuelta a la bóveda. Pocas: un mensaje vivo.
    this._msgKeys = new Map()
    this._traffic = new TrafficStats()

    this._rtc = this.enableWebRTC ? new WebRTCManager({
      getSelfToken: () => this.token,
      signalSend: (to, payload) => this._proxySendOne(to, payload),
      deliverMessage: (from, parsed, meta) => this._deliver(from, parsed, meta),
      emit: (event, ...args) => {
        // UN CANAL QUE SE CAE SE VUELVE A INTENTAR. Sin esto, el «un intento y no más» de
        // `_upgradeDirect` sería para siempre: una desconexión momentánea condenaría a ese
        // destinatario a ir por el proxio el resto de la vida del proceso.
        if (event === 'webrtc_close') this._rtcTried?.delete(args[0])
        this._emit(event, ...args)
      },
      count: (dir, token, bytes, route) =>
        this._traffic.peer(dir, route, { token, pubkey: this._tokenPubkeys.get(token) || null }, bytes),
      config: this.iceServers ? { iceServers: this.iceServers } : null
    }) : null
    // QUIÉN PUEDE HACERTE NEGOCIAR UN CANAL DIRECTO. Sin política, cualquiera que sepa
    // alcanzarte por el proxio — y negociar arranca DTLS/ICE/SCTP, o sea código que parsea
    // red no confiable. En un navegador se vive con ello; en un proceso que guarda llaves,
    // no. Quien monta el cliente lo acota (`acceptDirectFrom`).
    if (this._rtc && typeof options.acceptDirectFrom === 'function') {
      this._rtc.acceptFrom = options.acceptDirectFrom
    }

    // EL BLUETOOTH (docs/bluetooth.md): escalón entre WebRTC directo y TURN. Se enciende a
    // propósito, con `bluetooth: true` (en Node busca BlueZ, solo en Linux) o con un
    // adaptador propio. Encenderlo hace que el aparato anuncie que está ahí, y eso no lo
    // decide un script cualquiera que importe el pilar: lo decide quien monta el cliente.
    this._bleOption = options.bluetooth || null
    this._ble = this._bleOption ? new BluetoothManager({
      getSelfToken: () => this.token,
      signalSend: (to, payload) => this._proxySendOne(to, payload),
      deliverMessage: (from, parsed, meta) => this._deliver(from, parsed, meta),
      emit: (event, ...args) => this._emit(event, ...args),
      count: (dir, token, bytes, route) =>
        this._traffic.peer(dir, route, { token, pubkey: this._tokenPubkeys.get(token) || null }, bytes),
    }) : null
    if (this._ble && typeof options.acceptDirectFrom === 'function') this._ble.acceptFrom = options.acceptDirectFrom
    this._bleStarting = null
  }

  // ---------- public API ----------

  get isConnected () { return this._connected }

  /**
   * WEBRTC EN NODE, si hay con qué. Se busca UNA vez al conectar y no en medio de una
   * negociación: importar un paquete es asíncrono y hacerlo tarde metería una espera justo
   * donde no puede haberla. Si no hay implementación, no pasa nada — se sigue por el
   * proxio, que es el escalón que siempre funciona.
   */
  async _prepareWebRTC () {
    if (!this._rtc || resolvePeerConnection()) return
    await loadNodePeerConnection()
  }

  /**
   * ENCIENDE EL BLUETOOTH, una vez. Corre por detrás desde `connect()`: tiene que estar
   * anunciando antes de que el otro quiera subir de escalón. Que no haya Bluetooth es el caso
   * normal y no se dice; que lo haya y no arranque, sí (`bluetooth_unavailable`).
   */
  _prepareBluetooth () {
    if (!this._ble || this._ble.available || this._bleStarting) return this._bleStarting
    this._bleStarting = (async () => {
      let adapter = this._bleOption
      if (adapter === true) {
        const mod = './ble/bluez.js'
        const { openBluez } = await import(/* @vite-ignore */ mod)
        adapter = await openBluez()
        if (!adapter) return
      }
      await this._ble.start(adapter)
    })().catch((e) => {
      this._emit('error', { type: 'bluetooth_unavailable', error: e, code: e?.code || null })
    }).finally(() => { this._bleStarting = null })
    return this._bleStarting
  }

  /** Hay Bluetooth encendido en este cliente. */
  get bluetoothAvailable () { return !!this._ble?.available }

  /**
   * Anuncia `{kind, data}` por Bluetooth hasta que se llame a lo que devuelve
   * (docs/bluetooth.md §3). `kind: 'pair'` es la invitación de emparejar; `'contact'`, la
   * tarjeta de contacto. Lanza `no-bluetooth` si aquí no lo hay.
   * @returns {() => void}
   */
  announceBluetooth (kind, data) {
    if (!this._ble) throw errorWithCode('bluetooth: this client was made without it (option `bluetooth`)', 'no-bluetooth')
    return this._ble.announce(kind, data)
  }

  /**
   * Lo que anuncian por Bluetooth los aparatos de alrededor con ese `kind`. No necesita el
   * proxio. `onFound` avisa de cada uno según aparece.
   * @returns {Promise<{kind: string, data: string}[]>}
   */
  async discoverBluetooth ({ kind, timeoutMs, onFound } = /** @type {any} */ ({})) {
    if (!this._ble) throw errorWithCode('bluetooth: this client was made without it (option `bluetooth`)', 'no-bluetooth')
    await this._prepareBluetooth()
    return this._ble.discover({ kind, timeoutMs, onFound })
  }

  connect () {
    this._prepareBluetooth()
    return new Promise((resolve, reject) => {
      if (this._connected) return resolve(this.token)
      // Un reintento que estaba esperando su turno sobra: este `connect()` ya abre uno.
      if (this._reconnectTimer) { clearTimeout(this._reconnectTimer); this._reconnectTimer = null }
      this._connectResolve = resolve
      this._connectReject = reject
      this._open()
    })
  }

  close () {
    this.autoReconnect = false
    unregisterTransport(this)
    if (this._reconnectTimer) {
      clearTimeout(this._reconnectTimer)
      this._reconnectTimer = null
    }
    if (this._turnTimer) {
      clearTimeout(this._turnTimer)
      this._turnTimer = null
    }
    if (this._rtc) this._rtc.closeAll()
    if (this._ble) this._ble.stop().catch(() => {})
    if (this.ws) {
      try { this.ws.close(1000) } catch (_) {}
    }
    // Cerrar es una decisión de la app: lo que estuviera en vuelo ya no va a
    // llegar (`close()` apaga autoReconnect, y una reconexión tampoco reenvía
    // las peticiones pendientes). Sin esto, quien esperaba un `publish` se comía
    // los 10 s completos del timeout para enterarse de algo que ya se sabía, y
    // el temporizador mantenía vivo el proceso en Node ese rato.
    this._rejectAllPending(errorWithCode('Connection closed', 'CONNECTION_CLOSED'))
  }

  /** Corta en seco todo lo que esperaba respuesta, con su motivo. */
  _rejectAllPending (error) {
    const pending = [...this._pending.values()]
    this._pending.clear()
    for (const entry of pending) {
      clearTimeout(entry.timer)
      entry.reject(error)
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

    // La configuración de sellado TAMBIÉN se aplica aquí. Casi todas las apps piden el
    // cliente con `getWebSocketProxyClient()`, que es un singleton: si el primero en
    // pedirlo no puso `requireSealed`, el que sí lo pide después se quedaba sin él y
    // sin enterarse — la garantía perdida en silencio, que es la peor forma de
    // perderla.
    if (options.sealing) this.sealing = options.sealing
    if (options.myEncPrivateKey) this.myEncPrivateKey = options.myEncPrivateKey
    if (options.myEncPub) this.myEncPub = options.myEncPub
    if (typeof options.encPubResolver === 'function') this.encPubResolver = options.encPubResolver

    // Se puede ENCENDER, no apagar. Bajar la exigencia en caliente dejaría que
    // cualquier otro módulo de la app la desactivara sin querer, y no hay ningún
    // motivo legítimo para hacerlo a mitad de una sesión.
    if (options.requireSealed === true) this.requireSealed = true

    // La APP también, por la misma razón (el singleton): si se perdiera, esta app ni sonaría
    // con lo suyo ni se llevaría solo su cola. Se fija una vez; otra distinta después es que
    // dos apps comparten el cliente de la página, y eso es un error, no algo que resolver aquí.
    if (options.app != null) {
      const app = checkApp(options.app)
      if (this.app && this.app !== app) {
        throw errorWithCode(`app: this client is already "${this.app}", not "${app}"`, 'app-conflict')
      }
      this.app = app
    }
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
    // `requireSealed` vale para los DOS caminos dirigidos, no solo para el de pubkey
    // (CONVENCIONES §4.1 nombra `sendByPubkey` / `send`). Guardar uno y dejar el otro
    // abierto es no guardar ninguno: la app manda por donde le sale y el proxio lo lee
    // igual. Para sellar por token está `sendSealedTo`.
    if (this.requireSealed && !this._isSealed(payload)) {
      throw errorWithCode(
        'requireSealed: refusing to send a directed message in the clear — use sendSealedTo()',
        'unsealed')
    }
    const tokens = Array.isArray(to) ? to : [to]
    const messageStr = this._wire(payload)
    if (!this._rtc && !this._ble) {
      this._sendRaw({ to: tokens, message: messageStr })
      return
    }
    const proxyTokens = []
    for (const t of tokens) {
      if (!this._tryDirect(t, messageStr)) proxyTokens.push(t)
    }
    if (proxyTokens.length) {
      this._sendRaw({ to: proxyTokens, message: messageStr })
      // Y SE INTENTA IR DIRECTO PARA LA PRÓXIMA, sin esperar a nadie.
      this._upgradeDirect(proxyTokens)
    }
  }

  /**
   * SIEMPRE EL CAMINO MÁS DIRECTO (dueño, 2026-09-03), pero sin pagar por ello.
   *
   * Hablarle a alguien por primera vez sale por el proxio, que es lo que hay AHORA. En
   * paralelo se abre un canal directo, y desde el segundo mensaje `trySend` ya lo prefiere
   * solo — eso no hay que cambiarlo, ya estaba.
   *
   * **No se espera a la negociación.** Bloquear el primer mensaje hasta tener canal directo
   * haría más lento justo el arranque, que es lo que se quiere arreglar: se manda por donde
   * se pueda y la conexión mejora por debajo.
   *
   * Un intento por destinatario y no más: si no salió, casi siempre es que no se puede
   * (dos NAT que no se dejan, un navegador sin permisos) y reintentar en cada mensaje sería
   * quemar CPU y señalización para nada. Si el canal se cae, `webrtc_close` lo desapunta y
   * el siguiente mensaje vuelve a intentarlo.
   */
  _upgradeDirect (tokens) {
    // El Bluetooth negocia en paralelo con WebRTC y deduplica solo (ble/manager.js).
    if (this._ble?.available) for (const t of tokens) if (!this._ble.isOpen(t)) this._ble.upgrade(t)
    if (!this._rtc) return
    this._rtcTried = this._rtcTried || new Set()
    for (const t of tokens) {
      if (this._rtcTried.has(t) || this._rtc.isOpen(t)) continue
      this._rtcTried.add(t)
      // La implementación se busca AQUÍ, justo antes de negociar, y no al conectar: esto ya
      // corre desatendido, así que la espera no se la come nadie. Lanzarlo desde `connect`
      // metía un microtask de más y descuadraba los tiempos de otras cosas — lo cazaron
      // las pruebas del protocolo, que fallaban solo al correr todas juntas.
      Promise.resolve()
        .then(() => this._prepareWebRTC())
        .then(() => this._rtc.connect(t))
        .catch(() => {})   // no poder ir directo no es un fallo: es el caso normal en internet
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

  /**
   * EL MEJOR CANAL ABIERTO, en el orden de la escalera (docs/bluetooth.md §1): WebRTC si va
   * directo, si no Bluetooth, si no WebRTC por TURN. False = por el proxio.
   */
  _directFor (token) {
    const rtcOpen = !!this._rtc?.isOpen(token)
    if (rtcOpen && this._rtc.peers?.get(token)?.route !== 'turn') return this._rtc
    if (this._ble?.isOpen(token)) return this._ble
    if (rtcOpen) return this._rtc
    return null
  }

  /** Manda por el mejor canal abierto; si no hay, deja que WebRTC empiece a negociar y da false. */
  _tryDirect (token, wire) {
    const d = this._directFor(token)
    if (d) return d.trySend(token, wire)
    return this._rtc ? this._rtc.trySend(token, wire) : false
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
    const tokens = res.tokens || []
    // Vacío pero con una bóveda despertándose detrás (websocket-proxy ≥ 1.7.0): quien lista
    // puede esperar unos segundos en vez de concluir que no hay nadie.
    if (res.waking) tokens.waking = true
    return tokens
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
  /**
   * Enviar a una o varias pubkeys.
   *
   * `opts.ephemeral` marca el mensaje como de TIEMPO REAL: si el destinatario no
   * está conectado en ese momento, se descarta en vez de guardarse en la cola
   * offline de 24 h. Úsalo para lo que caduca —jugadas de una partida,
   * señalización WebRTC, presencia—: entregar eso mañana no es tarde, es
   * incorrecto (reinicia negociaciones imposibles y muestra movimientos fuera de
   * contexto). NO lo uses para mensajes de chat, que sí quieren esperar.
   *
   * `opts.quiet` hace lo contrario de despertar: el mensaje SE GUARDA en la cola igual,
   * pero el proxio no toca el timbre push del destinatario. Úsalo para lo que puede
   * esperar a que la otra punta abra por su cuenta —un aviso de que algo cambió—. Sin
   * él, cada aviso hace sonar el teléfono, y un timbre que no trae nada que hacer
   * enseña a ignorar el siguiente, que sí lo trae.
   */
  /**
   * Seal a payload towards a peer's encryption key and send it. This is what an app
   * should use for anything that is not meant for the proxy's eyes.
   */
  async sendSealed (toPubkeys, payload, { peerEncPub, ...opts } = {}) {
    const list = Array.isArray(toPubkeys) ? toPubkeys : [toPubkeys]
    // Por pubkey el mensaje puede quedarse ESPERANDO en el proxio, y ahí se deja como mucho
    // 8 MB de archivo (parts.js). Lo que pasa de eso no se manda: se dice, y la app decide.
    const m = this._measure(payload)
    const queueMax = m.bin ? QUEUE_MAX_BYTES : QUEUE_MAX_CHARS
    if (m.len > queueMax) {
      throw errorWithCode(`sendSealed: ${m.len} ${m.bin ? 'bytes' : 'chars'} is more than can wait in the proxy (${queueMax}); send it by token while both ends are connected`, 'too-big-for-queue')
    }
    // Por pubkey todo va por el proxio: si no admite bytes, se dice antes de mandar nada. Y
    // si alguno de los destinatarios dijo que no los entiende, tampoco.
    if (m.bin) { this._needBinaryProxy(); this._needPeerBinary(list) }
    const partSize = m.bin ? PROXY_PART_BYTES : PROXY_PART_CHARS
    const pieces = m.len <= partSize ? [m.bin ? m.whole : payload]
      : m.bin ? splitBinParts(m.whole, partSize) : splitParts(m.whole, partSize)
    // Con la llave puesta a mano se respeta tal cual: quien la pasa está diciendo que ya
    // sabe de quién es (se emparejaron), y un sobre vale para todos los destinatarios.
    if (peerEncPub) {
      const sealPiece = await this._sealerFor(m.bin, peerEncPub, list.length === 1 ? list[0] : undefined)
      for (const piece of pieces) this._sendByPubkeyRaw(list, await sealPiece(piece), opts)
      return
    }
    // Sin ella, se averigua. UNA ENVOLTURA POR DESTINATARIO: cada uno tiene su llave, así
    // que un solo sobre solo lo abriría uno.
    //
    // Y SE RESUELVEN TODAS ANTES DE MANDAR NADA. Enviar a los que se pudo y fallar por el
    // resto deja a la app creyendo que el mensaje salió, con la mitad de la sala sin él y
    // sin forma de saber cuál mitad.
    const keys = await Promise.all(list.map(async (pk) => [pk, await this.encPubOf(pk)]))
    for (const [pk, encPub] of keys) {
      const sealPiece = await this._sealerFor(m.bin, encPub, pk)
      for (const piece of pieces) this._sendByPubkeyRaw([pk], await sealPiece(piece), opts)
    }
  }

  /**
   * Sellar y mandar POR TOKEN, que es como hablan entre sí los de una sala (y lo único
   * que puede subir a WebRTC, §transporte: el camino más directo).
   *
   * `peerPubkey` no es un adorno: el token es una dirección del proxio y no dice de quién
   * es. Quien puede afirmar «este token es de esta identidad» es la app —lo sabe por el
   * canal, por el saludo de la sala o por la invitación—, así que lo dice ella y aquí se
   * sella a esa identidad. Sin ese dato no hay a quién sellarle y no se manda nada.
   *
   * @param {string|string[]} toTokens
   * @param {any} payload
   * @param {{ peerPubkey?:string, peerEncPub?:string }} opts
   */
  async sendSealedTo (toTokens, payload, { peerPubkey, peerEncPub } = /** @type {any} */ ({})) {
    const tokens = Array.isArray(toTokens) ? toTokens : [toTokens]
    if (!peerEncPub) {
      // Si la app no lo dice, lo dice el SALUDO: `helloTo` dejó apuntado de quién es
      // cada token. Con más de uno no se adivina —cada identidad tiene su llave y un
      // solo sobre solo lo abriría una—, así que ahí se exige decirlo.
      if (!peerPubkey && tokens.length === 1) peerPubkey = this.pubkeyOfToken(tokens[0])
      if (!peerPubkey) {
        throw errorWithCode(
          'sendSealedTo: nobody has said whose this token is — greet it (helloTo) or pass peerPubkey',
          'no-peer-identity')
      }
      peerEncPub = await this.encPubOf(peerPubkey)
    }
    if (!peerPubkey && tokens.length === 1) peerPubkey = this.pubkeyOfToken(tokens[0]) || undefined
    // Por token los dos están conectados y NO HAY TOPE (parts.js): lo que no cabe en un
    // mensaje del camino que toca sale en partes. El tamaño de parte lo decide el camino
    // de ahora: el canal directo admite mucho menos por mensaje que el proxio.
    const m = this._measure(payload)
    const direct = tokens.length === 1 && !!this._directFor(tokens[0])
    const size = m.bin ? (direct ? DIRECT_PART_BYTES : PROXY_PART_BYTES) : (direct ? DIRECT_PART_CHARS : PROXY_PART_CHARS)
    const relayMax = m.bin ? RELAY_MAX_BYTES : RELAY_MAX_CHARS
    const queueMax = m.bin ? QUEUE_MAX_BYTES : QUEUE_MAX_CHARS
    // Por token decide lo que dijo ESA conexión: lo recordado de la identidad puede ser de una
    // versión que ya se actualizó.
    if (m.bin) this._needPeerBinary(tokens)
    if (m.bin && !direct) this._needBinaryProxy()
    const sealPiece = await this._sealerFor(m.bin, peerEncPub, peerPubkey)
    if (m.len <= size) {
      const envelope = await sealPiece(m.bin ? m.whole : payload)
      if (tokens.length === 1 && peerPubkey) { this._sendToTokenOrQueue(tokens[0], envelope, peerPubkey); return }
      // Por `send`, no por `_sendRaw`: así sigue prefiriendo el canal directo si lo hay.
      this.send(tokens, envelope)
      return
    }
    // Por el proxio en vivo hay tope (parts.js): lo que pasa de él solo sale por canal
    // directo. Se pide el canal para que el siguiente intento lo encuentre abierto.
    if (!direct && m.len > relayMax) {
      this._upgradeDirect(tokens)
      throw errorWithCode(`sendSealedTo: ${m.len} ${m.bin ? 'bytes' : 'chars'} is more than goes through the proxy live (${relayMax}); it needs a direct channel`, 'too-big-for-relay')
    }
    // Si el token muere a mitad, lo que quede se iría a la cola por pubkey; solo se permite
    // si el mensaje entero cabe ahí. Si no, se dice (`too-big-for-queue`), no se deja.
    const queueFallback = m.len <= queueMax
    // Y si el canal directo se cae a mitad, el resto va por el proxio en vivo solo si el
    // mensaje entero cabe por ahí; si no, se para y se dice (`direct-lost`).
    const relayFallback = m.len <= relayMax
    for (const piece of (m.bin ? splitBinParts(m.whole, size) : splitParts(m.whole, size))) {
      const envelope = await sealPiece(piece)
      if (tokens.length === 1 && peerPubkey) await this._sendPiece(tokens[0], envelope, peerPubkey, queueFallback, relayFallback)
      else this.send(tokens, envelope)
    }
  }

  /**
   * POR DÓNDE LE LLEGA AHORA un mensaje a este token: `socket` (la otra punta en esta
   * máquina), `direct` (WebRTC sin nadie en medio), `turn` (WebRTC por el relevo, que no puede
   * leer lo que pasa), `proxy` (en vivo por el proxio) u `offline` (no hay conexión: por
   * pubkey quedaría esperando en el proxio). Cada camino tiene su tope (parts.js), y para eso
   * existe esto: que la app lo enseñe antes de que el usuario intente algo que no cabe.
   * `webrtc` es un canal directo abierto del que todavía no se sabe si va por TURN.
   * @param {string|null} token
   * @returns {Promise<'socket'|'direct'|'turn'|'webrtc'|'bluetooth'|'proxy'|'offline'>}
   */
  async routeTo (token) {
    if (!this._connected) return 'offline'
    if (!token) return 'offline'
    const d = this._directFor(token)
    if (d && d === this._ble) return 'bluetooth'
    if (d) {
      const peer = this._rtc.peers.get(token)
      try { return (await this._rtc.probeRoute(peer)) || 'webrtc' } catch (_) { return 'webrtc' }
    }
    return 'proxy'
  }

  /**
   * Una parte por token: por el canal directo esperando a que vacíe su búfer (sin eso, un
   * archivo grande lo desborda y el navegador cierra el canal), o por el proxio en vivo con
   * una pausa corta entre partes, para no chocar con su límite de mensajes por segundo.
   */
  async _sendPiece (token, envelope, peerPubkey, queueFallback, relayFallback = true) {
    const d = this._directFor(token)
    if (d && await d.sendDirect(token, this._wire(envelope))) return
    if (!relayFallback) {
      throw errorWithCode('the direct channel closed in the middle of a message too big for the proxy', 'direct-lost')
    }
    if (envelope instanceof Uint8Array) this._needBinaryProxy()
    this._sendToTokenOrQueue(token, envelope, peerPubkey, { queueFallback, skipDirect: true })
    await new Promise((r) => setTimeout(r, 20))
  }

  /**
   * Mandar POR TOKEN algo que la app YA CIFRÓ por su cuenta (un canal de sesión propio,
   * como el de `@dotrino/remote-agent`), con la misma red que `sendSealedTo`: sube al
   * canal directo si lo hay, y si el token murió el mismo mensaje sale por `peerPubkey`
   * y se avisa con `token_gone`.
   *
   * Existe porque `sendByPubkey` NUNCA sube de escalón —la cola es del proxio— y `send`
   * a secas pierde en silencio lo que va a un token que ya no existe. Con `requireSealed`
   * se niega igual que los demás: esto no abre una puerta para ir en claro.
   *
   * @param {string} token
   * @param {any} payload
   * @param {{ peerPubkey:string }} opts
   */
  sendToOrQueue (token, payload, { peerPubkey } = /** @type {any} */ ({})) {
    if (!token || !peerPubkey) {
      throw errorWithCode('sendToOrQueue: needs the token and whose it is (peerPubkey)', 'no-peer-identity')
    }
    this._sendToTokenOrQueue(token, payload, peerPubkey)
  }

  /**
   * UN TOKEN MUERTO NO SE TRAGA EL MENSAJE. Un token es una conexión, y cuando la otra punta
   * reinicia la app su token deja de existir; la app que lo tenía apuntado sigue mandando ahí
   * y el proxio contesta `message_sent` con ese token en `failed` (solo contesta si algo
   * falla). Antes nadie escuchaba esa respuesta: el mensaje se daba por enviado y se perdía.
   *
   * Si sabemos de quién es el token, el MISMO sobre —ya va sellado a esa identidad— sale por
   * su pubkey: la cola de 24 h del proxio, que además timbra su teléfono. Y se avisa con
   * `token_gone` para que la app deje de usar ese token. No bloquea a nadie: se manda ya y
   * el arreglo, si hace falta, llega detrás.
   */
  _sendToTokenOrQueue (token, envelope, peerPubkey, { queueFallback = true, skipDirect = false } = {}) {
    if (this.requireSealed && !this._isSealed(envelope)) {
      throw errorWithCode('requireSealed: refusing to send a directed message in the clear — use sendSealedTo()', 'unsealed')
    }
    const messageStr = this._wire(envelope)
    if (!skipDirect && this._tryDirect(token, messageStr)) return
    const id = `msg_${this._nextId++}`
    const timer = setTimeout(() => this._tokenWatch.delete(id), 15000)
    timer.unref?.()
    this._tokenWatch.set(id, { token, envelope, peerPubkey, timer, queueFallback })
    try {
      this._sendRaw({ to: [token], message: messageStr, id })
    } catch (e) {
      clearTimeout(timer)
      this._tokenWatch.delete(id)
      throw e
    }
    this._upgradeDirect([token])
  }

  /** `message_sent` con fallos: lo que iba a un token que ya no existe sale por pubkey. */
  _tokenFailed (data) {
    const w = data.id && this._tokenWatch.get(data.id)
    if (!w) return
    clearTimeout(w.timer)
    this._tokenWatch.delete(data.id)
    if (!Array.isArray(data.failed) || !data.failed.includes(w.token)) return
    this._emit('token_gone', w.token, w.peerPubkey)
    // Una parte de un mensaje que no cabe en la cola no se deja en el proxio (parts.js).
    if (!w.queueFallback) {
      this._emit('error', { type: 'client', error: 'the peer left in the middle of a message too big to wait in the proxy', code: 'too-big-for-queue', peerPubkey: w.peerPubkey })
      return
    }
    try { this._sendByPubkeyRaw([w.peerPubkey], w.envelope) } catch (e) { this._emit('error', { type: 'client', error: e.message, code: e.code || null }) }
  }

  // ---------- el saludo: de quién es este token ----------

  /**
   * SALUDAR: decirle a uno o varios tokens quién soy.
   *
   * Un token es una dirección del proxio y no dice de quién es, así que sin esto no hay
   * a quién sellarle: una sala de desconocidos se queda muda o —lo que pasaba— hablando
   * en claro. El saludo lleva SOLO mi llave pública, la misma que el proxio ya tiene
   * atada a esta conexión desde `identify`, y lo que este cliente entiende (`SPEAKS`, que es
   * lo mismo para todos los de esta versión); no hay nada del usuario dentro y por eso no
   * necesita sobre.
   *
   * Quien lo recibe contesta el suyo una vez, así que basta con que salude UNA de las
   * dos puntas y la app no tiene que coreografiar nada.
   *
   * **No autentica, y no hace falta que lo haga.** Mentir sobre la propia identidad solo
   * consigue que te sellen a una llave que no puedes abrir: el embustero se queda sin
   * leer, y nadie se queda suplantado. Quién firma de verdad lo dice el reto de la app,
   * o el `from_publickey` que pone el proxio cuando se enruta por pubkey.
   */
  helloTo (to) {
    if (!this.myPublickey) {
      throw errorWithCode('helloTo: identify first — a greeting with no identity says nothing', 'not-identified')
    }
    const tokens = Array.isArray(to) ? to : [to]
    for (const t of tokens) {
      if (!t || t === this.token) continue
      this._helloSent.add(t)
      this._proxySendOne(t, { t: HELLO_TAG, publickey: this.myPublickey, speaks: SPEAKS })
    }
  }

  /** De quién es este token, si alguien lo ha dicho. `null` es «todavía no lo sé». */
  pubkeyOfToken (token) {
    return this._tokenPubkeys.get(token) || null
  }

  /** Olvidar un token (se fue, o se quiere volver a preguntar). Sin argumento, todos. */
  forgetToken (token) {
    if (token == null) { this._tokenPubkeys.clear(); this._helloSent.clear(); this._tokenSpeaks.clear(); return }
    this._tokenPubkeys.delete(token)
    this._helloSent.delete(token)
    this._tokenSpeaks.delete(token)
  }

  /**
   * ¿Entiende esto la otra punta? `true` o `false` si lo dijo en su saludo, y `null` si
   * todavía no ha saludado (no se sabe). Acepta un token o una pubkey.
   * @param {string} who
   * @param {string} [feature]
   * @returns {boolean|null}
   */
  speaks (who, feature = 'binary') {
    let set = this._tokenSpeaks.get(who) || this._pubkeySpeaks.get(who)
    if (!set) {
      for (const [pk, s] of this._pubkeySpeaks) if (samePubkey(pk, who)) { set = s; break }
    }
    return set ? set.has(feature) : null
  }

  /** Antes de mandar bytes: si alguno dijo que no los entiende, no sale nada y se dice. */
  _needPeerBinary (targets) {
    for (const t of targets) {
      if (t && this.speaks(t, 'binary') === false) {
        throw errorWithCode('the other side does not take binary messages (it needs @dotrino/proxy-client >= 0.36.0)', 'peer-no-binary')
      }
    }
  }

  _onHello (from, msg) {
    if (typeof msg.publickey !== 'string' || !msg.publickey) return
    const antes = this._tokenPubkeys.get(from)
    // UN TOKEN NO CAMBIA DE DUEÑO: la conexión ES la identidad, y el proxio no recicla
    // tokens. Un segundo saludo con otra identidad es un intento de que le sellemos a
    // otro; manda el primero y esto se dice en voz alta en vez de pisarlo.
    if (antes && !samePubkey(antes, msg.publickey)) {
      this._emit('error', { type: 'hello_conflict', from, code: 'hello-conflict' })
      return
    }
    this._tokenPubkeys.set(from, msg.publickey)
    const speaks = new Set(Array.isArray(msg.speaks) ? msg.speaks.filter((x) => typeof x === 'string').slice(0, 32) : [])
    this._tokenSpeaks.set(from, speaks)
    this._pubkeySpeaks.set(msg.publickey, speaks)
    // Contestar UNA vez: el saludo queda simétrico sin rebotar para siempre.
    if (!this._helloSent.has(from) && this.myPublickey) this.helloTo(from)
    this._emit('peer_identity', from, msg.publickey)
  }

  /** Sella con lo que haya: la bóveda de la app (`sealing`) o las primitivas del pilar. */
  async _seal (payload, peerEncPub, peerPubkey) {
    if (!peerEncPub) throw errorWithCode('seal: missing peerEncPub', 'unsealed')
    return this.sealing
      ? this.sealing.seal(payload, peerEncPub, { publickey: peerPubkey })
      : seal(payload, peerEncPub)
  }

  /**
   * Quién sella las piezas de UN mensaje hacia UN destinatario. Con bytes (sealing.js): una
   * CEK para el mensaje entero, sellada una vez con el sellado de siempre, y cada pieza
   * cifrada como bytes con ella. Sin bytes, el sobre de texto de siempre por pieza.
   */
  async _sealerFor (bin, peerEncPub, peerPubkey) {
    if (!bin) return (piece) => this._seal(piece, peerEncPub, peerPubkey)
    const cek = await makeMessageKey()
    const k = await this._seal({ cek }, peerEncPub, peerPubkey)
    return async (bytes) => {
      const { iv, ct } = await encryptBytes(cek, bytes)
      return pack({ bv: BIN_SEALED, k, iv, ct })
    }
  }

  /** Lo que mide un mensaje para sus topes: su paquete si lleva bytes, su JSON si no. */
  _measure (payload) {
    if (hasBinary(payload)) {
      const whole = pack(payload)
      return { bin: true, whole, len: whole.byteLength }
    }
    const whole = JSON.stringify(payload)
    return { bin: false, whole, len: whole.length }
  }

  /** Cómo va por el cable: los bytes tal cual, el texto tal cual, y un objeto en JSON (o empaquetado, si lleva bytes). */
  _wire (payload) {
    if (typeof payload === 'string' || payload instanceof Uint8Array) return payload
    if (hasBinary(payload)) return pack(payload)
    return JSON.stringify(payload)
  }

  /** Un mensaje con bytes por el proxio necesita uno que admita tramas binarias (websocket-proxy ≥ 1.6.0). */
  _needBinaryProxy () {
    if (!Array.isArray(this.caps) || !this.caps.includes('binary')) {
      throw errorWithCode('this proxy does not take binary frames (it needs websocket-proxy >= 1.6.0)', 'no-binary-support')
    }
  }

  /** La CEK de un mensaje con bytes, abriendo su sobre una vez por mensaje. */
  _openMessageKey (k, meta) {
    const id = JSON.stringify(k)
    let p = this._msgKeys.get(id)
    if (!p) {
      p = (async () => {
        const o = this.sealing ? await this.sealing.open(k, meta) : await open(k, this.myEncPrivateKey)
        if (!o || typeof o.cek !== 'string') throw errorWithCode('the sealed key of a message has no key inside', 'bad-pack')
        return o.cek
      })()
      this._msgKeys.set(id, p)
      if (this._msgKeys.size > 64) this._msgKeys.delete(this._msgKeys.keys().next().value)
      p.catch(() => this._msgKeys.delete(id))
    }
    return p
  }

  // ---------- llaves de cifrado ajenas ----------

  /**
   * ANUNCIAR MI LLAVE DE CIFRADO. Una frase firmada por la misma identidad con la que me
   * identifico; el proxio la guarda y se la da a quien pregunte, y quien pregunta la
   * verifica contra mi pubkey. El proxio es el buzón, no la autoridad.
   *
   * Lo llama `identify` solo cuando el cliente tiene `myEncPub`. Se expone aparte para el
   * caso de anunciar una llave nueva sin reconectar.
   */
  async announceEncPub ({ publickey, encPub, sign } = /** @type {any} */ ({})) {
    const statement = await buildEncPubStatement({ publickey, encPub, sign })
    await this._request({ type: 'encpub', ...statement }, 'encpub-announced')
    // Lo mío también va a la caché: si una app se escribe a sí misma (otro aparato del
    // mismo perfil no, ése tiene otra llave) no hace falta preguntar por ello.
    this._encPubs.set(publickey, encPub)
    return encPub
  }

  /**
   * LA LLAVE DE CIFRADO DE UNA IDENTIDAD, verificada. Devuelve la llave o LANZA:
   *
   *   · `no-encpub`          nadie ha anunciado llave para esa identidad — se arregla
   *                          cuando el otro lado actualice; esperar no sirve
   *   · `encpub-unverified`  llegó una llave que NO firmó esa identidad. Es el caso que
   *                          importa: significa que alguien intentó ponerte la suya
   *   · `no-encpub-support`  este proxio no sabe de esto (es viejo)
   *
   * Nunca devuelve `null` y nunca cae a «manda igual»: si no se puede sellar, no se manda.
   */
  async encPubOf (publickey) {
    if (typeof publickey !== 'string' || !publickey) {
      throw errorWithCode('encPubOf: missing publickey', 'encpub-shape')
    }
    const cached = this._encPubs.get(publickey)
    if (cached) return cached
    // Una pregunta en vuelo por llave: una sala de ocho manda ocho mensajes a la vez y
    // preguntaría ocho veces por lo mismo.
    const inflight = this._encPubInflight.get(publickey)
    if (inflight) return inflight
    const promise = this._lookupEncPub(publickey)
      .finally(() => this._encPubInflight.delete(publickey))
    this._encPubInflight.set(publickey, promise)
    return promise
  }

  async _lookupEncPub (publickey) {
    // EL CAMINO MÁS DIRECTO PRIMERO. Si la app comparte acta con el destinatario, la llave
    // ya la tiene en la mano y firmada por el master: preguntársela a un servidor sería
    // dar la vuelta para llegar a lo que ya está aquí.
    if (this.encPubResolver) {
      const own = await this.encPubResolver(publickey)
      if (own) {
        if (!isEncPub(own)) {
          throw errorWithCode('encPubResolver returned something that is not a P-256 public JWK', 'encpub-unverified')
        }
        this._encPubs.set(publickey, own)
        return own
      }
    }
    // SI EL PROXIO DICE QUE NO SABE DE ESTO, se dice con su propio código en vez de
    // esperar diez segundos a un timeout. Un proxio que no manda `caps` es de antes de
    // que esto existiera y no se sabe: se pregunta igual, y contesta la pregunta.
    if (Array.isArray(this.caps) && !this.caps.includes('encpub')) {
      throw errorWithCode(
        `this proxy (${this.url}) does not serve encryption keys: it needs websocket-proxy >= 1.1.0`,
        'no-encpub-support')
    }
    const res = await this._request({ type: 'enc-lookup', publickeys: [publickey] }, 'enc-lookup')
    // `samePubkey`, no `===`: el proxio guarda el string exacto con el que se anunció, y
    // la app puede tener el mismo JWK escrito de otra forma.
    const statement = (res.keys || []).find((k) => samePubkey(k?.data?.publickey, publickey))
    if (!statement) {
      throw errorWithCode('no encryption key announced for that identity — it cannot be sealed to yet', 'no-encpub')
    }
    // AQUÍ ES DONDE EL PROXIO DEJA DE IMPORTAR: la firma se comprueba contra la pubkey a
    // la que vamos a escribir. Si cambió la llave por la suya, esto lanza.
    const encPub = await readEncPubStatement(statement, { publickey })
    this._encPubs.set(publickey, encPub)
    return encPub
  }

  /** Guardar una llave que ya viene firmada por su dueño (de un canal, de una invitación). */
  async learnEncPub (statement, { publickey } = /** @type {any} */ ({})) {
    const encPub = await readEncPubStatement(statement, { publickey })
    this._encPubs.set(publickey, encPub)
    return encPub
  }

  /** Olvidar lo aprendido de una identidad (rotó su llave, o se quiere volver a preguntar). */
  forgetEncPub (publickey) {
    if (publickey == null) this._encPubs.clear()
    else this._encPubs.delete(publickey)
  }

  _isSealed (msg) {
    if (msg instanceof Uint8Array) {
      let env
      try { env = unpack(msg) } catch (_) { return false }
      return isBinSealed(env) && this._isSealed(env.k)
    }
    return this.sealing ? this.sealing.isSealed(msg) : isSealed(msg)
  }

  sendByPubkey (toPubkeys, payload, opts = {}) {
    if (this.requireSealed && !this._isSealed(payload)) {
      throw Object.assign(
        new Error('requireSealed: refusing to send a directed message in the clear — use sendSealed()'),
        { code: 'unsealed' })
    }
    this._sendByPubkeyRaw(toPubkeys, payload, opts)
  }

  /**
   * Hands a message to the app, opening it first when it is sealed.
   *
   * With `requireSealed`, anything that arrives in the clear is DROPPED and reported
   * as `{ type: 'unsealed' }`. Sealing on the way out is not enough on its own: if the
   * receiving end still accepts plaintext, sending it that way bypasses the sealing
   * entirely — and a peer that never read anything could still push a forged payload
   * into the app.
   */
  async _deliver (from, payload, meta) {
    // BYTES (binpack.js): un paquete. Si es un sobre binario se abre aquí; si no, es un
    // objeto con bytes sin sellar, y decide `requireSealed` igual que con el texto.
    if (payload instanceof Uint8Array) {
      let env
      try { env = unpack(payload) } catch (e) {
        this._emit('error', { type: 'bad_pack', from, code: e.code || 'bad-pack', error: e })
        return
      }
      if (isBinSealed(env)) {
        if (!this.sealing && !this.myEncPrivateKey) {
          this._emit('error', { type: 'unsealed', reason: 'no_encryption_key', from })
          return
        }
        let opened
        try {
          if (!this._isSealed(env.k)) throw errorWithCode('the key of a sealed message is not sealed', 'bad-pack')
          opened = unpack(await decryptBytes(await this._openMessageKey(env.k, meta), env))
        } catch (e) {
          this._emit('error', { type: 'undecipherable', from, error: e })
          return
        }
        const senderEncPub = this.sealing?.senderOf?.(env.k) || null
        this._handOpened(from, opened, { ...meta, sealed: true, ...(senderEncPub ? { senderEncPub } : {}) })
        return
      }
      payload = env
    }
    if (this._isSealed(payload)) {
      if (!this.sealing && !this.myEncPrivateKey) {
        this._emit('error', { type: 'unsealed', reason: 'no_encryption_key', from })
        return
      }
      try {
        const opened = this.sealing
          ? await this.sealing.open(payload, meta)
          : await open(payload, this.myEncPrivateKey)
        // Quién selló (la llave de cifrado), si el sobre lo dice: es lo que autentica al
        // remitente, porque solo quien tiene esa privada pudo armarlo.
        const senderEncPub = this.sealing?.senderOf?.(payload) || null
        this._handOpened(from, opened, { ...meta, sealed: true, ...(senderEncPub ? { senderEncPub } : {}) })
      } catch (e) {
        // Sealed to somebody else, or tampered with. Staying quiet is the point.
        this._emit('error', { type: 'undecipherable', from, error: e })
      }
      return
    }

    if (this.requireSealed) {
      this._emit('error', { type: 'unsealed', reason: 'plaintext_rejected', from })
      return
    }
    this._emit('message', from, payload, { ...meta, sealed: false })
  }

  /** Lo ya abierto a la app: entero, o a rearmar si es una parte (parts.js). */
  _handOpened (from, opened, fullMeta) {
    if (isPart(opened)) {
      // Se agrupa por quien selló: solo esa llave pudo armar cada parte.
      let whole
      try { whole = this._parts.add(fullMeta.senderEncPub || fullMeta.fromPubkey || from || '', opened) }
      catch (e) { this._emit('error', { type: 'bad_part', from, code: e.code || 'bad-part', error: e }); return }
      if (whole !== null) this._emit('message', from, whole, { ...fullMeta, parts: opened.__dotrino_part.n })
      return
    }
    this._emit('message', from, opened, fullMeta)
  }

  _sendByPubkeyRaw (toPubkeys, payload, opts = {}) {
    const list = Array.isArray(toPubkeys) ? toPubkeys : [toPubkeys]
    const msg = {
      to_publickey: list,
      message: this._wire(payload)
    }
    if (opts.ephemeral) msg.ephemeral = true
    if (opts.quiet) msg.quiet = true
    // A QUÉ APP va (ruteo): el proxio timbra y entrega solo a esa app de ese aparato.
    const app = checkApp(opts.app)
    if (app) msg.app = app
    this._sendRaw(msg)
  }

  /** `{ app }` para lo firmado (suscribirse al timbre), o nada si esta conexión no dijo cuál. */
  _appField () { return this.app ? { app: this.app } : {} }

  /**
   * Pedir una CITA: el código corto que una persona lee, dicta o escanea para
   * emparejarse con esta conexión.
   *
   * Es un código de 6 caracteres (los 2 primeros dicen qué proxio lo emitió),
   * que **caduca en minutos y se quema al usarse**. Esa es la diferencia con el
   * token de 4 caracteres de antes: aquel era permanente mientras durara la
   * conexión Y era la dirección de ruteo, así que tenía que ser adivinable-seguro
   * y corto a la vez, dos cosas incompatibles.
   *
   * @param {{ttlMs?:number}} [opts] vida del código (30s–30min, por defecto 5min)
   * @returns {Promise<{code:string, expiresAt:number, node:string}>}
   */
  requestPairingCode (opts = {}) {
    const msg = { type: 'pair-code' }
    if (opts.ttlMs) msg.ttlMs = opts.ttlMs
    return this._request(msg, 'pair-code')
  }

  /**
   * Canjear una cita ajena: devuelve a qué conexión (y a qué identidad) apunta.
   * Acepta el código en minúsculas y con espacios o guiones.
   *
   * Si el código lo emitió otro proxio, este le pregunta a ESE proxio — no a
   * toda la malla: un pregón se lo queda el primero que conteste, y así es como
   * un nodo hostil se mete en emparejamientos ajenos.
   *
   * @returns {Promise<{ok:boolean, instance?:string, publickey?:string, error?:string}>}
   */
  redeemPairingCode (code) {
    return this._request({ type: 'pair-redeem', code }, 'pair-redeem')
  }

  /**
   * Registrar la conexión actual bajo una publickey estable. Se requiere un
   * sobre `{data:{op,publickey,token,ts}, signature}` firmado externamente
   * (típicamente por el identity vault). Devuelve la respuesta del proxy con
   * `queued_delivered` (mensajes offline despachados al instante).
   */
  /**
   * @param {(data:any)=>Promise<any>} [opts.sign] Con qué firmar. Solo se usa para encender
   *   TURN, y por eso es opcional: quien no lo pase se queda como estaba.
   *
   *   TURN NO ES UN CANAL APARTE: es lo que WebRTC usa cuando no consigue ir directo. Pero
   *   un canal por TURN sigue siendo mejor que el proxio, y no por velocidad — **el relevo
   *   no puede leer lo que reenvía** (va cifrado extremo a extremo) y el proxio sí. Por eso
   *   el orden es: aquí mismo, directo, por TURN, y el proxio el último (dueño, 2026-09-03).
   *
   *   Se enciende SOLO y por detrás: encenderlo pide credenciales al proxio, y hacer
   *   esperar a `identify` por eso retrasaría todo lo que viene después para ganar algo que
   *   solo hace falta cuando se negocie el primer canal.
   */
  /**
   * PARA QUIÉN firmamos cuando le hablamos a ESTE proxio. Sale de la URL a la que estamos
   * conectados: quien levanta su propio proxio tiene otro destinatario, y con un valor fijo
   * un sobre firmado para el nuestro valdría ante el suyo.
   */
  get audience () { return String(this.url || '').replace(/\/+$/, '') }

  /**
   * IDENTIFICARSE, ARMANDO EL SOBRE AQUÍ. Doce repos lo escribían a mano
   * (`{op:'identify', publickey, token, ts}` + firma), o sea el protocolo copiado doce
   * veces: al añadirle el destinatario habría que acertar en los doce, y quien escribiera
   * el trece lo haría sin él.
   *
   * `sign` es lo que firma (normalmente `(d) => identity.signData(d)`); acepta tanto la
   * firma en texto como el paquete del vault.
   */
  async identifyAs ({ publickey, sign, cert, acta } = {}) {
    if (typeof sign !== 'function') throw new Error('identifyAs requires sign(data)')
    if (!publickey) throw new Error('identifyAs requires publickey')
    if (!this.token) throw new Error('identifyAs: not connected yet (no token)')
    // El `token` lo da el proxio al conectar y va firmado aquí dentro: es el reto de esta
    // conexión, y por eso este sobre no necesita otro. Lo que le faltaba era decir a quién
    // se lo estamos dando.
    const data = { op: 'identify', aud: this.audience, publickey, token: this.token, ts: Date.now() }
    const signed = await sign(data)
    const signature = typeof signed === 'string' ? signed : signed?.signature
    // «No pude firmar» y «se cayó la red» son cosas distintas, y se distinguen por el
    // `code`: la bóveda usa esto para saber si su llave de comunicación firma todavía, y
    // tragarse un fallo de red como si fuera lo primero la mandaría al camino equivocado.
    if (typeof signature !== 'string') {
      throw errorWithCode('identifyAs: sign() returned no signature', 'no-signature')
    }
    return this.identify({ data, signature, cert, acta, sign })
  }

  identify ({ data, signature, cert, acta, sign }) {
    if (!data || !signature) throw new Error('identify requires {data, signature}')
    const msg = { type: 'identify', data, signature }
    if (this.app) msg.app = this.app
    if (cert) msg.cert = cert // "una identidad": el proxy bindea este token también bajo tu maestra M
    // Acta de perfil: el proxy la verifica (va firmada) y bindea también el `profileId`, así
    // escribirle a la PERSONA llega a cualquiera de sus dispositivos. Ver acta-de-perfil.md.
    if (acta) msg.acta = acta
    const done = this._request(msg, 'identified')
    // Mi identidad en el cable, para poder decirla en el saludo sin que la app la
    // repita. Se apunta al pedirlo y no al confirmarlo: si la identificación falla,
    // el saludo tampoco sale (el proxio no reparte a una conexión sin identidad).
    this.myPublickey = data.publickey
    if (this._rtc && typeof sign === 'function' && data.publickey) {
      done.then(() => this.enableTurn({ publicKey: data.publickey, sign })).catch(() => {})
    }
    // ANUNCIAR LA LLAVE DE CIFRADO, y por detrás. Identificarse es lo que da dirección a
    // esta identidad; anunciar su llave es lo que hace que alguien pueda sellarle sin
    // haberla emparejado antes. Va después y sin bloquear, como TURN: esperar a esto
    // retrasaría el primer mensaje para ganar algo que solo hace falta cuando el OTRO
    // quiera escribirnos.
    if (typeof sign === 'function' && data.publickey && this.myEncPub) {
      done
        .then(() => this.announceEncPub({ publickey: data.publickey, encPub: this.myEncPub, sign }))
        .catch((e) => {
          // Se dice en voz alta: sin anuncio nadie podrá sellarnos, y el síntoma llega
          // días después y del otro lado («no puedo escribirte»). Callarlo es justo el
          // fallo mudo que el ecosistema paga caro.
          this._emit('error', { type: 'encpub_announce_failed', error: e, code: e?.code || null })
        })
    }
    return done
  }

  /**
   * Pedir al proxy credenciales TURN temporales (Cloudflare) para WebRTC.
   * Requiere haber llamado antes a `identify` en ESTA conexión con la misma
   * pubkey: el proxy solo emite a conexiones identificadas (así el TURN se
   * usa solo desde apps Dotrino y no como relay abierto). Las credenciales
   * expiran solas (TTL corto) y hay cuota por pubkey/hora.
   *
   * @param {Object} opts
   * @param {string} opts.publicKey  Pubkey JWK string del vault (la de identify).
   * @param {(data:any)=>Promise<string|{signature:string}>} opts.sign  Firma del vault (id.signData).
   * @returns {Promise<{enabled:boolean, iceServers:any[]|null, expiresAt:number|null}>}
   */
  async getTurnCredentials ({ publicKey, sign } = {}) {
    if (!publicKey || typeof sign !== 'function') {
      throw new Error('getTurnCredentials requires { publicKey, sign }')
    }
    const data = { op: 'turn-credentials', publickey: publicKey, ts: Date.now() }
    const signature = await normalizeSignature(sign, data)
    const res = await this._request({ type: 'turn-credentials', data, signature }, 'turn-credentials')
    return {
      enabled: !!res.enabled,
      iceServers: res.iceServers || null,
      expiresAt: res.expiresAt || null
    }
  }

  /**
   * Activar TURN para WebRTC: obtiene credenciales temporales del proxy, las
   * inyecta como ICE servers (junto a los STUN por defecto) y las renueva
   * sola antes de expirar. Si el proxy no tiene TURN configurado, no cambia
   * nada (los peers siguen STUN-only con fallback al proxy).
   *
   * Afecta a las conexiones P2P NUEVAS (los peers ya negociados conservan su
   * configuración). Llamalo después de `identify`.
   *
   * @param {Object} opts  Igual que getTurnCredentials ({ publicKey, sign }).
   * @returns {Promise<boolean>} true si TURN quedó activo.
   */
  async enableTurn ({ publicKey, sign } = {}) {
    if (!this._rtc) throw new Error('WebRTC is disabled in this client')
    if (this._turnTimer) {
      clearTimeout(this._turnTimer)
      this._turnTimer = null
    }
    let res
    try {
      res = await this.getTurnCredentials({ publicKey, sign })
    } catch (e) {
      if (e?.status !== 429) throw e
      // 429: EL PROXIO DICE «AHORA NO» (tope diario de tráfico, cuota por hora, o no puede
      // leer el consumo). No es un fallo: se sigue por el proxio, que es el escalón que
      // siempre funciona. Se quita el relevo que hubiera (sus credenciales ya no se
      // renuevan), se dice por un evento y en `stats()`, y se vuelve a pedir cuando el
      // proxio dice que se puede — si no, un aparato que pasó por un día con el tope
      // alcanzado se quedaría sin relevo hasta su siguiente reconexión.
      this._rtc.setIceServers(DEFAULT_ICE_SERVERS)
      const retryAfterMs = Math.max(60000, Number(e.retryAfterMs) || 0)
      this._turn = { active: false, code: e.code || null, retryAt: Date.now() + retryAfterMs }
      this._emit('turn_unavailable', { code: e.code || null, retryAfterMs })
      this._turnTimer = setTimeout(() => {
        this._turnTimer = null
        this.enableTurn({ publicKey, sign }).catch(() => {})
      }, retryAfterMs)
      return false
    }
    if (!res.enabled || !res.iceServers) {
      this._turn = { active: false, code: 'turn-disabled', retryAt: null }
      return false
    }
    this._turn = { active: true, code: null, expiresAt: res.expiresAt || null }
    // En Node el relevo va con su dirección IPv4 ya escrita (ver `pinTurnToIPv4`).
    const turnServers = await pinTurnToIPv4(res.iceServers)
    this._rtc.setIceServers([...turnServers, ...DEFAULT_ICE_SERVERS])
    // Renovar con margen antes de expirar (mínimo 30 s entre renovaciones)
    const refreshIn = Math.max(30000, (res.expiresAt || 0) - Date.now() - 60000)
    this._turnTimer = setTimeout(() => {
      this._turnTimer = null
      this.enableTurn({ publicKey, sign }).catch(() => {
        // Sin conexión o cuota: reintento suave en 60 s; mientras tanto los
        // peers nuevos usan los STUN por defecto.
        this._turnTimer = setTimeout(() => {
          this._turnTimer = null
          this.enableTurn({ publicKey, sign }).catch(() => {})
        }, 60000)
      })
    }, refreshIn)
    return true
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
      throw new Error('Service Worker is not supported in this environment')
    }
    if (typeof PushManager === 'undefined') {
      throw new Error('the Push API is not supported in this browser')
    }
    if (!publicKey || typeof sign !== 'function') {
      throw new Error('enablePush requires { publicKey, sign }')
    }
    if (!vapidPublicKey) {
      const cfg = await this.getPushConfig()
      if (!cfg.enabled || !cfg.vapidPublicKey) throw new Error('the proxy does not have Web Push enabled')
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
    const data = { op: 'push-subscribe', publickey: publicKey, subscription: JSON.stringify(subJson), ts: Date.now(), ...this._appField() }
    const signature = await normalizeSignature(sign, data)
    await this._request({ type: 'push-subscribe', data, signature }, 'push-subscribed')
    return sub
  }

  /**
   * Registrar el TOKEN DE PUSH de una app nativa (FCM en Android; APNs más adelante) bajo
   * esta pubkey, en vez de una PushSubscription del navegador. El proxy lo usa para el
   * mismo timbre sin contenido. Firma del vault, igual que enablePush.
   * @param {{ publicKey:string, sign:Function, token:string, kind?:'fcm' }} opts
   */
  async registerPushToken ({ publicKey, sign, token, kind = 'fcm' } = {}) {
    if (!publicKey || typeof sign !== 'function' || !token) throw new Error('registerPushToken requires { publicKey, sign, token }')
    const data = { op: 'push-subscribe', publickey: publicKey, subscription: JSON.stringify({ kind, token }), ts: Date.now(), ...this._appField() }
    const signature = await normalizeSignature(sign, data)
    await this._request({ type: 'push-subscribe', data, signature }, 'push-subscribed')
    return { kind, token }
  }

  /**
   * DESPIÉRTAME AQUÍ: el timbre de una bóveda que no vive conectada (la de una Lambda). Si
   * llega algo para la PERSONA de este acta y no hay nadie suyo conectado, el proxio guarda el
   * mensaje en la cola de siempre y hace un POST a `url`; la bóveda arranca, se identifica y
   * recibe lo encolado.
   *
   * Lo firma la llave que habla por la bóveda (su llave de comunicación), no la maestra, y el
   * `acta` es lo que prueba que esa llave es de la cuenta: el timbre se guarda para la cuenta
   * (`profileId`), que es a quien le escriben los servicios.
   *
   * `channel` (opcional): el canal donde la buscan quienes no saben su llave —quien entra con
   * usuario y contraseña—. Listarlo vacío también la despierta (`list()` devuelve `waking`).
   *
   * `self` (websocket-proxy ≥ 1.8.0): el timbre es de ESTA llave y no de la cuenta. Lo usa una
   * réplica que vive en una función: se identifica con su llave, y es a ella a la que le
   * escribe un servicio cuando la bóveda no contesta. Un proxio que no anuncia `wake-self` lo
   * guardaría para la cuenta y le quitaría el timbre a la bóveda, así que ahí no se manda.
   *
   * @param {{ publicKey:string, sign:Function, url:string, acta:object, channel?:string, self?:boolean }} opts
   */
  async registerWake ({ publicKey, sign, url, acta, channel, self = false } = {}) {
    if (!publicKey || typeof sign !== 'function' || !url || !acta) throw errorWithCode('registerWake requires { publicKey, sign, url, acta }', 'bad-args')
    if (self && channel) throw errorWithCode('registerWake: a self wake has no channel', 'bad-args')
    if (self && !(Array.isArray(this.caps) && this.caps.includes('wake-self'))) throw errorWithCode('registerWake: this proxy does not support a wake for the device key (needs websocket-proxy >= 1.8.0)', 'no-wake-self-support')
    const data = { op: 'push-subscribe', publickey: publicKey, subscription: JSON.stringify({ kind: 'wake', url, ...(channel ? { channel } : {}), ...(self ? { self: true } : {}) }), ts: Date.now() }
    const signature = await normalizeSignature(sign, data)
    const r = await this._request({ type: 'push-subscribe', data, signature, acta }, 'push-subscribed')
    return { kind: 'wake', url, profile: r?.publickey || null }
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
      const data = { op: 'push-unsubscribe', publickey: publicKey, ts: Date.now(), ...this._appField() }
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
    // La app va firmada, como en enablePush: el recordatorio suena solo en ella (proxio ≥ 1.9.0;
    // uno más viejo la ignora y suena en todas, como antes).
    const data = { op: 'schedule-push', publickey: publicKey, spec: JSON.stringify(spec), ts: Date.now(), ...this._appField() }
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
   * @returns {Promise<Array<{ jobId:number, app:string|null, nextFire:number, cron:string|null, tz:string|null, payload:object|null }>>}
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
    registerTransport(this)
    // El intento anterior, si sigue a medio abrir, se suelta: sus eventos tardíos ya se
    // ignoran (`ws !== this.ws`), pero el socket quedaría abierto sin dueño.
    const prev = this.ws
    if (prev && prev.readyState === 0 /* CONNECTING */) {
      this.ws = null   // antes de cerrarlo: su `close` ya no es de este cliente
      try { prev.close() } catch (_) {}
    }
    const ws = new WebSocket(this.url)
    // Las tramas binarias (binpack.js) llegan como ArrayBuffer: un Blob obligaría a leerlas
    // de forma asíncrona y desordenaría lo que llega detrás.
    try { ws.binaryType = 'arraybuffer' } catch (_) {}
    this.ws = ws
    const openTimer = this.connectTimeout > 0 ? setTimeout(() => this._onConnectTimeout(ws), this.connectTimeout) : null
    openTimer?.unref?.()
    // `ws !== this.ws` ⇒ es un socket que ya abandonamos (p.ej. por heartbeat
    // muerto). Ignoramos sus eventos tardíos para no disparar reconexiones dobles.
    ws.addEventListener('open', () => {
      if (openTimer) clearTimeout(openTimer)
      if (ws !== this.ws) return
      this._connected = true
      this._reconnectAttempts = 0
      this._emit('connect')
      this._startHeartbeat()
    })
    ws.addEventListener('message', (ev) => {
      if (ws !== this.ws) return
      this._noteActivity()           // cualquier frame entrante prueba que está vivo
      this._traffic.frame('in', utf8Length(ev.data))
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
      if (openTimer) clearTimeout(openTimer)
      if (ws !== this.ws) return
      this._stopHeartbeat()
      const wasConnected = this._connected
      this._connected = false
      this._emit('disconnect', { code: ev.code, reason: ev.reason })
      // Reconectar ante cualquier cierre del servidor (incluido code 1000 de un
      // restart limpio del proxy): los cierres INTENCIONALES del cliente ya
      // tienen autoReconnect=false (puesto por close()), así que este guard no
      // filtra desconexiones pedidas por la app. Sin esto, un restart del proxy
      // deja a clientes de larga duración (bots, apps abiertas) zombis para siempre.
      //
      // Y TAMBIÉN CUANDO EL INTENTO NI LLEGÓ A ABRIRSE (`reintentando`). Ese era el
      // agujero, y costó 36 horas de bóveda muda el 2026-09-16: un socket que falla al
      // conectar cierra con `_connected` en false, así que con solo `wasConnected` no se
      // programaba el siguiente intento. O sea que el cliente hacía UN reintento —el de
      // la caída— y si ese caía en un momento en que la red seguía mal, se rendía para
      // siempre, en silencio y con `maxReconnectAttempts` en 100000. Justo el caso normal:
      // cuando se cae la red, el primer reintento a los pocos segundos tampoco encuentra a
      // nadie.
      //
      // Los eventos que se veían: `disconnect reconnecting#1 disconnect` y nada más.
      //
      // `_reconnectAttempts` vuelve a 0 al abrir, así que esto NO convierte un `connect()`
      // inicial fallido en un bucle de fondo: ahí vale 0 y la promesa se rechaza como
      // siempre.
      const retrying = this._reconnectAttempts > 0
      if ((wasConnected || retrying) && this.autoReconnect) {
        this._scheduleReconnect()
      }
    })
  }

  // El intento no abrió ni falló a tiempo: se suelta y se trata como un cierre fallido.
  _onConnectTimeout (ws) {
    if (ws !== this.ws || this._connected) return
    this.ws = null   // a partir de acá, los eventos tardíos de `ws` se ignoran
    try { ws.close() } catch (_) {}
    const err = errorWithCode(`could not open the connection to ${this.url} in ${Math.round(this.connectTimeout / 1000)}s`, 'CONNECT_TIMEOUT')
    this._emit('error', { type: 'connect_timeout', error: err })
    if (this._connectReject) {
      this._connectReject(err)
      this._connectResolve = null
      this._connectReject = null
    }
    // Lo mismo que en `close`: se sigue reintentando solo si esto ya era un reintento. Un
    // `connect()` inicial que no abre se rechaza y ya.
    if (this._reconnectAttempts > 0 && this.autoReconnect) this._scheduleReconnect()
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
    try { const ping = JSON.stringify({ type: 'ping' }); this.ws.send(ping); this._traffic.frame('out', ping.length) }
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
    // UN REINTENTO PENDIENTE NO MANTIENE VIVO EL PROCESO. Desde que se reintenta de verdad
    // —antes la cadena se cortaba sola al primer fallo—, este temporizador basta para que un
    // programa de Node que se olvidó de cerrar el cliente no termine nunca. Lo de siempre:
    // esto es mantenimiento de fondo, y quién se va es decisión de la app. En el navegador
    // `unref` no existe y no hace falta.
    this._reconnectTimer.unref?.()
  }

  _handleFrame (raw) {
    let data
    if (typeof raw === 'string') {
      try { data = JSON.parse(raw) } catch (e) {
        this._emit('error', { type: 'parse_error', error: e })
        return
      }
    } else {
      // Trama binaria: la cabecera de siempre y el `message` en crudo.
      try {
        const { header, body } = decodeFrame(raw)
        data = { ...header, message: body }
      } catch (e) {
        this._emit('error', { type: 'parse_error', code: e.code || 'bad-frame', error: e })
        return
      }
    }
    const { type } = data
    switch (type) {
      case 'connected':
        // `instance` es el identificador de esta conexión, ya cualificado por
        // nodo: se le puede escribir desde cualquier proxio de la malla. Es el
        // mismo valor que `token` (el nombre histórico), pero ya NO es un código
        // de 4 caracteres para dictar — para eso está `requestPairingCode()`.
        this.instance = data.instance || data.token
        this.node = data.node || null
        // Los nodos que conoce este proxio. Sirve para los descubrimientos que
        // son de TODO el ecosistema y no tienen dueño natural (la lista pública
        // de salas): se pregunta en cada nodo y se mezcla, en vez de designar a
        // uno como árbitro. Son públicos: van en cada instancia y en /peers.
        this.peers = Array.isArray(data.peers) ? data.peers : []
        // QUÉ SABE HACER ESTE PROXIO, dicho por él al conectar (§14: una incompatibilidad
        // que no se anuncia se vive como silencio). `caps` ausente = proxio anterior a que
        // esto existiera: no se da por hecho nada, se pregunta igual y contesta la
        // pregunta.
        this.protocol = Number.isInteger(data.protocol) ? data.protocol : null
        this.caps = Array.isArray(data.caps) ? data.caps : null
        /** Este nodo + los que conoce, sin repetidos. */
        this.knownNodes = [this.node, ...this.peers].filter((n, i, a) => n && a.indexOf(n) === i)
        this.token = this.instance
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
        this._traffic.peer('in', 'proxy', { token: from || null, pubkey: from_publickey || this._tokenPubkeys.get(from) || null }, utf8Length(message))
        if (this._rtc && parsed && parsed.t === RTC_TAG) {
          this._rtc.handleIncoming(from, parsed)
          break
        }
        // La señalización del Bluetooth tampoco sube a la app, haya Bluetooth o no.
        if (parsed && parsed.t === BLE_TAG) {
          this._ble?.handleIncoming(from, parsed)
          break
        }
        // El saludo se atiende AQUÍ, antes de `_deliver`: es del transporte y no sube a
        // la app, así que `requireSealed` no lo ve pasar ni tiene que hacerle una
        // excepción.
        if (parsed && parsed.t === HELLO_TAG) {
          this._onHello(from, parsed)
          break
        }
        this._deliver(from, parsed ?? message, {
          raw: message, timestamp, via: 'proxy',
          fromPubkey: from_publickey || null,
          queued: !!queued,
          queuedAt: queued_at || null
        })
        break
      }
      case 'disconnected':
        // El token muere con la conexión y no se recicla: lo aprendido de él deja de
        // valer en el acto. Guardarlo «por si vuelve» sería sellarle a quien ya no está.
        this.forgetToken(data.token)
        this._emit('peer_disconnected', data.token, data.channel || null)
        if (this._rtc && data.token) this._rtc.closePeer(data.token)
        if (this._ble && data.token) this._ble.closePeer(data.token)
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
      case 'message_sent':
        this._tokenFailed(data)
        this._resolvePending(data, type)
        break
      case 'identified':
      case 'push-config':
      case 'push-subscribed':
      case 'push-unsubscribed':
      case 'push-scheduled':
      case 'push-canceled':
      case 'push-list':
      case 'turn-credentials':
      case 'pair-code':
      case 'pair-redeem':
      case 'encpub-announced':
      case 'enc-lookup':
        this._resolvePending(data, type)
        break
      case 'error':
        this._emit('error', {
          type: 'server',
          error: data.error,
          // El código es el contrato; la frase es para las personas (CONVENCIONES §8.1).
          code: data.code || null,
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
      throw errorWithCode('WebSocket not connected', 'NOT_CONNECTED')
    }
    if (frame.message instanceof Uint8Array) {
      this._needBinaryProxy()
      const { message, ...header } = frame
      const bytes = encodeFrame(header, message)
      this.ws.send(bytes)
      this._countOut(frame, bytes)
      return
    }
    const text = JSON.stringify(frame)
    this.ws.send(text)
    this._countOut(frame, text)
  }

  /** Cuenta un frame que sale por el proxio, y a quién iba. */
  _countOut (frame, text) {
    this._traffic.frame('out', utf8Length(text))
    if (typeof frame.message !== 'string' && !(frame.message instanceof Uint8Array)) return
    const bytes = utf8Length(frame.message)
    for (const token of Array.isArray(frame.to) ? frame.to : []) {
      this._traffic.peer('out', 'proxy', { token, pubkey: this._tokenPubkeys.get(token) || null }, bytes)
    }
    for (const pubkey of Array.isArray(frame.to_publickey) ? frame.to_publickey : []) {
      this._traffic.peer('out', 'proxy', { pubkey }, bytes)
    }
  }

  /**
   * ESTADÍSTICAS DE RED: cuánto entró y salió, por conexión, y por qué camino.
   *
   * `route` es por dónde va AHORA cada conexión: `proxy`, `connecting` (por el proxio
   * mientras se negocia WebRTC), `direct` o `turn` (WebRTC, sin o con relevo), `webrtc`
   * (canal abierto sin poder saber cuál) o `failed` (WebRTC no salió: sigue por el proxio).
   * Los bytes van separados por el camino por el que pasaron de verdad.
   *
   * Los bytes son de payload (UTF-8), no del cable: las cabeceras de TLS/DTLS no se ven
   * desde aquí.
   */
  async stats () {
    const t = this._traffic
    const routes = this._rtc ? await this._rtc.describe() : new Map()
    // Un canal de Bluetooth abierto manda sobre un WebRTC que no salió o va por TURN (§1).
    if (this._ble) {
      for (const [tok, r] of this._ble.describe()) {
        const cur = routes.get(tok)
        if (r === 'bluetooth' ? cur !== 'direct' : !cur) routes.set(tok, r)
      }
    }
    const peers = [...t.peers.values()].map((p) => {
      const pubkey = p.pubkey || (p.token && this._tokenPubkeys.get(p.token)) || null
      const rtc = p.token ? routes.get(p.token) : null
      return {
        token: p.token,
        pubkey,
        route: rtc && rtc !== 'failed' && rtc !== 'connecting' ? rtc : (rtc || 'proxy'),
        bytesIn: { ...p.bytesIn },
        bytesOut: { ...p.bytesOut },
        msgsIn: p.msgsIn,
        msgsOut: p.msgsOut,
        firstAt: p.firstAt,
        lastAt: p.lastAt
      }
    }).sort((a, b) => b.lastAt - a.lastAt)
    return {
      url: this.url,
      app: this.app,
      node: this.node || null,
      token: this.token,
      publickey: this.myPublickey,
      connected: this._connected,
      webrtc: !!this._rtc,
      bluetooth: !!this._ble?.available,
      // El relevo: null si nunca se pidió; si no, activo o por qué no (`code`, `retryAt`).
      turn: this._turn ? { ...this._turn } : null,
      since: t.since,
      proxy: { ...t.proxy },
      peers
    }
  }

  _request (frame, expectedType, channelKey) {
    return new Promise((resolve, reject) => {
      const id = `req_${this._nextId++}`
      const out = { ...frame, id }
      const timer = setTimeout(() => {
        this._pending.delete(id)
        reject(errorWithCode(`Timeout waiting for ${expectedType}`, 'REQUEST_TIMEOUT'))
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
    // Con su `code`: quien llama distingue los casos por él, no por la frase (que el proxio
    // puede cambiar o traducir). Antes se perdía aquí y solo quedaba comparar el texto.
    const e = errorWithCode(data.error || 'Server error', data.code || null)
    // «Ahora no» (429) y cuánto esperar, cuando el proxio lo dice.
    if (data.status) e.status = data.status
    if (data.retry_after_ms) e.retryAfterMs = data.retry_after_ms
    entry.reject(e)
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
  if (!sig) throw new Error('sign() must return a base64 signature (a string or {signature})')
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
