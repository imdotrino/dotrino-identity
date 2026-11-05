/**
 * WebRTC layer for the Dotrino proxy client.
 *
 * - One RTCPeerConnection + RTCDataChannel per remote token (lazy).
 * - Signaling (offer / answer / ICE) goes through the proxy as regular
 *   `send()` payloads tagged with `_rtc`.
 * - Once the DataChannel is open, payloads from `client.send(token, ...)`
 *   travel P2P; before that (or on failure) they fall back to the proxy.
 * - STUN by default; `client.enableTurn()` adds the proxy's temporary TURN servers.
 *
 * Glare resolution: the peer with the lexicographically smaller token is
 * the "polite" one (rolls back on collision).
 */

import { routeOf, utf8Length } from './stats.js'

export const DEFAULT_ICE_SERVERS = [
  { urls: 'stun:stun.l.google.com:19302' },
  { urls: 'stun:stun1.l.google.com:19302' },
  { urls: 'stun:global.stun.twilio.com:3478' }
]

const RTC_TAG = '__cc_rtc__'

/**
 * DE DÓNDE SALE `RTCPeerConnection`, y por qué esto existe.
 *
 * En un navegador es nativo. En Node no hay ninguno, y por eso el ecosistema tenía WebRTC
 * apagado a mano en todas partes: dos máquinas Node se hablaban por el proxio aunque
 * estuvieran en la misma red, que es lo contrario de la regla («siempre el camino más
 * directo», CLAUDE.md).
 *
 * Se resuelve en este orden:
 *
 *   1. el del entorno (navegador, o un Node que algún día lo traiga);
 *   2. el que le inyecten (`setPeerConnection`), para no atarse a un paquete concreto;
 *   3. **`@dotrino/webrtc`**, si está instalado — y si no, **`werift`**, del que aquél es
 *      una poda. Los dos son WebRTC en JavaScript puro, sin binario nativo, y eso no es una
 *      preferencia estética: la bóveda se distribuye como un ejecutable único (SEA) y un
 *      `.node` no entra ahí. Se cargan PEREZOSO y ninguno es dependencia de este paquete:
 *      quien lo quiera en Node lo instala.
 *
 *      La poda va primero porque es la mitad de paquetes y sin la pila de audio y vídeo,
 *      que un canal de datos no toca. Se sigue aceptando el de arriba para no obligar a
 *      nadie a cambiar, y porque son el mismo código.
 *
 * Si no hay ninguno, WebRTC queda apagado y se sigue por el proxio. Eso no es un fallo:
 * es el escalón 4, que siempre funciona.
 */
let _PC = null
let _PCLookedUp = false

/**
 * Si este canal sirve AHORA para mandar: abierto Y con la conexión de debajo `connected`. Un
 * canal abierto sobre una conexión `disconnected` acepta `send()` y lo pierde.
 */
export function usable (peer) {
  return !!(peer && peer.dc && peer.dc.readyState === 'open' && peer.pc && peer.pc.connectionState === 'connected')
}

export function setPeerConnection (impl) { _PC = impl; _PCLookedUp = true }

export function resolvePeerConnection () {
  if (_PCLookedUp) return _PC
  _PCLookedUp = true
  if (typeof globalThis.RTCPeerConnection === 'function') { _PC = globalThis.RTCPeerConnection; return _PC }
  return _PC
}

/**
 * Busca una implementación para Node. Es ASÍNCRONO —importar un paquete lo es— así que se
 * llama una vez al arrancar, no en medio de una negociación.
 */
export async function loadNodePeerConnection () {
  if (_PCLookedUp && _PC) return _PC
  if (typeof globalThis.RTCPeerConnection === 'function') { _PC = globalThis.RTCPeerConnection; _PCLookedUp = true; return _PC }
  for (const name of ['@dotrino/webrtc', 'werift']) {
    try {
      const w = await import(name)
      if (typeof w?.RTCPeerConnection === 'function') { _PC = w.RTCPeerConnection; _PCLookedUp = true; return _PC }
    } catch (_) { /* no está: se prueba el siguiente, y si no, el proxio (escalón 4) */ }
  }
  _PCLookedUp = true
  return _PC
}

/**
 * EL RELEVO, FIJADO A IPv4 — solo fuera del navegador.
 *
 * La implementación de Node (`@dotrino/webrtc`, o sea werift) abre el socket UDP hacia el
 * relevo en IPv4 y nada más, pero resuelve el nombre sin pedir familia. En una máquina con
 * las dos, el nombre sale en IPv6: el pedido se manda a una dirección que ese socket no
 * alcanza, se reintenta siete veces (6,4 s medidos) y solo entonces se cae a TCP. Y como la
 * oferta espera a que termine de reunir candidatos, CADA negociación arrancaba 6,4 s tarde
 * por punta — una sesión más corta que eso no salía nunca del proxio.
 *
 * Con la dirección ya escrita no hay nada que resolver: 30 ms, y el relevo va por UDP.
 *
 * Solo las `turn:`. Una `turns:` necesita el nombre para comprobar el certificado, y a un
 * `stun:` no le pasa esto. Se envuelve desde aquí y no se toca la librería, que es una poda
 * sin cambios de lógica (README de `dotrino-webrtc`).
 *
 * Si el nombre no tiene dirección IPv4, se deja como vino: esa máquina no tiene por dónde
 * llegar en UDP, y con el nombre la librería todavía llega por TCP.
 *
 * @param {any[]} iceServers
 * @param {{ native?: boolean, lookup?: (host: string) => Promise<string> }} [opts]
 * @returns {Promise<any[]>}
 */
export async function pinTurnToIPv4 (iceServers, opts = {}) {
  const native = opts.native ?? (typeof globalThis.RTCPeerConnection === 'function')
  if (native || !Array.isArray(iceServers)) return iceServers
  let lookup = opts.lookup
  if (!lookup) {
    // El nombre va en una variable para que ningún empaquetador lo siga: esto lo importan
    // las apps de navegador, donde `node:dns` no existe (y donde no se llega hasta aquí).
    const mod = 'node:dns'
    const dns = await import(mod)
    lookup = async (host) => (await dns.promises.lookup(host, { family: 4 })).address
  }
  const cache = new Map()
  const pin = async (url) => {
    const m = /^(turn:)([^:?[\]]+)((?::\d+)?(?:\?.*)?)$/i.exec(String(url).trim())
    if (!m || /^[\d.]+$/.test(m[2])) return url
    if (!cache.has(m[2])) cache.set(m[2], lookup(m[2]).catch(() => null))
    const ip = await cache.get(m[2])
    return ip ? m[1] + ip + m[3] : url
  }
  return Promise.all(iceServers.map(async (s) => {
    if (!s || s.urls == null) return s
    const urls = Array.isArray(s.urls) ? await Promise.all(s.urls.map(pin)) : await pin(s.urls)
    return { ...s, urls }
  }))
}

export class WebRTCManager {
  /**
   * @param {object} opts
   * @param {() => string|null} opts.getSelfToken
   * @param {(to: string, payload: any) => void} opts.signalSend  raw proxy send
   * @param {(from: string, parsed: any, meta: any) => void} opts.deliverMessage forwards
   *        an incoming P2P payload as if it had arrived via the proxy
   * @param {(event: string, ...args: any[]) => void} opts.emit
   * @param {(dir: 'in'|'out', token: string, bytes: number, route: 'direct'|'turn'|'webrtc') => void} [opts.count]
   *        cuenta el tráfico que va por el canal (ver stats.js)
   * @param {{iceServers?: any[]}} [opts.config]
   */
  constructor (opts) {
    this.acceptFrom = null   // ver `handleIncoming`: lo pone quien monta el cliente
    this.getSelfToken = opts.getSelfToken
    this.signalSend = opts.signalSend
    this.deliverMessage = opts.deliverMessage
    this.emit = opts.emit
    this.count = typeof opts.count === 'function' ? opts.count : null
    this.iceServers = (opts.config && opts.config.iceServers) || DEFAULT_ICE_SERVERS
    this.peers = new Map() // remoteToken -> PeerState
    this.closed = false    // `closeAll()`: no se abre nada más hasta `reopen()`
  }

  /** El cliente vuelve a conectar tras un `close()`: se puede negociar otra vez. */
  reopen () { this.closed = false }

  /**
   * True if this is a control envelope and was consumed.
   * Otherwise the caller should keep delivering it normally.
   */
  /**
   * QUIÉN PUEDE HACERTE NEGOCIAR. Antes: cualquiera que supiera alcanzarte por el proxio.
   *
   * Aceptar una señal arranca DTLS, ICE y SCTP — código que parsea red no confiable— así
   * que quien decide si eso corre no puede ser el que llama a la puerta. En un navegador
   * eso ya era así y se vivía con ello; en la bóveda es el proceso que tiene la maestra.
   *
   * `acceptFrom` lo decide quien monta el cliente: la bóveda solo acepta a MIEMBROS DE SU
   * ACTA. Sin política se mantiene lo de antes, para no romper a quien ya dependía de ello.
   */
  handleIncoming (from, parsed) {
    if (!parsed || typeof parsed !== 'object' || parsed.t !== RTC_TAG) return false
    if (this.acceptFrom && !this.acceptFrom(from)) return false
    // Cerrado: una señal que llega tarde no abre una conexión que ya nadie va a cerrar.
    if (this.closed) return true
    const peer = this._ensurePeer(from)
    this._handleSignal(peer, parsed).catch((e) => {
      this.emit('error', { type: 'webrtc_signal', error: e, peer: from })
    })
    return true
  }

  /**
   * Try to send the given JSON payload over a DataChannel.
   * Returns true if it was sent P2P; false if the caller should fall back
   * to the proxy. Also opportunistically starts the connection negotiation.
   */
  trySend (to, payloadString) {
    if (this.closed) return false
    const peer = this._ensurePeer(to)
    if (usable(peer)) {
      try {
        peer.dc.send(payloadString)
        this.count?.('out', to, utf8Length(payloadString), peer.route || 'webrtc')
        return true
      } catch (_) {
        return false
      }
    }
    if (!peer.negotiating && !peer.failed) this._startNegotiation(peer).catch(() => {})
    return false
  }

  /**
   * Mandar por el canal directo ESPERANDO a que su búfer baje. Para las partes de un
   * mensaje grande: soltarlas todas de golpe desborda el búfer del canal, el navegador lo
   * cierra y el resto se pierde. Devuelve false si el canal no está (o se cerró), y quien
   * llama sigue por el proxio.
   */
  async sendDirect (to, payloadString, highWater = 1024 * 1024) {
    const peer = this.peers.get(to)
    const dc = peer && peer.dc
    if (!usable(peer)) return false
    while (dc.bufferedAmount > highWater) {
      await new Promise((r) => setTimeout(r, 15))
      if (!usable(peer)) return false
    }
    try {
      dc.send(payloadString)
      this.count?.('out', to, utf8Length(payloadString), peer.route || 'webrtc')
      return true
    } catch (_) {
      return false
    }
  }

  /** Optional: explicitly preconnect to a peer. */
  connect (to) {
    if (this.closed) return Promise.reject(new Error('WebRTC closed'))
    const peer = this._ensurePeer(to)
    if (usable(peer)) return Promise.resolve()
    if (!peer.negotiating) this._startNegotiation(peer).catch(() => {})
    return new Promise((resolve, reject) => {
      peer.openWaiters.push({ resolve, reject })
    })
  }

  /**
   * CERRAR CON UNA DESCRIPCIÓN EN VUELO DEJA SOCKETS ABIERTOS. En Node (`@dotrino/webrtc`, o
   * sea werift), `setLocalDescription` reúne los candidatos y abre un socket UDP por
   * dirección; si `close()` llega en medio, cierra los que ya estaban y los que terminan de
   * abrirse después no los cierra nadie. El proceso no sale nunca: así se colgaron las
   * pruebas de la bóveda en CI (0.186.0 y 0.186.1). Por eso, con una descripción en vuelo,
   * la conexión se cierra al terminar esta, que ya ha reunido todo.
   */
  closePeer (to) {
    const peer = this.peers.get(to)
    if (!peer) return
    this.peers.delete(to)
    peer.closing = true
    try { if (peer.dc) peer.dc.close() } catch (_) {}
    if (!peer.busy) this._closePC(peer)
  }

  closeAll () {
    this.closed = true
    for (const t of Array.from(this.peers.keys())) this.closePeer(t)
  }

  _closePC (peer) {
    try { if (peer.pc) peer.pc.close() } catch (_) {}
  }

  /** Una descripción (local o remota) en vuelo: mientras dure, cerrar espera a que acabe. */
  async _describe (peer, fn) {
    peer.busy = (peer.busy || 0) + 1
    try { return await fn() } finally {
      peer.busy--
      if (peer.closing && !peer.busy) this._closePC(peer)
    }
  }

  /**
   * Reemplaza la lista de ICE servers para las PRÓXIMAS conexiones (los peers
   * ya negociados conservan la suya). Lo usa `client.enableTurn()` para
   * inyectar las credenciales TURN temporales del proxy.
   */
  setIceServers (list) {
    if (Array.isArray(list) && list.length) this.iceServers = list
  }

  /** Pregunta a ICE por dónde va el canal y lo apunta en `peer.route`. */
  async probeRoute (peer) {
    const r = await routeOf(peer.pc)
    if (r) peer.route = r
    return peer.route || null
  }

  /**
   * El estado de cada canal, para las estadísticas: `connecting` mientras se negocia,
   * `direct`/`turn`/`webrtc` con el canal abierto, `failed` si no salió.
   */
  async describe () {
    const out = new Map()
    for (const peer of this.peers.values()) {
      const open = usable(peer)
      if (open) { try { await this.probeRoute(peer) } catch (_) {} }
      out.set(peer.remote, open ? (peer.route || 'webrtc') : peer.failed ? 'failed' : peer.negotiating ? 'connecting' : null)
    }
    return out
  }

  isOpen (to) {
    return usable(this.peers.get(to))
  }

  // ---------- internals ----------

  _ensurePeer (remoteToken) {
    let peer = this.peers.get(remoteToken)
    if (peer) return peer
    peer = {
      remote: remoteToken,
      pc: null,
      dc: null,
      makingOffer: false,
      ignoreOffer: false,
      negotiating: false,
      failed: false,
      polite: this._isPolite(remoteToken),
      pendingCandidates: [],
      openWaiters: []
    }
    this.peers.set(remoteToken, peer)
    return peer
  }

  _isPolite (remoteToken) {
    const self = this.getSelfToken()
    if (!self) return false
    return self < remoteToken
  }

  _createPC (peer) {
    const PC = resolvePeerConnection()
    if (!PC) throw new Error('no WebRTC here: install `werift` for Node, or run this in a browser')
    const pc = new PC({ iceServers: this.iceServers })
    peer.pc = pc
    peer.polite = this._isPolite(peer.remote)

    pc.onicecandidate = (ev) => {
      if (ev.candidate) {
        this._signal(peer, { kind: 'ice', candidate: ev.candidate })
      }
    }
    // EL CANAL «ABIERTO» NO BASTA. Si la red de debajo se corta (pantalla apagada, cambio de
    // wifi, la pestaña congelada en Android), el canal sigue diciendo `open` hasta que ICE da
    // la conexión por muerta, y eso tarda decenas de segundos: lo que se mandara ahí se perdía
    // sin subir al TURN ni al proxio. Por eso solo se usa con la conexión `connected` (ver
    // `usable`), y cada cambio se anuncia para que quien escribe vuelva a mirar el camino.
    pc.onconnectionstatechange = () => {
      const st = pc.connectionState
      if (st === 'failed' || st === 'closed') {
        this._failPeer(peer)
        // Cerrarlo es lo que avisa (`dc.onclose` → `webrtc_close`).
        try { if (peer.dc) peer.dc.close() } catch (_) {}
      } else if (st === 'disconnected') {
        if (peer.dc && peer.dc.readyState === 'open') this.emit('webrtc_close', peer.remote)
      } else if (st === 'connected') {
        // Volvió de `disconnected` con el canal intacto: vuelve a ser el camino.
        if (peer.dc && peer.dc.readyState === 'open' && peer.wasOpened) this.emit('webrtc_open', peer.remote)
      }
    }
    pc.ondatachannel = (ev) => this._attachDC(peer, ev.channel)
    pc.onnegotiationneeded = async () => {
      try {
        peer.makingOffer = true
        await this._describe(peer, () => pc.setLocalDescription())
        if (peer.closing) return
        this._signal(peer, { kind: 'sdp', sdp: pc.localDescription })
      } catch (e) {
        this.emit('error', { type: 'webrtc_negotiate', error: e, peer: peer.remote })
      } finally {
        peer.makingOffer = false
      }
    }
    return pc
  }

  async _startNegotiation (peer) {
    if (peer.negotiating) return
    peer.negotiating = true
    try {
      if (!peer.pc) this._createPC(peer)
      // Caller side creates the data channel; the other end gets it via
      // `ondatachannel`. The token comparison decides who initiates.
      const self = this.getSelfToken()
      if (self && self > peer.remote && !peer.dc) {
        const dc = peer.pc.createDataChannel('cc', { ordered: true })
        this._attachDC(peer, dc)
      } else if (self && self < peer.remote && !peer.dc) {
        // EL QUE NO CREA EL CANAL TIENE QUE PEDIRLO. Sin un canal nuevo no hay nada que
        // negociar (`onnegotiationneeded` no salta), así que si el que quiere ir directo
        // era el del token menor, el otro nunca se enteraba y el canal no se abría jamás:
        // la mitad de las parejas se quedaban en el proxio según cómo cayera el sorteo de
        // tokens. Se le pide al otro que arranque; el que crea el canal sigue siendo uno
        // solo, así que no hay ofertas cruzadas.
        this._signal(peer, { kind: 'start' })
      }
    } catch (e) {
      this.emit('error', { type: 'webrtc_start', error: e, peer: peer.remote })
      this._failPeer(peer)
    }
  }

  _attachDC (peer, dc) {
    peer.dc = dc
    // Los bytes como ArrayBuffer: un Blob se lee de forma asíncrona y desordenaría las partes.
    try { dc.binaryType = 'arraybuffer' } catch (_) {}
    dc.onopen = () => {
      peer.wasOpened = true
      // Por dónde salió: directo o por TURN. Por detrás, sin retrasar a nadie.
      this.probeRoute(peer).catch(() => {})
      this.emit('webrtc_open', peer.remote)
      const waiters = peer.openWaiters
      peer.openWaiters = []
      for (const w of waiters) w.resolve()
    }
    dc.onclose = () => {
      this.emit('webrtc_close', peer.remote)
    }
    dc.onerror = (err) => {
      this.emit('error', { type: 'webrtc_dc', error: err, peer: peer.remote })
    }
    dc.onmessage = (ev) => {
      let parsed = null
      let raw = ev.data
      this.count?.('in', peer.remote, utf8Length(raw), peer.route || 'webrtc')
      if (typeof raw === 'string') {
        try { parsed = JSON.parse(raw) } catch (_) { parsed = null }
      } else if (raw instanceof ArrayBuffer) {
        // Un mensaje con bytes (binpack.js). En Node llega ya como Buffer, que es un Uint8Array.
        raw = new Uint8Array(raw)
      }
      this.deliverMessage(peer.remote, parsed ?? raw, { raw, timestamp: Date.now(), via: 'webrtc' })
    }
  }

  _failPeer (peer) {
    peer.failed = true
    peer.negotiating = false
    const waiters = peer.openWaiters
    peer.openWaiters = []
    const err = new Error('WebRTC failed')
    for (const w of waiters) w.reject(err)
  }

  _signal (peer, body) {
    this.signalSend(peer.remote, { t: RTC_TAG, ...body })
  }

  async _handleSignal (peer, msg) {
    if (!peer.pc) this._createPC(peer)
    const pc = peer.pc

    if (msg.kind === 'start') {
      // El otro quiere ir directo y el canal lo creamos nosotros (ver `_startNegotiation`).
      // Solo lo atiende el del token mayor: así un `start` nunca rebota.
      const self = this.getSelfToken()
      if (self && self > peer.remote && !peer.dc) {
        peer.negotiating = false
        await this._startNegotiation(peer)
      }
      return
    }

    if (msg.kind === 'sdp' && msg.sdp) {
      const offerCollision = msg.sdp.type === 'offer' &&
        (peer.makingOffer || pc.signalingState !== 'stable')
      peer.ignoreOffer = !peer.polite && offerCollision
      if (peer.ignoreOffer) return
      await this._describe(peer, () => pc.setRemoteDescription(msg.sdp))
      if (peer.closing) return
      // flush any queued candidates
      for (const c of peer.pendingCandidates) {
        try { await pc.addIceCandidate(c) } catch (_) {}
      }
      peer.pendingCandidates = []
      if (msg.sdp.type === 'offer') {
        await this._describe(peer, () => pc.setLocalDescription())
        if (peer.closing) return
        this._signal(peer, { kind: 'sdp', sdp: pc.localDescription })
      }
    } else if (msg.kind === 'ice' && msg.candidate) {
      try {
        if (!pc.remoteDescription || !pc.remoteDescription.type) {
          peer.pendingCandidates.push(msg.candidate)
        } else {
          await pc.addIceCandidate(msg.candidate)
        }
      } catch (e) {
        if (!peer.ignoreOffer) throw e
      }
    }
  }
}

export { RTC_TAG }
