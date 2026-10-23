/**
 * EL ESCALÓN DEL BLUETOOTH (docs/bluetooth.md): va después de WebRTC directo y antes de
 * TURN. Misma forma que `WebRTCManager`, así el cliente los trata igual: la señalización
 * entra por `handleIncoming`, se sube con `upgrade`, se manda con `trySend` / `sendDirect`.
 *
 * No toca el Bluetooth: habla con un ADAPTADOR, que es lo único que cambia de una
 * plataforma a otra.
 *
 *   start(server)        server = { hello(): Uint8Array, beacon(): Uint8Array,
 *                                   onWrite(centralId, bytes), onDisconnect(centralId) }
 *                        empieza a anunciar y a servir el GATT
 *   notify(centralId, bytes)      Promise: un valor de `tx` a ese central
 *   chunkFor(centralId)           bytes por valor hacia ese central (MTU − 3)
 *   drop(centralId)               Promise: desconecta a ese central
 *   scan(onFound)                 Promise<stop()>: avisa de cada periférico de Dotrino visto ({ id })
 *   connect(device)               Promise<Link>
 *       Link = { chunk, read(uuid), write(bytes), subscribe(onValue), close(), onClose(cb) }
 *   stop()
 *
 * Lo implementan `bluez.js` (Linux), el aire falso de las pruebas y, si hiciera falta, un
 * puente nativo.
 */

import * as W from './wire.js'

const FAIL_RETRY_MS = 60_000
const SEEN_TTL_MS = 60_000

export class BluetoothManager {
  /**
   * @param {object} opts
   * @param {() => string|null} opts.getSelfToken
   * @param {(to: string, payload: any) => void} opts.signalSend   trama por el proxio
   * @param {(from: string, parsed: any, meta: any) => void} opts.deliverMessage
   * @param {(event: string, ...args: any[]) => void} opts.emit
   * @param {(dir: 'in'|'out', token: string, bytes: number, route: 'bluetooth') => void} [opts.count]
   */
  constructor (opts) {
    this.acceptFrom = null
    this.getSelfToken = opts.getSelfToken
    this.signalSend = opts.signalSend
    this.deliverMessage = opts.deliverMessage
    this.emit = opts.emit
    this.count = typeof opts.count === 'function' ? opts.count : null
    this.adapter = null
    this.bid = null
    this.beacon = new Uint8Array(0)
    this.peers = new Map()      // token -> estado de la negociación / canal
    this.centrals = new Map()   // centralId -> { rx, peer, chain } (lado periférico)
    this.wanted = new Map()     // bid -> peer que buscamos en el aire (lado central)
    this._seen = new Map()      // deviceId -> { bid, at }
    this._probing = new Set()
    this._scanListeners = new Set()
    this._stopScan = null
    this._scanStarting = null
    this._connectLock = Promise.resolve()
    this._rotate = null
  }

  /** Hay Bluetooth en marcha en este proceso. */
  get available () { return !!this.adapter }

  async start (adapter) {
    if (this.adapter) return
    this.bid = W.randomBid()
    await adapter.start({
      hello: () => W.encodeHello(this.bid),
      beacon: () => this.beacon,
      onWrite: (centralId, bytes) => this._onWrite(centralId, bytes),
      onDisconnect: (centralId) => this._onCentralGone(centralId),
    })
    this.adapter = adapter
    this._rotate = setInterval(() => { this.bid = W.randomBid() }, W.BID_ROTATE_MS)
    this._rotate.unref?.()
  }

  async stop () {
    this.closeAll()
    if (this._rotate) clearInterval(this._rotate)
    this._rotate = null
    const a = this.adapter
    this.adapter = null
    if (this._stopScan) { const s = this._stopScan; this._stopScan = null; await s().catch(() => {}) }
    if (a) await a.stop()
  }

  // ---------- señalización ----------

  /** True si era una trama de este escalón (se consume aunque no haya Bluetooth). */
  handleIncoming (from, parsed) {
    if (!parsed || typeof parsed !== 'object' || parsed.t !== W.BLE_TAG) return false
    if (this.acceptFrom && !this.acceptFrom(from)) return true
    if (!this.adapter) return true
    if (typeof parsed.bid !== 'string' || typeof parsed.epub !== 'string') return true
    this._handleSignal(from, parsed).catch((e) => {
      this.emit('error', { type: 'bluetooth_signal', error: e, peer: from })
      const p = this.peers.get(from)
      if (p) this._fail(p)
    })
    return true
  }

  /** Empieza a negociar con `token` si no hay nada en curso. Sin esperas y sin errores. */
  upgrade (token) {
    if (!this.adapter || !this.getSelfToken()) return
    const p = this.peers.get(token)
    if (p && p.state !== 'failed') return
    if (p && Date.now() - p.failedAt < FAIL_RETRY_MS) return
    this._offer(token).catch((e) => this.emit('error', { type: 'bluetooth_offer', error: e, peer: token }))
  }

  async _offer (token) {
    const p = this._newPeer(token)
    p.eph = await W.makeEphemeral()
    p.state = 'offered'
    p.myBid = this.bid
    this._timer(p, W.ANSWER_TIMEOUT_MS)
    this.signalSend(token, { t: W.BLE_TAG, kind: 'offer', bid: p.myBid, epub: p.eph.epub })
  }

  async _handleSignal (from, msg) {
    let p = this.peers.get(from)
    if (msg.kind === 'offer') {
      if (p && p.state === 'offered') {
        // Ofertas cruzadas: la del otro sirve de respuesta. El ECDH es simétrico, así que
        // los dos llegan a la misma llave sin que nadie conteste.
      } else {
        if (p) this._drop(p)
        p = this._newPeer(from)
        p.eph = await W.makeEphemeral()
        p.myBid = this.bid
        this.signalSend(from, { t: W.BLE_TAG, kind: 'answer', bid: p.myBid, epub: p.eph.epub })
      }
    } else if (msg.kind === 'answer') {
      if (!p || p.state !== 'offered') return
    } else {
      return
    }
    const self = this.getSelfToken()
    if (!self) return this._fail(p)
    p.key = await W.deriveKey(p.eph.privateKey, msg.epub, self, from)
    p.eph = null
    p.theirBid = msg.bid
    p.role = self > from ? 'central' : 'peripheral'
    // Los trozos de `tx` llevan la etiqueta del CENTRAL (docs §5): BlueZ notifica a todos.
    p.tag = W.tagOf(p.role === 'central' ? p.myBid : p.theirBid)
    p.state = 'keyed'
    this._timer(p, W.FIND_TIMEOUT_MS)
    if (p.role === 'peripheral') this._retryHellos()
    if (p.role === 'central') {
      this.wanted.set(p.theirBid, p)
      this._addScan(this._onFoundForPeers).catch((e) => {
        this.emit('error', { type: 'bluetooth_scan', error: e })
        this._fail(p)
      })
    }
  }

  // ---------- lado central ----------

  _onFoundForPeers = (dev) => {
    if (!this.wanted.size || this._probing.has(dev.id)) return
    const seen = this._seen.get(dev.id)
    if (seen && Date.now() - seen.at < SEEN_TTL_MS && !this.wanted.has(seen.bid)) return
    this._probing.add(dev.id)
    this._withConnectLock(async () => {
      let link = null
      try {
        link = await this.adapter.connect(dev)
        const bid = W.decodeHello(await link.read(W.HELLO_UUID))
        this._seen.set(dev.id, { bid, at: Date.now() })
        const p = bid ? this.wanted.get(bid) : null
        if (!p || p.state !== 'keyed') { await link.close(); return }
        this.wanted.delete(bid)
        if (!this.wanted.size) this._removeScan(this._onFoundForPeers)
        await this._attachLink(p, link)
        link = null   // ya es del canal: se cierra con él
      } catch (e) {
        // Se sigue buscando, pero se DICE: es un aparato de Dotrino (anuncia el servicio) que no
        // se dejó leer o se fue a mitad, y callarlo es dejar un canal que no abre sin un porqué.
        this.emit('error', { type: 'bluetooth_probe', device: dev.id, error: e, code: e?.code || null })
        if (link) await link.close().catch(() => {})
      } finally {
        this._probing.delete(dev.id)
      }
    })
  }

  async _attachLink (p, link) {
    p.link = link
    p.chunk = link.chunk
    link.onClose(() => this._closed(p))
    const rx = new W.Reassembler(W.TAG_BYTES)
    await link.subscribe((chunk) => { if (W.hasTag(chunk, p.tag)) this._onChunk(p, rx, chunk) })
    this._sendRecord(p, W.TYPE_HELLO, W.encodeText(this.getSelfToken() || ''))
  }

  _onChunk (p, rx, chunk) {
    let rec
    try { rec = rx.push(chunk) } catch (_) { return this._closed(p) }
    if (rec) p.recvChain = p.recvChain.then(() => this._onRecord(p, rec))
  }

  // ---------- lado periférico ----------

  _onWrite (centralId, bytes) {
    let c = this.centrals.get(centralId)
    if (!c) { c = { rx: new W.Reassembler(), peer: null, pendingHello: null, chain: Promise.resolve() }; this.centrals.set(centralId, c) }
    let rec
    try { rec = c.rx.push(bytes) } catch (_) { this.centrals.delete(centralId); if (c.peer) this._closed(c.peer); return }
    if (!rec) return
    c.chain = c.chain.then(() => c.peer ? this._onRecord(c.peer, rec) : this._identify(centralId, c, rec))
  }

  /** Quién se conectó: la llave que descifra su saludo dice de qué negociación es. */
  async _identify (centralId, c, rec) {
    for (const p of this.peers.values()) {
      if (p.role !== 'peripheral' || p.state !== 'keyed' || p.central != null) continue
      let r
      try { r = await W.openRecord(p.key, W.DIR_TO_PERIPHERAL, 0, rec) } catch (_) { continue }
      if (r.type !== W.TYPE_HELLO || W.decodeText(r.body) !== p.token) continue
      p.central = centralId
      p.chunk = this.adapter.chunkFor(centralId)
      p.recvCtr = 1
      c.peer = p
      this._sendRecord(p, W.TYPE_HELLO, W.encodeText(this.getSelfToken() || ''))
      c.pendingHello = null
      this._open(p)
      return
    }
    // Nadie lo esperaba TODAVÍA: el central puede escribir antes de que aquí termine de
    // calcularse la llave. Se guarda el saludo y se prueba otra vez cuando una negociación
    // quede lista (`_retryHellos`). A quien no se negoció no se le contesta nada.
    c.pendingHello = rec
  }

  _retryHellos () {
    for (const [id, c] of this.centrals) {
      if (c.peer || !c.pendingHello) continue
      const rec = c.pendingHello
      c.chain = c.chain.then(() => c.peer ? null : this._identify(id, c, rec))
    }
  }

  _onCentralGone (centralId) {
    const c = this.centrals.get(centralId)
    this.centrals.delete(centralId)
    if (c && c.peer) this._closed(c.peer)
  }

  // ---------- registros ----------

  async _onRecord (p, rec) {
    if (p.state === 'closed' || p.state === 'failed') return
    const dir = p.role === 'central' ? W.DIR_TO_CENTRAL : W.DIR_TO_PERIPHERAL
    let r
    try {
      r = await W.openRecord(p.key, dir, p.recvCtr, rec)
      p.recvCtr++
    } catch (_) {
      this.emit('error', { type: 'bluetooth_bad_record', peer: p.token })
      return this._closed(p)
    }
    if (r.type === W.TYPE_HELLO) {
      if (W.decodeText(r.body) !== p.token) return this._closed(p)
      if (p.role === 'central') this._open(p)
      return
    }
    if (p.state !== 'open') return this._closed(p)
    this.count?.('in', p.token, r.body.length, 'bluetooth')
    if (r.type === W.TYPE_TEXT) {
      const raw = W.decodeText(r.body)
      let parsed = null
      try { parsed = JSON.parse(raw) } catch (_) {}
      this.deliverMessage(p.token, parsed ?? raw, { raw, timestamp: Date.now(), via: 'bluetooth' })
    } else if (r.type === W.TYPE_BINARY) {
      const raw = new Uint8Array(r.body)
      this.deliverMessage(p.token, raw, { raw, timestamp: Date.now(), via: 'bluetooth' })
    }
  }

  _sendRecord (p, type, body) {
    const dir = p.role === 'central' ? W.DIR_TO_PERIPHERAL : W.DIR_TO_CENTRAL
    p.pending += body.length
    p.queue = p.queue.then(async () => {
      if (p.state === 'closed' || p.state === 'failed') return
      const rec = await W.sealRecord(p.key, dir, p.sendCtr++, type, body)
      for (const chunk of W.toChunks(rec, p.chunk, p.role === 'central' ? null : p.tag)) {
        if (p.role === 'central') await p.link.write(chunk)
        else await this.adapter.notify(p.central, chunk)
      }
    }).catch(() => this._closed(p)).finally(() => { p.pending -= body.length })
  }

  // ---------- envío ----------

  trySend (to, wire) {
    const p = this.peers.get(to)
    if (!p || p.state !== 'open') return false
    const isText = typeof wire === 'string'
    const body = isText ? W.encodeText(wire) : wire
    this._sendRecord(p, isText ? W.TYPE_TEXT : W.TYPE_BINARY, body)
    this.count?.('out', to, body.length, 'bluetooth')
    return true
  }

  /** Como `trySend`, esperando a que baje lo pendiente: para las partes de un mensaje grande. */
  async sendDirect (to, wire, highWater = 256 * 1024) {
    const p = this.peers.get(to)
    if (!p || p.state !== 'open') return false
    while (p.pending > highWater) {
      await new Promise((r) => setTimeout(r, 15))
      if (p.state !== 'open') return false
    }
    return this.trySend(to, wire)
  }

  isOpen (to) { return this.peers.get(to)?.state === 'open' }

  describe () {
    const out = new Map()
    for (const p of this.peers.values()) {
      out.set(p.token, p.state === 'open' ? 'bluetooth' : p.state === 'failed' ? 'failed' : 'connecting')
    }
    return out
  }

  closePeer (to) {
    const p = this.peers.get(to)
    if (p) this._closed(p)
  }

  closeAll () { for (const p of [...this.peers.values()]) this._closed(p) }

  // ---------- anunciar y descubrir ----------

  /**
   * Pone `{kind, data}` en `beacon` (docs/bluetooth.md §3) hasta que se llame a lo que
   * devuelve. Lanza `no-bluetooth` si aquí no hay Bluetooth: quien anuncia tiene que saberlo.
   */
  announce (kind, data) {
    if (!this.adapter) throw Object.assign(new Error('bluetooth: not available here'), { code: 'no-bluetooth' })
    const b = W.encodeBeacon(kind, data)
    this.beacon = b
    return () => { if (this.beacon === b) this.beacon = new Uint8Array(0) }
  }

  /**
   * Busca en el aire durante `timeoutMs` lo que otros anuncian con `kind`. No necesita el
   * proxio. `onFound` avisa de cada uno según aparece; la promesa devuelve todos.
   * @param {{ kind: string, timeoutMs?: number, onFound?: (b: {kind: string, data: string}) => void }} opts
   */
  async discover ({ kind, timeoutMs = 8000, onFound }) {
    if (!this.adapter) throw Object.assign(new Error('bluetooth: not available here'), { code: 'no-bluetooth' })
    const found = []
    const done = new Set()
    const listener = (dev) => {
      if (done.has(dev.id)) return
      done.add(dev.id)
      this._withConnectLock(async () => {
        let link = null
        try {
          link = await this.adapter.connect(dev)
          const b = W.decodeBeacon(await link.read(W.BEACON_UUID))
          if (b && b.kind === kind && !found.some((f) => f.data === b.data)) {
            found.push(b)
            try { onFound?.(b) } catch (_) {}
          }
        } catch (_) {
          // Uno que no se deja leer no anuncia nada para nosotros.
        } finally {
          if (link) await link.close().catch(() => {})
        }
      })
    }
    await this._addScan(listener)
    await new Promise((r) => setTimeout(r, timeoutMs))
    this._removeScan(listener)
    await this._connectLock
    return found
  }

  // ---------- internos ----------

  _newPeer (token) {
    const p = {
      token, state: 'new', role: null, eph: null, key: null, theirBid: null, myBid: null, tag: null,
      link: null, central: null, chunk: 20, sendCtr: 0, recvCtr: 0, pending: 0,
      queue: Promise.resolve(), recvChain: Promise.resolve(), timer: null, failedAt: 0,
    }
    this.peers.set(token, p)
    return p
  }

  _timer (p, ms) {
    if (p.timer) clearTimeout(p.timer)
    p.timer = setTimeout(() => { if (p.state !== 'open') this._fail(p) }, ms)
    p.timer.unref?.()
  }

  _open (p) {
    if (p.timer) clearTimeout(p.timer)
    p.timer = null
    p.state = 'open'
    this.emit('bluetooth_open', p.token)
  }

  _fail (p) {
    if (p.state === 'closed') return
    this._release(p)
    p.state = 'failed'
    p.failedAt = Date.now()
  }

  _closed (p) {
    if (p.state === 'closed') return
    const wasOpen = p.state === 'open'
    this._release(p)
    p.state = 'closed'
    if (this.peers.get(p.token) === p) this.peers.delete(p.token)
    if (wasOpen) this.emit('bluetooth_close', p.token)
  }

  /** Quita una negociación sin avisar: la reemplaza otra del mismo token. */
  _drop (p) {
    this._release(p)
    p.state = 'closed'
  }

  _release (p) {
    if (p.timer) clearTimeout(p.timer)
    p.timer = null
    if (p.theirBid && this.wanted.get(p.theirBid) === p) {
      this.wanted.delete(p.theirBid)
      if (!this.wanted.size) this._removeScan(this._onFoundForPeers)
    }
    if (p.link) { const l = p.link; p.link = null; l.close().catch(() => {}) }
    if (p.central != null) {
      const id = p.central
      const c = this.centrals.get(id)
      if (c && c.peer === p) c.peer = null
      p.central = null
      this.adapter?.drop(id).catch(() => {})
    }
  }

  _withConnectLock (fn) {
    const run = this._connectLock.then(fn, fn)
    this._connectLock = run.catch(() => {})
    return run
  }

  async _addScan (listener) {
    this._scanListeners.add(listener)
    if (this._stopScan) return
    if (!this._scanStarting) {
      // Una búsqueda que se está parando todavía ocupa el adaptador: BlueZ contesta `InProgress`
      // a la siguiente si no se espera a que acabe (dos `discover` seguidos).
      const stopping = this._scanStopping || Promise.resolve()
      this._scanStarting = stopping.then(() => this.adapter.scan((dev) => {
        for (const l of [...this._scanListeners]) l(dev)
      })).then((stop) => {
        this._stopScan = stop
        this._scanStarting = null
        if (!this._scanListeners.size) this._removeScan(null)
      }, (e) => { this._scanStarting = null; throw e })
    }
    await this._scanStarting
  }

  _removeScan (listener) {
    if (listener) this._scanListeners.delete(listener)
    if (this._scanListeners.size || !this._stopScan) return
    const stop = this._stopScan
    this._stopScan = null
    const stopping = this._scanStopping = stop().catch(() => {}).then(() => {
      if (this._scanStopping === stopping) this._scanStopping = null
    })
  }
}
