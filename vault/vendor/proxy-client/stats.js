/**
 * CUÁNTO TRÁFICO Y POR DÓNDE. Contadores del transporte, por conexión.
 *
 * Existe para poder VER la regla del camino más directo (CLAUDE.md, «el transporte SIEMPRE
 * prefiere el camino más directo»): sin números, «el segundo mensaje ya no toca el proxio»
 * solo se podía comprobar con una prueba en contenedores. Con esto lo enseña cualquier app
 * (el topbar tiene un modal que lo pinta).
 *
 * Se cuentan los BYTES DEL PAYLOAD que pasa por este cliente (UTF-8), no los del cable:
 * las cabeceras de TCP, TLS, DTLS o SCTP no las ve JavaScript. Para el proxio se cuenta el
 * frame entero; por conexión, lo que iba dirigido a ella.
 *
 * Los caminos:
 *   proxy    por el proxio (incluye la señalización de WebRTC y el saludo)
 *   direct   WebRTC sin relevo
 *   turn     WebRTC por un relevo TURN
 *   webrtc   WebRTC sin saber todavía cuál de los dos (getStats no contestó)
 */

/** Longitud en bytes UTF-8 de un string, sin reservar un buffer por mensaje. */
export function utf8Length (s) {
  if (typeof s !== 'string') {
    if (s && typeof s.byteLength === 'number') return s.byteLength
    if (s && typeof s.size === 'number') return s.size
    return 0
  }
  let n = 0
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i)
    if (c < 0x80) n += 1
    else if (c < 0x800) n += 2
    else if (c >= 0xd800 && c <= 0xdbff && i + 1 < s.length) { n += 4; i++ } // par sustituto
    else n += 3
  }
  return n
}

export const PATHS = ['proxy', 'direct', 'turn', 'webrtc']

const ceros = () => ({ proxy: 0, direct: 0, turn: 0, webrtc: 0 })

export class TrafficStats {
  constructor () {
    this.since = Date.now()
    this.proxy = { bytesIn: 0, bytesOut: 0, framesIn: 0, framesOut: 0 }
    /** clave (`t:<token>` | `k:<pubkey>`) → contadores de esa conexión */
    this.peers = new Map()
  }

  /** Un frame entero del WebSocket del proxio. */
  frame (dir, bytes) {
    if (dir === 'in') { this.proxy.bytesIn += bytes; this.proxy.framesIn++ } else { this.proxy.bytesOut += bytes; this.proxy.framesOut++ }
  }

  /**
   * Un mensaje dirigido a (o venido de) una conexión.
   * @param {'in'|'out'} dir
   * @param {'proxy'|'direct'|'turn'|'webrtc'} path
   * @param {{ token?: string|null, pubkey?: string|null }} who
   * @param {number} bytes
   */
  peer (dir, path, who, bytes) {
    const key = who.token ? `t:${who.token}` : who.pubkey ? `k:${who.pubkey}` : null
    if (!key) return
    let p = this.peers.get(key)
    if (!p) {
      p = { token: who.token || null, pubkey: who.pubkey || null, bytesIn: ceros(), bytesOut: ceros(), msgsIn: 0, msgsOut: 0, firstAt: Date.now(), lastAt: 0 }
      this.peers.set(key, p)
    }
    if (who.pubkey && !p.pubkey) p.pubkey = who.pubkey
    if (dir === 'in') { p.bytesIn[path] += bytes; p.msgsIn++ } else { p.bytesOut[path] += bytes; p.msgsOut++ }
    p.lastAt = Date.now()
  }
}

/**
 * POR DÓNDE VA UN CANAL ABIERTO: `direct` o `turn`, según el par de candidatos que ICE
 * eligió. Si cualquiera de las dos puntas es `relay`, hay un TURN en medio.
 *
 * `null` si no se puede saber (la implementación no tiene getStats, o aún no hay par
 * elegido). No se adivina: «no lo sé» se enseña como tal.
 *
 * @param {any} pc RTCPeerConnection
 * @returns {Promise<'direct'|'turn'|null>}
 */
export async function routeOf (pc) {
  if (!pc || typeof pc.getStats !== 'function') return null
  let report
  try { report = await pc.getStats() } catch (_) { return null }
  if (!report || typeof report.forEach !== 'function') return null
  const byId = new Map()
  report.forEach((s) => { if (s && s.id) byId.set(s.id, s) })
  let pair = null
  // El par vigente lo dice el transporte; si no, el que está nominado y funcionando.
  for (const s of byId.values()) {
    if (s.type === 'transport' && s.selectedCandidatePairId) { pair = byId.get(s.selectedCandidatePairId) || null; break }
  }
  if (!pair) {
    for (const s of byId.values()) {
      if (s.type === 'candidate-pair' && (s.selected || (s.nominated && s.state === 'succeeded'))) { pair = s; break }
    }
  }
  if (!pair) return null
  const local = byId.get(pair.localCandidateId)
  const remote = byId.get(pair.remoteCandidateId)
  if (!local && !remote) return null
  const tipo = (c) => c && (c.candidateType || c.type)
  return tipo(local) === 'relay' || tipo(remote) === 'relay' ? 'turn' : 'direct'
}

/**
 * LOS CLIENTES VIVOS DE ESTA PÁGINA, para quien quiera enseñarlos sin que la app lo
 * cablee (el topbar). Va en `globalThis` con un Symbol.for, no en una variable del módulo:
 * una app puede llevar dos copias de este paquete (la suya y la de otro pilar), y las dos
 * tienen que verse.
 */
const REGISTRY = Symbol.for('dotrino.transports')

function registry () {
  if (!globalThis[REGISTRY]) globalThis[REGISTRY] = new Set()
  return globalThis[REGISTRY]
}

function avisar () {
  if (typeof globalThis.dispatchEvent === 'function' && typeof Event === 'function') {
    try { globalThis.dispatchEvent(new Event('dotrino-transports')) } catch (_) {}
  }
}

export function registerTransport (client) {
  const r = registry()
  if (r.has(client)) return
  r.add(client)
  avisar()
}

export function unregisterTransport (client) {
  if (registry().delete(client)) avisar()
}

/** Los clientes registrados en esta página (o proceso). */
export function listTransports () {
  return [...registry()]
}
