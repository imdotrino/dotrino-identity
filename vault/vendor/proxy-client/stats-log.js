/**
 * LAS ESTADÍSTICAS DE RED, AL LOG. Para lo que no tiene pantalla: un daemon, un agente, un
 * servicio bajo pm2.
 *
 * En el navegador las enseña el topbar (su modal de red lee el registro de clientes). Un
 * proceso de Node no tiene dónde, así que «¿esto va por WebRTC o sigue dando la vuelta por
 * el proxio?» solo se contestaba con una prueba en contenedores. Esto escribe lo mismo que
 * pinta el modal, una línea cada tanto, con el `log` que el servicio ya usa.
 *
 * Lee el MISMO registro que el topbar (`listTransports`), así que el servicio no le pasa
 * sus clientes: los que haya en el proceso, salen.
 *
 * Tres cosas a propósito:
 *  - Solo escribe si algo cambió. Un servicio quieto no llena el log de líneas iguales.
 *  - Los contadores son ACUMULADOS desde `since`: dos líneas se restan, y una sola ya dice
 *    si hubo tráfico directo alguna vez.
 *  - De la otra punta solo sale el TOKEN, que es efímero. La pubkey no: con quién habla
 *    una máquina es justo lo que no se deja escrito en un disco.
 */
import { listTransports, PATHS } from './stats.js'

const sum = (peers, dir) => {
  const t = { proxy: 0, direct: 0, turn: 0, webrtc: 0, bluetooth: 0 }
  for (const p of peers) for (const k of PATHS) t[k] += p[dir][k]
  return t
}

const pairs = (prefix, o) => PATHS.map((k) => `${prefix}.${k}=${o[k]}`).join(' ')

/**
 * Las líneas de UN cliente, a partir de lo que devuelve `client.stats()`.
 * La primera es el resumen; después, una por conexión.
 *
 * @param {object} s lo que devuelve `client.stats()` (`TransportStats` en los tipos)
 * @param {{ label?: string }} [opts]
 * @returns {string[]}
 */
export function formatStats (s, opts = {}) {
  const tag = opts.label ? `[net] ${opts.label}` : '[net]'
  // QUIÉN CONTESTÓ Y QUIÉN NO. Un sondeo (un ping a cada aparato del acta) deja una entrada
  // por destinatario aunque nadie responda: esas no son conexiones y van resumidas
  // (`unanswered`), igual que en el informe del topbar y de las apps nativas.
  // `unknown`: quien nos escribió, nunca recibió respuesta y no sabemos su llave (otro aparato
  // sondeando qué máquinas están encendidas). Tampoco es una conexión.
  const isUnknown = (p) => p.msgsIn > 0 && !(p.msgsOut > 0) && !p.pubkey
  const unknown = s.peers.filter(isUnknown)
  const talking = s.peers.filter((p) => p.msgsIn > 0 && !isUnknown(p))
  const silent = s.peers.filter((p) => !(p.msgsIn > 0))
  const routes = {}
  for (const p of talking) routes[p.route] = (routes[p.route] || 0) + 1
  const routeList = Object.keys(routes).sort().map((r) => `${r}=${routes[r]}`).join(',') || 'none'
  const lines = [
    `${tag} url=${s.url} connected=${s.connected ? 'yes' : 'no'} webrtc=${s.webrtc ? 'on' : 'off'}` +
    ` ws.in=${s.proxy.bytesIn} ws.out=${s.proxy.bytesOut}` +
    ` ${pairs('in', sum(s.peers, 'bytesIn'))} ${pairs('out', sum(s.peers, 'bytesOut'))}` +
    ` peers=${talking.length} routes=${routeList}` +
    (s.turn ? ` turn=${s.turn.active ? 'on' : `off(${s.turn.code || '?'})`}` : '') +
    (silent.length ? ` unanswered=${silent.length} unanswered.out=${silent.reduce((n, p) => n + PATHS.reduce((m, k) => m + p.bytesOut[k], 0), 0)}` : '') +
    (unknown.length ? ` unknown=${unknown.length} unknown.in=${unknown.reduce((n, p) => n + PATHS.reduce((m, k) => m + p.bytesIn[k], 0), 0)}` : '')
  ]
  for (const p of talking) {
    lines.push(
      `${tag}   peer=${p.token || 'by-key'} route=${p.route}` +
      ` ${pairs('in', p.bytesIn)} ${pairs('out', p.bytesOut)} msgs.in=${p.msgsIn} msgs.out=${p.msgsOut}`
    )
  }
  return lines
}

/**
 * Escribe las estadísticas de todos los clientes del proceso cada `everyMs`, si cambiaron.
 *
 * @param {{ log?: (line: string) => void, everyMs?: number, label?: string }} [opts]
 * @returns {{ stop: () => Promise<void>, flush: () => Promise<void> }}
 *   `flush` escribe ya (si cambió algo); `stop` escribe una última vez y para.
 */
export function logStats (opts = {}) {
  const log = opts.log || ((line) => console.log(line))
  const everyMs = opts.everyMs || 5 * 60 * 1000
  /** cliente → lo último que se escribió de él */
  const last = new WeakMap()

  const flush = async () => {
    for (const client of listTransports()) {
      if (typeof client.stats !== 'function') continue
      let lines
      try {
        lines = formatStats(await client.stats(), opts)
      } catch (e) {
        // No poder leer NO es «no hubo tráfico»: se dice, para que no parezca silencio.
        lines = [`${opts.label ? `[net] ${opts.label}` : '[net]'} could not read stats: ${e?.message || e}`]
      }
      const text = lines.join('\n')
      if (last.get(client) === text) continue
      last.set(client, text)
      for (const line of lines) log(line)
    }
  }

  const timer = setInterval(() => { flush() }, everyMs)
  // El log no puede ser lo que mantiene vivo un proceso que ya terminó.
  if (typeof timer.unref === 'function') timer.unref()

  return {
    flush,
    stop: async () => { clearInterval(timer); await flush() }
  }
}

/** Bytes para el informe de texto: `B`, `KB` con un decimal, `MB` con dos. */
const rBytes = (n) => (n < 1024 ? `${n} B` : n < 1024 * 1024 ? `${(n / 1024).toFixed(1)} KB` : `${(n / 1024 / 1024).toFixed(2)} MB`)
const rPaths = (o) => {
  const parts = PATHS.filter((k) => (o?.[k] || 0) > 0).map((k) => `${k} ${rBytes(o[k])}`)
  return parts.length ? parts.join(', ') : '0 B'
}

/**
 * Los que contestaron algo (`talking`) y los que solo recibieron (`silent`, resumidos): a un
 * aparato apagado al que se le mandó un ping no se le llama conexión. `unknown`: quien nos
 * escribió, nunca recibió respuesta y no sabemos su llave. Tampoco es una conexión.
 *
 * @param {Array<object>} peers `TransportStats.peers`
 */
export function splitPeers (peers) {
  const total = (o) => PATHS.reduce((n, k) => n + (o?.[k] || 0), 0)
  const talking = []
  const silent = { count: 0, bytesOut: 0, msgsOut: 0 }
  const unknown = { count: 0, bytesIn: 0, msgsIn: 0 }
  for (const p of peers) {
    if (!((p.msgsIn || 0) > 0)) { silent.count++; silent.bytesOut += total(p.bytesOut); silent.msgsOut += p.msgsOut || 0 } else if (!p.pubkey && !((p.msgsOut || 0) > 0)) { unknown.count++; unknown.bytesIn += total(p.bytesIn); unknown.msgsIn += p.msgsIn || 0 } else talking.push(p)
  }
  return { talking, silent, unknown }
}

/**
 * EL INFORME DE RED COMO TEXTO, para que lo lea una persona: las mismas líneas que el modal de
 * red del topbar y que las apps nativas (`NetworkStats.report`). A diferencia de `formatStats`
 * (que va a un log en disco y por eso calla la llave), este se enseña en pantalla a quien lo
 * pidió, y dice con quién es cada conexión.
 *
 * @param {Array<object>} list lo que devolvió `client.stats()` de cada cliente (o `{ url, error }`)
 * @param {{ label?: (pubkey: string) => string | Promise<string>, now?: Date }} [opts]
 *   `label`: cómo se nombra un aparato a partir de su llave (su id `AB12-CD34`, su nombre).
 *   Sin él, o si falla, sale `?`: nunca un trozo de la llave.
 * @returns {Promise<string>}
 */
export async function netReport (list, opts = {}) {
  const now = opts.now || new Date()
  let out = `Dotrino network stats · ${now.toISOString().replace(/\.\d{3}Z$/, 'Z')}\n`
  if (!list.length) out += '(no transports)\n'
  for (const s of list) {
    if (s.error) { out += `Proxy ${s.url} | error: ${s.error}\n`; continue }
    const hhmm = new Date(s.since).toTimeString().slice(0, 8)
    out += `Proxy ${s.url}${s.app ? ` | app=${s.app}` : ''}${s.node ? ` | node=${s.node}` : ''} | ${s.connected ? 'connected' : 'disconnected'} | since ${hhmm}\n`
    out += `  proxy total: in ${rBytes(s.proxy.bytesIn)} / out ${rBytes(s.proxy.bytesOut)} (frames ${s.proxy.framesIn ?? '?'}/${s.proxy.framesOut ?? '?'})\n`
    const { talking, silent, unknown } = splitPeers(s.peers)
    out += `  peers: ${talking.length}\n`
    for (const p of talking) {
      let who = '?'
      if (p.pubkey && opts.label) { try { who = (await opts.label(p.pubkey)) || '?' } catch (_) { who = '?' } }
      const tok = p.token ? ` (token ${p.token})` : ''
      out += `  - ${who}${tok} | route=${p.route} | in: ${rPaths(p.bytesIn)} | out: ${rPaths(p.bytesOut)} | ${(p.msgsIn || 0) + (p.msgsOut || 0)} msgs\n`
    }
    if (silent.count) out += `  no answer: ${silent.count} (out ${rBytes(silent.bytesOut)}, ${silent.msgsOut} msgs)\n`
    if (unknown.count) out += `  unknown senders: ${unknown.count} (in ${rBytes(unknown.bytesIn)}, ${unknown.msgsIn} msgs)\n`
  }
  return out
}
