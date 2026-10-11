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
  const t = { proxy: 0, direct: 0, turn: 0, webrtc: 0 }
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
