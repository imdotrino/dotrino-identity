/**
 * QUÉ MÁQUINA ES CADA APARATO: dónde corre, y nada más.
 *
 * En la lista de aparatos de la bóveda solo había un ID (`AB12-CD34`), una etiqueta que pone
 * el propio aparato —muchas veces el apodo del usuario, igual en todos— y la fecha de alta.
 * Con tres navegadores y dos agentes no había forma de saber cuál era cuál (dueño,
 * 2026-10-15). Esto es lo que lo distingue a simple vista:
 *
 *   · `kind` — qué es: `node` (un agente o un comando), `browser`, `extension`, `ios`, `android`.
 *   · `os`   — el sistema donde corre (`Linux 7.0.0`, `Windows`, `macOS`, `Android 14`).
 *   · `name` — en Node, el hostname; en un navegador, el navegador (`Chrome`). Un navegador no
 *     sabe el nombre de la máquina, y lo que no se sabe no se inventa.
 *
 * Lo DICE el aparato y va dentro de lo que firma, así que nadie más puede escribirlo por él.
 * Tampoco es una prueba de nada: un aparato puede llamarse como quiera. Sirve para reconocerlo,
 * no para decidir — ninguna puerta mira esto.
 *
 * Una sola pieza para las dos puntas: lo limpia igual quien lo manda y quien lo guarda (el acta,
 * la bóveda), para que un campo de más o una cadena de un megabyte no entren por ningún lado.
 */

export const MACHINE_KINDS = ['node', 'browser', 'extension', 'ios', 'android']

const clip = (s, n) => (typeof s === 'string' ? s.replace(/[\u0000-\u001f\u007f]/g, '').trim().slice(0, n) : '')

/**
 * Lo deja en la forma de siempre, o `null` si no dice nada que valga. Nunca lanza: un aparato
 * viejo o raro no puede tumbar un emparejamiento por cómo describe su máquina.
 * @param {any} raw
 * @returns {{ kind: string, os: string, name: string } | null}
 */
export function cleanMachine (raw) {
  if (!raw || typeof raw !== 'object') return null
  const kind = MACHINE_KINDS.includes(raw.kind) ? raw.kind : ''
  const os = clip(raw.os, 40)
  const name = clip(raw.name, 64)
  if (!kind && !os && !name) return null
  return { kind, os, name }
}

/** Una línea para enseñarlo: `node · Linux 7.0.0 · mi-pc`. Vacía si no hay nada. */
export function machineLine (m) {
  const c = cleanMachine(m)
  return c ? [c.kind, c.os, c.name].filter(Boolean).join(' · ') : ''
}

/** ¿Dicen lo mismo? Para no reescribir un archivo cada vez que un aparato repite lo de siempre. */
export const sameMachine = (a, b) => machineLine(a) === machineLine(b)

/** @type {Array<[RegExp, (v: string) => string]>} */
const UA_OS = [
  [/Android ([\d.]+)/, (v) => 'Android ' + v.split('.')[0]],
  [/(?:iPhone|iPad|iPod).*? OS (\d+)/, (v) => 'iOS ' + v],
  [/Windows NT/, () => 'Windows'],
  [/CrOS/, () => 'ChromeOS'],
  [/Mac OS X/, () => 'macOS'],
  [/Linux/, () => 'Linux']
]
/** @type {Array<[RegExp, string]>} */
const UA_BROWSER = [
  [/Edg\//, 'Edge'], [/OPR\//, 'Opera'], [/Firefox\//, 'Firefox'], [/SamsungBrowser\//, 'Samsung Internet'],
  [/Chrome\//, 'Chrome'], [/Safari\//, 'Safari']
]

/**
 * La máquina de ESTE navegador. `env` se inyecta en las pruebas; en la página es `globalThis`.
 * Lo nativo se reconoce por el puente de `dotrino-native` (`DotrinoNative.platform()`), la
 * extensión por tener `chrome.runtime.id`, y el resto es un navegador.
 * @param {any} [env]
 */
export function browserMachine (env = globalThis) {
  /** @type {any} */
  const nav = env?.navigator || {}
  const ua = String(nav.userAgent || '')
  // Node también tiene `navigator` (`Node.js/22`): no es un navegador, y su máquina la dice
  // quien sabe mirarla (`selfMachine` de `@dotrino/vault`). Aquí no se inventa.
  if (env?.process?.versions?.node || !ua || ua.startsWith('Node.js')) return null
  let kind = 'browser'
  try {
    const p = env?.DotrinoNative?.platform?.()
    if (p === 'ios' || p === 'android') kind = p
    else if (env?.chrome?.runtime?.id) kind = 'extension'
  } catch (_) { /* un puente roto no cambia qué navegador es: se queda en `browser` */ }
  let os = ''
  for (const [re, fmt] of UA_OS) { const m = ua.match(re); if (m) { os = fmt(m[1] || ''); break } }
  // iPadOS se presenta como un Mac de escritorio: lo delata la pantalla táctil.
  if (os === 'macOS' && nav.maxTouchPoints > 1) os = 'iPadOS'
  let name = ''
  if (kind === 'browser' || kind === 'extension') {
    for (const [re, n] of UA_BROWSER) if (re.test(ua)) { name = n; break }
  }
  return cleanMachine({ kind, os, name })
}

export default { MACHINE_KINDS, cleanMachine, machineLine, sameMachine, browserMachine }
