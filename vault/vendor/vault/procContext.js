/**
 * LA PARTE PORTABLE DE `proc.js`: limpiar el contexto que declara quien pide, su huella y su
 * línea. La usan el binario y la bóveda del navegador (que no tiene `/proc` y nunca mide,
 * así que todo lo que le llega se queda como declarado). Leer `/proc` sigue en `proc.js`,
 * que es solo de Node.
 */
import { sha256Hex } from './core/sha256.js'

/** Topes. Un `argv` puede ser enorme y esto viaja en cada pedido y se pinta en un teléfono. */
export const MAX_ARGV_BYTES = 4096
export const MAX_PATH_BYTES = 1024
/** Cuántos argumentos como mucho: más que esto no lo lee nadie. */
export const MAX_ARGV_ITEMS = 64

const enc = new TextEncoder()
const byteLength = (s) => enc.encode(s).length
export const clip = (s, max) => {
  if (typeof s !== 'string') return ''
  const b = enc.encode(s)
  return b.length <= max ? s : new TextDecoder().decode(b.subarray(0, max))
}

/**
 * Recorta el `argv` a lo que se puede enseñar y transportar. Devuelve también si sobró
 * algo: un comando cortado que no dice que está cortado se lee como otro comando.
 */
export function trimArgv (argv) {
  const list = (Array.isArray(argv) ? argv : []).map((a) => String(a))
  let cut = list.length > MAX_ARGV_ITEMS
  const kept = list.slice(0, MAX_ARGV_ITEMS)
  let total = 0
  const out = []
  for (const a of kept) {
    const b = byteLength(a)
    if (total + b > MAX_ARGV_BYTES) { cut = true; break }
    total += b
    out.push(a)
  }
  return { argv: out, truncated: cut }
}

/**
 * LO QUE LLEGA POR LA RED NO SE CREE NI EN LA FORMA. Este dato lo manda otro proceso, se
 * guarda en memoria y se pinta en un teléfono: se recorta a lo que cabe y se tira lo que no
 * tiene el tipo que debería. Devuelve `null` si no queda nada que enseñar — que no es lo
 * mismo que un contexto vacío, y por eso no se devuelve un objeto a medias.
 */
export function sanitizeContext (raw) {
  if (!raw || typeof raw !== 'object') return null
  const argvRaw = Array.isArray(raw.argv) ? raw.argv.filter((a) => typeof a === 'string') : []
  const { argv, truncated } = trimArgv(argvRaw)
  const exe = clip(typeof raw.exe === 'string' ? raw.exe : '', MAX_PATH_BYTES)
  const cwd = clip(typeof raw.cwd === 'string' ? raw.cwd : '', MAX_PATH_BYTES)
  if (!exe && !argv.length) return null
  return {
    pid: Number.isInteger(raw.pid) && raw.pid > 0 ? raw.pid : null,
    uid: Number.isInteger(raw.uid) ? raw.uid : null,
    exe,
    cwd,
    argv,
    truncated: truncated || raw.truncated === true,
    start: Number.isFinite(raw.start) ? raw.start : null,
    user: clip(typeof raw.user === 'string' ? raw.user : '', 64),
    host: clip(typeof raw.host === 'string' ? raw.host : '', 64)
  }
}

/**
 * LA HUELLA DEL COMANDO: qué binario, desde qué carpeta y con qué argumentos. Es la llave
 * de la concesión por tiempo — aprobar `node server.js` en `/srv/app` no aprueba otra cosa
 * ni la misma cosa en otro sitio.
 *
 * El pid NO entra: cambia en cada arranque y la gracia es justamente que el mismo comando
 * se reconozca la próxima vez.
 */
export function commandFingerprint (ctx) {
  if (!ctx || typeof ctx !== 'object') return null
  const argv = Array.isArray(ctx.argv) ? ctx.argv : []
  if (!ctx.exe && !argv.length) return null
  const material = [ctx.exe || '', ctx.cwd || '', ...argv].join('\0')
  return sha256Hex(material)
}

/** ¿Son el mismo comando? Mismo binario, misma carpeta, mismos argumentos. */
export const sameCommand = (a, b) => {
  const fa = commandFingerprint(a)
  return !!fa && fa === commandFingerprint(b)
}

/** El comando en una línea, para un log o una pantalla estrecha. */
export function commandLine (ctx, max = 160) {
  const argv = Array.isArray(ctx?.argv) ? ctx.argv : []
  const line = argv.length ? argv.join(' ') : (ctx?.exe || '')
  return line.length > max ? line.slice(0, max - 1) + '…' : line
}

export default { sanitizeContext, commandFingerprint, sameCommand, commandLine, trimArgv }
