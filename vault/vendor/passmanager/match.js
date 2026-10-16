// Emparejamiento de una entrada con el sitio que el usuario tiene delante.
//
// Es la pieza de la que depende la seguridad del autocompletado: emparejar de más
// entrega una credencial al sitio equivocado. Por eso todo se compara por ETIQUETAS
// de dominio, nunca por sufijo de cadena — `evil-salesforce.com` termina en
// `salesforce.com` como texto y no tiene nada que ver con él.

// Sufijos públicos de dos etiquetas más comunes. NO es la Public Suffix List entera
// (son miles de reglas y varios cientos de KB); es la aproximación que cubre el caso
// real. Deuda anotada: cargar la PSL de verdad cuando el autocompletado esté maduro.
// Mientras tanto un sufijo desconocido solo hace el emparejamiento MÁS estricto, que
// es el lado seguro por el que fallar.
const TWO_LABEL_SUFFIXES = new Set([
  'co.uk', 'org.uk', 'ac.uk', 'gov.uk', 'me.uk', 'net.uk', 'sch.uk',
  'com.au', 'net.au', 'org.au', 'edu.au', 'gov.au', 'id.au',
  'com.br', 'net.br', 'org.br', 'gov.br',
  'com.ec', 'net.ec', 'org.ec', 'gob.ec', 'edu.ec', 'fin.ec', 'med.ec',
  'com.ar', 'net.ar', 'org.ar', 'gob.ar', 'edu.ar',
  'com.mx', 'net.mx', 'org.mx', 'gob.mx', 'edu.mx',
  'com.co', 'net.co', 'org.co', 'gov.co', 'edu.co',
  'co.jp', 'ne.jp', 'or.jp', 'ac.jp', 'go.jp',
  'com.cn', 'net.cn', 'org.cn', 'gov.cn', 'edu.cn',
  'co.nz', 'net.nz', 'org.nz', 'govt.nz',
  'co.za', 'org.za', 'net.za',
  'com.tr', 'com.tw', 'com.hk', 'com.sg', 'com.my', 'com.pe', 'com.uy',
  'com.ve', 'com.py', 'com.bo', 'com.do', 'com.gt', 'com.pa', 'com.pl',
  'com.es', 'com.pt', 'com.ua', 'com.ru', 'com.vn', 'com.ph',
])

/** Extrae el host de una URL o de algo que ya es un host. Devuelve '' si no vale. */
export function hostOf (input) {
  if (typeof input !== 'string') return ''
  let s = input.trim().toLowerCase()
  if (!s) return ''
  if (!s.includes('://')) s = 'https://' + s
  let u
  try { u = new URL(s) } catch { return '' }
  // Solo esquemas web: un `javascript:` o un `file:` no tienen sitio con el que emparejar.
  if (u.protocol !== 'https:' && u.protocol !== 'http:') return ''
  return u.hostname.replace(/\.$/, '')
}

/** Dominio registrable (eTLD+1 aproximado). Para una IP o un host raro, el host tal cual. */
export function registrableDomain (host) {
  if (!host) return ''
  if (/^\d+\.\d+\.\d+\.\d+$/.test(host) || host.includes(':')) return host
  const parts = host.split('.')
  if (parts.length <= 2) return host
  const lastTwo = parts.slice(-2).join('.')
  if (TWO_LABEL_SUFFIXES.has(lastTwo)) return parts.slice(-3).join('.')
  return lastTwo
}

/** ¿`host` es igual a `base` o un subdominio suyo? Compara por etiquetas. */
export function isSameOrSubdomainOf (host, base) {
  if (!host || !base) return false
  if (host === base) return true
  return host.endsWith('.' + base)
}

export const MATCH = {
  EXACT: 3,
  SUBDOMAIN: 2,
  /** Sin sitios: sirve en cualquier parte, y por eso va la última. */
  ANY: 0.5,
  NONE: 0,
}

// `DOMAIN` (mismo dominio registrable) EXISTIÓ y se quitó el 2026-08-29, porque hacía
// justo lo que un gestor de contraseñas no puede hacer: con `pass.dotrino.com` guardado,
// `r.dotrino.com` recibía sus credenciales — dos servicios distintos que solo comparten
// el dominio de arriba (lo vio el dueño: *«en r.dotrino.com me salen records de
// pass.dotrino.com»*).
//
// Se puso para el caso «el subdominio cambió y la clave es la misma», pero para eso no
// hacía falta: guardar el dominio a secas (`empresa.com`) YA cubre todos sus subdominios
// por la vía de SUBDOMAIN, y traerse la cuenta de otro dominio ya tiene su camino
// explícito —buscarla (§4.1)—, que además lo decide una persona en vez de la máquina.
//
// Lo único que aportaba era el sentido contrario: un subdominio GUARDADO emparejando con
// sus hermanos y con el dominio padre. Y ese sentido es exactamente la fuga.

/**
 * Compara UN patrón de `sites` con el host actual.
 * Patrones admitidos: `ejemplo.com`, `*.ejemplo.com`, o una URL entera.
 *
 * Un patrón cubre **el host y lo que cuelga de él**, nunca hacia arriba ni hacia los
 * lados: `empresa.com` vale en `login.empresa.com`, pero `login.empresa.com` NO vale en
 * `otra.empresa.com`. Por eso el comodín casi nunca hace falta — un dominio a secas ya
 * trae sus subdominios— y por eso `*.x` y `x` cubren hoy lo mismo.
 */
export function matchSite (pattern, currentHost) {
  if (!currentHost) return MATCH.NONE
  let p = String(pattern || '').trim().toLowerCase()
  if (!p) return MATCH.NONE

  let wildcard = false
  if (p.startsWith('*.')) { wildcard = true; p = p.slice(2) }

  const base = hostOf(p)
  if (!base) return MATCH.NONE

  if (wildcard) return isSameOrSubdomainOf(currentHost, base) ? MATCH.SUBDOMAIN : MATCH.NONE
  if (currentHost === base) return MATCH.EXACT
  if (isSameOrSubdomainOf(currentHost, base)) return MATCH.SUBDOMAIN
  // Y nada más. Un hermano NO empareja: ver la nota de `MATCH`.
  return MATCH.NONE
}

/**
 * Mejor nivel de emparejamiento de una entrada con la URL actual.
 *
 * **Una entrada SIN sitios sirve en cualquier parte.** Es como se dice «esto no es de
 * un dominio»: el correo o la cédula valen en todas partes, la contraseña del banco
 * no. No hace falta un tipo aparte para eso, y así hay una sola regla que mantener.
 * Empareja siempre por debajo de lo que sí es de este sitio.
 */
export function matchEntry (entry, url) {
  const host = hostOf(url)
  if (!host) return MATCH.NONE
  if (!entry?.sites?.length) return MATCH.ANY
  let best = MATCH.NONE
  for (const s of entry?.sites || []) {
    const m = matchSite(s, host)
    if (m > best) best = m
    if (best === MATCH.EXACT) break
  }
  return best
}

/** Entradas que sirven para esta URL, de mejor a peor emparejamiento. */
export function findForUrl (entries, url) {
  return (entries || [])
    .map(e => ({ entry: e, match: matchEntry(e, url) }))
    .filter(x => x.match > MATCH.NONE)
    .sort((a, b) => b.match - a.match || (b.entry.updatedAt || 0) - (a.entry.updatedAt || 0))
}
