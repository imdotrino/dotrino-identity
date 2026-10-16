/**
 * ranges.js — RANGOS DE VERSIONES, acotados a lo que el ecosistema usa de verdad.
 *
 * El dueño pidió que los manifiestos digan **qué rangos son compatibles con qué**
 * (2026-09-04), así que hace falta comparar versiones. Mi objeción de la mañana seguía en
 * pie —un comparador de semver mal escrito es peor que no tenerlo, porque falla en silencio
 * y del lado que no toca— y la respuesta no es no tenerlo, es acotarlo:
 *
 *   · **`x.y.z` y nada más.** Sin prereleases, sin `+build`, sin `^` ni `~`. Todas las
 *     versiones del ecosistema tienen esa forma; no se inventa soporte para lo que no hay.
 *   · **Lo que no se entiende NO pasa.** Un rango con una forma rara devuelve `false`, no
 *     «bueno, adelante». Es la regla de siempre: si falta lo que hace falta para decidir,
 *     se para.
 *
 * Formas admitidas, y son todas:
 *
 *     "0.106.2"              exacta
 *     "0.106.0+"             ABIERTO hacia arriba: de esa en adelante
 *     ">=0.106.0"            lo mismo, en el otro idioma. También >  <=  <
 *     "0.100.0 - 0.106.2"    intervalo, extremos incluidos
 *     "0.100.0 - *"          abierto por el extremo de arriba
 *     "*"                    cualquiera
 *     [">=0.5.0", "0.4.2"]   una lista es un O
 */

const PARTES = /^(\d+)\.(\d+)\.(\d+)$/

/** `[major, minor, patch]`, o `null` si no tiene la forma. */
export function parseVersion (v) {
  const m = PARTES.exec(String(v || '').trim())
  return m ? [Number(m[1]), Number(m[2]), Number(m[3])] : null
}

/** -1, 0 o 1. Lanza si alguna no tiene forma: comparar basura no puede dar un resultado. */
export function compareVersions (a, b) {
  const x = parseVersion(a)
  const y = parseVersion(b)
  if (!x || !y) throw new Error(`compat: cannot compare versions "${a}" and "${b}"`)
  for (let i = 0; i < 3; i++) {
    if (x[i] !== y[i]) return x[i] < y[i] ? -1 : 1
  }
  return 0
}

const OPS = [
  ['>=', (c) => c >= 0],
  ['<=', (c) => c <= 0],
  ['>', (c) => c > 0],
  ['<', (c) => c < 0]
]

/**
 * ¿`version` cae dentro de `range`?
 * @param {string} version
 * @param {string|string[]} range
 * @returns {boolean} `false` también cuando el rango no se entiende
 */
export function satisfies (version, range) {
  if (Array.isArray(range)) return range.some((r) => satisfies(version, r))
  if (typeof range !== 'string') return false
  const r = range.trim()
  if (!r) return false
  if (r === '*') return true
  if (!parseVersion(version)) return false

  // ABIERTO HACIA ARRIBA: «0.106.0+» es «de esa en adelante». Es la forma que más se usa
  // en un manifiesto —«esto y lo que venga»— y se lee mejor que `>=` cuando hay veinte
  // líneas seguidas (dueño, 2026-09-04).
  if (r.endsWith('+')) {
    try { return compareVersions(version, r.slice(0, -1).trim()) >= 0 } catch (_) { return false }
  }

  const guion = r.split(' - ')
  if (guion.length === 2) {
    const desde = guion[0].trim()
    const hasta = guion[1].trim()
    try {
      if (compareVersions(version, desde) < 0) return false
      // El extremo de arriba también puede quedar abierto: «0.100.0 - *».
      return hasta === '*' ? true : compareVersions(version, hasta) <= 0
    } catch (_) { return false }
  }

  for (const [signo, cumple] of OPS) {
    if (r.startsWith(signo)) {
      try { return cumple(compareVersions(version, r.slice(signo.length).trim())) } catch (_) { return false }
    }
  }

  try { return compareVersions(version, r) === 0 } catch (_) { return false }
}

export default { parseVersion, compareVersions, satisfies }
