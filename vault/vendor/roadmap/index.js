/**
 * @dotrino/roadmap — EL REGISTRO COMÚN, COMO PIEZA DE CONSULTA.
 *
 * Los manifiestos de este repo dicen **qué versión va cada producto, qué protocolo habla,
 * qué rangos necesita de los demás y qué versiones se saben rotas**. Esta librería es la
 * forma de leerlos: cada producto la importa en vez de abrir el JSON a mano, porque
 * treinta piezas parseando el mismo archivo a su manera son treinta formas de equivocarse
 * y ninguna hace ruido cuando se equivoca.
 *
 * REPARTO DE TRABAJO, para que no se mezcle:
 *
 *   · **`@dotrino/compat`** decide. Es la lógica: declarar, comparar, avisar.
 *   · **esto** es el registro. Son los datos, y se editan aquí.
 *
 * Va como `peerDependency` de `@dotrino/compat` a propósito: un pilar dentro de otro se
 * cuela anidado a cada consumidor, y ya pasó (`PENDIENTES.md`, «pilar anidado»).
 *
 * EL MANIFIESTO ES POLÍTICA DEL CÓDIGO (dueño, 2026-09-04): viaja con la versión que lo
 * trae. Lo que llega por la red es el **aviso** firmado de `@dotrino/compat/advisory`, que
 * suma incompatibilidades y no quita ninguna.
 */
import { satisfies } from '@dotrino/compat/ranges'
import { MANIFESTS } from './manifests.js'

/**
 * NADA DE DISCO, y esto costó un binario que no arrancaba.
 *
 * La primera versión leía los JSON con `fileURLToPath(import.meta.url)` calculado AL
 * IMPORTARSE. En un ejecutable único eso no existe: la bóveda murió al arrancar con «The
 * "path" argument must be of type string», y en un navegador no habría arrancado nunca.
 *
 * Los consumen ~30 PWAs, varios daemons y un binario. Un registro que hay que leer del
 * disco no sirve para eso, así que los manifiestos van DENTRO del código
 * (`src/manifests.js`, generado desde `manifests/*.json`).
 */

/** Los manifiestos que trae esta versión. Hay uno («dotrino») y caben varios. */
export function manifestNames () {
  return Object.keys(MANIFESTS).sort()
}

/**
 * Un manifiesto por nombre. LANZA si no está: quien pregunta por un registro que no existe
 * tiene un error, y devolverle un objeto vacío lo convertiría en «todo compatible».
 */
export function loadManifest (name = 'dotrino') {
  const m = Object.hasOwn(MANIFESTS, String(name)) ? MANIFESTS[String(name)] : null
  if (!m) throw new Error(`roadmap: there is no manifest called "${name}"`)
  return m
}

/** Los productos que el registro conoce. */
export const products = (m) => Object.keys(m?.products || {}).sort()

/** La ficha de un producto, o `null` si el registro no lo conoce. */
export const productOf = (m, product) => m?.products?.[product] || null

/** La versión que el registro da por vigente. `null` si no lo conoce. */
export const currentOf = (m, product) => productOf(m, product)?.current || null

/** El rango que `product` necesita de `peer`, o `null` si no exige nada. */
export function requirementFor (m, product, peer) {
  const p = productOf(m, product)
  if (!p) return null
  return p.requires?.[peer] ?? null
}

/**
 * ¿La versión de `peer` cumple lo que `product` necesita?
 *
 * Tres respuestas y ninguna es «bueno, adelante»:
 *   · `true`  — cumple.
 *   · `false` — no cumple, y `reason` dice qué se esperaba.
 *   · cuando el registro NO exige nada, cumple: no exigir es una decisión, no una laguna.
 *
 * Si el registro no conoce al producto que pregunta, es `false`: preguntar por quien no
 * está en el registro no puede salir que sí.
 */
export function meets (m, { product, peer, version }) {
  if (!productOf(m, product)) {
    return { ok: false, reason: `the registry does not know "${product}"` }
  }
  const rango = requirementFor(m, product, peer)
  if (rango == null) return { ok: true, reason: '' }
  if (satisfies(version, rango)) return { ok: true, reason: '' }
  return { ok: false, reason: `${product} needs ${peer} ${rango} and this one is ${version}` }
}

/** La lista de rotas del registro, lista para pasarla a `check` de `@dotrino/compat`. */
export const brokenOf = (m) => Array.isArray(m?.broken) ? m.broken : []

/** Lo que el administrador enseña: qué versión debería ir cada pieza, según el registro. */
export function summary (m) {
  return {
    manifest: m?.manifest || null,
    seq: m?.seq ?? null,
    issued: m?.issued || null,
    products: products(m).map((p) => ({
      product: p,
      current: currentOf(m, p),
      protocol: productOf(m, p)?.protocol ?? null,
      requires: productOf(m, p)?.requires || {}
    })),
    broken: brokenOf(m)
  }
}

export default { manifestNames, loadManifest, products, productOf, currentOf, requirementFor, meets, brokenOf, summary }
