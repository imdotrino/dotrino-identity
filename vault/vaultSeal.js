/**
 * LO QUE UN APARATO LE PIDE A SU BÓVEDA VA SELLADO, Y LO QUE ELLA CONTESTA TAMBIÉN.
 *
 * El proxio no cifra (CONVENCIONES §4.1): una petición firmada pero sin sellar llevaba en
 * claro el `machine` del aparato, el cajón que pedía, el método del almacén o el id del
 * pedido que se aprobaba — todo legible para quien opere el proxio (regla `encrypted` de la
 * auditoría, dueño 2026-10-26: *nada viaja en claro por la red*).
 *
 * El diseño, sin cripto nueva — es el sellado del pilar (`sendSealed` de
 * `@dotrino/proxy-client`, que es `wrapForMember` de `./content.js`):
 *
 *   · **La petición ENTERA** (`{ type, data, signature, cert }`) se sella a la llave de
 *     cifrado del transporte de cada bóveda de la cuenta. Esas bóvedas son los miembros del
 *     acta con `cn: 'vault'` (sus llaves de comunicación), y su llave de cifrado la anuncia
 *     cada una firmada al identificarse; el pilar la averigua y verifica la firma. Fuera
 *     del sobre queda solo lo que el proxio necesita para enrutar: a quién va
 *     (`to_publickey`, la cuenta) y si timbra (`quiet`).
 *   · **Se enruta a la cuenta** (`dest`), no a cada bóveda: así sigue despertando a la que
 *     duerme (la de la Nube) y llega a todas, como antes. Va un sobre por bóveda y cada una
 *     abre solo el suyo.
 *   · **La respuesta vuelve sellada a una llave de un solo uso** (`rek`), que va DENTRO de lo
 *     firmado: solo quien abrió la petición la conoce, así que una respuesta sellada a ella
 *     solo pudo armarla la bóveda. La privada no sale del cliente de esta llamada.
 *
 * MIGRACIÓN — CADUCA EL 2026-12-15 (`PLAIN_UNTIL`). Hasta esa fecha, si no hay a quién
 * sellarle (acta sin la llave de comunicación de la bóveda, o una bóveda que todavía no
 * anuncia su llave de cifrado), la petición sale en claro **y se dice**; y una respuesta
 * sin sellar de una bóveda vieja se acepta **y se dice**. Desde esa fecha, ninguna de las
 * dos cosas: se para con `vault-unsealable` / `vault-reply-unsealed`. Lo cubre
 * `test/vault-seal.test.mjs`. Quitar este bloque en cuanto pase la fecha.
 */

import { VAULT_CN, canAdopt } from './acta.js'
export { VAULT_CN }

/** MIGRACIÓN: hasta cuándo se tolera hablar en claro con una bóveda vieja (2026-12-15 UTC). */
export const PLAIN_UNTIL = Date.UTC(2026, 11, 15)
export const PLAIN_UNTIL_TEXT = '2026-12-15'

/** ¿Todavía se tolera el claro de la migración? */
/** @param {number} [now] @returns {boolean} */
export function plainAllowed (now = Date.now()) { return now < PLAIN_UNTIL }

/** @param {string} message @param {string} code */
const withCode = (message, code) => Object.assign(new Error(message), { code })

/**
 * Las llaves de comunicación de las bóvedas de la cuenta, según el acta.
 * @param {import('./acta.js').MaybeActa} acta
 * @returns {string[]}
 */
export function vaultKeysOf (acta) {
  return [...new Set((acta?.members || [])
    .filter((m) => m && m.cn === VAULT_CN && typeof m.pub === 'string' && m.pub)
    .map((m) => /** @type {string} */ (m.pub)))]
}

/**
 * EL ACTA MÁS NUEVA QUE ENCADENA CON LA MÍA, de la copia que guarda el proxio
 * (`getActas`, websocket-proxy ≥ 1.10.0). Sin esto, un aparato con el acta atrasada le
 * sellaría a una llave de comunicación que la bóveda ya cambió, y la petición se perdería
 * en silencio: la bóveda no puede abrirla y no sabe de quién era.
 *
 * No se fía del proxio: cada acta tiene que verificarse y encadenar con la anterior aceptada
 * (`canAdopt`, la regla de siempre). Un proxio que no guarda actas (`no-acta-cache`) no es un
 * fallo: se sigue con la que ya se tenía, que es la verificada. Cualquier otro error se dice.
 * @param {any} client  un cliente de `@dotrino/proxy-client`
 * @param {import('./acta.js').MaybeActa} acta
 * @returns {Promise<import('./acta.js').MaybeActa>}
 */
export async function latestActa (client, acta) {
  if (!acta?.profileId || typeof acta.seq !== 'number' || typeof client?.getActas !== 'function') return acta
  let newer
  try { newer = await client.getActas(acta.profileId, { sinceSeq: acta.seq }) } catch (e) {
    if (/** @type {{ code?: string } | null | undefined} */ (e)?.code === 'no-acta-cache') return acta
    throw e
  }
  let current = acta
  for (const candidate of [...(newer || [])].filter((a) => typeof a?.seq === 'number' && a.seq > acta.seq).sort((a, b) => a.seq - b.seq)) {
    if ((await canAdopt({ candidate, current })).adopt) current = candidate
  }
  return current
}

/**
 * Manda `payload` a la bóveda SELLADO.
 *
 * @param {any} client  un cliente de `@dotrino/proxy-client` (o el local, `client.local`)
 * @param {object} o
 * @param {string} o.dest  a qué llave se enruta (la cuenta, o `to`)
 * @param {string|null} [o.to]  una bóveda concreta (su llave de comunicación): solo a ella
 * @param {import('./acta.js').MaybeActa} [o.acta]  el acta de la cuenta que este aparato ya aceptó: de ella (o de una
 *   más nueva que encadene con ella, `latestActa`) salen las bóvedas
 * @param {object} o.payload  `{ type, data, signature, cert }`
 * @param {boolean} [o.quiet]  no timbra a una bóveda dormida
 * @param {((line:string)=>void) | null} [o.warn]  dónde se dice que salió en claro (migración)
 * @param {number} [o.now]
 * @returns {Promise<{ sealed:number, why?:string }>}
 */
export async function sendToVault (client, { dest, to = null, acta = null, payload, quiet = false, warn = null, now = Date.now() }) {
  const opts = quiet ? { quiet: true } : {}
  // EL SOCKET DE ESTA MÁQUINA no toca la red (escalón 1 del transporte): no hay a quién
  // esconderle nada, y ahí la bóveda no tiene llave de cifrado que anunciar.
  if (client?.local) { client.sendByPubkey(dest, payload, opts); return { sealed: 0, why: 'local' } }
  const keys = to ? [to] : vaultKeysOf(await latestActa(client, acta))
  const encPubs = []
  let lastError = null
  for (const k of keys) {
    try { encPubs.push(await client.encPubOf(k)) } catch (e) { lastError = e }
  }
  if (encPubs.length) {
    for (const peerEncPub of encPubs) await client.sendSealed([dest], payload, { peerEncPub, ...opts })
    return { sealed: encPubs.length }
  }
  const why = keys.length ? (/** @type {{ code?: string } | null} */ (lastError)?.code || 'no-encpub') : 'no-vault-key'
  if (!plainAllowed(now)) {
    throw withCode(`cannot seal the request to the vault (${why}): update the vault, or let this device see the current record`, 'vault-unsealable')
  }
  // MIGRACIÓN (caduca 2026-12-15): ver la cabecera.
  try { warn?.(`[vault] request ${/** @type {{ type?: string } | null | undefined} */ (payload)?.type || ''} sent UNSEALED (${why}): tolerated only until ${PLAIN_UNTIL_TEXT} — update the vault`) } catch (_) {}
  client.sendByPubkey(dest, payload, opts)
  return { sealed: 0, why }
}

/**
 * ¿Se acepta esta respuesta? Sellada, siempre. Por el socket local, siempre. En claro, solo
 * durante la migración, y se dice. Devuelve `false` para ignorarla.
 * @param {{ meta?: { sealed?: boolean } | null, local?: boolean, type?: string, warn?: ((line: string) => void) | null, now?: number }} args
 * @returns {boolean}
 */
export function acceptReply ({ meta, local = false, type = '', warn = null, now = Date.now() }) {
  if (local || meta?.sealed) return true
  if (!plainAllowed(now)) return false
  // MIGRACIÓN (caduca 2026-12-15): una bóveda vieja todavía no sella lo que contesta.
  try { warn?.(`[vault] reply ${type} arrived UNSEALED from an old vault: tolerated only until ${PLAIN_UNTIL_TEXT} — update the vault`) } catch (_) {}
  return true
}
