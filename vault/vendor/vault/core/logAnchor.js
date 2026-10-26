/**
 * EL ANCLA DE LA BITÁCORA: que no se pueda cortar el final sin que se note.
 *
 * La bitácora es una cadena (`logSeq` + hash de la anterior), así que reescribir o quitar
 * una entrada del medio se ve. Cortar el FINAL no: un prefijo sigue siendo una cadena
 * válida (modelo de amenazas §4.3). Eso no se cierra en local, porque quien corta tiene la
 * máquina. Se cierra sacando la cabeza de la máquina.
 *
 * Decidido por el dueño (2026-10-26): la cabeza se sella con `signer.dotrino.com` —que da
 * el CUÁNDO, firmado por un tercero— y el recibo viaja a los aparatos con `approve`, que
 * lo GUARDAN. El signer no guarda nada: un recibo que se quedara en este disco se borraría
 * junto con el final que pretende proteger. Un aprobador que recibe un ancla con un
 * `logSeq` menor que el último que guardó, o con el mismo `logSeq` y otra cabeza, sabe que
 * cortaron la bitácora.
 *
 * Al signer solo llega un hash: ni el contenido de la bitácora ni quién es esta bóveda.
 * Sin dependencias de Node: lo corren el binario, la pestaña y la extensión.
 */
import { bytesToB64url } from '../b64.js'

export const SIGNER_URL = 'https://signer.dotrino.com'
/** Cada cuánto se mira si hay algo nuevo que anclar. Sin entradas nuevas no se manda nada. */
export const ANCHOR_EVERY_MS = 6 * 60 * 60 * 1000
/** Cuánto espera la primera, desde que arranca la bóveda. */
export const ANCHOR_FIRST_MS = 10 * 60 * 1000
const SIGNER_TIMEOUT_MS = 15000

const fail = (code, message) => Object.assign(new Error(message), { code })

/** hex → base64url, que es como el signer pide el hash. */
export function hexToB64url (hex) {
  if (typeof hex !== 'string' || !/^[0-9a-f]{64}$/.test(hex)) throw fail('anchor-bad-head', 'the log head must be a sha256 in hex')
  const bytes = new Uint8Array(32)
  for (let i = 0; i < 32; i++) bytes[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16)
  return bytesToB64url(bytes)
}

/**
 * Pide al signer que selle la cabeza. Devuelve su recibo tal cual (`{ v, op, hash, ts, alg,
 * signature, pubkey }`), que es lo que el aprobador puede verificar sin red. Si el signer no
 * contesta, LANZA: un ancla sin sello no se manda como si lo tuviera.
 */
export async function sealHead (head, { fetchFn = globalThis.fetch, signerUrl = SIGNER_URL, timeoutMs = SIGNER_TIMEOUT_MS } = {}) {
  if (typeof fetchFn !== 'function') throw fail('anchor-no-fetch', 'this platform cannot reach the signer')
  const hash = hexToB64url(head)
  const ctl = typeof AbortController === 'function' ? new AbortController() : null
  const timer = ctl ? setTimeout(() => ctl.abort(), timeoutMs) : null
  try {
    const res = await fetchFn(signerUrl + '/seal', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ hash }),
      ...(ctl ? { signal: ctl.signal } : {})
    })
    if (!res.ok) throw fail('anchor-signer-error', `the signer answered ${res.status}`)
    const r = await res.json()
    if (r?.op !== 'seal' || r.hash !== hash || typeof r.ts !== 'number' || typeof r.signature !== 'string') {
      throw fail('anchor-signer-bad-receipt', 'the signer receipt does not match the head it was asked to seal')
    }
    return r
  } catch (e) {
    if (e?.code) throw e
    throw fail('anchor-signer-unreachable', `could not reach the signer: ${e?.message || e}`)
  } finally {
    if (timer) clearTimeout(timer)
  }
}

/**
 * Lo que decide el APROBADOR al recibir un ancla, frente a la última que guardó de esa
 * bóveda. Pura, para que el navegador, Kotlin y Swift hagan exactamente lo mismo.
 *
 *   · `first`      no tenía ninguna: se guarda.
 *   · `advanced`   la bitácora creció: se guarda la nueva.
 *   · `same`       nada nuevo.
 *   · `truncated`  `logSeq` menor que el guardado: cortaron el final.
 *   · `forked`     mismo `logSeq`, otra cabeza: reescribieron el final.
 *
 * Los dos últimos son la alarma. No se guarda el ancla nueva: la buena es la que ya estaba.
 */
export function compareAnchor (last, next) {
  if (!next || typeof next.logSeq !== 'number' || typeof next.head !== 'string') throw fail('anchor-malformed', 'an anchor needs logSeq and head')
  if (!last) return 'first'
  if (next.logSeq < last.logSeq) return 'truncated'
  if (next.logSeq === last.logSeq) return next.head === last.head ? 'same' : 'forked'
  return 'advanced'
}
