/**
 * assertion.js — PARA QUIÉN vale una firma, y HASTA CUÁNDO.
 *
 * EL AGUJERO QUE TAPA. Una firma del ecosistema decía «esta identidad firmó esto» y nada
 * más. No decía a quién va dirigida, así que un sobre firmado para el proxio **valía ante
 * geo**: los dos comprueban la misma firma de la misma identidad y ninguno tenía con qué
 * notar que no le hablaban a él. La ventana de repetición evita que el MISMO sobre se
 * reenvíe dos veces al MISMO sitio; no evita el cruce de destinatario, que es otra cosa.
 *
 * Una prueba (`assertion`) es una firma normal del perfil —misma cripto, misma cadena de
 * actas— sobre un cuerpo que además dice `aud` (para quién), `nonce` (para qué petición) e
 * `iat`/`exp` (desde y hasta cuándo). Verificarla es lo de siempre MÁS comprobar esas
 * cuatro cosas.
 *
 * TRES REGLAS, y las tres son la razón de que esto exista:
 *
 *   · **`aud` es obligatorio al emitir Y al verificar.** Una prueba sin destinatario no se
 *     emite, y quien verifica tiene que decir quién es él. Sin eso no hay nada que
 *     comparar y devolver «vale» sería exactamente el agujero de arriba.
 *   · **El `nonce` lo pone quien PIDE.** Ata la prueba a esa petición y a ninguna otra.
 *     Aquí no se lleva registro de nonces vistos: el que pide sabe cuál mandó, y un nonce
 *     que no vuelve a usar no se puede repetir.
 *   · **SIN MODO PERMISIVO.** No hay bandera para saltarse una comprobación, ni valor por
 *     defecto que rellene lo que falta. Si falta el destinatario, el reto o la cadena, se
 *     devuelve `ok:false` con su motivo. Un verificador laxo es un verificador roto.
 *
 * Módulo PURO: sin red, sin kv, sin iframe. Lo importan las apps, los servicios y el
 * daemon.
 */
import { verifySignedBy } from './acta.js'

export const ASSERTION_V = 1

/**
 * VIGENCIA. Corta a propósito: es lo que hace barata la revocación —no hay nada que
 * invalidar, solo se deja de renovar— y lo que limita el daño de una prueba interceptada.
 *
 * El tope lo comprueba también QUIEN RECIBE, no solo quien emite: fiarse de que el otro
 * puso un `exp` sensato es fiarse de la buena fe del que firma, y una prueba con un año de
 * vigencia es una credencial al portador.
 */
export const ASSERTION_MAX_TTL_MS = 5 * 60 * 1000
export const ASSERTION_DEFAULT_TTL_MS = 2 * 60 * 1000

/**
 * Tolerancia de reloj para `iat`. No es un repliegue: dos máquinas honestas difieren en
 * segundos, y sin margen una prueba recién firmada se rechazaría por venir «del futuro».
 * Solo afecta al arranque de la ventana; el vencimiento no se estira (ver §verify).
 */
export const ASSERTION_MAX_SKEW_MS = 60 * 1000

/** Lo que se puede pedir. Lista CERRADA: lo que no está aquí no existe. */
export const SCOPES = Object.freeze(['id:whoami', 'profile:name', 'profile:avatar', 'profile:email', 'profile:social'])

/**
 * Qué dato deja ver cada alcance. `id:whoami` no deja ver NINGUNO —es el mínimo: dice
 * quién eres y nada más— y por eso es la lista vacía y no una omisión.
 */
export const SCOPE_CLAIMS = Object.freeze({
  'id:whoami': Object.freeze([]),
  'profile:name': Object.freeze(['name']),
  'profile:avatar': Object.freeze(['avatar']),
  'profile:email': Object.freeze(['email']),
  'profile:social': Object.freeze(['links'])
})

/** Un reto de un solo uso, para quien pide. Que sea él quien lo genere es la mitad del mecanismo. */
export const newAssertionNonce = () => crypto.randomUUID()

/**
 * Normaliza los alcances pedidos: solo los del catálogo, sin repetidos y en orden estable
 * (el cuerpo se firma canónicamente, así que el orden importa para no firmar dos cosas
 * distintas que dicen lo mismo).
 *
 * Pedir alcances desconocidos NO es un aviso que se pueda ignorar: se descartan, y si no
 * queda ninguno se emite el mínimo (`id:whoami`), que es lo que significa «solo quiero
 * saber quién eres».
 */
export function cleanScopes (scopes) {
  const list = [...new Set((Array.isArray(scopes) ? scopes : []).filter((s) => SCOPES.includes(s)))].sort()
  return list.length ? list : ['id:whoami']
}

/** Las claves de datos que esos alcances permiten llevar. */
export function claimsAllowed (scopes) {
  const out = new Set()
  for (const s of cleanScopes(scopes)) for (const c of SCOPE_CLAIMS[s]) out.add(c)
  return out
}

/**
 * El cuerpo que se firma. Se construye AQUÍ y en un solo sitio, porque quien firma y quien
 * verifica tienen que estar mirando exactamente los mismos campos: si el emisor añadiera
 * uno que el verificador no reconstruye, la firma no cuadraría y el fallo aparecería como
 * «firma inválida», que manda a buscar al sitio equivocado.
 *
 * Lanza si le falta algo: es un error de programación de quien emite, no un dato del otro
 * lado que pueda venir mal.
 */
export function assertionBody ({ sub, aud, nonce, scopes, claims, iat, exp }) {
  if (typeof sub !== 'string' || !sub) throw new Error('assertion: sub required')
  if (typeof aud !== 'string' || !aud.trim()) throw new Error('assertion: aud required')
  if (typeof nonce !== 'string' || !nonce) throw new Error('assertion: nonce required')
  if (!Number.isFinite(iat) || !Number.isFinite(exp)) throw new Error('assertion: iat/exp required')
  if (exp <= iat) throw new Error('assertion: exp must be after iat')
  if (exp - iat > ASSERTION_MAX_TTL_MS) throw new Error('assertion: lifetime over the cap')
  const granted = cleanScopes(scopes)
  const permitido = claimsAllowed(granted)
  const out = {}
  for (const [k, v] of Object.entries(claims || {})) {
    // NO se recorta en silencio lo que sobra: llevar un dato sin su alcance es entregar
    // algo que nadie concedió, y el emisor tiene que enterarse de que lo intentó.
    if (!permitido.has(k)) throw new Error(`assertion: claim "${k}" has no scope granting it`)
    if (v !== undefined && v !== null && v !== '') out[k] = v
  }
  return { v: ASSERTION_V, op: 'assertion', sub, aud: aud.trim(), nonce, iat, exp, scopes: granted, claims: out }
}

/** Los campos del cuerpo, sacados de una prueba completa (que además lleva firma y cadena). */
const bodyOf = (a) => ({ v: a.v, op: a.op, sub: a.sub, aud: a.aud, nonce: a.nonce, iat: a.iat, exp: a.exp, scopes: a.scopes, claims: a.claims })

/**
 * ¿Vale esta prueba, PARA MÍ y AHORA?
 *
 * `audience` y `nonce` los pone quien verifica, y son obligatorios: son las dos cosas que
 * él sabe y la prueba no puede inventar. Faltando cualquiera de las dos no se puede
 * juzgar, y decir «ok» sin haber comprobado es cómo un sobre de otro seguía entrando.
 *
 * Devuelve `{ ok:true, profileId, signer, seq, scopes, claims, aud, exp }` o
 * `{ ok:false, reason }`.
 */
/**
 * @param {any} assertion
 * @param {{ audience?: string, nonce?: string, expectedProfileId?: string|null, now?: number, maxSkewMs?: number }} [opts]
 */
export async function verifyAssertion (assertion, opts = {}) {
  const { audience, nonce, expectedProfileId = null, now = Date.now(), maxSkewMs = ASSERTION_MAX_SKEW_MS } = opts
  if (typeof audience !== 'string' || !audience.trim()) return { ok: false, reason: 'no-audience' }
  if (typeof nonce !== 'string' || !nonce) return { ok: false, reason: 'no-nonce' }
  const a = assertion
  if (!a || typeof a !== 'object') return { ok: false, reason: 'shape' }
  if (a.v !== ASSERTION_V || a.op !== 'assertion') return { ok: false, reason: 'shape' }
  if (typeof a.sub !== 'string' || typeof a.aud !== 'string' || typeof a.nonce !== 'string') return { ok: false, reason: 'shape' }
  if (!Number.isFinite(a.iat) || !Number.isFinite(a.exp)) return { ok: false, reason: 'shape' }
  if (!Array.isArray(a.scopes) || (a.claims != null && typeof a.claims !== 'object')) return { ok: false, reason: 'shape' }
  if (typeof a.signature !== 'string' || typeof a.publickey !== 'string') return { ok: false, reason: 'shape' }

  if (a.aud !== audience.trim()) return { ok: false, reason: 'otro-destinatario' }
  if (a.nonce !== nonce) return { ok: false, reason: 'otro-reto' }

  if (a.exp <= a.iat) return { ok: false, reason: 'vigencia-invalida' }
  // El TOPE lo comprueba quien recibe. Si no, el emisor decide solo cuánto dura su
  // credencial y el tope no es un tope.
  if (a.exp - a.iat > ASSERTION_MAX_TTL_MS) return { ok: false, reason: 'vigencia-excesiva' }
  // Y el vencimiento se juzga SIN margen: el margen es para el arranque (relojes que
  // difieren), no para seguir aceptando lo que ya venció.
  if (a.exp <= now) return { ok: false, reason: 'vencida' }
  if (a.iat > now + maxSkewMs) return { ok: false, reason: 'del-futuro' }

  if (a.scopes.some((s) => !SCOPES.includes(s))) return { ok: false, reason: 'alcance-desconocido' }
  const permitido = claimsAllowed(a.scopes)
  if (Object.keys(a.claims || {}).some((k) => !permitido.has(k))) return { ok: false, reason: 'claim-sin-alcance' }

  // Y lo de siempre: que la firma sea de alguien a quien el acta de esa cadena autoriza a
  // firmar por esta identidad. Es la misma comprobación que para cualquier contenido
  // firmado; aquí no se inventa una cripto aparte.
  const v = await verifySignedBy({ data: bodyOf(a), signature: a.signature, publickey: a.publickey, chain: a.chain, expectedProfileId })
  if (!v.ok) return { ok: false, reason: 'firma:' + v.reason }
  // A NOMBRE DE QUIÉN dice ir, contra a nombre de quién va de verdad. Sin esto una prueba
  // podría afirmar ser de otro perfil y la firma seguiría cuadrando: diría la verdad sobre
  // quién la firmó y una mentira sobre de quién es.
  if (a.sub !== v.profileId) return { ok: false, reason: 'otro-sujeto' }

  return { ok: true, profileId: v.profileId, signer: v.signer, seq: v.seq, scopes: [...a.scopes], claims: { ...(a.claims || {}) }, aud: a.aud, exp: a.exp }
}

export default { ASSERTION_V, ASSERTION_MAX_TTL_MS, ASSERTION_DEFAULT_TTL_MS, ASSERTION_MAX_SKEW_MS, SCOPES, SCOPE_CLAIMS, newAssertionNonce, cleanScopes, claimsAllowed, assertionBody, verifyAssertion }
