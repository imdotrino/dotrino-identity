/**
 * session.js — ENTRAR SIN ENROLAR.
 *
 * El ecosistema tenía muchas formas de ENLAZAR un aparato y ninguna de ENTRAR en uno. Y no
 * son lo mismo: enlazar mete una llave en el acta —hay que sellarla, o sea despertar a la
 * selladora y tener el perfil abierto— y salir es sellar otra vez. Nadie hace eso para
 * abrir una aplicación en un navegador prestado.
 *
 * Una SESIÓN es la otra puerta: una llave que vive en ese navegador y un PAPEL con
 * vencimiento que la respalda, firmado por un aparato tuyo que sí está en el acta. No toca
 * el acta, no necesita la selladora, y cerrar es inmediato.
 *
 *     llave de sesión  ←  papel  ←  aparato (miembro del acta)  ←  cadena  ←  perfil
 *
 * ESTO CREA UNA SEGUNDA AUTORIDAD, y por eso va acotada aquí y no en cada app:
 *
 *   · **Nunca amplía.** Un papel no concede lo que su firmante no tiene. Se comprueba
 *     contra el acta al verificar, no solo al emitir: quien emite podría mentir.
 *   · **Lista negra fija.** Una sesión jamás lleva `secrets`, `admin`, `approve`,
 *     `sealer`, `passwords`, `unattended` ni `replica` — ni aunque el aparato los tenga.
 *   · **Vence por reloj.** Es la excepción deliberada a «los papeles ya no caducan por
 *     reloj»: un certificado describe pertenencia, que dura; una sesión ES temporal, y su
 *     vencimiento es la mitad del producto.
 *   · **No se re-delega.** Una sesión no abre otra sesión. No hay operación para eso.
 *   · **Muere con su aparato.** Si revocas al que la respalda, su certificado deja de
 *     valer contra el acta y todos sus papeles caen con él. Sale gratis del modelo, y por
 *     eso `verifySession` EXIGE el acta: sin ella no se puede juzgar.
 *
 * Módulo PURO: sin red, sin kv, sin iframe.
 */
import { verifyDeviceSig } from './capabilities.js'
import { memberCan, verifySealerChain } from './acta.js'
import { canonicalStringify } from './core.js'

export const SESSION_V = 1

/** Cuánto dura una sesión. Horas, no meses: es un rato en un aparato que no es tuyo. */
export const SESSION_DEFAULT_TTL_MS = 8 * 60 * 60 * 1000
export const SESSION_MAX_TTL_MS = 24 * 60 * 60 * 1000
/** Tolerancia de reloj para el arranque (no para el vencimiento). */
export const SESSION_MAX_SKEW_MS = 60 * 1000

/**
 * Lo que una sesión puede llegar a hacer. Lista CERRADA y corta a propósito: es lo de bajo
 * riesgo, lo que haría inviable la sesión si hubiera que preguntarle al teléfono cada vez.
 *
 *   · `id:whoami`      — decir quién eres (identificarse ante el transporte).
 *   · `vault:store`    — leer y escribir en el almacén del perfil, si el papel lo dice.
 *
 * Firmar POR LA PERSONA no está aquí, y es deliberado: eso se le pide al aparato que
 * respalda, que es quien tiene una llave que el acta reconoce.
 */
export const SESSION_SCOPES = Object.freeze(['id:whoami', 'vault:store'])

/**
 * Lo que una sesión NUNCA lleva, dijera lo que dijera el papel. Está aparte de la lista
 * blanca a propósito: si mañana alguien añade un alcance a `SESSION_SCOPES` sin pensarlo,
 * esto sigue cortando lo que no puede pasar.
 */
export const SESSION_FORBIDDEN = Object.freeze(['secrets', 'admin', 'approve', 'sealer', 'passwords', 'unattended', 'replica'])

/** Qué capacidad del acta hace falta para conceder cada alcance de sesión. */
const SCOPE_NEEDS = Object.freeze({ 'id:whoami': null, 'vault:store': 'store' })

const enc = (s) => new TextEncoder().encode(s)
const isStr = (v) => typeof v === 'string' && !!v

/** Un identificador de sesión: lo que se enseña al usuario para que pueda cerrarla. */
export const newSessionId = () => crypto.randomUUID()

/** Normaliza los alcances pedidos: solo los del catálogo, sin repetidos y en orden estable. */
export function cleanSessionScopes (scopes) {
  const list = [...new Set((Array.isArray(scopes) ? scopes : []).filter((s) => SESSION_SCOPES.includes(s)))].sort()
  return list.length ? list : ['id:whoami']
}

/** El cuerpo que firma el aparato que respalda. Un solo sitio: quien firma y quien verifica miran lo mismo. */
export function sessionBody ({ sid, s, by, origin, scopes, iat, exp }) {
  if (!isStr(sid)) throw new Error('session: sid required')
  if (!isStr(s)) throw new Error('session: s (session pubkey) required')
  if (!isStr(by)) throw new Error('session: by (backing device pubkey) required')
  if (!isStr(origin)) throw new Error('session: origin required')
  if (!Number.isFinite(iat) || !Number.isFinite(exp)) throw new Error('session: iat/exp required')
  if (exp <= iat) throw new Error('session: exp must be after iat')
  if (exp - iat > SESSION_MAX_TTL_MS) throw new Error('session: lifetime over the cap')
  return { v: SESSION_V, op: 'session', sid, s, by, origin: origin.trim(), scopes: cleanSessionScopes(scopes), iat, exp }
}

/**
 * Firma un papel de sesión. Lo llama el APARATO que respalda, con su propia llave.
 *
 * `sign` recibe el cuerpo y devuelve la firma (o el paquete del vault). No se le pasa la
 * privada: este módulo no toca llaves.
 */
export async function signSession ({ sid, s, by, origin, scopes, ttlMs, now = Date.now() }, sign) {
  if (typeof sign !== 'function') throw new Error('session: sign(body) required')
  const ttl = Math.min(Math.max(Number(ttlMs) || SESSION_DEFAULT_TTL_MS, 60000), SESSION_MAX_TTL_MS)
  const body = sessionBody({ sid, s, by, origin, scopes, iat: now, exp: now + ttl })
  const firmado = await sign(body)
  const sig = typeof firmado === 'string' ? firmado : firmado?.signature
  if (!isStr(sig)) throw Object.assign(new Error('session: sign() returned no signature'), { code: 'no-signature' })
  return { ...body, sig }
}

/**
 * ¿Vale este papel de sesión, AHORA?
 *
 * `chain` es la cadena de actas del perfil, y es obligatoria: sin ella no se puede saber si
 * el aparato que respalda sigue siendo de la casa —que es lo que hace que quitar un aparato
 * se lleve por delante sus sesiones—. Devuelve `{ ok, profileId, scopes, sid, exp }` o
 * `{ ok:false, reason }`.
 */
export async function verifySession (paper, { chain, expectedProfileId = null, origin = null, now = Date.now(), maxSkewMs = SESSION_MAX_SKEW_MS } = {}) {
  const p = paper
  if (!p || typeof p !== 'object') return { ok: false, reason: 'shape' }
  if (p.v !== SESSION_V || p.op !== 'session') return { ok: false, reason: 'shape' }
  if (!isStr(p.sid) || !isStr(p.s) || !isStr(p.by) || !isStr(p.origin) || !isStr(p.sig)) return { ok: false, reason: 'shape' }
  if (!Number.isFinite(p.iat) || !Number.isFinite(p.exp) || !Array.isArray(p.scopes)) return { ok: false, reason: 'shape' }

  if (p.exp <= p.iat) return { ok: false, reason: 'vigencia-invalida' }
  if (p.exp - p.iat > SESSION_MAX_TTL_MS) return { ok: false, reason: 'vigencia-excesiva' }
  if (p.exp <= now) return { ok: false, reason: 'vencida' }
  if (p.iat > now + maxSkewMs) return { ok: false, reason: 'del-futuro' }

  // DÓNDE vale. Un papel para una aplicación no vale en otra: el origen va firmado dentro.
  if (origin != null && p.origin !== String(origin).trim()) return { ok: false, reason: 'otro-origen' }

  if (p.scopes.some((s) => !SESSION_SCOPES.includes(s))) return { ok: false, reason: 'alcance-desconocido' }
  if (p.scopes.some((s) => SESSION_FORBIDDEN.includes(s))) return { ok: false, reason: 'alcance-prohibido' }

  // EL ACTA MANDA, y por eso hace falta: dice si el aparato que respalda sigue siendo del
  // perfil y qué puede. Sin ella no se juzga, en vez de dar por bueno lo que diga el papel.
  const c = await verifySealerChain(chain, { expectedProfileId })
  if (!c.ok) return { ok: false, reason: 'cadena:' + c.reason }
  const acta = chain[chain.length - 1]

  // PRIMERO, ¿ES DE LA CASA? Y en este orden a propósito: si al aparato lo quitaron, el
  // motivo tiene que decir eso y no «le falta un permiso», que manda a mirar al sitio
  // equivocado. Es además el invariante que hace barata la revocación — quitar un aparato
  // se lleva sus sesiones sin avisar a nadie ni perseguir papeles.
  if (!(acta.members || []).some((m) => m?.pub === p.by)) return { ok: false, reason: 'aparato-no-es-del-perfil' }

  // Y DESPUÉS, NUNCA AMPLÍA: cada alcance exige que el aparato que firmó lo tenga HOY. Se
  // comprueba aquí y no solo al emitir, porque quien emite es precisamente quien podría
  // mentir — y porque el acta de hoy puede haberle quitado lo que tenía ayer.
  for (const s of p.scopes) {
    const cap = SCOPE_NEEDS[s]
    if (cap && !memberCan(acta, p.by, cap)) return { ok: false, reason: 'aparato-sin-' + cap }
  }

  const { sig, ...body } = p
  if (!(await verifyDeviceSig({ publickey: p.by, data: body, signature: sig }))) return { ok: false, reason: 'firma-invalida' }

  return { ok: true, profileId: c.profileId, seq: c.seq, sid: p.sid, s: p.s, by: p.by, origin: p.origin, scopes: [...p.scopes], exp: p.exp }
}

/**
 * ¿Firmó ESTA SESIÓN esto, y podía?
 *
 * Es lo que llama quien recibe algo de una sesión: comprueba la firma de la llave de
 * sesión, el papel que la respalda y —si se pide— que el alcance cubra lo que se pretende.
 */
export async function verifySessionSigned ({ data, signature, session, chain, scope = null, origin = null, expectedProfileId = null, now = Date.now() } = {}) {
  if (!data || !isStr(signature)) return { ok: false, reason: 'shape' }
  const v = await verifySession(session, { chain, expectedProfileId, origin, now })
  if (!v.ok) return v
  if (scope && !v.scopes.includes(scope)) return { ok: false, reason: 'fuera-de-alcance' }
  if (!(await verifyDeviceSig({ publickey: v.s, data, signature }))) return { ok: false, reason: 'firma-invalida' }
  return { ok: true, profileId: v.profileId, sid: v.sid, scopes: v.scopes, exp: v.exp }
}

export default {
  SESSION_V, SESSION_DEFAULT_TTL_MS, SESSION_MAX_TTL_MS, SESSION_MAX_SKEW_MS,
  SESSION_SCOPES, SESSION_FORBIDDEN, newSessionId, cleanSessionScopes,
  sessionBody, signSession, verifySession, verifySessionSigned
}
