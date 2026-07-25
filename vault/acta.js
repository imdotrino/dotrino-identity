/**
 * acta.js — el ACTA DE PERFIL: qué llaves son del mismo perfil y qué puede hacer cada una.
 *
 * Un perfil no es una llave: es un CONJUNTO de llaves miembro, ligadas por certificados,
 * más una política firmada. Ninguna llave privada viaja nunca; lo que se mueve es el acta.
 * Diseño completo y decisiones en `dotrino-vault/docs/acta-de-perfil.md`.
 *
 * Las cuatro reglas que este módulo hace cumplir:
 *   1. **Un solo sellador** (el «master»). Solo el sellador vigente puede producir la
 *      siguiente acta. Como las llaves son intransferibles no se puede clonar → dos actas
 *      legítimas con el mismo `seq` son imposibles: no hay bifurcaciones que resolver.
 *   2. **`seq` monotónico + `prev`** (hash del acta anterior): cadena verificable.
 *   3. **Nunca dejar el perfil sin quien firme**: un cambio que quite el último `sign` se
 *      rechaza.
 *   4. **Renunciar es aparte**: un miembro se quita capacidades a sí mismo con un registro
 *      suelto que solo QUITA (§2.2). No toca el acta ni el `seq`, así que funciona con la
 *      bóveda apagada; el master lo absorbe después.
 *
 * DOS CAMPOS, NO UNO: `sealedBy` es la llave que FIRMÓ esta acta y `sealer` es quien queda
 * como master de aquí en adelante. Normalmente coinciden; en un TRASPASO no, porque el acta
 * que nombra al nuevo master la firma el saliente. Esa distinción es la que hace el traspaso
 * auto-verificable: la firma del saliente es la prueba de su propia degradación.
 *
 * Los tiempos son epoch en ms (UTC) e INFORMATIVOS: la precedencia va por `seq` y por la
 * regla de traspaso (§2.4.1), nunca por reloj — si dependiera de la hora, un master mintiendo
 * reescribiría el orden cambiando el reloj de su máquina.
 *
 * Módulo PURO: sin kv, sin red, sin disco. Cripto de `./capabilities.js`.
 */
import { canonicalStringify } from './core.js'
import { signWithDevice, verifyDeviceSig, pubkeyId } from './capabilities.js'

export const ACTA_V = 1

/** Lista CERRADA de capacidades. Sellar y admitir no están: eso es ser el master. */
export const CAPS = Object.freeze(['sign', 'store', 'read'])

/** Cada capacidad es uno de los scopes que ya existen en los certs (sin scopes nuevos). */
export const CAP_SCOPE = Object.freeze({ sign: 'vault:sign', store: 'vault:store', read: 'vault:read' })

const enc = (s) => new TextEncoder().encode(s)
const hex = (buf) => [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, '0')).join('')
const isPub = (v) => typeof v === 'string' && v.length > 0
const cleanCaps = (caps) => [...new Set((Array.isArray(caps) ? caps : []).filter((c) => CAPS.includes(c)))].sort()

/** El acta SIN la firma: es lo que se sella y sobre lo que se calcula el hash. */
export function actaBody (acta) {
  const { sig, ...body } = acta || {}
  return body
}

/** Hash del acta (hex de SHA-256 sobre el cuerpo canónico). Es lo que apunta el `prev`. */
export async function actaHash (acta) {
  return hex(await crypto.subtle.digest('SHA-256', enc(canonicalStringify(actaBody(acta)))))
}

/** Id legible de un miembro (mismo formato que el deviceId del emparejamiento). */
export async function memberId (pub) {
  const id = (await pubkeyId(pub)).slice(0, 8).toUpperCase()
  return id.slice(0, 4) + '-' + id.slice(4, 8)
}

/** ¿Esta acta es un traspaso? (la firmó uno y nombra master a otro) */
export const isHandover = (acta) => !!acta && acta.sealer !== acta.sealedBy

/**
 * Acta de génesis: un perfil recién nacido tiene UN miembro (esta llave), que además es el
 * sellador, con todas las capacidades. `profileId` = su pubkey → el nombre del perfil es
 * estable para siempre y coincide con la identidad que el usuario ya tenía (cero migración).
 */
export function genesisActa ({ pub, encPub = null, label = '', now = Date.now() }) {
  if (!isPub(pub)) throw new Error('genesisActa: falta la pubkey de la génesis')
  return {
    v: ACTA_V,
    profileId: pub,
    sealer: pub,
    sealedBy: pub,
    seq: 1,
    prev: null,
    members: [{ pub, encPub, label: String(label || '').slice(0, 60), caps: [...CAPS], addedAt: now, cert: null }],
    revoked: [],
    renounced: [],
    updatedAt: now
  }
}

/** Comprobaciones de FORMA (sin cripto): que el acta sea un acta. */
export function checkShape (acta) {
  if (!acta || typeof acta !== 'object') return 'no-acta'
  if (acta.v !== ACTA_V) return 'version'
  if (!isPub(acta.profileId) || !isPub(acta.sealer) || !isPub(acta.sealedBy)) return 'shape'
  if (!Number.isInteger(acta.seq) || acta.seq < 1) return 'seq'
  if (acta.seq > 1 && typeof acta.prev !== 'string') return 'prev'
  if (!Array.isArray(acta.members) || acta.members.length === 0) return 'members'
  for (const m of acta.members) {
    if (!isPub(m?.pub) || !Array.isArray(m?.caps)) return 'member'
    if (m.caps.some((c) => !CAPS.includes(c))) return 'cap-desconocida'
  }
  if (new Set(acta.members.map((m) => m.pub)).size !== acta.members.length) return 'miembro-duplicado'
  if (!acta.members.some((m) => m.pub === acta.sealer)) return 'sealer-no-es-miembro'
  if (!acta.members.some((m) => m.caps.includes('sign'))) return 'sin-firmante'
  return null
}

/** Sella (firma) un acta. `privateKey` puede ser una CryptoKey no extractable. */
export async function sealActa ({ acta, privateKey, privateJwk }) {
  const shape = checkShape(acta)
  if (shape) throw new Error('acta inválida: ' + shape)
  const { signature } = await signWithDevice({ privateKey, privateJwk, publickey: acta.sealedBy, data: actaBody(acta) })
  return { ...acta, sig: signature }
}

/**
 * Verifica un acta: forma + firma de `sealedBy`. Que ESE firmante estuviera autorizado no se
 * decide aquí sino al adoptarla (`canAdopt`), comparándola con la que ya tienes.
 * @returns {{ok:boolean, reason?:string}}
 */
export async function verifyActa ({ acta, expectedProfileId } = {}) {
  const shape = checkShape(acta)
  if (shape) return { ok: false, reason: shape }
  if (typeof acta.sig !== 'string') return { ok: false, reason: 'sin-firma' }
  if (expectedProfileId != null && acta.profileId !== expectedProfileId) return { ok: false, reason: 'otro-perfil' }
  const ok = await verifyDeviceSig({ publickey: acta.sealedBy, data: actaBody(acta), signature: acta.sig })
  return ok ? { ok: true } : { ok: false, reason: 'firma-invalida' }
}

/**
 * Aplica cambios y devuelve el acta SIGUIENTE, **sin firmar** (hay que `sealActa`).
 * `by` es quien va a sellar: si no es el sellador vigente, se rechaza (regla 1).
 *
 * Cambios: `{op:'admit', member}` · `{op:'caps', pub, caps}` · `{op:'remove', pub}` ·
 * `{op:'handover', to}` · `{op:'revoke', nonce, until}` · `{op:'renounce', record}`.
 * Van en ARRAY porque hay combinaciones que deben ser atómicas: admitir al nuevo sellador y
 * traspasarle el master ocurre en el MISMO `seq` (§2.1.3).
 */
export async function applyChanges (acta, changes, { by, now = Date.now() } = {}) {
  const shape = checkShape(acta)
  if (shape) throw new Error('acta inválida: ' + shape)
  if (!by) throw new Error('applyChanges: falta `by` (quién sella)')
  if (by !== acta.sealer) throw new Error('solo el master puede cambiar el acta; este dispositivo no lo es')

  const list = Array.isArray(changes) ? changes : [changes]
  if (list.length === 0) throw new Error('applyChanges: no hay cambios')

  const next = {
    ...acta,
    sealedBy: by,
    seq: acta.seq + 1,
    prev: await actaHash(acta),
    members: acta.members.map((m) => ({ ...m, caps: [...m.caps] })),
    revoked: [...(acta.revoked || [])],
    renounced: [...(acta.renounced || [])],
    updatedAt: now
  }
  delete next.sig

  const find = (pub) => next.members.find((m) => m.pub === pub)

  for (const ch of list) {
    switch (ch?.op) {
      case 'admit': {
        const m = ch.member
        if (!isPub(m?.pub)) throw new Error('admit: falta la pubkey del miembro')
        if (find(m.pub)) throw new Error('admit: ese miembro ya está en el acta')
        next.members.push({
          pub: m.pub,
          encPub: m.encPub || null,
          label: String(m.label || '').slice(0, 60),
          caps: cleanCaps(m.caps),
          addedAt: now,
          cert: m.cert || null
        })
        break
      }
      case 'caps': {
        const m = find(ch.pub)
        if (!m) throw new Error('caps: ese miembro no está en el acta')
        m.caps = cleanCaps(ch.caps)
        break
      }
      case 'remove': {
        const i = next.members.findIndex((m) => m.pub === ch.pub)
        if (i < 0) throw new Error('remove: ese miembro no está en el acta')
        if (next.members[i].pub === next.sealer) throw new Error('remove: no puedes expulsar al master; primero traspasa el sellado')
        next.members.splice(i, 1)
        break
      }
      case 'handover': {
        if (!find(ch.to)) throw new Error('handover: el nuevo master tiene que ser miembro (admítelo en el mismo cambio)')
        next.sealer = ch.to
        break
      }
      case 'revoke': {
        if (typeof ch.nonce !== 'string') throw new Error('revoke: falta el nonce')
        next.revoked.push({ nonce: ch.nonce, until: ch.until || (now + 30 * 24 * 60 * 60 * 1000) })
        break
      }
      case 'renounce': {
        // Absorbe un registro de renuncia ya verificado (§2.2): solo puede QUITAR.
        const r = ch.record
        const m = find(r?.member)
        if (!m) break // el que renunció ya no está: nada que hacer
        m.caps = m.caps.filter((c) => !(r.caps || []).includes(c))
        next.renounced = next.renounced.filter((x) => x.member !== r.member)
        next.renounced.push(r)
        break
      }
      default:
        throw new Error('cambio desconocido: ' + ch?.op)
    }
  }

  // Poda: las revocaciones vencidas ya no hacen falta (el cert al que apuntan expiró).
  next.revoked = next.revoked.filter((r) => !r.until || r.until > now)

  // Reglas de cierre: sin firmante no se puede operar, y sin sellador no se puede cambiar.
  if (!next.members.some((m) => m.caps.includes('sign'))) {
    throw new Error('el cambio dejaría el perfil sin ningún miembro que pueda firmar')
  }
  if (!next.members.some((m) => m.pub === next.sealer)) {
    throw new Error('el cambio dejaría el acta sin master')
  }
  return next
}

// ----- renuncia (§2.2): el único cambio que no pasa por el master -----

/** Crea el registro firmado con el que un miembro se QUITA capacidades a sí mismo. */
export async function makeRenounce ({ member, caps, privateKey, privateJwk, now = Date.now() }) {
  const body = { op: 'renounce', member, caps: cleanCaps(caps), ts: now }
  if (body.caps.length === 0) throw new Error('renuncia: no hay capacidades que quitar')
  const { signature } = await signWithDevice({ privateKey, privateJwk, publickey: member, data: body })
  return { ...body, sig: signature }
}

/**
 * ¿Es válida esta renuncia? La firma tiene que ser del PROPIO miembro. Como solo puede
 * quitar, cualquiera puede honrarla sin riesgo, sin esperar a que el master la selle.
 */
export async function verifyRenounce (record) {
  if (!record || record.op !== 'renounce' || !isPub(record.member) || typeof record.sig !== 'string') return false
  if (!Array.isArray(record.caps) || record.caps.length === 0) return false
  const { sig, ...body } = record
  return verifyDeviceSig({ publickey: record.member, data: body, signature: sig })
}

/**
 * Capacidad EFECTIVA de un miembro: lo que dice el acta menos lo que haya renunciado.
 * `extraRenounces` son renuncias sueltas ya verificadas que todavía no absorbió el master.
 */
export function effectiveCaps (acta, pub, extraRenounces = []) {
  const m = (acta?.members || []).find((x) => x.pub === pub)
  if (!m) return []
  const quitadas = new Set()
  for (const r of [...(acta.renounced || []), ...extraRenounces]) {
    if (r?.member === pub) for (const c of (r.caps || [])) quitadas.add(c)
  }
  return m.caps.filter((c) => !quitadas.has(c))
}

/** ¿Puede este miembro hacer `cap` según el acta? (con el cert se cruza aparte: cert ∩ acta). */
export function memberCan (acta, pub, cap, extraRenounces = []) {
  return effectiveCaps(acta, pub, extraRenounces).includes(cap)
}

// ----- adopción y empates (§2.4.1) -----

/**
 * ¿Adopto `candidate` en lugar de `current`?
 *
 *   · `seq` mayor y contigua → sí, si encadena (`prev` = hash de la mía) y la firmó quien
 *     era master en la mía (`sealedBy === current.sealer`).
 *   · `seq` mayor con HUECO (estuve apagado) → solo si la firmó el master que conozco; si
 *     hubo un traspaso durante el hueco no puedo comprobarlo y toca re-admitirse (§1.3).
 *   · MISMO `seq` → gana la que TRASPASA. Es el caso del master obsoleto: un vault restaurado
 *     de un respaldo anterior al traspaso sella su propio `seq` creyéndose master, pero el
 *     acta del traspaso la firmó él mismo y esa firma prueba su degradación. Si las dos
 *     traspasan a destinos distintos (master mintiendo), desempata el hash menor —
 *     determinista, y nada salva de un master hostil.
 *   · `seq` menor → nunca (jamás retroceder).
 *
 * @returns {Promise<{adopt:boolean, reason:string}>}
 */
export async function canAdopt ({ candidate, current }) {
  const v = await verifyActa({ acta: candidate, expectedProfileId: current?.profileId })
  if (!v.ok) return { adopt: false, reason: v.reason }
  if (!current) return { adopt: true, reason: 'sin-acta-previa' }

  if (candidate.seq > current.seq) {
    if (candidate.sealedBy !== current.sealer) return { adopt: false, reason: 'sellador-no-autorizado' }
    if (candidate.seq === current.seq + 1 && candidate.prev !== await actaHash(current)) {
      return { adopt: false, reason: 'no-encadena' }
    }
    return { adopt: true, reason: 'seq-mayor' }
  }

  if (candidate.seq === current.seq) {
    const [hCan, hCur] = [await actaHash(candidate), await actaHash(current)]
    if (hCan === hCur) return { adopt: false, reason: 'misma-acta' }
    if (candidate.sealedBy !== current.sealedBy) return { adopt: false, reason: 'otro-sellador' }
    const canT = isHandover(candidate)
    const curT = isHandover(current)
    if (canT && !curT) return { adopt: true, reason: 'traspaso-gana' }
    if (!canT && curT) return { adopt: false, reason: 'traspaso-gana' }
    return hCan < hCur ? { adopt: true, reason: 'desempate-hash' } : { adopt: false, reason: 'desempate-hash' }
  }

  return { adopt: false, reason: 'seq-menor' }
}

export default {
  ACTA_V, CAPS, CAP_SCOPE, genesisActa, actaBody, actaHash, memberId, checkShape, isHandover,
  sealActa, verifyActa, applyChanges, makeRenounce, verifyRenounce,
  effectiveCaps, memberCan, canAdopt
}
