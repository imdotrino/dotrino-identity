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

/**
 * Lista CERRADA de capacidades. Sellar y admitir no están: eso es ser el master.
 *
 * `secrets` es distinta de las otras: solo la pueden tener los miembros con **CN**
 * (los servicios), y lo que abre es únicamente el cajón de SU nombre. Ver `cn` abajo.
 *
 * `admin` es la rendija que se le abre a la consola remota (`dotrino-vault/docs/
 * consola-remota.md`): deja **admitir y expulsar** miembros a distancia, y nada más.
 * NO deja cambiar permisos, traspasar el mando ni conceder `admin` — eso sigue siendo
 * el rol de master, que no se delega. Así un dispositivo con `admin` robado hace daño
 * acotado y **reversible** (se le revoca), en vez de poder dejarte fuera de tu cuenta.
 */
export const CAPS = Object.freeze(['sign', 'store', 'read', 'secrets', 'admin'])

/** Capacidades de un DISPOSITIVO (sin CN): acceso a todo lo del usuario. */
export const DEVICE_CAPS = Object.freeze(['sign', 'store', 'read', 'admin'])

/**
 * Lo que recibe un dispositivo recién emparejado. `admin` **no está**: no se
 * empareja, se concede después y a mano (`dotrino-vault caps <ID> +admin`), para que
 * ningún QR que circule pueda otorgar administración.
 */
export const PAIRED_CAPS = Object.freeze(['sign', 'store', 'read'])

/** Capacidades de un SERVICIO (con CN): solo su propio cajón de secretos. */
export const SERVICE_CAPS = Object.freeze(['secrets'])

/** Un CN válido: minúsculas, números y guiones (igual que el namespace de secretos). */
export const isValidCn = (cn) => typeof cn === 'string' && /^[a-z0-9-]{1,32}$/.test(cn)

/**
 * Scope del cert que corresponde a cada capacidad. `secrets` necesita el CN para
 * completarse: el miembro `proxy` obtiene `vault:secrets:proxy` y nada más — no existe un
 * scope de secretos «de todos».
 */
export function capScope (cap, cn = null) {
  if (cap === 'sign') return 'vault:sign'
  if (cap === 'store') return 'vault:store'
  if (cap === 'read') return 'vault:read'
  if (cap === 'admin') return 'vault:admin'
  if (cap === 'secrets') return isValidCn(cn) ? 'vault:secrets:' + cn : null
  return null
}

/** Compat: el mapa directo, para las capacidades de dispositivo. */
export const CAP_SCOPE = Object.freeze({ sign: 'vault:sign', store: 'vault:store', read: 'vault:read', admin: 'vault:admin' })

const enc = (s) => new TextEncoder().encode(s)
const hex = (buf) => [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, '0')).join('')
const isPub = (v) => typeof v === 'string' && v.length > 0
const cleanCaps = (caps) => [...new Set((Array.isArray(caps) ? caps : []).filter((c) => CAPS.includes(c)))].sort()

/**
 * El acta SIN la firma ni la tarjeta: es lo que se sella y sobre lo que se calcula el hash.
 * La `card` va aparte porque lleva su propia firma y se comparte sola (ver `makeProfileCard`).
 */
export function actaBody (acta) {
  const { sig, card, ...body } = acta || {}
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
  if (!isPub(pub)) throw new Error('genesisActa: missing genesis pubkey')
  return {
    v: ACTA_V,
    profileId: pub,
    sealer: pub,
    sealedBy: pub,
    seq: 1,
    prev: null,
    members: [{ pub, encPub, label: String(label || '').slice(0, 60), cn: null, caps: [...PAIRED_CAPS], addedAt: now, cert: null }],
    revoked: [],
    renounced: [],
    // Llavero del contenido: una entrada por generación, con la clave del perfil ENVUELTA
    // a cada miembro (ver content.js). Envuelto es público: solo lo abre su destinatario.
    keyring: [],
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
    // El CN es la frontera: un SERVICIO solo puede abrir su propio cajón, y un
    // DISPOSITIVO no tiene cajón que abrir. Que no se pueda escribir un acta que
    // mezcle las dos cosas es lo que hace que el límite sea real y no una costumbre.
    if (m.cn != null) {
      if (!isValidCn(m.cn)) return 'cn-invalido'
      if (m.caps.some((c) => !SERVICE_CAPS.includes(c))) return 'servicio-con-capacidades-de-dispositivo'
    } else if (m.caps.includes('secrets')) {
      return 'secretos-sin-cn'
    }
  }
  if (new Set(acta.members.map((m) => m.pub)).size !== acta.members.length) return 'miembro-duplicado'
  if (!acta.members.some((m) => m.pub === acta.sealer)) return 'sealer-no-es-miembro'
  if (!acta.members.some((m) => m.caps.includes('sign'))) return 'sin-firmante'
  return null
}

/** Sella (firma) un acta. `privateKey` puede ser una CryptoKey no extractable. */
export async function sealActa ({ acta, privateKey, privateJwk }) {
  const shape = checkShape(acta)
  if (shape) throw new Error('invalid record: ' + shape)
  const { signature } = await signWithDevice({ privateKey, privateJwk, publickey: acta.sealedBy, data: actaBody(acta) })
  const sealed = { ...acta, sig: signature }
  // La TARJETA se firma en el mismo gesto y viaja con el acta: así cualquier miembro puede
  // entregársela a un contacto sin ser el master y sin contarle nada de más.
  sealed.card = await makeProfileCard({ acta: sealed, privateKey, privateJwk })
  return sealed
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
  if (shape) throw new Error('invalid record: ' + shape)
  if (!by) throw new Error('applyChanges: missing `by` (who seals)')
  if (by !== acta.sealer) throw new Error('only the master can change the record; this device is not the master')

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
    keyring: (acta.keyring || []).map((g) => ({ ...g, wraps: { ...g.wraps } })),
    updatedAt: now
  }
  delete next.sig

  const find = (pub) => next.members.find((m) => m.pub === pub)

  for (const ch of list) {
    switch (ch?.op) {
      case 'admit': {
        const m = ch.member
        if (!isPub(m?.pub)) throw new Error('admit: falta la pubkey del miembro')
        if (find(m.pub)) throw new Error('admit: that member is already in the record')
        const cn = m.cn != null ? String(m.cn) : null
        if (cn !== null && !isValidCn(cn)) throw new Error('admit: invalid CN (lowercase, digits and hyphens)')
        next.members.push({
          pub: m.pub,
          encPub: m.encPub || null,
          label: String(m.label || '').slice(0, 60),
          cn,
          // Un servicio (con CN) solo puede tener `secrets`; un dispositivo, las otras tres.
          caps: cleanCaps(m.caps).filter((c) => (cn ? SERVICE_CAPS : DEVICE_CAPS).includes(c)),
          addedAt: now,
          cert: m.cert || null,
          // Puente con la identidad que este miembro traía de antes (ver makeContinuity).
          ...(m.continuity ? { continuity: m.continuity } : {})
        })
        break
      }
      case 'caps': {
        const m = find(ch.pub)
        if (!m) throw new Error('caps: that member is not in the record')
        // No se puede ascender un servicio a dispositivo cambiándole las capacidades: para
        // eso hay que sacarlo y volver a admitirlo, que es un gesto visible.
        m.caps = cleanCaps(ch.caps).filter((c) => (m.cn ? SERVICE_CAPS : DEVICE_CAPS).includes(c))
        // CONCEDER LIMPIA LA RENUNCIA. `effectiveCaps` resta lo renunciado, así que sin
        // esto una renuncia sellada era IRREVERSIBLE: el master le devolvía el permiso en
        // `caps` y la resta seguía dejándolo fuera, para siempre. La interfaz promete
        // «puedes devolvérselo desde el Master», así que tiene que ser verdad.
        // Se tira el registro entero y no se le recortan capacidades: va FIRMADO por el
        // miembro, y editarlo lo dejaría sin firma válida.
        const renunciadas = new Set()
        for (const r of next.renounced) if (r.member === m.pub) for (const c of (r.caps || [])) renunciadas.add(c)
        if (m.caps.some((c) => renunciadas.has(c))) next.renounced = next.renounced.filter((r) => r.member !== m.pub)
        break
      }
      case 'label': {
        // RENOMBRAR un miembro. La etiqueta se escribía solo al admitir, con lo que el
        // aparato se quedaba para siempre con el nombre que tuviera el día que entró
        // (normalmente el apodo del usuario en ese momento), y para cambiarlo había que
        // revocarlo y volver a emparejarlo. Es un nombre para el humano: no toca permisos
        // ni llaves, pero se sella y se firma como cualquier otro cambio del acta.
        const m = find(ch.pub)
        if (!m) throw new Error('label: that member is not in the record')
        m.label = String(ch.label || '').slice(0, 60)
        break
      }
      case 'remove': {
        const i = next.members.findIndex((m) => m.pub === ch.pub)
        if (i < 0) throw new Error('remove: that member is not in the record')
        if (next.members[i].pub === next.sealer) throw new Error('remove: cannot remove the master; hand the sealing over first')
        const fuera = next.members.splice(i, 1)[0]
        // Sus envolturas se van con él: sin ellas no puede abrir ninguna generación. (El
        // acceso al contenido FUTURO se corta rotando, ver content.js; lo ya leído no vuelve.)
        next.keyring = next.keyring.map((g) => {
          const { [fuera.pub]: _, ...resto } = g.wraps || {}
          return { ...g, wraps: resto }
        })
        break
      }
      case 'handover': {
        if (!find(ch.to)) throw new Error('handover: the new master must be a member (admit them in the same change)')
        next.sealer = ch.to
        break
      }
      case 'keyring': {
        // Generación NUEVA de la clave de contenido (al rotar: expulsar a alguien).
        const g = ch.generation
        if (!g || !Number.isInteger(g.gen)) throw new Error('keyring: invalid generation')
        next.keyring = [...next.keyring.filter((x) => x.gen !== g.gen), g].sort((a, b) => a.gen - b.gen)
        break
      }
      case 'wrap': {
        // Envolver la clave YA existente para un miembro nuevo (al admitir: no hace falta rotar).
        const g = next.keyring.find((x) => x.gen === ch.gen)
        if (!g) throw new Error('wrap: that generation is not in the keyring')
        g.wraps = { ...g.wraps, [ch.pub]: ch.wrap }
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
    throw new Error('the change would leave the profile with no member able to sign')
  }
  if (!next.members.some((m) => m.pub === next.sealer)) {
    throw new Error('the change would leave the record with no master')
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

/**
 * ¿Puede este miembro leer el cajón de secretos `ns`? Solo si su CN es exactamente ése.
 * Es la frontera que pediste: la llave del proxy no ve nada más que lo del proxy.
 */
export function memberCanReadSecrets (acta, pub, ns) {
  const m = (acta?.members || []).find((x) => x.pub === pub)
  if (!m || !m.cn) return false
  return m.cn === ns && effectiveCaps(acta, pub).includes('secrets')
}

/** Los scopes de cert que le corresponden a un miembro según el acta. */
export function memberScopes (acta, pub, extraRenounces = []) {
  const m = (acta?.members || []).find((x) => x.pub === pub)
  if (!m) return []
  return effectiveCaps(acta, pub, extraRenounces).map((c) => capScope(c, m.cn)).filter(Boolean)
}

/** ¿Es un servicio (tiene CN) o un dispositivo del usuario? */
export const isService = (acta, pub) => !!(acta?.members || []).find((x) => x.pub === pub)?.cn

/** ¿Puede este miembro hacer `cap` según el acta? (con el cert se cruza aparte: cert ∩ acta). */
export function memberCan (acta, pub, cap, extraRenounces = []) {
  return effectiveCaps(acta, pub, extraRenounces).includes(cap)
}

// ----- TARJETA DE PERFIL: lo mínimo que se comparte con otra persona -----

/**
 * Para escribirle a alguien cifrado hay que conocer las llaves de CIFRADO de todos sus
 * dispositivos — si no, el mensaje solo lo abre el aparato desde el que hablaste. Pero
 * pasarle el ACTA a un contacto le contaría de más: cuántos dispositivos tienes, cómo se
 * llaman y qué puede cada uno. Nada de eso es asunto suyo.
 *
 * Así que se comparte una TARJETA: el mínimo imprescindible —el perfil, su versión y las
 * llaves— firmada por el master, y por lo tanto verificable sin tener el acta. Sin
 * etiquetas, sin permisos, sin certificados.
 *
 * La firma el MASTER al sellar, y viaja con el acta, para que cualquier miembro pueda
 * entregarla aunque no sea él quien manda.
 */
export function cardBody (acta) {
  return {
    v: 1,
    profileId: acta.profileId,
    seq: acta.seq,
    sealedBy: acta.sealedBy,
    // Solo las llaves. Los servicios (con CN) NO van: no son la persona, y no tienen por
    // qué recibir los mensajes de nadie.
    keys: acta.members
      .filter((m) => !m.cn && m.encPub)
      .map((m) => ({ pub: m.pub, encPub: m.encPub }))
      .sort((a, b) => (a.pub < b.pub ? -1 : 1)),
    iat: acta.updatedAt
  }
}

/** Firma la tarjeta de este acta (lo hace el master al sellar). */
export async function makeProfileCard ({ acta, privateKey, privateJwk }) {
  const body = cardBody(acta)
  const { signature } = await signWithDevice({ privateKey, privateJwk, publickey: acta.sealedBy, data: body })
  return { ...body, sig: signature }
}

/** Verifica que la tarjeta la firmó quien dice (`sealedBy`). Que ÉSE sea el master de esa
 * persona se decide al adoptarla, comparándola con la que ya tenías (`canAdoptCard`). */
export async function verifyProfileCard (card) {
  if (!card || card.v !== 1 || !isPub(card.profileId) || !isPub(card.sealedBy)) return false
  if (!Number.isInteger(card.seq) || !Array.isArray(card.keys) || typeof card.sig !== 'string') return false
  const { sig, ...body } = card
  return verifyDeviceSig({ publickey: card.sealedBy, data: body, signature: sig })
}

/**
 * ¿Me quedo con esta tarjeta en vez de la que tenía de esa persona?
 *   · la primera vez, sí (confías en el contacto que agregaste: es el mismo criterio
 *     que ya usas al añadirlo);
 *   · después, solo si el `seq` es mayor o igual Y la firmó el mismo master que la
 *     anterior — así nadie te cuela dispositivos ajenos en el perfil de tu contacto,
 *     y nunca se retrocede a una versión vieja.
 * Si el master cambió legítimamente (traspaso), la tarjeta nueva la firma el entrante y
 * hay que re-confirmarla: se devuelve `master-cambiado` para que la app lo diga en vez de
 * aceptarlo en silencio.
 */
export async function canAdoptCard ({ card, current }) {
  if (!(await verifyProfileCard(card))) return { adopt: false, reason: 'firma-invalida' }
  if (current && current.profileId !== card.profileId) return { adopt: false, reason: 'otro-perfil' }
  if (!current) return { adopt: true, reason: 'primera-vez' }
  if (card.seq < current.seq) return { adopt: false, reason: 'seq-menor' }
  if (card.sealedBy !== current.sealedBy) return { adopt: false, reason: 'master-cambiado' }
  return { adopt: true, reason: card.seq > current.seq ? 'seq-mayor' : 'igual' }
}

// ----- continuidad: unir una identidad que ya existía -----

/**
 * CERTIFICADO DE CONTINUIDAD. Cuando una identidad que ya existía entra en otro perfil,
 * firma —con su propia llave— que a partir de ahora es miembro de él. Sirve de puente:
 * lo que hizo antes (su reputación, lo que firmó, quien la tenía de contacto) se puede
 * seguir atribuyendo a la misma persona en vez de quedar huérfano.
 *
 * No otorga nada por sí solo: es una declaración del que se une, y solo tiene efecto
 * dentro del acta donde el master la mete.
 */
export async function makeContinuity ({ member, from, privateKey, privateJwk, now = Date.now() }) {
  const body = { op: 'continuity', member, from: from || member, ts: now }
  const { signature } = await signWithDevice({ privateKey, privateJwk, publickey: member, data: body })
  return { ...body, sig: signature }
}

/** ¿La firmó de verdad la identidad que dice venir? (única comprobación posible). */
export async function verifyContinuity (record) {
  if (!record || record.op !== 'continuity' || !isPub(record.member) || typeof record.sig !== 'string') return false
  const { sig, ...body } = record
  return verifyDeviceSig({ publickey: record.member, data: body, signature: sig })
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
  makeContinuity, verifyContinuity,
  cardBody, makeProfileCard, verifyProfileCard, canAdoptCard,
  effectiveCaps, memberCan, memberCanReadSecrets, memberScopes, isService, capScope, isValidCn, canAdopt
}
