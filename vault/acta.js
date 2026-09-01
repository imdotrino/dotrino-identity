/**
 * acta.js — el ACTA DE PERFIL: qué llaves son del mismo perfil y qué puede hacer cada una.
 *
 * Un perfil no es una llave: es un CONJUNTO de llaves miembro, ligadas por certificados,
 * más una política firmada. Ninguna llave privada viaja nunca; lo que se mueve es el acta.
 * Diseño completo y decisiones en `dotrino-vault/docs/acta-de-perfil.md`.
 *
 * Las cuatro reglas que este módulo hace cumplir:
 *   1. **Solo sella quien el acta nombra.** Normalmente uno —`sealer`, el master—, y
 *      entonces dos actas legítimas con el mismo `seq` son imposibles: no hay
 *      bifurcaciones que resolver.
 *      **MULTIVAULT** (dueño, 2026-08-30): se pueden nombrar selladores adicionales en
 *      `cosealers`, para que perder una bóveda no se lleve la cuenta por delante. Ahí la
 *      imposibilidad pasa de criptográfica a práctica —«no suelen estar las dos abiertas
 *      a la vez»—, así que el empate deja de ser imposible y pasa a ser raro. Lo resuelve
 *      `canAdopt` con las reglas que ya existían: gana el traspaso, y si no, la de hash
 *      menor. Determinista, sin relojes y sin votación. Lo que NO resuelve: el que pierde
 *      el desempate **pierde su cambio**, y quien lo selló tiene que enterarse (§2.4.1.5).
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

export const ACTA_V = 5

/**
 * Versiones de acta que se ACEPTAN al leer. La 1 sigue entrando porque una v1 en el disco
 * es un perfil con sus aparatos dentro: rechazarla dejaría al vault sin poder verificar a
 * nadie —y a los servicios sin configuración— por un campo que ni siquiera existía. Se
 * asciende sola: el acta siguiente que selle la maestra ya sale v2 (ver `applyChanges`).
 * La única diferencia es la llave de sellado (§8.9), que en una v1 simplemente no hay.
 */
/**
 * v3 quita `acta.sealer` (dueño, 2026-08-31: «SEAL es el nuevo master»): sellar es un
 * permiso y nada más.
 *
 * Las anteriores SE SIGUEN LEYENDO, y no por nostalgia: dejar de hacerlo dejaría sin abrir
 * TODAS las cuentas que existen hoy —cada una tendría que rehacerse aparato por aparato—
 * cuando lo único que hace falta es traducir el campo a un permiso al leerlas. Un acta
 * vieja no se puede reescribir (está firmada), así que se lee tal cual y `canSeal` la
 * entiende; la PRIMERA vez que esa cuenta cambie algo, la nueva sale ya en v3 y el campo
 * desaparece solo.
 */
// v5 mete DENTRO del acta el eslabón publicable de la cadena de selladores, firmado
// aparte (ver `sealerLinkOf`): así se publica solo eso y no el acta entera, que llevaba
// los aparatos con sus nombres. Una v4 se sigue leyendo, pero no tiene eslabón y por tanto
// no puede publicar: su cuenta no aparece en el registro hasta que selle una v5 nueva.
const ACTA_LEIBLES = Object.freeze([1, 2, 3, 4, 5])
/** Desde esta versión, el acta lleva su eslabón de la cadena de selladores. */
const V_CON_CADENA = 4
/** ¿Esta acta lleva el eslabón? Las anteriores se leen igual; no pueden encadenar. */
const conCadena = (acta) => Number(acta?.v) >= V_CON_CADENA
/**
 * Solo `https`, y sin excepción para localhost: esta dirección la va a abrir un TERCERO
 * que no te conoce, y mandarlo por texto plano es dejar que cualquiera en el camino le
 * conteste otra cosa. Que no lleve `#` ni credenciales: no es un enlace para una persona.
 */
const isChainUrl = (u) => {
  if (typeof u !== 'string' || u.length > 300) return false
  try {
    const x = new URL(u)
    return x.protocol === 'https:' && !x.hash && !x.username && !x.password
  } catch (_) { return false }
}
/** Desde esta versión, sellar es solo un permiso y no hay campo `sealer`. */
const V_SIN_CAMPO_SELLADOR = 3
/** ¿Este acta es de las viejas, con el campo? */
const conCampoSellador = (acta) => Number(acta?.v) < V_SIN_CAMPO_SELLADOR

/**
 * Lista CERRADA de capacidades.
 *
 * `sealer` es SELLAR EL ACTA, y desde 2026-08-30 es un permiso como los demás — se da y se
 * quita con `caps <ID> +sella`. Antes no existía: sellar era «ser el master», y punto. Se
 * abrió para el **multivault**: que una segunda bóveda pueda sellar hace que perder una
 * máquina no se lleve la cuenta por delante. Cuidado con no confundirlo con el CAMPO
 * `acta.sealer`, que es otra cosa: el campo dice **quién manda** (y solo cambia en un
 * traspaso); el permiso dice **quién puede firmar el acta**. Admitir sigue sin ser un
 * permiso: se admite sellando.
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
export const CAPS = Object.freeze(['sign', 'store', 'read', 'secrets', 'admin', 'approve', 'passwords', 'sealer', 'unattended'])

/** Capacidades de un DISPOSITIVO (sin CN): acceso a todo lo del usuario. */
/**
 * `approve` es el aparato que APRUEBA: cuando un cajón exige aprobación por uso, el
 * vault le avisa y solo su firma libera los secretos (normalmente el teléfono). Como
 * `admin`, no viaja en un QR: se concede a mano (`dotrino-vault caps <ID> +approve`).
 *
 * `passwords` es el aparato que puede PEDIR CREDENCIALES de la bóveda de contraseñas
 * (el gestor: la extensión del navegador, la app del teléfono). Pide de a una y por
 * dominio; nunca lista la bóveda. Va aquí y no en una lista aparte porque quién puede
 * pedirle algo a la bóveda es exactamente lo que decide el acta — tener dos registros
 * de lo mismo obliga a acordarse de los dos al quitar un aparato.
 *
 * `unattended` es RECIBIR CLAVES PRIVADAS SIN QUE NADIE APRUEBE. Sin él, la bóveda no
 * entrega nada hasta que un aparato con `approve` lo firme — una vez por arranque del
 * servicio, no por petición.
 *
 * El defecto es al revés que antes, y esa es la gracia (dueño, 2026-09-01): antes había
 * que marcar a mano quién NECESITA aprobación, así que un aparato nuevo nacía pudiendo
 * llevarse las claves y nadie se enteraba de que esa era la elección. Ahora hay que
 * conceder a propósito quién puede llevárselas SOLO — y si el dato falta, se pide permiso,
 * que es lo que hay que hacer cuando no se sabe.
 *
 * Y va EN EL ACTA, no en una marca local de una máquina: así lo respeta cualquier bóveda
 * de la cuenta, se ve en la pantalla de permisos como los demás, y se quita quitándolo —
 * sin acordarse de un segundo registro escondido.
 */
export const DEVICE_CAPS = Object.freeze(['sign', 'store', 'read', 'admin', 'approve', 'passwords', 'sealer', 'unattended'])

/**
 * Lo que recibe un dispositivo recién emparejado. `admin` **no está**: no se
 * empareja, se concede después y a mano (`dotrino-vault caps <ID> +admin`), para que
 * ningún QR que circule pueda otorgar administración.
 */
export const PAIRED_CAPS = Object.freeze(['sign', 'store', 'read'])

/** Capacidades de un SERVICIO (con CN): solo su propio cajón de secretos. */
export const SERVICE_CAPS = Object.freeze(['secrets'])

/**
 * Qué capacidades puede llevar un miembro según tenga cajón (CN) o no. Con CN: su cajón
 * y, si se le conceden, las de aparato. Sin CN: solo las de aparato (no hay cajón que abrir).
 */
export const allowedCaps = (cn) => (cn ? [...SERVICE_CAPS, ...DEVICE_CAPS] : [...DEVICE_CAPS])

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
  if (cap === 'approve') return 'vault:approve'
  if (cap === 'passwords') return 'vault:passwords'
  if (cap === 'sealer') return 'vault:sealer'
  if (cap === 'secrets') return isValidCn(cn) ? 'vault:secrets:' + cn : null
  return null
}

/** Compat: el mapa directo, para las capacidades de dispositivo. */
export const CAP_SCOPE = Object.freeze({ sign: 'vault:sign', store: 'vault:store', read: 'vault:read', admin: 'vault:admin', approve: 'vault:approve', passwords: 'vault:passwords', sealer: 'vault:sealer' })

const enc = (s) => new TextEncoder().encode(s)
const hex = (buf) => [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, '0')).join('')
const isPub = (v) => typeof v === 'string' && v.length > 0

/**
 * La llave de CIFRADO de un miembro (`encPub`): JWK público de una ECDH P-256.
 * Se valida de verdad —no basta con «es un string»— porque es lo que decide si a
 * ese aparato se le puede envolver un secreto: una `encPub` mal formada no falla al
 * escribir el acta, falla mucho después al intentar sellarle algo.
 */
const isEncPub = (v) => {
  if (typeof v !== 'string' || !v) return false
  try {
    const j = JSON.parse(v)
    return j?.kty === 'EC' && j?.crv === 'P-256' && typeof j?.x === 'string' && typeof j?.y === 'string'
  } catch (_) { return false }
}
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

/**
 * EL ESLABÓN DE LA CADENA DE SELLADORES: lo ÚNICO que se publica.
 *
 * El problema que resuelve (dueño, 2026-08-31). Publicar «los eslabones donde cambia quién
 * sella» sonaba a publicar poco, pero un eslabón ERA un acta entera: se fue a un repo
 * público con los `label` y los `cn` de cada aparato y el llavero. Recortar el acta no
 * vale, porque su firma cubre el acta entera y dejaría de verificar.
 *
 * La salida es del dueño y es mejor que tener dos documentos que puedan discrepar: se
 * construye el eslabón, **se firma**, se mete en el acta, y **se firma el acta encima**.
 * Resultado: uno solo, firmado dos veces.
 *
 *   · quien tiene el acta la verifica y con eso el eslabón de dentro queda validado —
 *     no hay nada aparte en lo que confiar;
 *   · quien solo tiene el registro verifica la firma del eslabón, que es de la misma
 *     llave y dice lo mismo. Discrepar es imposible por construcción.
 *
 * ENCADENA CONTRA EL ESLABÓN ANTERIOR, no contra el acta anterior. El `sealerAnchor` del
 * acta apunta al hash del ACTA previa, y quien solo lee el registro no la tiene ni puede
 * calcularla — la cadena publicada tiene que sostenerse sola.
 *
 * Lo que lleva es lo mínimo para responder «¿esta llave sigue pudiendo sellar?»: nada de
 * miembros, ni etiquetas, ni cajones, ni llavero.
 */
export const SEALER_LINK_V = 1

/** El cuerpo firmable del eslabón (todo menos su propia firma). */
export const sealerLinkBody = (link) => { const { sig, ...body } = link || {}; return body }

/** Hash del eslabón. Es a esto a lo que apunta el `prev` del siguiente. */
export async function sealerLinkHash (link) {
  return hex(await crypto.subtle.digest('SHA-256', enc(canonicalStringify(sealerLinkBody(link)))))
}

/** El eslabón que hay que publicar de esta acta, o `null` si no cambió el sellador. */
export const sealerLinkOf = (acta) => (acta?.sealerChanged && acta?.sealerLink) || null

/**
 * ¿Es este eslabón coherente con el acta que lo lleva? Es lo que hace verdad la frase «ya
 * está validado dentro del acta»: la firma del acta cubre el eslabón, pero eso solo prueba
 * que está ahí — que DIGA lo mismo que el acta hay que comprobarlo.
 */
export function checkSealerLink (acta) {
  const l = acta?.sealerLink
  if (!l) return acta?.sealerChanged && acta?.v >= 5 ? 'eslabon-ausente' : null
  if (l.v !== SEALER_LINK_V) return 'eslabon-version'
  if (typeof l.sig !== 'string') return 'eslabon-sin-firma'
  if (l.profileId !== acta.profileId) return 'eslabon-otro-perfil'
  // EL ACTA VIGENTE ARRASTRA EL ÚLTIMO ESLABÓN, que casi nunca es de ella: los selladores
  // cambian poquísimo y las actas cambian con cada emparejamiento. Así que solo cuando
  // ESTA acta es el eslabón se le exige que coincida en `seq` y en quién lo firmó; si lo
  // hereda, basta con que venga de antes.
  if (acta.sealerChanged) {
    if (l.seq !== acta.seq) return 'eslabon-otro-seq'
    if (l.by !== acta.sealedBy) return 'eslabon-otro-sellador'
  } else if (!(l.seq < acta.seq)) {
    return 'eslabon-del-futuro'
  }
  // Y en los dos casos tiene que DECIR LO MISMO que el acta sobre quién sella: si no
  // cambiaron, el heredado los sigue describiendo. Esto es lo que impide que el acta y su
  // eslabón cuenten cosas distintas — que es todo el punto de meterlo dentro.
  const dice = [...(l.sealers || [])].slice().sort().join('|')
  const segunElActa = sealersOf(acta).slice().sort().join('|')
  if (dice !== segunElActa) return 'eslabon-no-cuadra'
  return null
}

/** Firma del eslabón por quien sella. Se hace ANTES de firmar el acta que lo lleva. */
export async function verifySealerLink (link) {
  if (!link || link.v !== SEALER_LINK_V) return { ok: false, reason: 'eslabon-version' }
  if (!isPub(link.profileId) || !isPub(link.by)) return { ok: false, reason: 'eslabon-forma' }
  if (!Array.isArray(link.sealers) || !link.sealers.length || !link.sealers.every(isPub)) return { ok: false, reason: 'eslabon-selladores' }
  if (typeof link.seq !== 'number' || link.seq < 1) return { ok: false, reason: 'eslabon-seq' }
  if (typeof link.sig !== 'string') return { ok: false, reason: 'eslabon-sin-firma' }
  const ok = await verifyDeviceSig({ publickey: link.by, data: sealerLinkBody(link), signature: link.sig })
  return ok ? { ok: true } : { ok: false, reason: 'eslabon-firma-invalida' }
}

/**
 * VERIFICA LA CADENA PUBLICADA — la que vive en el registro, sin actas de por medio.
 *
 * Es la hermana de `verifySealerChain`, que hace lo mismo con actas enteras para quien las
 * tiene. Lo que comprueba, y por qué basta:
 *   1. el primero es el GÉNESIS: `seq 1`, sin `prev`, y firmado por `profileId` — el ancla,
 *      que no se puede fabricar sin la llave que da nombre al perfil;
 *   2. cada siguiente lo firmó alguien a quien el ANTERIOR autorizaba;
 *   3. y apunta al anterior por `seq` + hash, así que no se cuela uno de otra rama.
 *
 * Lo que NO resuelve, y no lo esconde: la frescura. Quien guardó una cadena vieja sigue
 * aceptando a un sellador retirado; para eso está mirar el registro, no más firmas.
 */
export async function verifySealerLinkChain (chain, { expectedProfileId = null } = {}) {
  if (!Array.isArray(chain) || !chain.length) return { ok: false, reason: 'cadena-vacia' }
  const [raiz] = chain
  if (raiz?.seq !== 1 || raiz?.prev != null) return { ok: false, reason: 'no-empieza-en-genesis' }
  if (raiz.by !== raiz.profileId) return { ok: false, reason: 'genesis-no-autofirmado' }
  if (expectedProfileId != null && raiz.profileId !== expectedProfileId) return { ok: false, reason: 'otro-perfil' }
  const vr = await verifySealerLink(raiz)
  if (!vr.ok) return { ok: false, reason: 'genesis:' + vr.reason }

  for (let i = 1; i < chain.length; i++) {
    const previo = chain[i - 1]
    const actual = chain[i]
    if (actual?.profileId !== raiz.profileId) return { ok: false, reason: `eslabon-${i}:otro-perfil` }
    if (!(actual.seq > previo.seq)) return { ok: false, reason: `eslabon-${i}:seq-no-crece` }
    const v = await verifySealerLink(actual)
    if (!v.ok) return { ok: false, reason: `eslabon-${i}:` + v.reason }
    const a = actual.prev
    if (!a || a.seq !== previo.seq || a.hash !== await sealerLinkHash(previo)) {
      return { ok: false, reason: `eslabon-${i}:no-encadena` }
    }
    // Y lo que da la autoridad: quien lo firmó podía sellar SEGÚN EL ESLABÓN ANTERIOR.
    if (!previo.sealers.includes(actual.by)) return { ok: false, reason: `eslabon-${i}:sellador-no-autorizado` }
  }
  const ultimo = chain[chain.length - 1]
  return { ok: true, profileId: raiz.profileId, seq: ultimo.seq, sealers: [...ultimo.sealers] }
}

/** Id legible de un miembro (mismo formato que el deviceId del emparejamiento). */
export async function memberId (pub) {
  const id = (await pubkeyId(pub)).slice(0, 8).toUpperCase()
  return id.slice(0, 4) + '-' + id.slice(4, 8)
}

/** ¿Esta acta es un traspaso? (la firmó uno y nombra master a otro) */
/**
 * QUIÉNES PUEDEN SELLAR ESTA ACTA: quien manda (`sealer`) más todo miembro con el permiso
 * `sealer`. Normalmente solo el primero, y entonces dos actas legítimas con el mismo `seq`
 * son imposibles (D4) — de ahí salía «no hay merge, ni precedencia, ni votación».
 *
 * **MULTIVAULT** (dueño, 2026-08-30): dándole el permiso a otra bóveda, perder una máquina
 * deja de llevarse la cuenta. El precio es que la imposibilidad baja de criptográfica a
 * práctica —«no suelen estar las dos abiertas a la vez»—, así que el empate ya no es
 * imposible: es raro. Lo resuelve `canAdopt` con las reglas que ya existían: gana el
 * traspaso, y si no, la de hash menor. Determinista, sin relojes y sin votación. Lo que NO
 * resuelve: el que pierde el desempate **pierde su cambio**, y quien selló tiene que
 * enterarse (§2.4.1 punto 5).
 *
 * Es un PERMISO y no un campo aparte, y eso se nota en todo lo que ya no hace falta
 * escribir: se da y se quita con `caps`, quitar al miembro se lo lleva, y no hay forma de
 * nombrar sellador a quien no está en la cuenta.
 */
export const sealersOf = (acta, renounces = []) => {
  if (!acta) return []
  const porPermiso = (acta.members || [])
    .filter((m) => memberCan(acta, m.pub, 'sealer', renounces))
    .map((m) => m.pub)
  // Acta vieja: el que estaba en el campo sellaba SIN tener el permiso. Se traduce al
  // leerla, que es la única forma —está firmada y no se puede reescribir—.
  if (conCampoSellador(acta) && acta.sealer && !porPermiso.includes(acta.sealer)) {
    return [acta.sealer, ...porPermiso]
  }
  return porPermiso
}

/** ¿Puede `pub` sellar la siguiente acta de este perfil? */
export const canSeal = (acta, pub, renounces = []) =>
  !!acta && (memberCan(acta, pub, 'sealer', renounces) || (conCampoSellador(acta) && pub === acta.sealer))

/**
 * Acta de génesis: un perfil recién nacido tiene UN miembro (esta llave), que además es el
 * sellador, con todas las capacidades. `profileId` = su pubkey → el nombre del perfil es
 * estable para siempre y coincide con la identidad que el usuario ya tenía (cero migración).
 */
export function genesisActa ({ pub, encPub = null, sealPub = null, label = '', chainUrl = null, now = Date.now() }) {
  if (!isPub(pub)) throw new Error('genesisActa: missing genesis pubkey')
  if (chainUrl != null && !isChainUrl(chainUrl)) throw new Error('genesisActa: chainUrl must be https')
  return {
    v: ACTA_V,
    profileId: pub,
    sealedBy: pub,
    /**
     * DÓNDE PREGUNTAR SI ESTA CADENA SIGUE VIGENTE. Va en el GÉNESIS y en ningún otro
     * sitio, y esa es toda la idea.
     *
     * La cadena que te llega prueba quién puede sellar, pero no que no haya algo más
     * nuevo — si retiraste una bóveda, quien tenga la cadena vieja la sigue aceptando.
     * Para enterarse hay que poder mirar a algún lado.
     *
     * Si la dirección viajara en la parte cambiable, el sellador expulsado la cambiaría
     * a la suya y te mandaría a mirar su rama. En el génesis no puede: está autofirmada
     * por la llave que da nombre al perfil, y cambiarla exige esa llave.
     *
     * `null` es lo normal y no es un defecto: una cuenta de una sola bóveda no tiene nada
     * que pueda quedar obsoleto —su conjunto de selladores no puede cambiar— así que no
     * hay a dónde preguntar ni falta que hace.
     */
    chainUrl: chainUrl || null,
    seq: 1,
    prev: null,
    // LA CADENA DE SELLADORES. El génesis es el ancla: está autofirmado por la llave que
    // da nombre al perfil, así que no apunta a nada y no hay nada que falsificar sin ella.
    sealerAnchor: null,
    // `true` porque el génesis ESTABLECE el primer conjunto de selladores: es el eslabón
    // 1 de la cadena, y por eso la siguiente acta tiene que apuntarle a él.
    sealerChanged: true,
    // EL ESLABÓN 1 de la cadena publicable, todavía SIN FIRMAR: lo firma `sealActa` con la
    // misma llave, y después firma el acta que lo lleva. Es lo único que sale al registro.
    sealerLink: { v: SEALER_LINK_V, profileId: pub, seq: 1, by: pub, sealers: [pub], prev: null, iat: now },
    members: [{ pub, encPub, label: String(label || '').slice(0, 60), cn: null, caps: [...PAIRED_CAPS, 'sealer'], addedAt: now, cert: null }],
    revoked: [],
    renounced: [],
    // Llavero del contenido: una entrada por generación, con la clave del perfil ENVUELTA
    // a cada miembro (ver content.js). Envuelto es público: solo lo abre su destinatario.
    keyring: [],
    // LLAVE DE SELLADO (§8.9 de dotrino-vault/docs/secretos-sellados.md): con ella la
    // bóveda FIRMA los sobres de los secretos, para que se sepa que salieron de ella.
    // Vive aquí y no en un certificado aparte porque rota con el acta: cada acta nueva
    // puede nombrar una llave nueva, y quien selle el acta es —siempre— la maestra.
    // Nace en null: un perfil no tiene por qué sellar secretos.
    sealPub: sealPub || null,
    sealSince: sealPub ? 1 : 0,
    sealKeys: [],
    updatedAt: now
  }
}

/** Comprobaciones de FORMA (sin cripto): que el acta sea un acta. */
export function checkShape (acta) {
  if (!acta || typeof acta !== 'object') return 'no-acta'
  if (!ACTA_LEIBLES.includes(acta.v)) return 'version'
  if (!isPub(acta.profileId) || !isPub(acta.sealedBy)) return 'shape'
  if (acta.chainUrl != null && !isChainUrl(acta.chainUrl)) return 'chainurl'
  // El campo solo existe —y solo se exige— en las viejas.
  if (conCampoSellador(acta) && !isPub(acta.sealer)) return 'shape'
  if (!conCampoSellador(acta) && acta.sealer != null) return 'sealer-no-va-en-v3'
  if (!Number.isInteger(acta.seq) || acta.seq < 1) return 'seq'
  if (acta.seq > 1 && typeof acta.prev !== 'string') return 'prev'
  if (!Array.isArray(acta.members) || acta.members.length === 0) return 'members'
  for (const m of acta.members) {
    if (!isPub(m?.pub) || !Array.isArray(m?.caps)) return 'member'
    // UN PERMISO DESCONOCIDO SE IGNORA, NO INVALIDA EL ACTA (dueño, 2026-09-01).
    //
    // Aquí ponía `if (m.caps.some((c) => !CAPS.includes(c))) return 'cap-desconocida'`, y
    // eso convertía CADA permiso nuevo en una rotura de toda la flota: al añadir
    // `unattended`, los aparatos con un pilar anterior empezaron a contestar «the record
    // does not verify» y se quedaron sin configuración. El acta estaba perfectamente
    // firmada; lo que fallaba era el lector, que la tiraba al suelo por ver una palabra
    // que no conocía.
    //
    // Y el acta VIAJA — a otros aparatos, a otras bóvedas, al proxio —, así que un
    // documento firmado tiene que poder leerlo alguien que no está al día. La firma cubre
    // el documento tal cual, de modo que un permiso desconocido no la rompe: rechazarlo era
    // una decisión del validador, y la equivocada.
    //
    // POR QUÉ IGNORARLO ES SEGURO, que es lo único que hace válido este cambio: todas las
    // comprobaciones preguntan por un permiso CONCRETO (`memberCan(acta, pub, 'sign')`), así
    // que una palabra que el lector no conoce no puede satisfacer ninguna — no concede nada.
    // Ignorar cae siempre del lado estricto.
    //
    // ⚠️ La regla que hay que respetar al añadir permisos futuros: **un permiso nuevo
    // CONCEDE, nunca restringe**. Si algún día se inventa uno cuya AUSENCIA sea lo
    // permisivo, un lector viejo lo ignoraría y actuaría de más — y entonces sí habría que
    // subir `ACTA_V` y negarse a leer las versiones que no se entienden. `unattended`
    // cumple la regla: sin él se pide aprobación.
    if (m.caps.some((c) => typeof c !== 'string' || !c)) return 'member'
    // El CN es la frontera: un SERVICIO solo puede abrir su propio cajón, y un
    // DISPOSITIVO no tiene cajón que abrir. Que no se pueda escribir un acta que
    // mezcle las dos cosas es lo que hace que el límite sea real y no una costumbre.
    if (m.cn != null) {
      if (!isValidCn(m.cn)) return 'cn-invalido'
    } else if (m.caps.includes('secrets')) {
      return 'secretos-sin-cn'
    }
    // La llave de cifrado: por ahora se valida la FORMA y solo si viene. NO se exige
    // todavía, aunque el destino sea exigírsela a quien recibe secretos.
    //
    // El motivo es que `checkShape` corre en CADA `verifyActa`, también sobre actas ya
    // selladas: exigirla hoy invalidaría de golpe las actas en las que un servicio
    // entró sin ella —que son todas las anteriores a esto— y el vault dejaría de
    // arrancar en vez de avisar. Primero los servicios registran su llave (op
    // `encpub`), y cuando no quede ninguno sin ella se aprieta aquí.
    if (m.encPub != null && !isEncPub(m.encPub)) return 'encpub-invalido'
  }
  // LA LLAVE DE SELLADO Y SU REGISTRO. `sealPub` puede no estar (un perfil que no sella
  // secretos), pero si está tiene que decir DESDE QUÉ acta manda: sin `sealSince` no se
  // puede decidir con qué llave verificar un sobre viejo.
  if (acta.v >= 2) {
  if (acta.sealPub != null) {
    if (!isPub(acta.sealPub)) return 'sealpub-invalido'
    if (!Number.isInteger(acta.sealSince) || acta.sealSince < 1 || acta.sealSince > acta.seq) return 'sealsince'
  } else if (acta.sealSince) return 'sealsince'
  if (!Array.isArray(acta.sealKeys)) return 'sealkeys'
  for (const k of acta.sealKeys) {
    if (!isPub(k?.pub)) return 'sealkey-invalida'
    if (!Number.isInteger(k.from) || !Number.isInteger(k.to) || k.from < 1 || k.to < k.from) return 'sealkey-rango'
  }
  }
  if (new Set(acta.members.map((m) => m.pub)).size !== acta.members.length) return 'miembro-duplicado'
  // SIN NADIE QUE SELLE, el acta está muerta: no habría forma de volver a cambiarla nunca.
  // Es el hermano del cierre de `sign`, y sustituye a «el sellador tiene que ser miembro»
  // ahora que sellar es solo un permiso y los permisos ya son de miembros por definición.
  if (!sealersOf(acta).length) return 'sin-sellador'
  // La cadena de selladores: el génesis es el ancla (`null`); cualquier otra apunta a un
  // eslabón anterior. Sin `hash` no se puede encadenar nada, así que se exige la forma.
  if (acta.sealerAnchor != null) {
    const a = acta.sealerAnchor
    if (typeof a !== 'object' || !Number.isInteger(a.seq) || a.seq < 1 || a.seq >= acta.seq) return 'sealeranchor'
    if (typeof a.hash !== 'string' || !/^[0-9a-f]{64}$/.test(a.hash)) return 'sealeranchor'
  }
  // El ancla NO se exige: una cuenta que viene de antes de v4 escribe su primera acta
  // nueva sin poder apuntar a nada (su padre no era eslabón), y exigirla la dejaría
  // inválida. Lo que sostiene la cadena no es el ancla sino que **cada eslabón lo selle
  // alguien a quien el anterior autorizaba**; el ancla añade que no se pueda empalmar un
  // eslabón de otra rama, y se comprueba cuando viene (ver `verifySealerChain`).
  if (!acta.members.some((m) => m.caps.includes('sign'))) return 'sin-firmante'
  return null
}

/** Sella (firma) un acta. `privateKey` puede ser una CryptoKey no extractable. */
export async function sealActa ({ acta, privateKey, privateJwk }) {
  const shape = checkShape(acta)
  if (shape) throw new Error('invalid record: ' + shape)
  // PRIMERO EL ESLABÓN, DESPUÉS EL ACTA. Este es el orden que hace que no puedan discrepar:
  // se firma el eslabón, se mete en el acta, y la firma del acta lo cubre. Quien tiene el
  // acta lo da por bueno con verificarla; quien solo tiene el registro verifica su firma.
  // Si ya viene firmado no se vuelve a firmar: se está arrastrando el de un acta anterior.
  let conEslabon = acta
  if (acta.sealerLink && !acta.sealerLink.sig) {
    if (acta.sealerLink.by !== acta.sealedBy) throw new Error('invalid record: the chain link names a sealer other than the one signing')
    const { signature: firmaEslabon } = await signWithDevice({
      privateKey, privateJwk, publickey: acta.sealedBy, data: sealerLinkBody(acta.sealerLink)
    })
    conEslabon = { ...acta, sealerLink: { ...acta.sealerLink, sig: firmaEslabon } }
  }
  const { signature } = await signWithDevice({ privateKey, privateJwk, publickey: conEslabon.sealedBy, data: actaBody(conEslabon) })
  const sealed = { ...conEslabon, sig: signature }
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
/**
 * ¿HABLA ESTA ACTA POR ESTA IDENTIDAD? Lo que comprueba un EXTRAÑO, sin saber nada de ti.
 *
 * Recibe la cadena de selladores: `[génesis, …cambios de sellador…, acta actual]`. No son
 * todas tus actas —eso crecería con cada emparejamiento— sino solo los eslabones donde
 * cambió quién sella, que casi nunca pasa. Lo normal es longitud 1 o 2.
 *
 * Qué se comprueba, y por qué basta:
 *   1. el primer eslabón es el GÉNESIS y está autofirmado por `profileId`. Ese es el
 *      ancla: sin esa llave no se puede fabricar, y el `profileId` ya lo conoce quien
 *      verifica (viaja en cada firma tuya);
 *   2. cada eslabón siguiente lo selló alguien a quien el ANTERIOR autorizaba;
 *   3. y apunta al anterior por `seq` + hash, así que no se puede colar uno de otra rama.
 *
 * Sin esto, un acta suelta es falsificable: con tu `profileId` cualquiera fabrica una
 * donde él sella, y `verifyActa` la da por buena — está firmada, solo que por él.
 *
 * Lo que NO resuelve, y no lo esconde: la frescura. Quien guardó una cadena vieja sigue
 * aceptando a un sellador que ya retiraste. Es el problema de siempre y hace falta un
 * oráculo, no más firmas.
 */
/**
 * ¿DE QUIÉN ES ESTO? La pregunta que se hacen geo, reputación y cualquiera que reciba algo
 * firmado de un desconocido. Es lo único que necesitan llamar.
 *
 * Devuelve el `profileId` —la identidad— o por qué no.
 *
 * EL CERTIFICADO NO HACE FALTA AQUÍ, y conviene decirlo porque es lo que uno espera:
 * el acta ya dice quién puede firmar por la identidad, y la cadena prueba el acta. El
 * certificado es del protocolo aparato↔bóveda (autenticar peticiones), no de atribuir
 * contenido. Mezclarlos obligaba a que cada post arrastrara un papel que no aporta nada.
 *
 * Lo que SÍ hay que entender: esto dice «esta identidad firmó esto», no «esto es
 * reciente». Si la cadena que te llega es vieja, sigue verificando — para eso está el
 * registro público, que es otra capa.
 */
export async function verifySignedBy ({ data, signature, publickey, chain, expectedProfileId = null } = {}) {
  if (!data || typeof signature !== 'string' || typeof publickey !== 'string') {
    return { ok: false, reason: 'shape' }
  }
  const c = await verifySealerChain(chain, { expectedProfileId })
  if (!c.ok) return { ok: false, reason: 'cadena:' + c.reason }
  const cabeza = chain[chain.length - 1]
  // Quien firmó tiene que ser miembro CON `sign` en el acta vigente de esa cadena. Si le
  // quitaste el permiso, sus firmas dejan de contar en cuanto se ve un acta más nueva.
  if (!memberCanSign(cabeza, publickey)) return { ok: false, reason: 'firmante-no-autorizado' }
  if (!(await verifyDeviceSig({ publickey, data, signature }))) return { ok: false, reason: 'firma-invalida' }
  return { ok: true, profileId: c.profileId, seq: c.seq, signer: publickey }
}

export async function verifySealerChain (chain, { expectedProfileId = null } = {}) {
  if (!Array.isArray(chain) || !chain.length) return { ok: false, reason: 'cadena-vacia' }
  const [raiz] = chain

  if (raiz.seq !== 1 || raiz.sealerAnchor != null) return { ok: false, reason: 'no-empieza-en-genesis' }
  // El ancla: el génesis se firma a sí mismo con la llave que da nombre al perfil.
  if (raiz.sealedBy !== raiz.profileId) return { ok: false, reason: 'genesis-no-autofirmado' }
  if (expectedProfileId != null && raiz.profileId !== expectedProfileId) return { ok: false, reason: 'otro-perfil' }
  const vr = await verifyActa({ acta: raiz })
  if (!vr.ok) return { ok: false, reason: 'genesis:' + vr.reason }

  for (let i = 1; i < chain.length; i++) {
    const previo = chain[i - 1]
    const actual = chain[i]
    if (actual.profileId !== raiz.profileId) return { ok: false, reason: 'otro-perfil' }
    const v = await verifyActa({ acta: actual })
    if (!v.ok) return { ok: false, reason: `eslabon-${i}:` + v.reason }
    // Encadena con el anterior: mismo `seq` y mismo hash. Sin el hash bastaría con
    // acertar un número para colar un eslabón de otra rama.
    // El ancla, SI viene: fija que este eslabón sale del anterior y no de otra rama. Una
    // cuenta anterior a v4 puede no traerla, y entonces lo que sostiene la cadena es lo de
    // abajo — que es lo que de verdad impide falsificarla.
    const a = actual.sealerAnchor
    if (a && (a.seq !== previo.seq || a.hash !== await actaHash(previo))) {
      return { ok: false, reason: `eslabon-${i}:no-encadena` }
    }
    // Y lo que da la autoridad: quien la selló tenía permiso SEGÚN EL ESLABÓN ANTERIOR.
    if (!canSeal(previo, actual.sealedBy)) return { ok: false, reason: `eslabon-${i}:sellador-no-autorizado` }
  }
  const ultima = chain[chain.length - 1]
  return { ok: true, profileId: raiz.profileId, seq: ultima.seq, sealers: sealersOf(ultima) }
}

export async function verifyActa ({ acta, expectedProfileId } = {}) {
  const shape = checkShape(acta)
  if (shape) return { ok: false, reason: shape }
  if (typeof acta.sig !== 'string') return { ok: false, reason: 'sin-firma' }
  if (expectedProfileId != null && acta.profileId !== expectedProfileId) return { ok: false, reason: 'otro-perfil' }
  const ok = await verifyDeviceSig({ publickey: acta.sealedBy, data: actaBody(acta), signature: acta.sig })
  if (!ok) return { ok: false, reason: 'firma-invalida' }
  // El eslabón va DENTRO y la firma de arriba lo cubre, pero eso solo prueba que está ahí.
  // Que diga lo mismo que el acta es lo que hace verdad «ya está validado dentro».
  const mal = checkSealerLink(acta)
  return mal ? { ok: false, reason: mal } : { ok: true }
}

/**
 * Aplica cambios y devuelve el acta SIGUIENTE, **sin firmar** (hay que `sealActa`).
 * `by` es quien va a sellar: si no es el sellador vigente, se rechaza (regla 1).
 *
 * Cambios: `{op:'admit', member}` · `{op:'caps', pub, caps}` · `{op:'remove', pub}` ·
 * `{op:'handover', to}` · `{op:'revoke', nonce, until}` · `{op:'renounce', record}`.
 * Sellar se concede con `{op:'caps'}` como cualquier otro permiso.
 * Van en ARRAY porque hay combinaciones que deben ser atómicas: admitir al nuevo sellador y
 * traspasarle el master ocurre en el MISMO `seq` (§2.1.3).
 */
export async function applyChanges (acta, changes, { by, now = Date.now(), sealPub = null } = {}) {
  const shape = checkShape(acta)
  if (shape) throw new Error('invalid record: ' + shape)
  if (!by) throw new Error('applyChanges: missing `by` (who seals)')
  // El mensaje conserva «not the master» a propósito: es una cadena que hay código y
  // pruebas emparejando, y cambiarla en silencio es justo lo que rompe cosas sin ruido.
  if (!canSeal(acta, by)) throw new Error('only a sealer named by the record can change it: this device is not the master, nor a co-sealer')

  const list = (Array.isArray(changes) ? changes : [changes]).filter(Boolean)
  // Estrenar la llave de sellado ES un cambio del acta, aunque no toque a ningún miembro:
  // rota con el acta (§8.9) y el acta es lo que le da autoridad. Por eso una lista vacía
  // se acepta si viene con llave nueva, y solo entonces.
  if (list.length === 0 && !sealPub) throw new Error('applyChanges: no changes')

  const next = {
    ...acta,
    // Asciende de v1 a v2 sin ceremonia: los campos de sellado nacen vacíos y la llave
    // entra en cuanto quien sella pase una (`sealPub`).
    v: ACTA_V,
    sealPub: acta.sealPub || null,
    sealSince: acta.sealPub ? acta.sealSince : 0,
    sealedBy: by,
    seq: acta.seq + 1,
    prev: await actaHash(acta),
    members: acta.members.map((m) => ({ ...m, caps: [...m.caps] })),
    revoked: [...(acta.revoked || [])],
    renounced: [...(acta.renounced || [])],
    keyring: (acta.keyring || []).map((g) => ({ ...g, wraps: { ...g.wraps } })),
    sealKeys: (acta.sealKeys || []).map((k) => ({ ...k })),
    updatedAt: now
  }
  delete next.sig

  // LA LLAVE DE SELLADO ROTA CON EL ACTA (§8.9 de `secretos-sellados.md`). Quien sella
  // pasa la llave nueva; si no pasa ninguna, la de antes sigue mandando —un master que no
  // sella secretos (el navegador) no tiene por qué inventarse una—.
  //
  // La anterior NO se tira: se guarda con el tramo de `seq` en el que estuvo en vigor,
  // porque los sobres que firmó tienen que seguir verificando. Re-firmarlos al rotar
  // sería recorrer todos los secretos en cada cambio de membresía.
  if (sealPub && sealPub !== next.sealPub) {
    if (next.sealPub) next.sealKeys.push({ pub: next.sealPub, from: next.sealSince, to: acta.seq })
    next.sealPub = sealPub
    next.sealSince = next.seq
  }

  const find = (pub) => next.members.find((m) => m.pub === pub)

  for (const ch of list) {
    switch (ch?.op) {
      case 'admit': {
        const m = ch.member
        if (!isPub(m?.pub)) throw new Error('admit: missing member pubkey')
        if (find(m.pub)) throw new Error('admit: that member is already in the record')
        const cn = m.cn != null ? String(m.cn) : null
        if (cn !== null && !isValidCn(cn)) throw new Error('admit: invalid CN (lowercase, digits and hyphens)')
        next.members.push({
          pub: m.pub,
          encPub: m.encPub || null,
          label: String(m.label || '').slice(0, 60),
          cn,
          // PERMISOS, no tipos (2026-08-22): el CN dice qué cajón abre; no recorta lo demás.
          // Un miembro con CN puede llevar además las capacidades de aparato (un bot que
          // firma como aparato del acta Y lee su cajón). Sin CN, `secrets` no significa nada.
          caps: cleanCaps(m.caps).filter((c) => allowedCaps(cn).includes(c)),
          addedAt: now,
          cert: m.cert || null,
          // Puente con la identidad que este miembro traía de antes (ver makeContinuity).
          ...(m.continuity ? { continuity: m.continuity } : {})
        })
        break
      }
      // Registra (o reemplaza) la llave de CIFRADO de un miembro que YA está admitido.
      //
      // Existe para no tener que expulsar y volver a admitir a un servicio solo porque
      // le falta la llave: re-enrolar le cambia la pubkey, y con ella pierde su cajón de
      // variables —que va indexado por esa llave— y se queda sin configuración en
      // silencio. Registrar la llave en el sitio no toca ni `pub`, ni `cn`, ni `caps`.
      case 'encpub': {
        const m = find(ch.pub)
        if (!m) throw new Error('encpub: that member is not in the record')
        if (!isEncPub(ch.encPub)) throw new Error('encpub: invalid encryption key (expected a P-256 public JWK)')
        m.encPub = ch.encPub
        break
      }
      case 'caps': {
        const m = find(ch.pub)
        if (!m) throw new Error('caps: that member is not in the record')
        // El CN no cambia por aquí (quitar el cajón es sacar al miembro y volver a admitirlo,
        // que es un gesto visible); las capacidades sí, dentro de lo que su CN permite.
        m.caps = cleanCaps(ch.caps).filter((c) => allowedCaps(m.cn).includes(c))
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
        // Quitar al miembro se lleva su permiso de sellar: no hay lista aparte que limpiar.
        const fuera = next.members.splice(i, 1)[0]
        // Sus envolturas se van con él: sin ellas no puede abrir ninguna generación. (El
        // acceso al contenido FUTURO se corta rotando, ver content.js; lo ya leído no vuelve.)
        next.keyring = next.keyring.map((g) => {
          const { [fuera.pub]: _, ...resto } = g.wraps || {}
          return { ...g, wraps: resto }
        })
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
        if (typeof ch.nonce !== 'string') throw new Error('revoke: missing nonce')
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
        throw new Error('unknown change: ' + ch?.op)
    }
  }

  // Poda: las revocaciones vencidas ya no hacen falta (el cert al que apuntan expiró).
  next.revoked = next.revoked.filter((r) => !r.until || r.until > now)

  // Reglas de cierre: sin firmante no se puede operar, y sin sellador no se puede cambiar.
  if (!next.members.some((m) => m.caps.includes('sign'))) {
    throw new Error('the change would leave the profile with no member able to sign')
  }
  // ASCENDER DE UNA VIEJA: el que sellaba por el CAMPO pasa a sellar por el PERMISO. Es
  // toda la migración, y va aquí porque este es el momento en que la cuenta escribe su
  // primera v3 — el acta vieja no se puede tocar, está firmada.
  if (conCampoSellador(acta) && acta.sealer) {
    const m = next.members.find((x) => x.pub === acta.sealer)
    if (m && !m.caps.includes('sealer')) m.caps = cleanCaps([...m.caps, 'sealer'])
    // Y el campo se va con la vieja: la nueva es v3 y en v3 no existe.
    delete next.sealer
  }
  if (!sealersOf(next).length) {
    throw new Error('the change would leave the record with nobody able to seal it')
  }

  /**
   * LA CADENA DE SELLADORES. Es lo que deja a un EXTRAÑO comprobar que quien firmó esto
   * habla por esta identidad, sin tener que mandarle todas las actas.
   *
   * El problema: el acta suelta es falsificable —con tu `profileId`, que es público,
   * cualquiera fabrica una donde él sella—. Y mandar la cadena entera no sale a cuenta
   * porque crece con cada emparejamiento, que es lo que más cambia.
   *
   * La salida: solo encadenar los eslabones donde CAMBIA quién sella, que casi nunca pasa.
   * Un usuario normal tiene cadena de longitud 1 —el génesis— para siempre; con una
   * segunda bóveda, 2. Ese es el tamaño real, no el número de actas.
   *
   * Cada acta apunta al último cambio ANTERIOR a ella, nunca a sí misma (sería circular:
   * el puntero va dentro de lo que se firma). Y `sealerChanged` dice si ELLA es uno, para
   * que la siguiente sepa a dónde apuntar teniendo solo a su padre delante.
   *
   * Y lo que esto resuelve y el génesis firmando no resolvía: **no hace falta la llave del
   * génesis para sumar un sellador.** La bóveda que ya está autorizada sella el acta que
   * autoriza a la siguiente, y ese eslabón vale porque el anterior la autorizaba a ella.
   * El génesis firmó el eslabón 1 y puede estar perdido desde entonces — que es justo el
   * desastre para el que existe el multivault.
   */
  const antes = sealersOf(acta).slice().sort().join('|')
  const despues = sealersOf(next).slice().sort().join('|')
  next.sealerChanged = antes !== despues
  next.sealerAnchor = acta.sealerChanged
    ? { seq: acta.seq, hash: await actaHash(acta) }
    : (acta.sealerAnchor || null)
  // EL DOBLE FILTRO (dueño, 2026-08-31): un acta nueva tiene que pasar el filtro de la
  // ANTERIOR —quién podía sellar, arriba— y también el de LA QUE SE VA A FIRMAR. Si no
  // pasa los dos, no se firma.
  //
  // Lo que cierra: un sellador que se quita a sí mismo el permiso en la misma acta que
  // firma. Es absurdo —se firma con una autoridad que uno acaba de retirarse— y no tiene
  // vuelta atrás: deshacerlo requeriría sellar, que es justo lo que se acaba de perder.
  //
  // Y por qué aquí y no con una marca de «traspaso»: mirando el acta SOLA, ceder el mando
  // y quitarse el permiso se ven igual. Con las dos actas delante no hay ambigüedad, y las
  // dos veces que esto importa —construirla, y adoptar una ajena— se tienen las dos.
  if (!canSeal(next, by)) {
    throw new Error('the change would leave whoever seals it unable to seal: a record must pass the filter of the one it replaces AND its own')
  }
  // EL ESLABÓN PUBLICABLE. Si cambió quién sella se acuña uno nuevo —sin firmar, lo firma
  // `sealActa`— encadenado al que traía el acta anterior. Si no cambió, se arrastra el
  // mismo: así el acta vigente SIEMPRE lleva el último eslabón, y `prev` apunta al eslabón
  // anterior de la cadena (no al acta anterior, que quien lee el registro no tiene).
  if (next.sealerChanged) {
    const anterior = acta.sealerLink || null
    next.sealerLink = {
      v: SEALER_LINK_V,
      profileId: next.profileId,
      seq: next.seq,
      by,
      sealers: sealersOf(next).slice().sort(),
      prev: anterior ? { seq: anterior.seq, hash: await sealerLinkHash(anterior) } : null,
      iat: now
    }
  } else if (acta.sealerLink) {
    next.sealerLink = acta.sealerLink
  }
  return next
}

/**
 * La llave que firmaba los sobres cuando el acta iba por `seq`. Es lo que necesita quien
 * VERIFICA un sobre: el sobre dice con qué acta se selló, y esto dice con qué llave hay
 * que comprobarlo. `null` si no había ninguna (perfil que no sellaba) o si el `seq` viene
 * del futuro, que es un sobre que no puede ser bueno.
 */
export function sealKeyAt (acta, seq) {
  if (!acta || !Number.isInteger(seq) || seq < 1 || seq > acta.seq) return null
  if (acta.sealPub && seq >= acta.sealSince) return acta.sealPub
  for (const k of acta.sealKeys || []) if (seq >= k.from && seq <= k.to) return k.pub
  return null
}

// ----- renuncia (§2.2): el único cambio que no pasa por el master -----

/** Crea el registro firmado con el que un miembro se QUITA capacidades a sí mismo. */
export async function makeRenounce ({ member, caps, privateKey, privateJwk, now = Date.now() }) {
  const body = { op: 'renounce', member, caps: cleanCaps(caps), ts: now }
  if (body.caps.length === 0) throw new Error('resign: no capabilities to remove')
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
  // Lo que este lector no conoce no es una capacidad PARA ÉL: no la puede juzgar, así que
  // no la enseña ni la cuenta. Sigue en el acta —la firma la cubre— y un lector al día sí
  // la ve. Ver `checkShape` para por qué no se rechaza el acta entera.
  const quitadas = new Set()
  for (const r of [...(acta.renounced || []), ...extraRenounces]) {
    if (r?.member === pub) for (const c of (r.caps || [])) quitadas.add(c)
  }
  return m.caps.filter((c) => CAPS.includes(c) && !quitadas.has(c))
}

/**
 * ¿Puede este miembro leer el cajón de secretos `ns`? Solo si su CN es exactamente ése.
 * Es la frontera que pediste: la llave del proxy no ve nada más que lo del proxy.
 */
/**
 * ¿PUEDE ESTE MIEMBRO FIRMAR POR LA IDENTIDAD, Y QUÉ?
 *
 * Manda el acta, no el certificado (dueño, 2026-08-31). Y el matiz que hace falta decir en
 * voz alta: `sign` **no** es «firma lo que quiera». Va enmascarado, igual que `secrets` lo
 * va por el `cn` — *«puede firmar por identidad pero solo lo que permitan los permisos»*.
 *
 * Por qué existe con nombre propio en vez de un `memberCan(acta, pub, 'sign')` suelto: la
 * regla se comprueba en DOS bóvedas (el daemon y la de navegador) y se comprobaba mal en
 * las dos —miraban el papel—. Con un solo sitio, cuando el enmascarado crezca, crece una
 * vez y las dos lo heredan.
 *
 * `ns` es opcional y es para lo que va atado a un cajón: un servicio (miembro con `cn`)
 * solo firma dentro del suyo. Sin `ns`, se pregunta por la capacidad a secas.
 */
export function memberCanSign (acta, pub, ns = null) {
  if (!memberCan(acta, pub, 'sign')) return false
  const m = (acta?.members || []).find((x) => x.pub === pub)
  // SIN `cn` = un aparato TUYO: firma como tú, y no hay nada que preguntarle a nadie.
  if (!m?.cn) return true
  // CON `cn` = un servicio, y el cajón lo dice EL ACTA. Así que no hace falta —ni vale—
  // preguntarle al contenido de qué es: quien pregunta sin decir cajón está pidiendo
  // «firma por la identidad, en general», y eso un servicio no lo hace. Solo se le
  // reconoce la firma dentro del suyo.
  return ns != null && m.cn === ns
}

/**
 * ¿PUEDE ESTE MIEMBRO LO QUE PIDE EL SCOPE? La misma pregunta para todos los mostradores.
 *
 * El certificado dice a qué se comprometió la bóveda cuando conectó el aparato; el ACTA
 * dice lo que puede hoy. Y no coinciden: cambiar los permisos sella el acta pero NO
 * reemite ni revoca el papel, que vive hasta 30 días. Quitarle `lee` a un aparato y que
 * siguiera leyendo un mes es el mismo fallo que estaba en `sign`, en cada mostrador que
 * se olvidara de preguntar.
 *
 * Por eso esto existe y por eso traduce el SCOPE (el idioma del certificado) a la
 * capacidad (el idioma del acta): así el guardia se pone UNA vez, junto a la verificación
 * de la cadena, y un mostrador nuevo lo hereda en lugar de tener que acordarse.
 *
 * Devuelve `false` ante un scope que no reconoce: si aparece uno nuevo, lo que toca es
 * añadirlo aquí, no que se cuele por no estar en la lista.
 */
export function memberCanScope (acta, pub, scope) {
  if (!acta || typeof scope !== 'string') return false
  const secretos = /^vault:secrets:([a-z0-9-]{1,32})$/.exec(scope)
  if (secretos) return memberCanReadSecrets(acta, pub, secretos[1])
  if (scope === 'vault:sign') return memberCanSign(acta, pub)
  const cap = Object.keys(CAP_SCOPE).find((c) => CAP_SCOPE[c] === scope)
  return cap ? memberCan(acta, pub, cap) : false
}

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
    if (!canSeal(current, candidate.sealedBy)) return { adopt: false, reason: 'sellador-no-autorizado' }
    if (candidate.seq === current.seq + 1 && candidate.prev !== await actaHash(current)) {
      return { adopt: false, reason: 'no-encadena' }
    }
    return { adopt: true, reason: 'seq-mayor' }
  }

  if (candidate.seq === current.seq) {
    const [hCan, hCur] = [await actaHash(candidate), await actaHash(current)]
    if (hCan === hCur) return { adopt: false, reason: 'misma-acta' }
    // A igual `seq`, con multivault, las dos ramas pueden venir de selladores DISTINTOS y
    // ser las dos legítimas. Antes era imposible y se rechazaba de plano; ahora se
    // desempata con las reglas de abajo, que ya estaban escritas.
    //
    // Se conserva primero la comparación de siempre (`mismo sealedBy`) y no se sustituye:
    // en un TRASPASO las dos ramas las firmó el saliente, y `current` ya nombra al
    // entrante como `sealer` — así que preguntarle a `current` si el saliente puede
    // sellar da «no», y se perdería el desempate «gana la que traspasa». La pregunta
    // correcta es por el acta PADRE, que aquí no se tiene; tener el mismo `sealedBy` es
    // exactamente lo que dice que las dos salieron de ella.
    const mismoFirmante = candidate.sealedBy === current.sealedBy
    if (!mismoFirmante && !canSeal(current, candidate.sealedBy)) return { adopt: false, reason: 'otro-sellador' }
    // SOLO QUEDA EL HASH. Antes había una regla más —«gana la que traspasa»— que existía
    // para arbitrar el campo `sealer`: dos ramas que cedían el mando a destinos distintos.
    // Ese campo ya no existe (dueño, 2026-08-31: «SEAL es el nuevo master»), y con él se
    // va la regla y la ambigüedad que arrastraba: `sealer !== sealedBy` significaba
    // «traspaso» con un solo master y dejó de significarlo con varios selladores.
    return hCan < hCur ? { adopt: true, reason: 'desempate-hash' } : { adopt: false, reason: 'desempate-hash' }
  }

  return { adopt: false, reason: 'seq-menor' }
}

export default {
  ACTA_V, CAPS, CAP_SCOPE, genesisActa, actaBody, actaHash, memberId, checkShape, verifySealerChain, verifySignedBy,
  sealActa, verifyActa, applyChanges, makeRenounce, verifyRenounce,
  makeContinuity, verifyContinuity,
  cardBody, makeProfileCard, verifyProfileCard, canAdoptCard, sealersOf, canSeal,
  effectiveCaps, memberCan, memberCanSign, memberCanScope, memberCanReadSecrets, memberScopes, isService, capScope, isValidCn, canAdopt
}
