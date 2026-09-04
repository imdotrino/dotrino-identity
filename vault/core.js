/**
 * Núcleo runtime-agnóstico de la identidad Dotrino.
 *
 * Contiene TODA la criptografía y los handlers del vault, SIN depender de
 * `localStorage`, `iframe`, `IndexedDB` ni `postMessage`. El almacenamiento
 * (kv), el peer book (peers) y el sync se inyectan, de modo que el mismo código
 * corre:
 *   - dentro del iframe del vault (`vault.js` → kv=localStorage, peers=IndexedDB,
 *     sync=Google Drive, transporte=postMessage), y
 *   - headless en Node (`src/node.js` → kv y peers respaldados en archivos,
 *     sync deshabilitado, llamadas directas a los handlers).
 *
 * Sólo usa globals presentes en navegadores modernos y Node ≥ 20:
 * `crypto.subtle`, `crypto.randomUUID`, `crypto.getRandomValues`,
 * `TextEncoder`/`TextDecoder`, `btoa`/`atob`.
 *
 * NO reimplementa el protocolo: es la única fuente de verdad de la cripto del
 * vault, compartida por todos los runtimes.
 */

import { signDelegationWith } from './capabilities.js'
import * as Acta from './acta.js'
import * as Content from './content.js'
import { pubkeyId as pubkeyIdOf, signWithDevice } from './capabilities.js'
import { enrollDevice as remoteEnroll, requestSign as remoteSign, requestStore as remoteStore, requestDevices as remoteDevices, requestRenew as remoteRenew, requestAdmin as remoteAdmin, requestApproval as remoteApproval, requestRenounce as remoteRenounce, checkMembership as remoteCheck } from './remote.js'

export const KEY_STORAGE = 'dotrino.identity.keypair'
export const ENC_KEY_STORAGE = 'dotrino.identity.enc-keypair'
export const ME_STORAGE = 'dotrino.identity.me'
export const NONCE_STORAGE = 'dotrino.identity.nonces' // replay window
export const DELEGATIONS_STORAGE = 'dotrino.identity.delegations'   // caps emitidas
export const REVOCATIONS_STORAGE = 'dotrino.identity.revocations'   // nonces revocados
export const VAULT_DEVICE_STORAGE = 'dotrino.identity.vault.device' // sub-clave D de ESTE dispositivo (custodia en el iframe)
export const VAULT_CERT_STORAGE = 'dotrino.identity.vault.cert'     // { cert, master, proxy, deviceId, pairedAt }
export const ACTA_STORAGE = 'dotrino.identity.acta'                 // acta de perfil vigente (quién es del perfil y qué puede)
export const ACTA_HISTORY_STORAGE = 'dotrino.identity.acta.history' // últimas actas selladas (§1.3)
export const PENDING_JOIN_STORAGE = 'dotrino.identity.pendingJoin'  // «nací para adoptar la cuenta de otro»
export const RENOUNCE_STORAGE = 'dotrino.identity.renounced'        // renuncias propias aún no absorbidas por el master
// Multi-perfil por dispositivo: lista de perfiles + el activo. Cada perfil tiene su propio
// namespace `dotrino.identity.p.<id>.<suffix>` para TODAS las claves de arriba (keypair, me, etc.).
export const PROFILES_STORAGE = 'dotrino.identity.profiles' // [{ id, name, pubkey }]
export const CURRENT_STORAGE = 'dotrino.identity.current'   // id del perfil activo

const NONCE_TTL_MS = 5 * 60 * 1000

// ----- crypto helpers (puros) -----

export function canonicalStringify (v) {
  if (v === null || typeof v !== 'object') return JSON.stringify(v)
  if (Array.isArray(v)) return '[' + v.map(canonicalStringify).join(',') + ']'
  const ks = Object.keys(v).sort()
  return '{' + ks.map(k => JSON.stringify(k) + ':' + canonicalStringify(v[k])).join(',') + '}'
}

export function bufToBase64 (buf) {
  const bytes = new Uint8Array(buf)
  let s = ''
  for (let i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i])
  return btoa(s)
}

export function base64ToBuf (b64) {
  const s = atob(b64)
  const bytes = new Uint8Array(s.length)
  for (let i = 0; i < s.length; i++) bytes[i] = s.charCodeAt(i)
  return bytes.buffer
}

async function importPeerEncPubkey (jwkStr) {
  const jwk = typeof jwkStr === 'string' ? JSON.parse(jwkStr) : jwkStr
  return crypto.subtle.importKey('jwk', jwk, { name: 'ECDH', namedCurve: 'P-256' }, true, [])
}

async function deriveSharedAesKey (myPriv, peerPub) {
  return crypto.subtle.deriveKey(
    { name: 'ECDH', public: peerPub },
    myPriv,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt']
  )
}

async function signBytes (privateKey, bytes) {
  const sig = await crypto.subtle.sign({ name: 'ECDSA', hash: { name: 'SHA-256' } }, privateKey, bytes)
  return bufToBase64(sig)
}

async function verifyBytes (publicJwkStr, bytes, signatureBase64) {
  let publicKey
  try {
    const jwk = JSON.parse(publicJwkStr)
    publicKey = await crypto.subtle.importKey('jwk', jwk, { name: 'ECDSA', namedCurve: 'P-256' }, true, ['verify'])
  } catch (_) {
    return false
  }
  return crypto.subtle.verify(
    { name: 'ECDSA', hash: { name: 'SHA-256' } },
    publicKey,
    base64ToBuf(signatureBase64),
    bytes
  )
}

/**
 * Crea el núcleo de identidad sobre los backends inyectados.
 *
 * @param {Object} deps
 * @param {{getItem(k):string|null, setItem(k,v):void, removeItem(k):void}} deps.kv
 *        Almacén clave-valor síncrono estilo localStorage (keypairs, me, nonces).
 * @param {Object} deps.peers  Peer book con la interfaz de vault/peerStore.js:
 *        { initPeerStorage, loadPeers, savePeers, setPeersDirect, upsertPeer, onDirty }
 * @param {Function|null} [deps.makeSync]  Factory de sync (createSync). Si es null,
 *        los métodos sync* lanzan "sync not ready" (modo headless / sin Drive).
 * @returns {Promise<{ handlers:Object, get me():Object, sync:Object|null,
 *                      onSyncStatus(fn):void }>}
 */
// Campos personales estándar del perfil (escalares fijos), con su cap de longitud.
// Cada uno tiene un flag `<campo>Visible` (booleano) para mostrar/ocultar al compartir.
const STD_FIELD_CAPS = [
  ['nombres', 60], ['apellidos', 60], ['email', 120], ['telefono', 40], ['direccion', 200]
]
// Datos sensibles: OCULTOS por defecto. `publicMe` solo los incluye si su flag === true
// (los demás campos estándar se comparten salvo que su flag sea false).
const STD_FIELDS_SENSITIVE = new Set(['telefono', 'direccion'])

/**
 * QUÉ CLASE ES CADA DATO DEL PERFIL: `public` o `private`
 * (`dotrino-vault/docs/datos-del-perfil.md` §2).
 *
 * La regla no es nueva —es la que ya decidía `publicMe()`: lo que marcaste visible es lo
 * que ve quien pregunta desde fuera—. Lo que cambia es que ahora decide **cómo se guarda**:
 * en claro o en sobre. Por eso vive aquí, exportada y a nivel de módulo, en vez de escondida
 * dentro de una función: es política y hay que poder mirarla y probarla.
 *
 * Sensibles (teléfono, dirección) OCULTOS salvo que su marca diga que sí, explícitamente.
 * El resto se comparte salvo que digas que no.
 */
export function profileFieldClasses (m = {}) {
  const out = {}
  const clase = (esPublico) => (esPublico ? 'public' : 'private')
  if (m.nickname) out.nickname = clase(true)
  if (m.avatar) out.avatar = clase(m.avatarVisible !== false)
  for (const [k] of STD_FIELD_CAPS) {
    if (!m[k]) continue
    out[k] = clase(STD_FIELDS_SENSITIVE.has(k) ? (m[k + 'Visible'] === true) : (m[k + 'Visible'] !== false))
  }
  return out
}

// Sanea un patch de perfil (avatar/links/fields/nickname + campos estándar). Cada link/field
// lleva `visible` (oculto = no se comparte). Caps de tamaño para no inflar el `me`. Los ids los pone la UI.
function sanitizeProfilePatch (patch = {}) {
  const out = {}
  if (typeof patch.nickname === 'string') out.nickname = patch.nickname.slice(0, 40)
  // Campos personales estándar (Nombres/Apellidos/Correo/Teléfono/Dirección) + su visibilidad.
  for (const [k, cap] of STD_FIELD_CAPS) {
    if (typeof patch[k] === 'string') out[k] = patch[k].slice(0, cap)
    const vk = k + 'Visible'
    if (typeof patch[vk] === 'boolean') out[vk] = patch[vk]
  }
  if (patch.avatar === null) out.avatar = null
  else if (typeof patch.avatar === 'string') out.avatar = patch.avatar.slice(0, 120000) // ~90KB: data-URI 250x250
  if (typeof patch.avatarVisible === 'boolean') out.avatarVisible = patch.avatarVisible
  if (Array.isArray(patch.links)) {
    // Filtra vacíos ANTES del tope: un draft vacío no debe consumir cupo ni desplazar un enlace real.
    out.links = patch.links.slice(0, 100).map((l) => ({
      id: String(l?.id || '').slice(0, 24),
      type: String(l?.type || 'web').slice(0, 16),
      value: String(l?.value || '').slice(0, 200),
      visible: l?.visible !== false
    })).filter((l) => l.value).slice(0, 30)
  }
  if (Array.isArray(patch.fields)) {
    out.fields = patch.fields.slice(0, 20).map((f) => ({
      id: String(f?.id || '').slice(0, 24),
      label: String(f?.label || '').slice(0, 40),
      value: String(f?.value || '').slice(0, 280),
      visible: f?.visible !== false
    })).filter((f) => f.label || f.value)
  }
  return out
}

export async function createIdentityCore ({ kv: rawKv, peers, makeSync = null, keyStore = null, sessionKv = null, removeAccountOnExpulsion = true, keyLock = null }) {
  const {
    initPeerStorage, loadPeers, savePeers, setPeersDirect, upsertPeer, onDirty
  } = peers

  // ----- multi-perfil: kv SCOPEADO por el perfil activo -----
  // Todas las claves `dotrino.identity.*` (keypair, me, nonces, delegations, vault.*) se
  // namespacean transparentemente bajo `dotrino.identity.p.<currentPid>.*`. Las dos claves
  // globales (lista de perfiles + activo) usan el kv crudo. Cambiar de perfil = setear el
  // activo; la app recarga la página y re-inicializa con el nuevo (no reactivo, por diseño).
  let currentPid = null
  const _scoped = (k) => (!currentPid || k === PROFILES_STORAGE || k === CURRENT_STORAGE)
    ? k : k.replace(/^dotrino\.identity\./, `dotrino.identity.p.${currentPid}.`)
  const kv = {
    getItem: (k) => rawKv.getItem(_scoped(k)),
    setItem: (k, v) => rawKv.setItem(_scoped(k), v),
    removeItem: (k) => rawKv.removeItem(_scoped(k))
  }
  const loadProfiles = () => { try { return JSON.parse(rawKv.getItem(PROFILES_STORAGE) || '[]') || [] } catch { return [] } }
  const saveProfiles = (list) => rawKv.setItem(PROFILES_STORAGE, JSON.stringify(list))

  // ----- la MARCA de «este perfil nació para adoptar la cuenta de una bóveda» -----
  // Unirse a otra cuenta borra la que este perfil tenía, así que no puede pasar por
  // accidente ni deducirse de heurísticas tipo «parece vacío»: se pide a propósito con
  // `createProfile({ forVault: true })` y esa marca es el único permiso que vale.
  // Además identity NO PUEDE ver el contenido del store (vive en otro origen), así que
  // «vacío» no es algo que pueda comprobar por su cuenta.
  // Ver `dotrino-vault/docs/vinculacion-de-cuentas.md` §5.1.
  // La marca vive en DOS sitios porque hay dos formas de tener perfiles: en el
  // navegador son entradas de una lista dentro del mismo almacén (`pendingJoin` en la
  // entrada), y en la bóveda es UN directorio por perfil, donde esa lista está vacía y
  // no hay ninguna entrada que marcar. El kv es lo único que existe siempre y ya está
  // acotado al perfil abierto, así que ahí va la marca de la bóveda.
  const isPendingJoin = (pid = currentPid) =>
    kv.getItem(PENDING_JOIN_STORAGE) === '1' || !!loadProfiles().find((p) => p.id === pid)?.pendingJoin
  const clearPendingJoin = (pid = currentPid) => {
    try { kv.removeItem(PENDING_JOIN_STORAGE) } catch (_) {}
    const list = loadProfiles(); const e = list.find((p) => p.id === pid)
    if (e?.pendingJoin) { delete e.pendingJoin; saveProfiles(list) }
  }

  // ----- keypair loaders -----
  // Con `keyStore` (IndexedDB del navegador): la privada vive como CryptoKey
  // NO EXTRACTABLE — puede FIRMAR/DERIVAR pero nadie (ni este código, ni un XSS)
  // puede leer sus bytes. Migración transparente: si existe el JWK plano viejo en
  // kv, se importa como no extractable y se BORRA el plano. Sin keyStore
  // (Node/tests) se conserva el comportamiento kv anterior.

  const ALGO_OF = {
    sign: { algo: { name: 'ECDSA', namedCurve: 'P-256' }, privUses: ['sign'], pubUses: ['verify'], pairUses: ['sign', 'verify'] },
    enc: { algo: { name: 'ECDH', namedCurve: 'P-256' }, privUses: ['deriveBits', 'deriveKey'], pubUses: [], pairUses: ['deriveBits', 'deriveKey'] }
  }

  async function loadOrCreatePair (kind, storageKey) {
    const { algo, privUses, pubUses, pairUses } = ALGO_OF[kind]
    const importPub = (jwk) => crypto.subtle.importKey('jwk', jwk, algo, true, pubUses)
    if (keyStore) {
      const name = _scoped(storageKey)
      const stored = await keyStore.get(name).catch(() => null)
      if (stored?.privateKey && stored?.publicJwk) {
        return { privateKey: stored.privateKey, publicKey: await importPub(stored.publicJwk), publicJwk: stored.publicJwk }
      }
      // migrar el JWK plano viejo (si hay) → no extractable + borrar el plano
      const raw = kv.getItem(storageKey)
      if (raw) {
        try {
          const { privateJwk, publicJwk } = JSON.parse(raw)
          const privateKey = await crypto.subtle.importKey('jwk', privateJwk, algo, false, privUses)
          await keyStore.set(name, { privateKey, publicJwk })
          kv.removeItem(storageKey)
          return { privateKey, publicKey: await importPub(publicJwk), publicJwk }
        } catch (_) {}
      }
      const pair = await crypto.subtle.generateKey(algo, false, pairUses) // privada NO extractable
      const publicJwk = await crypto.subtle.exportKey('jwk', pair.publicKey)
      await keyStore.set(name, { privateKey: pair.privateKey, publicJwk })
      return { privateKey: pair.privateKey, publicKey: pair.publicKey, publicJwk }
    }
    // ---- camino legado (sin keyStore): JWK en kv, extractable ----
    const raw = kv.getItem(storageKey)
    if (raw) {
      try {
        const guardado = JSON.parse(raw)
        const { publicJwk } = guardado
        // BAJO CANDADO. La mitad PRIVADA viaja sellada con una llave que no está en este
        // disco (la deriva la contraseña del dueño); la PÚBLICA se queda en claro, que es
        // lo que es. Cerrado se devuelve la identidad SIN con qué firmar: se sabe quién
        // eres, no se puede hablar por ti.
        //
        // Y lo que NO se hace, que es el fallo que se paga caro: **no se genera otra**.
        // Un `catch` que cae a `generateKey` con la llave delante, sellada, le cambiaría
        // la identidad a la cuenta y la dejaría fuera de su propio perfil para siempre.
        if (guardado.sealed) {
          const abierto = keyLock?.open ? await keyLock.open(guardado.sealed) : null
          if (!abierto) return { privateKey: null, publicKey: await importPub(publicJwk), publicJwk, locked: true }
          const privateKey = await crypto.subtle.importKey('jwk', JSON.parse(abierto), algo, true, privUses)
          return { privateKey, publicKey: await importPub(publicJwk), publicJwk }
        }
        const privateKey = await crypto.subtle.importKey('jwk', guardado.privateJwk, algo, true, privUses)
        return { privateKey, publicKey: await importPub(publicJwk), publicJwk }
      } catch (e) {
        // Solo se sigue de largo si NO había nada que abrir. Con una llave sellada
        // delante, un error es un error: se propaga en vez de fabricar otra identidad.
        if (String(raw).includes('"sealed"')) throw e
      }
    }
    const pair = await crypto.subtle.generateKey(algo, true, pairUses)
    const privateJwk = await crypto.subtle.exportKey('jwk', pair.privateKey)
    const publicJwk = await crypto.subtle.exportKey('jwk', pair.publicKey)
    await guardarPar(storageKey, privateJwk, publicJwk)
    return { privateKey: pair.privateKey, publicKey: pair.publicKey, publicJwk }
  }

  /**
   * Escribe un par. Si hay candado ABIERTO, la privada va sellada; si no, en claro bajo el
   * cifrado en reposo de siempre. Un perfil sin contraseña se queda como estaba.
   */
  async function guardarPar (storageKey, privateJwk, publicJwk) {
    if (keyLock?.seal) {
      const sealed = await keyLock.seal(JSON.stringify(privateJwk))
      if (sealed) return kv.setItem(storageKey, JSON.stringify({ sealed, publicJwk }))
    }
    kv.setItem(storageKey, JSON.stringify({ privateJwk, publicJwk }))
  }

  /**
   * ECHAR EL CANDADO A LA MAESTRA QUE YA EXISTE: se llama al abrir el perfil, cuando la
   * llave de la contraseña está en la mano. Idempotente.
   */
  async function sealMasterKey () {
    const raw = kv.getItem(KEY_STORAGE)
    if (!raw || !keyLock?.seal) return { ok: false, reason: 'sin-candado' }
    const guardado = JSON.parse(raw)
    if (guardado.sealed) return { ok: true, already: true }
    await guardarPar(KEY_STORAGE, guardado.privateJwk, guardado.publicJwk)
    return { ok: true, sealed: true }
  }

  /**
   * LA LLAVE PARA FIRMAR, o un error con nombre.
   *
   * Todo lo que firme con la maestra pasa por aquí. Cerrada, `keypair.privateKey` es
   * `null` y sin esto reventaría con un `TypeError` a diez marcos de profundidad —
   * ilegible para quien lo recibe e indistinguible de un fallo de red. El código va
   * aparte del texto porque el texto se traduce (ver el contrato de errores).
   */
  function masterKey () {
    if (!keypair?.privateKey) {
      throw Object.assign(new Error('vault locked: the master key is sealed; unlock the profile to sign'), { code: 'vault-locked' })
    }
    return keypair.privateKey
  }

  const loadOrCreateKeypair = () => loadOrCreatePair('sign', KEY_STORAGE)
  const loadOrCreateEncKeypair = () => loadOrCreatePair('enc', ENC_KEY_STORAGE)

  // ----- nonce replay protection (kv-backed) -----

  function loadNonces () {
    try {
      const raw = kv.getItem(NONCE_STORAGE)
      if (!raw) return {}
      const obj = JSON.parse(raw) || {}
      const now = Date.now()
      for (const k of Object.keys(obj)) if (now - obj[k] > NONCE_TTL_MS) delete obj[k]
      return obj
    } catch (_) {
      return {}
    }
  }
  function saveNonces (obj) { kv.setItem(NONCE_STORAGE, JSON.stringify(obj)) }
  function rememberNonce (nonce) { const o = loadNonces(); o[nonce] = Date.now(); saveNonces(o) }
  function isFreshNonce (nonce) { return Object.prototype.hasOwnProperty.call(loadNonces(), nonce) }

  // ----- delegaciones de capacidad emitidas + revocaciones (kv-backed) -----

  function loadJson (key) { try { return JSON.parse(kv.getItem(key) || '{}') || {} } catch (_) { return {} } }

  // YA NO SE PODA NADA, y el motivo es que la poda existía por el reloj.
  //
  // Antes se tiraba lo VENCIDO, porque la renovación automática firmaba un papel nuevo cada
  // 30 días y sin podar cada aparato dejaba doce entradas muertas al año. Con el papel atado
  // al acta esa renovación desaparece: solo se emite uno nuevo cuando el acta cambia lo que
  // ese aparato puede, y ahí `revokePriorCertsFor` ya retira el anterior. O sea que el
  // registro crece con los CAMBIOS DE POLÍTICA, no con el calendario.
  //
  // Se probó podar «lo que el acta ya no nombra» y se descartó: borra en silencio, y un
  // registro que se borra solo es justo lo que no quieres tener delante cuando estás
  // averiguando qué pasó. Las revocaciones, por lo mismo, son PARA SIEMPRE: se podaban a
  // los 30 días porque para entonces el papel estaba vencido seguro, y sin vencimiento
  // olvidar una revocación lo resucita.
  const loadDelegations = () => loadJson(DELEGATIONS_STORAGE)
  const saveDelegations = (o) => kv.setItem(DELEGATIONS_STORAGE, JSON.stringify(o))

  /**
   * Las revocaciones NO se podan por tiempo. Se podaban a los 30 días porque para entonces
   * el papel al que apuntaban estaba vencido seguro; sin vencimiento ese razonamiento se
   * cae, y olvidar una revocación **resucita el papel**. Se quedan mientras el aparato siga
   * en el acta; cuando se le echa, se van con él (`loadDelegations` hace lo mismo).
   */
  function loadRevocations () {
    return loadJson(REVOCATIONS_STORAGE)
  }
  const saveRevocations = (o) => kv.setItem(REVOCATIONS_STORAGE, JSON.stringify(o))

  /**
   * Retira todos los certificados vigentes de la llave `sub`, menos `keepNonce` (el recién
   * emitido, cuando esto se llama desde `signDelegation`). Devuelve los nonces retirados.
   * Solo toca las listas locales: avisar al aparato es cosa del mostrador de enrolamiento,
   * que es quien puede firmar la orden de autoborrado.
   */
  function revokePriorCertsFor (sub, keepNonce) {
    const store = loadDelegations()
    const rev = loadRevocations()
    const now = Date.now()
    const hit = []
    for (const [nonce, d] of Object.entries(store)) {
      if (nonce === keepNonce || d?.sub !== sub || d?.revokedAt) continue
      rev[nonce] = now
      d.revokedAt = now
      hit.push(nonce)
    }
    if (hit.length) { saveRevocations(rev); saveDelegations(store) }
    return hit
  }

  // ----- emparejamiento con el vault del usuario (este dispositivo enrolado) -----
  // Canal de eventos 'vault' (p.ej. el código a tipear durante el emparejamiento).
  const vaultListeners = new Set()
  const emitVault = (p) => { for (const fn of vaultListeners) { try { fn(p) } catch (_) {} } }

  /**
   * BORRADO por revocación. Solo lo dispara un `vault.revoked` FIRMADO por la maestra
   * pineada (lo verifica `remote.js` antes de llamar aquí).
   *
   * Se va la CUENTA ENTERA, no solo el enlace. Una cuenta que vivía en una bóveda y de la
   * que te echaron no es «una cuenta sin bóveda»: no es nada. Dejarla ahí —sin acta, sin
   * certificado, con su llave— era dejar un cascarón que seguía saliendo en el conmutador
   * de perfiles, con su nombre y su foto, sin poder hacer nada y sin que nadie supiera qué
   * era ni cómo quitarlo.
   *
   * El aparato no se queda sin cuenta utilizable: al recargar, el arranque estrena una si
   * no quedó ninguna, o entra en la primera que haya. Así al terminar hay exactamente lo
   * que tiene que haber: un dispositivo con su cuenta, listo para usarse o para volver a
   * conectarse a una bóveda.
   *
   * Los pasos van EN ESTE ORDEN a propósito:
   *   1. fuera el enlace y el acta (deja de poder hablar con la bóveda y de enseñar el
   *      perfil del que lo echaron);
   *   2. 'revoked' → `@dotrino/store` borra el store de ESE perfil (apunta al id que ya
   *      tenía fijado, así que da igual lo que hagamos después con el perfil activo);
   *   3. se borra la cuenta;
   *   4. 'account-removed' → la app RECARGA (multi-perfil no es reactivo, por diseño), y
   *      es el ARRANQUE quien deja puesta la que toque: si no queda ninguna estrena la
   *      primera, y si quedan cae a la primera de la lista. Esa decisión ya vivía ahí.
   *
   * El paso 3 es SOLO del navegador (`removeAccountOnExpulsion`). En Node las cuentas las
   * lleva quien hospeda —el daemon del vault tiene su propio registro de perfiles, en
   * `profiles.js`— y borrar una por debajo le dejaría el suyo apuntando a algo que ya no
   * existe. Ahí se borra el enlace y el acta, y de la cuenta decide su dueño.
   */
  const wipeVaultLink = () => {
    try { kv.removeItem(VAULT_CERT_STORAGE); kv.removeItem(VAULT_DEVICE_STORAGE) } catch (_) {}
    try { kv.removeItem(ACTA_STORAGE) } catch (_) {}
    emitVault({ phase: 'revoked' })
    // Sin `await`: quien llama es un manejador de mensajes que no espera nada (y si algo
    // aquí revienta, el enlace y el acta ya se fueron, que es lo que no puede quedar).
    if (removeAccountOnExpulsion) removeThisAccount().catch(() => {})
  }

  /** Borra la cuenta de ESTE dispositivo al ser expulsado; ver `wipeVaultLink`. */
  let removingAccount = false
  async function removeThisAccount () {
    // UNA VEZ: puede haber varias peticiones en vuelo y a todas les llega el mismo aviso.
    if (removingAccount) return
    removingAccount = true
    const gone = currentPid
    try { await purgeProfile(gone) } catch (e) {
      emitVault({ phase: 'account-removed', removed: gone, error: e?.message || String(e) })
      return
    }
    // Y ya está: qué cuenta queda puesta lo resuelve el ARRANQUE al recargar, que es donde
    // esa decisión ya vivía —si no queda ninguna estrena la primera, y si quedan cae a la
    // primera de la lista—. No hace falta decidirlo aquí también.
    emitVault({ phase: 'account-removed', removed: gone, current: currentPid })
  }

  /**
   * Deja ABIERTA otra cuenta de este dispositivo: puntero, peers, llaves y `me`. Es lo que
   * el arranque hace con la cuenta activa, en una función, para que crear una cuenta y
   * volver atrás cuando algo falla sean el mismo camino recorrido en los dos sentidos.
   *
   * Ojo: no es «cambiar de cuenta» de cara a las apps (eso exige recargar, multi-perfil no
   * es reactivo). Es dejar esta identidad coherente consigo misma antes de contestar.
   */
  async function openProfileInMemory (pid) {
    currentPid = pid
    rawKv.setItem(CURRENT_STORAGE, pid)
    await peers.setProfile?.(pid)
    await initPeerStorage()
    keypair = await loadOrCreateKeypair(); publickeyJwkStr = JSON.stringify(keypair.publicJwk)
    encKeypair = await loadOrCreateEncKeypair(); encPublickeyJwkStr = JSON.stringify(encKeypair.publicJwk)
    const saved = loadMe()
    me = (saved && saved.publickey === publickeyJwkStr)
      ? { ...saved, encryptionPubkey: encPublickeyJwkStr }
      : { publickey: publickeyJwkStr, encryptionPubkey: encPublickeyJwkStr }
    return { id: pid, name: me.nickname || '', pubkey: publickeyJwkStr }
  }

  /**
   * Tira la cuenta que NACIÓ para un emparejamiento que no llegó a término, y vuelve a la
   * que estabas usando.
   *
   * Sin esto, cada intento fallido dejaba una cuenta fantasma —vacía, sin bóveda y encima
   * puesta como activa—: probar tres veces con el código vencido te dejaba tres cuentas
   * que no eran de nadie y la tuya sin abrir. La cuenta que se descarta es siempre una
   * recién creada por `vaultPair`, así que no hay nada dentro que perder.
   */
  async function discardBornProfile (pid, backTo) {
    try {
      await purgeProfile(pid)
      if (backTo && loadProfiles().some((p) => p.id === backTo)) await openProfileInMemory(backTo)
    } catch (e) {
      console.warn('[identity] could not discard the account born for the pairing:', e?.message || e)
    }
  }

  /** El certificado de bóveda guardado en OTRA cuenta de este dispositivo (sin abrirla). */
  const vaultCertOf = (pid) => {
    try {
      const raw = rawKv.getItem(VAULT_CERT_STORAGE.replace(/^dotrino\.identity\./, `dotrino.identity.p.${pid}.`))
      return raw ? JSON.parse(raw) : null
    } catch (_) { return null }
  }

  /** La cuenta de este dispositivo que YA está emparejada con la bóveda `master`, si la hay. */
  const profilePairedWith = (master) => {
    if (!master) return null
    return loadProfiles().find((p) => vaultCertOf(p.id)?.master === master) || null
  }

  /**
   * Borra un perfil y todo lo suyo. Sin preguntas: el freno de «no te quedes sin ninguna»
   * es de la interfaz y vive en `deleteProfile`.
   */
  async function purgeProfile (id) {
    const list = loadProfiles().filter((p) => p.id !== id)
    saveProfiles(list)
    for (const s of ['keypair', 'enc-keypair', 'me', 'nonces', 'delegations', 'revocations', 'vault.device', 'vault.cert', 'acta', 'renounced']) {
      rawKv.removeItem(`dotrino.identity.p.${id}.${s}`)
    }
    // …y sus CryptoKeys no extractables del keyStore (IndexedDB).
    if (keyStore) {
      for (const s of ['keypair', 'enc-keypair']) {
        try { await keyStore.remove(`dotrino.identity.p.${id}.${s}`) } catch (_) {}
      }
    }
    if (currentPid === id) {
      if (list.length) { currentPid = list[0].id; rawKv.setItem(CURRENT_STORAGE, currentPid) }
      else {
        // No queda ninguna: el arranque estrenará la primera. Se borra el puntero, pero
        // `currentPid` se deja como está a propósito — sin él, el kv deja de estar
        // scopeado y cualquier escritura de aquí a la recarga caería en las claves SIN
        // namespace, que son justo las que el arranque adopta como «Perfil 1». Apuntando
        // a un perfil que ya no existe, lo que se escriba es inerte.
        rawKv.removeItem(CURRENT_STORAGE)
      }
    }
    return { ok: true, current: currentPid }
  }

  /**
   * El vault RECHAZÓ una petición diciendo «revocado». Ese mensaje NO va firmado: lo
   * puede falsificar cualquiera que conozca la pubkey de este dispositivo, así que
   * **jamás borra nada** (sería un wipe-DoS: destruir datos ajenos con un mensaje suelto,
   * prohibido por `dotrino-vault/docs/pairing-protocol.md §2.3`). Lo único que hacemos es
   * DEGRADAR: avisar a la app de que la bóveda nos está rechazando, y que sea el usuario
   * quien decida. El borrado real llega por `vault.revoked` firmado (ver `wipeVaultLink`).
   */
  const handleVaultError = (e) => {
    if (e && /\brevoked\b/.test(e.message || '')) emitVault({ phase: 'rejected', reason: e.message })
    throw e
  }
  /** Id estable y corto de una llave de cifrado: con esto se indexan las envolturas. */
  const encKeyId = async (encPub) => (await pubkeyIdOf(encPub)).slice(0, 16)

  const loadVaultCert = () => { try { return JSON.parse(kv.getItem(VAULT_CERT_STORAGE) || 'null') } catch (_) { return null } }
  const loadVaultDevice = () => {
    try {
      const d = JSON.parse(kv.getItem(VAULT_DEVICE_STORAGE) || 'null')
      if (!d) return null
      // Marcador nuevo (o JWK legado que ES la llave del perfil): usar la CryptoKey
      // no extractable del perfil para firmar; nada de privadas en claro.
      if (d.useIdentityKey || (d.publickey === publickeyJwkStr && !d.privateJwk)) {
        return { publickey: publickeyJwkStr, privateKey: masterKey() }
      }
      // MIGRACIÓN: el emparejamiento viejo persistía la privada del perfil en
      // claro aquí. Si es la misma llave del perfil, reemplazar por el marcador
      // (borra el último JWK plano) y firmar con la CryptoKey.
      if (d.privateJwk && d.publickey === publickeyJwkStr) {
        kv.setItem(VAULT_DEVICE_STORAGE, JSON.stringify({ useIdentityKey: true, publickey: publickeyJwkStr }))
        return { publickey: publickeyJwkStr, privateKey: masterKey() }
      }
      return d // legado real (dispositivo con llave propia distinta)
    } catch (_) { return null }
  }

  // ----- ACTA DE PERFIL: qué llaves son de este perfil y qué puede hacer cada una -----
  // Diseño en `dotrino-vault/docs/acta-de-perfil.md`. Aquí solo se guarda, se lee y se
  // sella; las reglas (sellador único, seq/prev, no dejar el perfil sin firmante) viven en
  // `acta.js`, que es puro y está probado aparte.
  const loadActa = () => { try { return JSON.parse(kv.getItem(ACTA_STORAGE) || 'null') } catch (_) { return null } }
  const saveActa = (a) => kv.setItem(ACTA_STORAGE, JSON.stringify(a))
  // VENTANA DE RETENCIÓN (§1.3): el master conserva las últimas actas para que un miembro
  // que estuvo apagado pueda comprobar el encadenamiento al volver. Un tercero no las
  // necesita —le basta el snapshot actual—, pero entre miembros hay que poder verificar
  // que la nueva desciende de la que uno tenía. Más viejo que la ventana ⇒ re-admitirse.
  const ACTA_WINDOW = 50
  const loadHistory = () => { try { return JSON.parse(kv.getItem(ACTA_HISTORY_STORAGE) || '[]') || [] } catch (_) { return [] } }
  /**
   * LOS ESLABONES DE LA CADENA DE SELLADORES NO CADUCAN (dueño, 2026-08-31).
   *
   * El resto sí: la ventana existe para que un miembro que estuvo apagado compruebe el
   * encadenamiento al volver, y para eso las últimas bastan. Pero los eslabones donde
   * CAMBIÓ quién sella son otra cosa — son lo que deja a un EXTRAÑO anclar en el génesis
   * y saber que hablas tú. Si la poda se los lleva, nadie de fuera puede verificar nada
   * tuyo nunca más, y no hay forma de reconstruirlos.
   *
   * El comentario de la ventana decía «un tercero no las necesita, le basta el snapshot
   * actual». Era cierto mientras el ancla fuera una llave fija; dejó de serlo en cuanto
   * varias llaves pueden sellar.
   *
   * No crecen: solo suman al añadir o quitar una bóveda, que casi nunca pasa. Un usuario
   * normal guarda uno —el génesis— para siempre.
   */
  const pushHistory = (acta) => {
    if (!acta) return
    const h = loadHistory().filter((a) => a.seq !== acta.seq)
    h.push(acta)
    h.sort((a, b) => a.seq - b.seq)
    const ventana = h.slice(-ACTA_WINDOW)
    const enVentana = new Set(ventana.map((a) => a.seq))
    const eslabones = h.filter((a) => a.sealerChanged && !enVentana.has(a.seq))
    kv.setItem(ACTA_HISTORY_STORAGE, JSON.stringify([...eslabones, ...ventana].sort((a, b) => a.seq - b.seq)))
  }

  /**
   * La CADENA DE SELLADORES para mandarla con una firma: `[génesis, …cambios…, actual]`.
   * Es lo que un extraño necesita para anclar en el `profileId`, y es corta a propósito —
   * no lleva las actas de emparejar aparatos, que son casi todas.
   */
  const sealerChain = () => {
    const cur = loadActa()
    if (!cur) return []
    // La vigente cuenta como parte del material aunque todavía no esté en la historia
    // (ahí entra al dejar de serlo). Sin esto, una cuenta recién creada devolvía [].
    const porSeq = new Map([...loadHistory(), cur].map((a) => [a.seq, a]))
    const eslabones = [...porSeq.values()].filter((a) => a.sealerChanged).sort((a, b) => a.seq - b.seq)
    // Y la actual va al final si ella misma no es un eslabón: el verificador necesita ver
    // la cabeza para saber en qué `seq` está y quién la selló.
    return eslabones.length && eslabones[eslabones.length - 1].seq === cur.seq ? eslabones : [...eslabones, cur]
  }

  const loadRenounces = () => { try { return JSON.parse(kv.getItem(RENOUNCE_STORAGE) || '[]') || [] } catch (_) { return [] } }
  const saveRenounces = (l) => kv.setItem(RENOUNCE_STORAGE, JSON.stringify(l))

  /** ¿Es ESTE dispositivo el master (el único que puede sellar)? */
  /**
   * ¿PUEDO SELLAR? Antes era «¿soy el master?» y miraba un campo. Con sellar convertido en
   * permiso, la pregunta correcta es esta — y su respuesta puede ser «sí» en más de un
   * aparato a la vez, que es justo el punto del multivault.
   */
  const amMaster = () => Acta.canSeal(loadActa(), publickeyJwkStr, loadRenounces())

  /**
   * Quien sella SOBRES (la bóveda) pone aquí una función que estrena una llave de sellado
   * y devuelve su pública. Se llama en cada acta, porque esa llave rota con el acta.
   * Un navegador no sella secretos: se queda en `null` y el acta no lleva llave.
   */
  let sealKeyProvider = null

  /** Sella con la llave del perfil (CryptoKey, puede ser no extractable). */
  const seal = (acta) => Acta.sealActa({ acta, privateKey: masterKey() })

  /**
   * Aplica cambios, sella y guarda. Solo funciona si este dispositivo es el master: es la
   * regla 1 del modelo, y `applyChanges` la vuelve a comprobar por su cuenta.
   */
  async function sealChanges (changes) {
    const acta = loadActa()
    if (!acta) throw new Error('this profile has no record yet')
    // LA LLAVE DE SELLADO ROTA CON EL ACTA (§8.9 de `secretos-sellados.md`): si quien usa
    // esta identidad sella secretos —la bóveda—, le pedimos una llave nueva para nombrarla
    // aquí. Si no hay proveedor, o falla, el acta sale igual con la llave de antes: no
    // admitir un aparato porque no se pudo estrenar una llave sería el peor de los canjes.
    let sealPub = null
    if (sealKeyProvider) {
      try { sealPub = await sealKeyProvider() } catch (_) { sealPub = null }
    }
    const next = await Acta.applyChanges(acta, changes, { by: publickeyJwkStr, sealPub })
    const sealed = await seal(next)
    pushHistory(acta) // la que deja de ser vigente entra en la ventana de retención
    saveActa(sealed)
    emitVault({ phase: 'acta', seq: sealed.seq, sealedBy: sealed.sealedBy })
    return sealed
  }

  /**
   * Si el perfil todavía no tiene acta, la crea: un miembro (esta llave), que es el master,
   * con todas las capacidades. `profileId` = la pubkey de este perfil → el perfil se llama
   * como la identidad que el usuario ya tenía, así que no hay nada que migrar.
   */
  async function ensureActa (label = '') {
    if (loadActa()) return loadActa()
    const base = Acta.genesisActa({
      pub: publickeyJwkStr, encPub: encPublickeyJwkStr, label: label || me?.nickname || ''
    })
    // La primera generación de la clave de contenido va DENTRO del acta de génesis, no en
    // un cambio aparte: un perfil recién nacido está en `seq 1`, no en `seq 2`.
    try {
      const { generation } = await Content.makeGeneration({ members: base.members, gen: 1 })
      base.keyring = [generation]
    } catch (e) { console.warn('[identity] could not create the content key:', e.message) }
    const genesis = await seal(base)
    saveActa(genesis)
    // EL GÉNESIS VA A LA HISTORIA DESDE EL PRIMER DÍA. Es el ancla de la cadena de
    // selladores —el único eslabón autofirmado por la llave que da nombre al perfil— y
    // sin él nadie de fuera puede verificar nada de esta cuenta, nunca. Antes solo se
    // guardaba lo que DEJABA de ser vigente, así que una cuenta que nunca cambió su acta
    // no tenía génesis guardado y su cadena salía vacía.
    pushHistory(genesis)
    return loadActa()
  }

  // ----- CLAVE DE CONTENIDO del perfil (para que todos tus dispositivos lean lo mismo) -----
  // Las llaves de FIRMA no se mueven nunca; la de CONTENIDO se comparte por diseño,
  // envuelta a la llave de cifrado de cada miembro (ver content.js).

  /** Mi copia de la clave de contenido vigente, o null si aún no me la han envuelto. */
  const myCek = () => Content.myContentKey({
    keyring: loadActa()?.keyring, myPub: publickeyJwkStr, myEncPrivateKey: encKeypair.privateKey
  })

  /** Envuelve la clave vigente para un miembro recién admitido (no hace falta rotar). */
  async function wrapForNewMember (pub) {
    const acta = loadActa()
    const gen = (acta?.keyring || []).at(-1)
    const m = acta?.members.find((x) => x.pub === pub)
    if (!gen || !m?.encPub) return false
    const mine = await myCek()
    if (!mine) return false
    const wrap = await Content.wrapForMember({ cek: mine.cek, memberEncPub: m.encPub })
    await sealChanges([{ op: 'wrap', gen: mine.gen, pub, wrap }])
    return true
  }

  /**
   * QUITAR UN APARATO, entero y de una vez.
   *
   * Esto era media operación repetida en dos sitios, y cada mitad fallaba a su manera:
   * la consola web sacaba al miembro del acta pero le dejaba los certificados vivos
   * (seguía pudiendo entrar y firmar), y la pantalla del PC le retiraba los
   * certificados pero lo dejaba dentro del acta (seguía apareciendo en la lista de la
   * web, «un dispositivo que en la bóveda ya no existe»). Las dos caras del mismo acto
   * van juntas o no van:
   *
   *   1. fuera del acta   → deja de ser miembro y deja de figurar en ninguna lista;
   *   2. fuera los papeles → ningún certificado suyo sirve ya para entrar;
   *   3. clave nueva      → no podrá abrir el contenido NUEVO. Lo que ya leyó no
   *      vuelve: eso no se puede deshacer y no se promete.
   */
  async function removeDevice (pub) {
    if (!pub || typeof pub !== 'string') throw new Error('pub (device pubkey) required')
    // Si no es miembro (papeles de antes de que existiera el acta), no es un error: se
    // le quitan igual los certificados, que es lo que de verdad le abría la puerta.
    const isMember = (loadActa().members || []).some((m) => m.pub === pub)
    const acta = isMember ? await sealChanges([{ op: 'remove', pub }]) : loadActa()
    const nonces = revokePriorCertsFor(pub, null)
    let rotated = null
    try { rotated = await rotateCek() } catch (_) {}
    return { ok: true, seq: acta.seq, nonces, rotated, revokedAt: Date.now() }
  }

  /** Rota la clave: generación nueva envuelta SOLO a los miembros actuales. */
  async function rotateCek () {
    const acta = loadActa()
    const gen = ((acta.keyring || []).at(-1)?.gen || 0) + 1
    const { generation, sinLlave } = await Content.makeGeneration({ members: acta.members, gen })
    await sealChanges([{ op: 'keyring', generation }])
    return { gen, sinLlave }
  }

  /**
   * UNIRSE a la cuenta de la bóveda con la que te acabas de emparejar (camino B de
   * `dotrino-vault/docs/vinculacion-de-cuentas.md`). NO es adoptar una versión nueva de TU
   * acta: es que ESTA llave pase a ser de OTRA cuenta, y por lo tanto **deja de tener la
   * suya**.
   *
   * Por eso solo procede sobre un perfil que **nació para esto** (`createProfile({ forVault:
   * true })`). Sin la marca no se une: se devuelve el conflicto para que la consola ofrezca
   * crear una cuenta nueva, y **no se escribe nada**.
   *
   * Antes bastaba con ser el único miembro del acta propia, y entonces se sobrescribía el
   * acta sin preguntar: una cuenta con su contenido pasaba a colgar de otra en silencio —
   * justo la fusión de cuentas que el modelo prohíbe (§4). Eso se acabó.
   */
  async function joinProfile (candidate) {
    const v = await Acta.verifyActa({ acta: candidate })
    if (!v.ok) return { joined: false, reason: 'acta-invalida:' + v.reason }
    if (!candidate.members.some((m) => m.pub === publickeyJwkStr)) {
      return { joined: false, reason: 'no-soy-miembro' }
    }
    const current = loadActa()

    // Misma cuenta: no es unirse, es ponerse al día. Va por las reglas de adopción (§2.4.1).
    if (current && current.profileId === candidate.profileId) {
      const r = await adoptActa(candidate)
      return { joined: r.adopted, reason: r.reason, profileId: candidate.profileId, seq: r.seq }
    }

    if (current && !isPendingJoin()) {
      return {
        joined: false,
        reason: 'perfil-con-datos',
        profileId: current.profileId,
        seq: current.seq,
        members: current.members.length
      }
    }

    saveActa(candidate)
    // El historial era de la cuenta anterior y no encadena con esta. La que se abandona es
    // siempre una génesis recién nacida (lo garantiza la marca), así que no hay nada que
    // retener; guardarla aquí solo mezclaría dos cuentas en la misma ventana (§1.3).
    kv.setItem(ACTA_HISTORY_STORAGE, '[]')
    clearPendingJoin()
    emitVault({ phase: 'acta', seq: candidate.seq, sealedBy: candidate.sealedBy, joined: true })
    return { joined: true, profileId: candidate.profileId, seq: candidate.seq }
  }

  /**
   * El emparejamiento propiamente dicho: con la cuenta ya decidida (`vaultPair`), genera el
   * cert contra la bóveda y entra a su cuenta. Aparte para que la decisión de CUÁL cuenta y
   * el deshacerla si esto falla vivan juntos arriba, y aquí solo quede el trámite.
   */
  async function pairWithVault ({ qr, label = '' }) {
    // Usa la PROPIA llave de identidad de este navegador como dispositivo: el cert delega
    // TU identidad (P) desde la maestra M → una sola identidad (signData/identify/cert = P).
    // La privada es la CryptoKey del perfil (no extractable): se pasa como `privateKey`
    // y NO se persiste ningún JWK del dispositivo (marcador useIdentityKey).
    const device = { publickey: publickeyJwkStr, privateKey: masterKey() }
    // Si esta identidad ya existía por su cuenta, se lleva un certificado de continuidad
    // firmado por ella misma: es el puente para que su reputación previa siga contando.
    // Solo si esta llave tenía vida propia. Una recién creada para adoptar (camino B) no
    // tiene pasado que salvar: mandarle un puente de continuidad sería puro ruido.
    const mine = loadActa()
    const continuity = (mine && mine.members.length === 1 && !isPendingJoin())
      ? await Acta.makeContinuity({ member: publickeyJwkStr, from: mine.profileId, privateKey: masterKey() })
      : null
    const res = await remoteEnroll({ qr, device, continuity, encPub: encPublickeyJwkStr, label: label || me?.nickname || '', onChallenge: (c) => emitVault({ phase: 'challenge', deviceId: c.deviceId, code: c.code }) })
    kv.setItem(VAULT_DEVICE_STORAGE, JSON.stringify({ useIdentityKey: true, publickey: publickeyJwkStr }))
    kv.setItem(VAULT_CERT_STORAGE, JSON.stringify({ cert: res.cert, master: res.master, proxy: res.proxy, deviceId: res.deviceId, pairedAt: Date.now() }))
    // Conectarse a una bóveda es ENTRAR A SU CUENTA: el acta viene con el cert.
    const unido = res.acta ? await joinProfile(res.acta) : { joined: false, reason: 'sin-acta' }
    emitVault({ phase: 'paired', deviceId: res.deviceId, master: res.master, join: unido })
    pullProfileFromVault() // adoptar el perfil que ya viva en el vault (si hay)
    return { ok: true, deviceId: res.deviceId, master: res.master, seq: res.cert.seq, scope: res.cert.scope, join: unido }
  }

  /**
   * Adopta un acta que llega de otro miembro, si gana según §2.4.1 (seq mayor que encadene,
   * o el traspaso a igual seq). Nunca retrocede.
   */
  /**
   * Adopta una CADENA de actas, una a una. Es lo que permite ponerse al día tras estar
   * apagado sin bajar la guardia: cada eslabón se comprueba contra el anterior en vez de
   * aceptar un salto a ciegas.
   */
  async function adoptChain (chain) {
    let last = null
    for (const a of [...(chain || [])].sort((x, y) => x.seq - y.seq)) {
      const r = await adoptActa(a)
      if (r.adopted) last = r
    }
    return last || { adopted: false, reason: 'nada-que-adoptar', seq: loadActa()?.seq ?? null }
  }

  /**
   * SI EL ACTA NUEVA YA NO ME NOMBRA, ME BORRO. Sin botón y sin preguntar.
   *
   * El acta manda —es quien dice de quién es el perfil— y viene FIRMADA por el master, así
   * que enterarse por ella es tan bueno como el aviso de expulsión: no hay wipe-DoS que
   * valga, porque un tercero no puede fabricar un acta sellada. Antes solo se hacía caso al
   * aviso, que es un mensaje suelto: si se perdía —el aparato apagado, la cola del proxy
   * dura 24 h— el aparato se quedaba enseñando para siempre una cuenta de la que ya lo
   * habían echado, aunque la propia acta que acababa de recibir dijera lo contrario.
   */
  async function adoptActa (candidate) {
    const current = loadActa()
    const r = await Acta.canAdopt({ candidate, current })
    if (!r.adopt) return { adopted: false, reason: r.reason, seq: current?.seq ?? null }
    saveActa(candidate)
    emitVault({ phase: 'acta', seq: candidate.seq, sealedBy: candidate.sealedBy, adopted: r.reason })
    const sigoDentro = (candidate.members || []).some((m) => m?.pub === publickeyJwkStr)
    if (!sigoDentro) {
      console.warn('[identity] the new record no longer lists this device: removing the account')
      wipeVaultLink()
      return { adopted: true, expelled: true, reason: r.reason, seq: candidate.seq }
    }
    return { adopted: true, reason: r.reason, seq: candidate.seq }
  }

  // ----- renovación AUTOMÁTICA del cert (sin QR ni aprobación) -----
  // Con el cert aún vigente y quedando <15 días, cualquier uso del vault dispara en
  // segundo plano un `vault.renew`: el vault firma un cert fresco (30 días) para la
  // misma sub-clave y scope. Mientras uses el ecosistema ~1 vez al mes, nunca vence.
  // Un cert YA vencido o revocado no puede renovarse (ahí sí, re-emparejar).
  // Ya no hay ventana de caducidad: el papel no vence. Lo único que obliga a pedir uno
  // nuevo es que el ACTA diga algo distinto de lo que lleva escrito.
  const RENEW_RETRY_MS = 60 * 60 * 1000 // si falla (vault apagado), no insistir >1 vez/hora
  let renewLastTry = 0
  /**
   * ¿El cert se quedó atrás respecto del ACTA? El acta es la política (lo que el dueño
   * decidió); el cert es su reflejo, y solo se refresca al renovar. Sin esta comprobación,
   * un permiso concedido después de emparejar tardaba en llegar lo que tardara el cert en
   * acercarse a su caducidad: hasta 30 días. En la práctica, dar «administra» y no ver
   * NUNCA aparecer la consola remota.
   */
  function certDesfasadoDelActa () {
    try {
      const v = loadVaultCert(); const acta = loadActa()
      if (!v?.cert || !acta) return false
      const debeTener = Acta.memberScopes(acta, publickeyJwkStr)
      if (!debeTener.length) return false           // ya no soy miembro: renovar no toca
      const tiene = new Set(v.cert.scope || [])
      return debeTener.length !== tiene.size || debeTener.some((s) => !tiene.has(s))
    } catch (_) { return false }
  }

  function maybeRenewVaultCert () {
    try {
      const v = loadVaultCert(); const device = loadVaultDevice()
      if (!v?.cert || !device) return
      const now = Date.now()
      // UN SOLO MOTIVO: que el acta diga algo distinto de lo que lleva el papel. El otro
      // —«se acerca su fin»— era el que obligaba a la bóveda a firmar sola cada mes, y con
      // él se va la última razón por la que la maestra tenía que estar disponible sin nadie
      // delante. Renovar pasa a ocurrir justo cuando ya hay una selladora abierta, porque
      // cambiar el acta ES tenerla abierta.
      if (!certDesfasadoDelActa()) return
      if (now - renewLastTry < RENEW_RETRY_MS) return
      renovarCert().catch(() => {}) // best-effort: el cert vigente sigue sirviendo mientras tanto
    } catch (_) {}
  }

  /** Pide un cert fresco y lo guarda. Devuelve promesa para poder ESPERARLO cuando hace falta. */
  async function renovarCert () {
    const v = loadVaultCert(); const device = loadVaultDevice()
    if (!v?.cert || !device) return null
    renewLastTry = Date.now()
    const { cert } = await remoteRenew({ master: v.master, proxy: v.proxy, device, cert: v.cert, onRevoked: wipeVaultLink })
    kv.setItem(VAULT_CERT_STORAGE, JSON.stringify({ ...v, cert, renewedAt: Date.now() }))
    emitVault({ phase: 'renewed', seq: cert.seq })
    return cert
  }

  // ----- me (kv-backed) -----

  function loadMe () {
    try { const raw = kv.getItem(ME_STORAGE); return raw ? JSON.parse(raw) : null }
    catch (_) { return null }
  }
  function saveMe (next) {
    kv.setItem(ME_STORAGE, JSON.stringify(next))
    me = next
    if (sync) sync.markDirty()
  }

  // ----- endorsement verify / merge (sync) -----

  async function verifyEndorsement (env) {
    if (!env || typeof env !== 'object') return false
    const { subject, rating, notes, ratedBy, issuedAt, signature } = env
    if (typeof ratedBy !== 'string' || typeof signature !== 'string') return false
    const canonical = canonicalStringify({ subject, rating, notes: typeof notes === 'string' ? notes : '', ratedBy, issuedAt })
    try { return await verifyBytes(ratedBy, new TextEncoder().encode(canonical), signature) }
    catch { return false }
  }

  async function mergePeerMaps (localPeers, remotePeers) {
    const out = { ...localPeers }
    let changed = false
    const allKeys = new Set([...Object.keys(localPeers || {}), ...Object.keys(remotePeers || {})])
    for (const pk of allKeys) {
      const a = localPeers[pk]
      const b = remotePeers[pk]
      if (a && !b) continue
      if (!a && b) {
        const adopted = { ...b }
        if (Array.isArray(adopted.endorsements)) {
          const verified = []
          for (const e of adopted.endorsements) if (await verifyEndorsement(e)) verified.push(e)
          adopted.endorsements = verified
        }
        out[pk] = adopted
        changed = true
        continue
      }
      const merged = { ...a }
      const aSeen = a.lastSeen || 0
      const bSeen = b.lastSeen || 0
      const newer = bSeen > aSeen ? b : a
      if (newer === b) {
        if (b.nickname !== undefined) merged.nickname = b.nickname
        if (b.notes !== undefined) merged.notes = b.notes
        if (b.contactNotes !== undefined) merged.contactNotes = b.contactNotes
        if (b.encryptionPubkey) merged.encryptionPubkey = b.encryptionPubkey
        if (typeof b.rating === 'number') merged.rating = b.rating
      }
      merged.firstSeen = Math.min(a.firstSeen || aSeen || Date.now(), b.firstSeen || bSeen || Date.now())
      merged.lastSeen = Math.max(aSeen, bSeen)
      merged.isContact = !!(a.isContact || b.isContact)
      const aMine = a.myRating
      const bMine = b.myRating
      if (bMine && (!aMine || (bMine.issuedAt || 0) > (aMine.issuedAt || 0))) {
        if (await verifyEndorsement(bMine)) merged.myRating = bMine
      }
      const byRater = new Map()
      for (const e of (a.endorsements || [])) if (e?.ratedBy) byRater.set(e.ratedBy, e)
      for (const e of (b.endorsements || [])) {
        if (!e?.ratedBy) continue
        const prev = byRater.get(e.ratedBy)
        if (prev && (prev.issuedAt || 0) >= (e.issuedAt || 0)) continue
        if (await verifyEndorsement(e)) byRater.set(e.ratedBy, e)
      }
      merged.endorsements = Array.from(byRater.values())
        .sort((x, y) => (y.issuedAt || 0) - (x.issuedAt || 0)).slice(0, 50)
      if (a.queryStats || b.queryStats) {
        merged.queryStats = {
          queriesMade: Math.max(a.queryStats?.queriesMade || 0, b.queryStats?.queriesMade || 0),
          queriesKnown: Math.max(a.queryStats?.queriesKnown || 0, b.queryStats?.queriesKnown || 0)
        }
      }
      if (JSON.stringify(merged) !== JSON.stringify(a)) changed = true
      out[pk] = merged
    }
    return { merged: out, changed }
  }

  async function exportLocalForSync () {
    // Las llaves privadas NO viajan al sync (no extractables): Drive respalda
    // perfil+contactos; la identidad se recupera ENROLANDO el navegador al vault.
    return {
      privateJwk: null,
      publicJwk: keypair?.publicJwk || null,
      encPrivateJwk: null,
      encPublicJwk: encKeypair?.publicJwk || null,
      me: loadMe(),
      peers: loadPeers()
    }
  }

  async function adoptJwkPair (kind, storageKey, privateJwk, publicJwk) {
    const { algo, privUses } = ALGO_OF[kind]
    if (keyStore) {
      const privateKey = await crypto.subtle.importKey('jwk', privateJwk, algo, false, privUses)
      await keyStore.set(_scoped(storageKey), { privateKey, publicJwk })
      kv.removeItem(storageKey)
    } else {
      kv.setItem(storageKey, JSON.stringify({ privateJwk, publicJwk }))
    }
  }

  async function applyMergedFromSync (merged) {
    const localKeys = kv.getItem(KEY_STORAGE) || (keyStore && (await keyStore.get(_scoped(KEY_STORAGE)).catch(() => null)))
    if (!localKeys && merged.privateJwk && merged.publicJwk) {
      await adoptJwkPair('sign', KEY_STORAGE, merged.privateJwk, merged.publicJwk)
      if (merged.encPrivateJwk && merged.encPublicJwk) {
        await adoptJwkPair('enc', ENC_KEY_STORAGE, merged.encPrivateJwk, merged.encPublicJwk)
      }
      keypair = await loadOrCreateKeypair()
      publickeyJwkStr = JSON.stringify(keypair.publicJwk)
      encKeypair = await loadOrCreateEncKeypair()
      encPublickeyJwkStr = JSON.stringify(encKeypair.publicJwk)
      if (merged.me) kv.setItem(ME_STORAGE, JSON.stringify(merged.me))
    } else if (localKeys && merged.publicJwk) {
      const localPub = JSON.parse(localKeys).publicJwk
      if (JSON.stringify(localPub) !== JSON.stringify(merged.publicJwk)) {
        console.warn('[vault.sync] Remote keypair differs from local — keeping local keypair.')
      }
    }
    if (merged.peers && typeof merged.peers === 'object') setPeersDirect(merged.peers)
  }

  async function mergeForSync (local, remote) {
    if (!remote) return { merged: local, changed: false }
    const { merged: mergedPeers, changed } = await mergePeerMaps(local.peers || {}, remote.peers || {})
    return {
      merged: {
        privateJwk: local.privateJwk || remote.privateJwk,
        publicJwk: local.publicJwk || remote.publicJwk,
        encPrivateJwk: local.encPrivateJwk || remote.encPrivateJwk,
        encPublicJwk: local.encPublicJwk || remote.encPublicJwk,
        me: local.me || remote.me,
        peers: mergedPeers
      },
      changed
    }
  }

  // ----- runtime state -----

  let keypair = null
  let publickeyJwkStr = null
  let encKeypair = null
  let encPublickeyJwkStr = null
  let sync = null
  let me = null

  // ----- handlers (idénticos a la versión iframe) -----

  // Merge de un patch de perfil en `me` (preserva lo demás), saneado. Refleja el nombre en la
  // meta del perfil (para el switcher). Devuelve el `me` resultante.
  function applyMeUpdate (patch) {
    const clean = sanitizeProfilePatch(patch || {})
    me = { ...(me || {}), ...clean, publickey: publickeyJwkStr, encryptionPubkey: encPublickeyJwkStr, updatedAt: Date.now() }
    if (clean.avatar === null) delete me.avatar
    saveMe(me)
    if (typeof clean.nickname === 'string') {
      const list = loadProfiles(); const e = list.find((p) => p.id === currentPid)
      if (e && e.name !== clean.nickname) { e.name = clean.nickname; saveProfiles(list) }
    }
    pushProfileToVault() // best-effort: mismo perfil en todos los dispositivos
    return me
  }

  // ----- PERFIL COMPARTIDO entre dispositivos (vía el vault) -----
  // El vault guarda la copia autoritativa del perfil (profileSet/profileGet en su
  // store). Al editar aquí se EMPUJA; al arrancar se JALA y gana el más nuevo
  // (updatedAt). Las llaves (publickey/encryptionPubkey) son POR dispositivo y
  // nunca se sincronizan. Todo best-effort: sin vault encendido no molesta.
  /**
   * QUÉ ES PÚBLICO Y QUÉ ES PRIVADO, en un solo sitio.
   *
   * Es la misma regla que ya decidía `publicMe()`: lo que marcaste visible es lo que ve
   * quien pregunta desde fuera. Lo que cambia es que ahora esa marca decide **cómo se
   * guarda** —en claro o en sobre— y no solo qué se enseña (`docs/datos-del-perfil.md` §2).
   *
   * @returns {Array<{key:string, value:string, cls:'public'|'private'}>}
   */
  function profileFields (m) {
    const out = []
    const add = (key, value, esPublico) => {
      if (typeof value !== 'string' || !value) return
      out.push({ key, value, cls: esPublico ? 'public' : 'private' })
    }
    // La clase la decide `profileFieldClasses`, que está exportada y probada: tener la
    // regla en dos sitios es como acaban divergiendo lo que se enseña y lo que se guarda.
    const clases = profileFieldClasses(m)
    for (const [k, cls] of Object.entries(clases)) add(k, m[k], cls === 'public')
    // Enlaces y campos libres viajan como UN dato cada lista: son arrays y partirlos por
    // elemento haría que reordenarlos pareciera media docena de cambios.
    const visibles = (arr) => (arr || []).filter((x) => x.visible !== false).map(({ visible, ...r }) => r)
    const ocultos = (arr) => (arr || []).filter((x) => x.visible === false)
    if (Array.isArray(m.links)) {
      const v = visibles(m.links); if (v.length) add('links', JSON.stringify(v), true)
      const o = ocultos(m.links); if (o.length) add('links_private', JSON.stringify(o), false)
    }
    if (Array.isArray(m.fields)) {
      const v = visibles(m.fields); if (v.length) add('fields', JSON.stringify(v), true)
      const o = ocultos(m.fields); if (o.length) add('fields_private', JSON.stringify(o), false)
    }
    return out
  }

  /**
   * EMPUJAR EL PERFIL, DATO A DATO Y EN SOBRES (`docs/datos-del-perfil.md`).
   *
   * Antes se mandaba el `me` entero por `profileSet`, y eso exigía la bóveda ABIERTA —era
   * ella quien decidía guardarlo, porque lo veía en claro—. Ahora cada dato viaja como un
   * sobre que la bóveda no puede leer ni fabricar, así que aceptarlo no es decisión suya y
   * el candado deja de estorbar. Los públicos van en claro porque no hay a quién sellarlos.
   *
   * Solo se manda LO QUE CAMBIÓ: cada escritura estrena generación, y reescribir un dato
   * que no cambió llenaría el llavero y el histórico de ruido.
   */
  async function pushProfileFields (v, device) {
    const campos = profileFields(me || {})
    const pendientes = campos.filter((c) => lastPushedFields[c.key] !== c.cls + '\u0000' + c.value)
    if (!pendientes.length) return

    const privados = pendientes.filter((c) => c.cls === 'private')
    let destinatarios = null
    if (privados.length) {
      destinatarios = await remoteStore({
        master: v.master, proxy: v.proxy, device, cert: v.cert,
        method: 'profileRecipients', args: {}, onRevoked: wipeVaultLink
      })
      if (!destinatarios?.recoveryPub) {
        throw new Error('the vault did not say who to seal the profile for')
      }
    }

    for (const c of pendientes) {
      const args = { key: c.key, cls: c.cls }
      if (c.cls === 'public') {
        args.value = c.value
      } else {
        // Envolver solo necesita PÚBLICAS: por eso esto se puede hacer aquí, en el
        // navegador, sin que ninguna privada ande suelta.
        const cek = await Content.makeContentKey()
        const e = await Content.encryptWithCek({ cek, gen: 0, plaintext: c.value })
        const wraps = { '#recovery': await Content.wrapForMember({ cek, memberEncPub: destinatarios.recoveryPub }) }
        for (const m of destinatarios.members || []) {
          if (m.encPub) wraps[m.pub] = await Content.wrapForMember({ cek, memberEncPub: m.encPub })
        }
        args.sobre = { e, wraps }
      }
      await remoteStore({ master: v.master, proxy: v.proxy, device, cert: v.cert, method: 'profilePut', args, onRevoked: wipeVaultLink })
      lastPushedFields[c.key] = c.cls + '\u0000' + c.value
    }
  }

  /** Lo último que se consiguió empujar de cada dato, para no reescribir lo que no cambió. */
  const lastPushedFields = Object.create(null)

  let profilePushTimer = null
  /**
   * CÓMO FUE EL ÚLTIMO EMPUJÓN. Se guarda para que la UI pueda decir «esto no se guardó»
   * en vez de enseñar un perfil que solo existe en este aparato. Sin esto, el usuario ve
   * su cambio en pantalla y cree que está hecho.
   */
  // `ok: null` = TODAVÍA NO SE HA EMPUJADO NADA. Nacía en `true`, así que «nunca se
  // intentó» y «salió bien» se veían igual — un valor por defecto que dice que sí, en la
  // función que existe justamente para no tragarse el fallo. Quien pregunte tiene que
  // poder distinguir las tres cosas, y por eso son tres valores y no dos.
  let lastProfilePush = { ok: null, at: 0, error: null }
  function pushProfileToVault () {
    const v = loadVaultCert(); const device = loadVaultDevice()
    if (!v?.cert || !device) return
    clearTimeout(profilePushTimer)
    profilePushTimer = setTimeout(() => {
      pushProfileFields(v, device)
        .then(() => { lastProfilePush = { ok: true, at: Date.now(), error: null } })
        .catch((e) => {
          // EL FALLO SE VE. Aquí había un `.catch(() => {})` con un comentario que decía
          // «se reintenta en la próxima edición», y era falso de dos maneras: la próxima
          // edición se encontraba la bóveda cerrada otra vez, y mientras tanto el aparato
          // se quedaba con datos que nadie más tenía. Es exactamente lo que produjo el
          // «edito y no funciona, y cada dispositivo ve algo distinto».
          lastProfilePush = { ok: false, at: Date.now(), error: e?.message || String(e) }
          try { console.warn('[identity] the profile change did NOT reach the vault:', lastProfilePush.error) } catch (_) {}
        })
    }, 800) // debounce: ediciones seguidas = un solo push
  }
  /**
   * SIN PAPEL, SE PREGUNTA. Y AL ARRANCAR, SOLO.
   *
   * Un aparato que perdió su certificado no puede firmar, ni leer, ni renovar: TODO lo que
   * habla con la bóveda lo exige. Así que tampoco tenía forma de enterarse de que lo habían
   * echado —el aviso firmado se emite al quitarlo, y si estaba apagado la cola del proxy
   * dura 24 h— y se quedaba enseñando para siempre una cuenta que ya no era suya.
   *
   * Se pregunta con la llave del propio aparato, que es la que el acta nombra, y a la
   * maestra que dice la propia acta (`sealer`). Si sigue dentro, no pasa nada. Si no, la
   * bóveda contesta con el aviso FIRMADO y aquí se ejecuta el borrado.
   */
  async function askIfStillAMember () {
    try {
      const acta = loadActa()
      if (!acta || Acta.canSeal(acta, publickeyJwkStr)) return       // sello yo: no hay cuenta ajena que confirmar
      // El acta que ya tengo no me nombra: no hace falta preguntar nada, el acta manda y va
      // firmada. (Normalmente esto lo resuelve `adoptActa` al recibirla.)
      if (!(acta.members || []).some((m) => m?.pub === publickeyJwkStr)) {
        console.warn('[identity] the stored record does not list this device: removing the account')
        return wipeVaultLink()
      }
      const v = loadVaultCert()
      if (v?.cert && loadVaultDevice()) return                      // con papel, ya lo comprueba el camino normal
      const r = await remoteCheck({
        master: Acta.sealersOf(acta)[0] || null,
        proxy: v?.proxy || 'wss://proxy.dotrino.com',
        device: { publickey: publickeyJwkStr, privateKey: masterKey() },
        onRevoked: wipeVaultLink
      })
      if (r?.error) console.warn('[identity] could not confirm membership with the vault:', r.error)
    } catch (e) { console.warn('[identity] could not confirm membership with the vault:', e?.message || e) }
  }

  /**
   * EL TOQUE AL ARRANCAR. Corre en cada apertura de la identidad, así que es también el
   * momento en el que este aparato se entera de que lo echaron: la bóveda contesta al
   * revocado —tiene que hacerlo— con el aviso FIRMADO, que es lo único que le borra la
   * cuenta. Sin `onRevoked` ese aviso llegaba y se tiraba a la basura, y el aparato se
   * quedaba enseñando un perfil del que ya no era, para siempre, sin que nadie pulsara
   * nada porque no había nada que pulsar.
   */
  /**
   * COMPONE EL `me` CON LO QUE SE PUDO ABRIR. Devuelve si cambió algo, para no avisar de
   * una sincronización que no movió nada.
   *
   * `links`/`fields` viajan como UN dato cada lista (y su gemelo privado), así que aquí se
   * vuelven a juntar con su marca de visibilidad — que es de dónde salió la separación.
   */
  function applyPulledProfile (content) {
    const antes = JSON.stringify(me || {})
    const next = { ...(me || {}) }
    const lista = (json, visible) => {
      try { return (JSON.parse(json) || []).map((x) => ({ ...x, visible })) } catch (_) { return [] }
    }
    for (const [k, v] of Object.entries(content)) {
      if (k === 'links' || k === 'fields' || k === 'links_private' || k === 'fields_private') continue
      next[k] = v
    }
    if (content.links != null || content.links_private != null) {
      next.links = [...lista(content.links, true), ...lista(content.links_private, false)]
    }
    if (content.fields != null || content.fields_private != null) {
      next.fields = [...lista(content.fields, true), ...lista(content.fields_private, false)]
    }
    next.publickey = publickeyJwkStr
    next.encryptionPubkey = encPublickeyJwkStr
    if (JSON.stringify(next) === antes) return false
    me = next
    saveMe(me)
    if (typeof next.nickname === 'string') {
      const list = loadProfiles(); const e = list.find((p) => p.id === currentPid)
      if (e && e.name !== next.nickname) { e.name = next.nickname; saveProfiles(list) }
    }
    return true
  }

  async function pullProfileFromVault () {
    try {
      const v = loadVaultCert(); const device = loadVaultDevice()
      // SE TOCA AUNQUE EL PAPEL ESTÉ VENCIDO. Antes se salía sin llamar, y ese es justo el
      // aparato que más falta le hace: no puede firmar, ni leer, ni renovar —o sea que ya
      // está roto para todo— y encima era el único que no tenía forma de enterarse de que
      // lo habían echado. La bóveda contesta «vencido» y no pasa nada; y si además ya no
      // está en el acta, contesta con el aviso firmado y aquí se le borra la cuenta.
      if (!v?.cert || !device) return
      // EL PAQUETE LO ARMA ESTE APARATO (dueño, 2026-09-03). La bóveda entrega los sobres
      // que tiene; aquí se abren los que nos tocan y se compone el perfil.
      const b = await remoteStore({ master: v.master, proxy: v.proxy, device, cert: v.cert, method: 'profileBundle', args: {}, onRevoked: wipeVaultLink })
      const entries = b?.entries || {}
      if (!Object.keys(entries).length) {
        // La bóveda aún no tiene perfil: sembrar con el local (si tiene contenido).
        if (me?.nickname || me?.avatar) pushProfileToVault()
        return
      }
      const keyring = (b.wraps || []).map((w) => ({ gen: w.gen, wraps: { [publickeyJwkStr]: w.wrap } }))
      const content = {}
      for (const [key, e] of Object.entries(entries)) {
        try {
          if (e.cls === 'public') { content[key] = e.pubv; continue }
          content[key] = await Content.decryptWithKeyring({
            envelope: e.e, keyring, myPub: publickeyJwkStr, myEncPrivateKey: encKeypair.privateKey
          })
        } catch (_) {
          // SIN ENVOLTURA NO SE INVENTA NADA. Un aparato que entró después de escribirse un
          // dato no tiene su llave hasta que el dueño abra la bóveda; dejarlo fuera es
          // correcto, y poner un valor por defecto sería fabricar un perfil falso.
        }
      }
      if (!applyPulledProfile(content)) return
      emitVault({ phase: 'profile-sync' })
    } catch (_) { /* vault apagado: el perfil local sigue mandando */ }
  }

  // ----- CANDADO por contraseña (OPCIONAL, POR PERFIL, LOCAL de este dispositivo) -----
  // El hash (PBKDF2) vive solo en el kv de ESTE navegador: no viaja al vault ni a
  // otros dispositivos (cada uno decide si protege su acceso y con qué contraseña).
  // Al desbloquear, la prueba va a sessionStorage (por PESTAÑA): sobrevive al
  // refresco y muere al cerrar la pestaña. No cifra datos: es un gate de acceso.
  const PWD_STORAGE = 'dotrino.identity.pwd'
  const PWD_SESSION = 'dotrino.identity.pwd.proof'
  const PWD_ITER = 300000
  let locked = false
  const b64 = (buf) => btoa(String.fromCharCode(...new Uint8Array(buf)))
  async function derivePwd (password, saltB64, iter) {
    const salt = Uint8Array.from(atob(saltB64), (c) => c.charCodeAt(0))
    const km = await crypto.subtle.importKey('raw', new TextEncoder().encode(String(password)), 'PBKDF2', false, ['deriveBits'])
    const bits = await crypto.subtle.deriveBits({ name: 'PBKDF2', hash: 'SHA-256', salt, iterations: iter }, km, 256)
    return b64(bits)
  }
  const loadPwd = () => { try { return JSON.parse(kv.getItem(PWD_STORAGE) || 'null') } catch (_) { return null } }
  const sessionProof = () => { try { return sessionKv?.getItem(_scoped(PWD_SESSION)) || null } catch (_) { return null } }
  function refreshLockState () {
    const pwd = loadPwd()
    locked = !!pwd && sessionProof() !== pwd.verifier
  }
  // Métodos disponibles AUN bloqueado (gestionar perfiles y el propio candado;
  // nada que lea datos o firme).
  const LOCK_EXEMPT = new Set([
    'profileLockStatus', 'unlockProfile', 'listProfiles', 'currentProfile',
    'switchProfile', 'createProfile',
    'profileActa', 'profileMembers', 'myMembership', 'isMaster', 'sealerChain'
  ])

  const handlers = {
    async profileLockStatus () {
      refreshLockState()
      return { protected: !!loadPwd(), locked }
    },
    async unlockProfile ({ password }) {
      const pwd = loadPwd()
      if (!pwd) { locked = false; return { ok: true, locked: false } }
      // Freno de fuerza bruta (un PIN de 4 dígitos se adivina probando): tras 5
      // fallos, espera exponencial (2^n s, tope 5 min) persistida en el kv.
      const tries = (() => { try { return JSON.parse(kv.getItem('dotrino.identity.pwd.tries') || 'null') } catch (_) { return null } })() || { n: 0, at: 0 }
      const waitMs = tries.n >= 5 ? Math.min(2 ** (tries.n - 4) * 1000, 5 * 60 * 1000) : 0
      const left = tries.at + waitMs - Date.now()
      if (left > 0) throw new Error(`too many attempts: wait ${Math.ceil(left / 1000)} s`)
      const proof = await derivePwd(password, pwd.salt, pwd.iter)
      if (proof !== pwd.verifier) {
        kv.setItem('dotrino.identity.pwd.tries', JSON.stringify({ n: tries.n + 1, at: Date.now() }))
        throw new Error('wrong password')
      }
      kv.removeItem('dotrino.identity.pwd.tries')
      try { sessionKv?.setItem(_scoped(PWD_SESSION), proof) } catch (_) {}
      locked = false
      return { ok: true, locked: false }
    },
    // Poner/cambiar contraseña (requiere estar desbloqueado; cambiar exige la actual vía unlock previo).
    async setProfilePassword ({ password }) {
      if (locked) throw new Error('profile locked')
      if (!password || String(password).length < 4) throw new Error('password must be at least 4 characters')
      const salt = b64(crypto.getRandomValues(new Uint8Array(16)))
      const verifier = await derivePwd(password, salt, PWD_ITER)
      kv.setItem(PWD_STORAGE, JSON.stringify({ v: 1, salt, iter: PWD_ITER, verifier }))
      try { sessionKv?.setItem(_scoped(PWD_SESSION), verifier) } catch (_) {}
      return { ok: true }
    },
    async removeProfilePassword () {
      if (locked) throw new Error('profile locked')
      kv.removeItem(PWD_STORAGE)
      try { sessionKv?.removeItem(_scoped(PWD_SESSION)) } catch (_) {}
      return { ok: true }
    },

    async makeChallenge () {
      const nonce = crypto.randomUUID()
      rememberNonce(nonce)
      return { nonce }
    },

    async signChallenge ({ nonce }) {
      if (!nonce || typeof nonce !== 'string') throw new Error('nonce required')
      const bytes = new TextEncoder().encode(nonce)
      const signature = await signBytes(masterKey(), bytes)
      return { nonce, publickey: publickeyJwkStr, encryptionPubkey: encPublickeyJwkStr, signature }
    },

    async verifyResponse ({ nonce, publickey, signature, encryptionPubkey }) {
      if (!nonce || !publickey || !signature) return { ok: false }
      if (!isFreshNonce(nonce)) return { ok: false, reason: 'nonce expired or unknown' }
      const bytes = new TextEncoder().encode(nonce)
      const ok = await verifyBytes(publickey, bytes, signature)
      if (!ok) return { ok: false }
      const patch = {}
      if (typeof encryptionPubkey === 'string' && encryptionPubkey) patch.encryptionPubkey = encryptionPubkey
      const peer = upsertPeer(publickey, patch)
      return { ok: true, publickey, encryptionPubkey: encryptionPubkey || null, peer }
    },

    async getPeer ({ publickey }) {
      const p = loadPeers()
      return p[publickey] || null
    },

    async setNickname ({ publickey, nickname }) {
      return upsertPeer(publickey, { nickname: String(nickname || '').slice(0, 40) })
    },

    async setRating ({ publickey, rating, notes }) {
      const r = Math.max(0, Math.min(5, Number(rating) || 0))
      const safeNotes = typeof notes === 'string' ? notes.slice(0, 500) : ''
      const issuedAt = Date.now()
      const envelope = { subject: publickey, rating: r, notes: safeNotes, ratedBy: publickeyJwkStr, issuedAt }
      const sigBytes = new TextEncoder().encode(canonicalStringify(envelope))
      const signature = await signBytes(masterKey(), sigBytes)
      const myRating = { ...envelope, signature }
      return upsertPeer(publickey, { myRating, rating: r, notes: safeNotes })
    },

    async mergeEndorsements ({ subject, endorsements, askerPubkey }) {
      if (!subject || !Array.isArray(endorsements)) return { merged: 0, total: 0 }
      const peersMap = loadPeers()
      const existing = peersMap[subject] || { publickey: subject, firstSeen: Date.now() }
      const current = Array.isArray(existing.endorsements) ? existing.endorsements : []
      const byRater = new Map()
      for (const e of current) if (e?.ratedBy) byRater.set(e.ratedBy, e)
      let merged = 0
      for (const env of endorsements) {
        if (!env || typeof env !== 'object') continue
        const { subject: s, rating, notes, ratedBy, issuedAt, signature } = env
        if (s !== subject) continue
        if (typeof ratedBy !== 'string' || !ratedBy) continue
        if (ratedBy === publickeyJwkStr) continue
        if (typeof signature !== 'string') continue
        if (typeof rating !== 'number' || rating < 0 || rating > 5) continue
        const prev = byRater.get(ratedBy)
        if (prev && (prev.issuedAt || 0) >= (issuedAt || 0)) continue
        const canonical = canonicalStringify({ subject: s, rating, notes: typeof notes === 'string' ? notes : '', ratedBy, issuedAt })
        const ok = await verifyBytes(ratedBy, new TextEncoder().encode(canonical), signature)
        if (!ok) continue
        byRater.set(ratedBy, env)
        merged++
      }
      const all = Array.from(byRater.values()).sort((a, b) => (b.issuedAt || 0) - (a.issuedAt || 0)).slice(0, 50)
      peersMap[subject] = { ...existing, publickey: subject, endorsements: all, lastSeen: Date.now() }
      if (typeof askerPubkey === 'string' && askerPubkey && askerPubkey !== publickeyJwkStr) {
        const askerRecord = peersMap[askerPubkey] || { publickey: askerPubkey, firstSeen: Date.now() }
        const stats = askerRecord.queryStats || { queriesMade: 0, queriesKnown: 0 }
        stats.queriesMade = (stats.queriesMade || 0) + 1
        const knewIt = !!(existing.myRating) || (Array.isArray(existing.endorsements) && existing.endorsements.length > 0)
        if (knewIt) stats.queriesKnown = (stats.queriesKnown || 0) + 1
        peersMap[askerPubkey] = { ...askerRecord, queryStats: stats, lastSeen: askerRecord.lastSeen || Date.now() }
      }
      savePeers(peersMap)
      return { merged, total: all.length }
    },

    async getRatingsForSubject ({ subject }) {
      const p = loadPeers()
      const r = p[subject]
      return { mine: r?.myRating || null, endorsements: Array.isArray(r?.endorsements) ? r.endorsements : [] }
    },

    async recordQuery ({ askerPubkey, subject }) {
      if (!askerPubkey || askerPubkey === publickeyJwkStr) return null
      const peersMap = loadPeers()
      const askerRecord = peersMap[askerPubkey] || { publickey: askerPubkey, firstSeen: Date.now() }
      const stats = askerRecord.queryStats || { queriesMade: 0, queriesKnown: 0 }
      stats.queriesMade = (stats.queriesMade || 0) + 1
      if (subject) {
        const subjectRec = peersMap[subject]
        const knewIt = !!(subjectRec?.myRating) || (Array.isArray(subjectRec?.endorsements) && subjectRec.endorsements.length > 0)
        if (knewIt) stats.queriesKnown = (stats.queriesKnown || 0) + 1
      }
      peersMap[askerPubkey] = { ...askerRecord, queryStats: stats, lastSeen: askerRecord.lastSeen || Date.now() }
      savePeers(peersMap)
      return peersMap[askerPubkey]
    },

    async listPeers () {
      return Object.values(loadPeers()).sort((a, b) => (b.lastSeen || 0) - (a.lastSeen || 0))
    },

    async forgetPeer ({ publickey }) {
      const p = loadPeers()
      delete p[publickey]
      savePeers(p)
    },

    async addContact ({ publickey, nickname, encryptionPubkey, lastToken, notes }) {
      if (!publickey) throw new Error('publickey required')
      const patch = { isContact: true }
      if (nickname != null) patch.nickname = String(nickname).slice(0, 40)
      if (encryptionPubkey) patch.encryptionPubkey = encryptionPubkey
      if (lastToken) patch.lastToken = lastToken
      if (notes != null) patch.contactNotes = String(notes).slice(0, 300)
      return upsertPeer(publickey, patch)
    },

    async updateContact ({ publickey, patch }) {
      if (!publickey) throw new Error('publickey required')
      if (!patch || typeof patch !== 'object') return null
      const allowed = {}
      for (const k of ['nickname', 'encryptionPubkey', 'lastToken', 'contactNotes']) if (k in patch) allowed[k] = patch[k]
      return upsertPeer(publickey, allowed)
    },

    async removeContact ({ publickey }) {
      const p = loadPeers()
      const rec = p[publickey]
      if (!rec) return null
      delete rec.isContact
      p[publickey] = rec
      savePeers(p)
      return rec
    },

    /**
     * Firma. Con `sign` en el acta, firma aquí mismo (como siempre). Si este dispositivo
     * RENUNCIÓ a firmar —o el master se lo quitó— la petición se re-enruta a quien sí
     * firma (tu bóveda) y vuelve su firma: la identidad de cara a los demás sigue siendo
     * UNA, y este aparato deja de poder firmar por ti aunque lo roben.
     *
     * El `identify` del transporte es la excepción y SIEMPRE se firma en local: es lo que
     * identifica esta conexión ante el proxy, no una firma tuya de cara a nadie, y sin él
     * el dispositivo no podría ni hablar con la bóveda para pedirle que firme.
     */
    async signData ({ data }) {
      if (data == null) throw new Error('data required')
      const local = async () => {
        const bytes = new TextEncoder().encode(canonicalStringify(data))
        const acta = loadActa()
        return {
          signature: await signBytes(masterKey(), bytes),
          publickey: publickeyJwkStr,
          // A NOMBRE DE QUIÉN VA. `publickey` es la llave de ESTE aparato, y las apps la
          // venían guardando como si fuera la identidad: publicar desde el teléfono y
          // desde el PC quedaba a nombre de dos «personas» distintas, y la reputación se
          // repartía entre ellas en vez de acumularse.
          //
          // La identidad es el `profileId` —la llave del génesis, que no cambia nunca— y
          // la cadena es lo que prueba que este firmante le pertenece. Van juntos porque
          // por separado no sirven: el `profileId` solo es una afirmación, y la cadena sin
          // él no dice a quién atribuir.
          profileId: acta?.profileId || publickeyJwkStr,
          chain: sealerChain()
        }
      }
      const acta = loadActa()
      const puedeFirmar = !acta || Acta.memberCan(acta, publickeyJwkStr, 'sign', loadRenounces())
      if (puedeFirmar || data?.op === 'identify') return local()

      const v = loadVaultCert(); const device = loadVaultDevice()
      if (!v?.cert || !device) {
        throw new Error('profile-without-signer: this device no longer signs for you and is not connected to any vault that can')
      }
      maybeRenewVaultCert()
      try { return await remoteSign({ master: v.master, proxy: v.proxy, device, cert: v.cert, payload: data, onRevoked: wipeVaultLink }) }
      catch (e) { return handleVaultError(e) }
    },

    // ----- delegación de capacidad: la maestra firma un cert para una sub-clave -----
    // de dispositivo `sub`, acotado por `scope` y `exp`, revocable por `nonce`.
    // Es la ÚNICA forma en que la autoridad sale de la clave maestra, y va limitada.

    /**
     * EL PAPEL NO CADUCA POR RELOJ: lleva el `seq` del acta con el que se emitió.
     *
     * `ttlMs`/`exp` se aceptan y se IGNORAN a propósito, para no romper a quien todavía los
     * pasa (el daemon, `enroll.js`). Reventar ahí dejaría sin emparejar a media cadena por
     * un parámetro que ya no significa nada.
     */
    async signDelegation ({ sub, scope, nonce, label, supersede }) {
      if (!sub || typeof sub !== 'string') throw new Error('sub (device pubkey) required')
      if (!scope || (typeof scope !== 'string' && !Array.isArray(scope))) throw new Error('scope required')
      const iat = Date.now()
      // El acta con la que se emite. Sin acta no hay papel: el certificado dice «una
      // selladora de ESTE perfil, mirando ESTA acta, avaló esta llave», y sin acta no se
      // puede decir ninguna de las dos cosas.
      const acta = loadActa()
      if (!acta) throw Object.assign(new Error('this profile has no record to issue against'), { code: 'sin-acta' })
      // `iss` se FUERZA a la propia maestra: el usuario no puede emitir cert para otro emisor.
      const cert = await signDelegationWith(masterKey(), publickeyJwkStr, { sub, scope, iat, seq: acta.seq, nonce: nonce || crypto.randomUUID() })
      const store = loadDelegations()
      store[cert.nonce] = { nonce: cert.nonce, sub, scope, iat, seq: acta.seq, label: typeof label === 'string' ? label.slice(0, 60) : '' }
      saveDelegations(store)
      // UNA LLAVE, UN CERTIFICADO VIGENTE. Renovar emitía uno nuevo y dejaba vivo el
      // anterior: el mismo aparato salía dos veces en la lista (parecían dos máquinas) y,
      // peor, «quitar el dispositivo» revocaba UN cert y el aparato seguía entrando con el
      // otro — a veces justo con el que llevaba `vault:admin`. Al firmar, los certs previos
      // de esa misma `sub` se retiran. Silencioso a propósito: NO se emite el aviso de
      // autoborrado (eso solo lo dispara una revocación de verdad, desde el mostrador).
      if (supersede !== false) revokePriorCertsFor(sub, cert.nonce)
      return { cert }
    },

    /**
     * Retira TODOS los certificados vigentes de un dispositivo (por su llave `sub`).
     * Es lo que significa «quitar el dispositivo»: revocar por `nonce` retira un papel,
     * no al aparato, que puede tener otros.
     */
    async revokeDevice ({ sub }) {
      if (!sub || typeof sub !== 'string') throw new Error('sub (device pubkey) required')
      return removeDevice(sub)
    },

    async revokeDelegation ({ nonce }) {
      if (!nonce || typeof nonce !== 'string') throw new Error('nonce required')
      const rev = loadRevocations()
      rev[nonce] = Date.now()
      saveRevocations(rev)
      const store = loadDelegations()
      if (store[nonce]) { store[nonce].revokedAt = rev[nonce]; saveDelegations(store) }
      return { ok: true, revokedAt: rev[nonce] }
    },

    // `issued` = lo que HOY sirve para entrar. Antes devolvía el almacén entero, revocados
    // incluidos (revocar solo estampa `revokedAt`), así que la consola seguía pintando como
    // activo un cert ya retirado: pulsabas «quitar» y la fila no se movía. Los caducados ya
    // los poda `loadDelegations`. El histórico retirado va aparte, en `revokedCerts`.
    async listDelegations () {
      const store = loadDelegations(); const rev = loadRevocations()
      const all = Object.values(store).sort((a, b) => (b.iat || 0) - (a.iat || 0))
      return {
        issued: all.filter((d) => !d.revokedAt && !rev[d.nonce]),
        revokedCerts: all.filter((d) => d.revokedAt || rev[d.nonce]),
        revoked: Object.keys(rev).map(nonce => ({ nonce, revokedAt: rev[nonce] }))
      }
    },

    // ----- perfiles (multi-perfil por dispositivo) -----
    // Cambiar/crear setea el perfil activo; la app RECARGA la página y re-inicializa con él
    // (no reactivo, por diseño). Las apps abiertas conservan el perfil con el que cargaron.
    /**
     * Los perfiles de este dispositivo, para el conmutador. Incluye el AVATAR de cada uno:
     * sin él, la lista caía siempre al identicon automático y tu foto no aparecía —aunque la
     * hubieras subido— porque el avatar vive en el `me` de cada perfil, no en el registro.
     */
    async listProfiles () {
      return loadProfiles().map((p) => {
        let avatar = null
        try {
          const raw = p.id === currentPid ? JSON.stringify(me || null) : rawKv.getItem(`dotrino.identity.p.${p.id}.me`)
          const m = raw ? JSON.parse(raw) : null
          if (m && typeof m.avatar === 'string') avatar = m.avatar
        } catch (_) {}
        // QUÉ PERFIL ESTÁ CONECTADO A UNA BÓVEDA, Y CUÁL APRUEBA.
        //
        // Con varios perfiles en el mismo aparato, el pedido que timbra el teléfono es de
        // UNO de ellos, y puede no ser el activo. Sin esto la pantalla de Pedidos abría con
        // el que hubiera y decía «este aparato no aprueba pedidos» — falso: el que aprueba
        // era otro perfil, y no había forma de saber cuál.
        //
        // Se lee el CERT de cada perfil, que está en claro en el kv (no es un secreto: dice
        // qué puede hacer este aparato, no cómo). Es solo lectura y no hace falta la llave
        // del otro perfil, así que no se cambia el activo ni se firma nada.
        let vault = false; let approve = false
        try {
          const raw = p.id === currentPid ? kv.getItem(VAULT_CERT_STORAGE) : rawKv.getItem(`dotrino.identity.p.${p.id}.vault.cert`)
          const v = raw ? JSON.parse(raw) : null
          vault = !!v?.cert
          approve = vault && (v.cert.scope || []).includes('vault:approve')
        } catch (_) {}
        return { id: p.id, name: p.name || '', pubkey: p.pubkey || null, avatar, current: p.id === currentPid, pendingJoin: !!p.pendingJoin, vault, approve }
      })
    },
    async currentProfile () {
      const e = loadProfiles().find((p) => p.id === currentPid) || {}
      return { id: currentPid, name: e.name || me?.nickname || '', pubkey: publickeyJwkStr }
    },
    /**
     * Crea una cuenta más en este dispositivo, con su propia llave.
     *
     * `forVault: true` la marca como **nacida para adoptar** la cuenta de una bóveda
     * (camino B): es el único permiso que acepta `joinProfile`, y se consume al unirse.
     * Sin la marca, la cuenta es de este dispositivo y nadie se la puede llevar.
     */
    async createProfile ({ name, forVault = false } = {}) {
      const pid = 'p' + crypto.randomUUID().slice(0, 8)
      // `from`: de qué cuenta se venía. Solo se anota en la que nace para una bóveda, y es
      // lo que deja volver a casa si el emparejamiento no llega a término —también cuando
      // se cortó por lo bruto (cerrar la pestaña) y quien limpia es el arranque siguiente.
      const from = currentPid
      await openProfileInMemory(pid)
      me = { publickey: publickeyJwkStr, encryptionPubkey: encPublickeyJwkStr, nickname: String(name || '').slice(0, 40) }
      saveMe(me)
      const list = loadProfiles()
      list.push({ id: pid, name: me.nickname, pubkey: publickeyJwkStr, ...(forVault ? { pendingJoin: true, ...(from ? { from } : {}) } : {}) })
      saveProfiles(list)
      await ensureActa(me.nickname) // el perfil nuevo nace con su acta (él mismo es el master)
      return { id: pid, name: me.nickname, pubkey: publickeyJwkStr, pendingJoin: !!forVault }
    },
    async switchProfile ({ id } = {}) {
      if (!loadProfiles().find((p) => p.id === id)) throw new Error('profile does not exist')
      rawKv.setItem(CURRENT_STORAGE, id) // la app recarga la página → re-init con el nuevo perfil
      return { id }
    },
    async renameProfile ({ id, name } = {}) {
      const list = loadProfiles(); const e = list.find((p) => p.id === (id || currentPid))
      if (!e) throw new Error('profile does not exist')
      e.name = String(name || '').slice(0, 40); saveProfiles(list)
      if (e.id === currentPid) { me = { ...(me || {}), nickname: e.name }; saveMe(me) }
      return { id: e.id, name: e.name }
    },
    async deleteProfile ({ id } = {}) {
      const list = loadProfiles()
      // El freno es de la INTERFAZ: el botón «Borrar» de la página de perfiles no puede
      // dejarte sin ninguna de un clic. La expulsión no pasa por aquí (ver `purgeProfile`):
      // ahí sí se va la última, porque no es un descuido sino que te echaron.
      if (list.length <= 1) throw new Error('cannot delete the only profile')
      if (!list.find((p) => p.id === id)) throw new Error('profile does not exist')
      return purgeProfile(id)
    },

    // ----- ACTA DE PERFIL -----
    // Quién es de este perfil y qué puede hacer cada uno. Solo el master sella; los demás
    // adoptan. Ver `dotrino-vault/docs/acta-de-perfil.md`.

    async profileActa () {
      const acta = loadActa()
      if (!acta) return null
      return { acta, isMaster: amMaster(), myCaps: Acta.effectiveCaps(acta, publickeyJwkStr, loadRenounces()) }
    },

    /**
     * LA CADENA DE SELLADORES, para mandarla junto con una firma.
     *
     * Es lo que deja a un EXTRAÑO comprobar que quien firmó habla por esta identidad, sin
     * preguntarle a nadie: `[génesis, …cambios de sellador…, acta actual]`. No son todas
     * las actas —eso crecería con cada emparejamiento— sino solo los eslabones donde
     * cambió quién sella, que casi nunca pasa. Lo normal es longitud 1: el génesis.
     *
     * Una cuenta de una sola bóveda devuelve SIEMPRE eso y nada más, y no puede quedarse
     * obsoleta: su conjunto de selladores no puede cambiar, porque el único no puede
     * quitarse a sí mismo y no hay otro que se lo quite.
     */
    async sealerChain () { return sealerChain() },

    /**
     * Quien sella sobres de secretos (la bóveda) registra aquí cómo estrenar su LLAVE DE
     * SELLADO: una función que crea el par, se guarda la privada y devuelve la pública. Se
     * llama al sellar cada acta, que es cuando esa llave rota (§8.9).
     *
     * Es opt-in a propósito: una identidad de navegador no sella nada, y un acta sin llave
     * de sellado es perfectamente válida.
     */
    setSealKeyProvider ({ provider } = {}) {
      sealKeyProvider = typeof provider === 'function' ? provider : null
      return { ok: true, set: !!sealKeyProvider }
    },

    /**
     * Estrena la llave de sellado sin tocar a nadie más: pide una al proveedor y la nombra
     * en un acta nueva. Es lo que hace la bóveda al arrancar si el acta no tiene llave, o
     * si la que nombra no es suya (el disco se restauró, otro master la puso…).
     */
    async rotateSealKey () {
      if (!sealKeyProvider) throw new Error('this identity does not seal envelopes')
      const acta = await sealChanges([])
      return { ok: true, seq: acta.seq, sealPub: acta.sealPub }
    },

    /** La llave con la que se firmaron los sobres de un acta dada. Para VERIFICARLOS. */
    sealKeyAt ({ seq } = {}) {
      return Acta.sealKeyAt(loadActa(), seq)
    },

    async profileMembers () {
      const acta = loadActa()
      if (!acta) return { members: [], profileId: null, seq: 0, sealers: [] }
      const pend = loadRenounces()
      const members = await Promise.all(acta.members.map(async (m) => ({
        pub: m.pub,
        id: await Acta.memberId(m.pub),
        label: m.label || '',
        cn: m.cn || null,
        isService: !!m.cn,
        caps: Acta.effectiveCaps(acta, m.pub, pend),
        addedAt: m.addedAt || null,
        isMe: m.pub === publickeyJwkStr,
        isMaster: Acta.canSeal(acta, m.pub),
        // La llave de CIFRADO del miembro y, derivado, si se le puede envolver algo.
        // Sale en la proyección porque sin ella ninguna interfaz (CLI, TUI, consola)
        // puede decir «a este aparato no se le puede escribir», y ese silencio es
        // justo el que hace que un secreto no llegue y nadie sepa por qué.
        encPub: m.encPub || null,
        canSeal: !!m.encPub
      })))
      return { members, profileId: acta.profileId, seq: acta.seq, sealers: Acta.sealersOf(acta), updatedAt: acta.updatedAt }
    },

    async myMembership () {
      const acta = loadActa()
      if (!acta) return { inProfile: false }
      const m = acta.members.find((x) => x.pub === publickeyJwkStr)
      return {
        inProfile: !!m,
        profileId: acta.profileId,
        seq: acta.seq,
        isMaster: Acta.canSeal(acta, publickeyJwkStr),
        caps: Acta.effectiveCaps(acta, publickeyJwkStr, loadRenounces()),
        id: m ? await Acta.memberId(m.pub) : null
      }
    },

    async isMaster () { return amMaster() },

    /**
     * Registra la llave de CIFRADO de un miembro ya admitido (solo el master).
     *
     * Es la alternativa a expulsarlo y volver a admitirlo: un servicio re-enrolado
     * estrena pubkey, y su cajón de variables va indexado por la vieja, así que
     * arrancaría sin configuración y sin decirlo. Esto le pone la llave sin moverle
     * nada más.
     */
    async setMemberEncPub ({ pub, encPub } = {}) {
      const acta = await sealChanges([{ op: 'encpub', pub, encPub }])
      return { ok: true, seq: acta.seq }
    },

    /**
     * Admite un miembro (solo el master). El cert lo emite quien llama, antes o después.
     * `continuity`: si esa identidad ya existía por su cuenta, su puente firmado (F3).
     */
    async admitMember ({ pub, encPub = null, label = '', cn = null, caps = null, cert = null, continuity = null } = {}) {
      // `cn`: si viene, este miembro es un SERVICIO y su único permiso es abrir el cajón de
      // secretos de ESE nombre — no ve nada más del usuario. Sin `cn` es un dispositivo.
      const finales = caps || (cn ? ['secrets'] : ['store', 'read'])
      const acta = await sealChanges([{ op: 'admit', member: { pub, encPub, label, cn, caps: finales, cert, continuity } }])
      // Que entre al perfil incluye poder LEER lo que ya hay: se le envuelve la clave
      // vigente (no hace falta rotar; rotar es para cuando alguien SALE).
      let wrapped = false
      try { wrapped = await wrapForNewMember(pub) } catch (_) {}
      return { ok: true, seq: acta.seq, wrapped }
    },

    async setCaps ({ pub, caps } = {}) {
      const acta = await sealChanges([{ op: 'caps', pub, caps }])
      return { ok: true, seq: acta.seq }
    },

    /**
     * RENOMBRA un miembro (el nombre con el que lo reconoces). Se escribe en el acta y
     * TAMBIÉN en la delegación: son dos registros distintos —el acta dice quién es del
     * perfil, las delegaciones qué certs se emitieron— y las listas de dispositivos leen
     * la segunda, así que tocar solo una deja el nombre viejo a la vista.
     */
    async setLabel ({ pub, label } = {}) {
      const limpio = String(label || '').slice(0, 60)
      const acta = await sealChanges([{ op: 'label', pub, label: limpio }])
      const store = loadDelegations()
      let tocadas = 0
      for (const d of Object.values(store)) { if (d.sub === pub) { d.label = limpio; tocadas++ } }
      if (tocadas) saveDelegations(store)
      return { ok: true, seq: acta.seq, label: limpio, delegations: tocadas }
    },

    async removeMember ({ pub } = {}) {
      return removeDevice(pub)
    },

    /**
     * Traspasa el master a otro miembro. Admitir y nombrar van en el MISMO seq: el nuevo
     * sellador tiene que ser miembro para poder serlo, y así no hay ventana intermedia.
     * Cubre igual dispositivo → bóveda y bóveda → bóveda (mudarse de PC).
     */
    /**
     * CEDER EL MANDO = CONCEDER `sella`. Ya no hay traspaso: sellar es un permiso, así que
     * «pasarle el mando a otro» es dárselo, y punto. Lo que ANTES hacía esto —dejar de
     * poder sellar uno mismo, en el mismo acto— ya no se puede: nadie se quita el sello a
     * sí mismo (dejaría un acta que él firma sin poder firmarla). Si quieres salir, se lo
     * pides al otro cuando ya pueda sellar.
     */
    async handoverMaster ({ to, member = null } = {}) {
      const changes = []
      const acta0 = loadActa()
      if (member) changes.push({ op: 'admit', member: { ...member, pub: to, caps: [...(member.caps || []), 'sealer'] } })
      else {
        const m = (acta0?.members || []).find((x) => x.pub === to)
        if (!m) throw new Error('handover: the new sealer must be a member (admit them in the same change)')
        changes.push({ op: 'caps', pub: to, caps: [...new Set([...(m.caps || []), 'sealer'])] })
      }
      const acta = await sealChanges(changes)
      return { ok: true, seq: acta.seq, sealers: Acta.sealersOf(acta) }
    },

    /**
     * RENUNCIA (§2.2): este dispositivo se quita capacidades a sí mismo. No pasa por el
     * master —por eso funciona con la bóveda apagada, que es justo cuando hace falta (te
     * robaron el aparato)— y solo puede QUITAR, así que cualquiera puede honrarla.
     */
    async renounceCaps ({ caps } = {}) {
      const acta = loadActa()
      if (!acta) throw new Error('this profile has no record yet')
      // SELLAR NO SE RENUNCIA. Es la misma auto-amputación que el acta ya impide, por otra
      // puerta: la renuncia es unilateral y no pasa por nadie, así que sin esto un
      // sellador podría dejarse —o dejar a la cuenta— sin nadie que pueda volver a sellar,
      // y eso no tiene marcha atrás. Que te lo quite otro sellador, que sí puede.
      if ((Array.isArray(caps) ? caps : [caps]).includes('sealer')) {
        throw new Error('sealing cannot be renounced: ask another sealer to take it from you')
      }
      const record = await Acta.makeRenounce({ member: publickeyJwkStr, caps, privateKey: masterKey() })
      const pend = loadRenounces().filter((r) => r.member !== publickeyJwkStr)
      pend.push(record)
      saveRenounces(pend)
      emitVault({ phase: 'renounced', caps: record.caps })
      // Y se le MANDA a la bóveda para que la selle en el acta. Sin esto la renuncia solo
      // valía aquí dentro: la bóveda seguía teniendo escrito que este aparato puede firmar
      // y le seguía aceptando peticiones. Best-effort: si la bóveda está apagada, la
      // renuncia ya está en pie localmente (para eso no necesita a nadie) y se reintenta
      // la próxima vez que se renuncie.
      const v = loadVaultCert(); const dev = loadVaultDevice()
      if (v?.cert && dev) {
        remoteRenounce({ master: v.master, proxy: v.proxy, device: dev, cert: v.cert, record })
          .catch(() => {})
      }
      // Si además soy el master, la absorbo ya en el acta.
      if (amMaster()) { try { await sealChanges([{ op: 'renounce', record }]) } catch (_) {} }
      return { ok: true, record, caps: Acta.effectiveCaps(loadActa(), publickeyJwkStr, loadRenounces()) }
    },

    /** Absorbe en el acta una renuncia ajena ya verificada (solo el master). */
    async absorbRenounce ({ record } = {}) {
      if (!(await Acta.verifyRenounce(record))) throw new Error('invalid renounce: the signature is not the member own')
      const acta = await sealChanges([{ op: 'renounce', record }])
      return { ok: true, seq: acta.seq }
    },

    /**
     * La clave de contenido de este perfil, ya abierta con la llave de cifrado de este
     * dispositivo. `null` si todavía no te la han envuelto (o si te expulsaron).
     */
    async contentKey () { return myCek() },

    /**
     * Cifra algo con la clave de contenido del perfil. Devuelve el sobre `{gen,iv,ct}`.
     * La llave privada de cifrado NUNCA sale de aquí: se cifra y descifra dentro.
     */
    async sealContent ({ plaintext } = {}) {
      const mine = await myCek()
      if (!mine) throw new Error('this device does not hold the profile content key yet')
      return Content.encryptWithCek({ cek: mine.cek, gen: mine.gen, plaintext: String(plaintext) })
    },

    /**
     * Abre un sobre SELLADO A ESTE APARATO: primero la envoltura de la llave —con la
     * privada de cifrado de este dispositivo, que nunca sale de aquí— y con ella el sobre.
     *
     * Es lo que deja a un aparato de administración VER un secreto de la bóveda **sin
     * teclear ninguna contraseña** (§8.2 de `dotrino-vault/docs/secretos-sellados.md`):
     * la capacidad de leer deja de ser una frase que se escribe en cualquier parte y pasa
     * a ser una llave que no se mueve del aparato.
     *
     * Distinto de `openContent`, que usa el llavero del PERFIL (el contenido del usuario);
     * aquí la envoltura viene suelta, del llavero de un cajón de secretos.
     */
    async openSealedValue ({ wrap, envelope } = {}) {
      if (!wrap || !envelope) throw new Error('openSealedValue: missing the wrap or the envelope')
      const cek = await Content.openWrap({ wrap, myEncPrivateKey: encKeypair.privateKey })
      return Content.decryptWithCek({ cek, envelope })
    },

    /**
     * RE-ENVUELVE para otro miembro una llave que este aparato ya puede abrir.
     *
     * Es lo que permite completar a un aparato que entró tarde **sin la frase del
     * perfil y sin que la bóveda tenga que abrir nada**: quien administra ya tiene su
     * envoltura de ese cajón —por eso puede pulsar «Ver»—, así que abre la llave con la
     * suya, que no sale de este dispositivo, y la vuelve a envolver para la pública del
     * recién llegado.
     *
     * No regala nada: quien hace esto ya podía leer ese cajón, y a quien se lo entrega
     * es a alguien que el ACTA —firmada por la maestra— ya reconoce como miembro. La
     * autorización es el acta; esto solo es el sobre.
     *
     * @param {{ wrap: any, encPub: string }} o `wrap`: mi envoltura · `encPub`: la
     *   pública de cifrado del miembro al que hay que envolvérsela.
     * @returns {Promise<any>} la envoltura nueva, para que la bóveda la guarde.
     */
    async rewrapFor ({ wrap, encPub } = {}) {
      if (!wrap || !encPub) throw new Error('rewrapFor: missing the wrap or the recipient key')
      const cek = await Content.openWrap({ wrap, myEncPrivateKey: encKeypair.privateKey })
      return Content.wrapForMember({ cek, memberEncPub: encPub })
    },

    /** Abre un sobre de contenido con el llavero del perfil (todas las generaciones). */
    async openContent ({ envelope } = {}) {
      return Content.decryptWithKeyring({
        envelope, keyring: loadActa()?.keyring, myPub: publickeyJwkStr, myEncPrivateKey: encKeypair.privateKey
      })
    },

    /**
     * Rota la clave de contenido: generación nueva envuelta solo a los miembros de ahora.
     * Corta el acceso al contenido FUTURO de quien ya no está; lo que ya leyó, ya lo leyó.
     */
    async rotateContentKey () {
      const r = await rotateCek()
      return { ok: true, ...r }
    },

    /**
     * Las actas que este master conserva desde `sinceSeq` (sin incluirla), para que un
     * miembro que volvió pueda comprobar el encadenamiento. Vacío si se salió de la ventana.
     *
     * SOLO SE MANDA CUANDO HACE FALTA, que es casi nunca. `canAdopt` adopta el acta actual
     * DE UN SALTO —sin mirar un solo eslabón— siempre que la haya sellado quien el que
     * pregunta tiene por sellador; el `prev` solo se comprueba cuando la nueva es contigua,
     * donde por definición no hay cadena que mandar. El único caso en que los eslabones
     * resuelven algo es un TRASPASO de master durante el hueco: ahí el acta actual la firmó
     * alguien que él no conoce, y el acta del traspaso —firmada por el sellador que sí
     * conocía— es el puente.
     *
     * No es una optimización cosmética: cada acta es un snapshot COMPLETO de los miembros
     * (~940 bytes por miembro), así que la ventana crece con cambios × miembros y llegó a
     * pesar 991 KB de una respuesta de 1,03 MB. El proxio corta el frame a 1 MB, cerraba la
     * conexión de la bóveda con un 1009 y la dejaba muda para TODO el ecosistema, sin un
     * solo log de su lado (2026-08-24: el bot social dejó de publicar y eco se quedó sin un
     * eco que mostrar).
     */
    async actaHistory ({ sinceSeq = 0 } = {}) {
      const cur = loadActa()
      if (!cur || !(cur.seq > sinceSeq)) return { chain: [], window: ACTA_WINDOW }
      const hist = loadHistory()
      const mine = hist.find((a) => a.seq === sinceSeq) || null
      // Sin acta previa (`sinceSeq` 0, un agente headless) se adopta la actual por
      // «sin-acta-previa». Y si la suya se salió de la ventana, la cadena tampoco encadena
      // hasta ella: en los dos casos, mandarla es tirar cientos de KB por el transporte.
      if (!mine) return { chain: [], window: ACTA_WINDOW }
      // Puede dar el salto él solo: el sellador no cambió.
      // Si quien selló la última YA podía sellar en el acta que tiene el otro, el salto lo
      // da él solo: no hace falta mandarle los eslabones. Antes esto comparaba contra el
      // campo `sealer`; ahora se le pregunta al permiso, que es lo mismo con un solo
      // sellador y lo correcto con varios.
      if (Acta.canSeal(mine, cur.sealedBy)) return { chain: [], window: ACTA_WINDOW }
      const all = [...hist.filter((a) => a.seq > sinceSeq), cur]
      return { chain: all.sort((a, b) => a.seq - b.seq), window: ACTA_WINDOW }
    },

    /**
     * MI tarjeta de perfil: lo mínimo que se le pasa a un contacto para que pueda cifrarme a
     * todos mis dispositivos (perfil, versión y llaves de cifrado). Sin etiquetas, sin
     * permisos, sin certificados: lo demás no es asunto de nadie.
     */
    async profileCard () { return loadActa()?.card || null },

    /**
     * Guarda la tarjeta de OTRA persona en su ficha de contacto. La primera vez se acepta
     * (es el mismo criterio con el que agregaste el contacto); después solo si no retrocede
     * y la firmó el mismo master. Si el master cambió, se avisa en vez de aceptarlo callando.
     */
    async adoptPeerCard ({ card } = {}) {
      if (!card?.profileId) throw new Error('invalid card')
      const peers = loadPeers()
      const prev = peers[card.profileId]?.card || null
      const r = await Acta.canAdoptCard({ card, current: prev })
      if (!r.adopt) return { adopted: false, reason: r.reason, devices: (prev?.keys || []).length }
      upsertPeer(card.profileId, { card, profileId: card.profileId })
      return { adopted: true, reason: r.reason, devices: card.keys.length }
    },

    /** Adopta un acta que llega de otro miembro (gana el seq mayor; a igual seq, el traspaso). */
    async adoptActa ({ acta } = {}) { return adoptActa(acta) },

    /** Adopta una cadena completa (para ponerse al día tras estar apagado). */
    async adoptActaChain ({ chain } = {}) { return adoptChain(chain) },

    /** Une este dispositivo al perfil de otra bóveda (solo si aquí no hay nada que perder). */
    async joinProfile ({ acta } = {}) { return joinProfile(acta) },

    // ----- emparejar ESTE dispositivo con el vault del usuario (Fase 1) -----
    // Genera D aquí dentro (su privada NUNCA sale de la identidad), hace el enroll
    // endurecido por el proxy y guarda el cert. NO cambia signData todavía (Fase 2).
    /**
     * Empareja este dispositivo con una bóveda.
     *
     * `join` dice **de qué cuenta estamos hablando** (V7: la intención es explícita, nunca
     * se adivina):
     *   · `'new'`     → camino B: crea aquí una cuenta más, con llave nueva, y ES ESA la que
     *                   entra al acta de la bóveda. La que estabas usando **no se toca**.
     *                   Con dos frenos, porque una cuenta más solo vale si de verdad es
     *                   otra: si ESTE dispositivo ya tiene la cuenta de esa bóveda, no nace
     *                   ninguna (se re-empareja la que hay, o se avisa con `ALREADY_PAIRED`
     *                   de que vive en otra cuenta de aquí); y si el intento falla, la que
     *                   nació para él se descarta en vez de quedarse de fantasma.
     *   · `'current'` → sigue con la cuenta abierta. Solo vale si nació para adoptar
     *                   (`forVault`) o si ya está emparejada con ESA misma bóveda
     *                   (re-emparejar). En cualquier otro caso falla **antes de tocar la
     *                   red**, en vez de traerse un acta ajena y pisar la tuya.
     *   · `'adopt'`    → camino A: la cuenta que YA vive en este aparato pasa a vivir en la
     *                   bóveda. Sigue siendo la misma cuenta para todo el mundo (mismo
     *                   `profileId`); lo que cambia es quién sella. Solo puede hacerlo el
     *                   master: si esta cuenta ya la manda otra bóveda, no hay nada que
     *                   regalar y falla en voz alta.
     */
    async vaultPair ({ qr, label = '', join = 'current' }) {
      if (join === 'adopt') return handlers.vaultAdopt({ qr, label })
      // La cuenta abierta AQUÍ y la que se cree para este intento. `born` es la que hay que
      // tirar si el emparejamiento no llega a término: nació para él y no tiene nada dentro.
      const from = currentPid
      let born = null
      if (join === 'new') {
        // RE-EMPAREJAR NO ES UNA CUENTA MÁS. Volver a esta pantalla con la bóveda que ya te
        // tiene —porque el papel venció, porque lo retiraron, porque se rehízo el
        // emparejamiento— pedía otra cuenta nueva y te dejaba la MISMA cuenta dos veces en
        // el conmutador, con dos llaves distintas metidas en el acta de la bóveda.
        if (qr?.iss && loadVaultCert()?.master === qr.iss) join = 'current'
        else {
          const otra = qr?.iss ? profilePairedWith(qr.iss) : null
          // Y si la que tiene esa bóveda es OTRA cuenta de este mismo dispositivo, tampoco se
          // duplica: cambiar de cuenta exige recargar (multi-perfil no es reactivo), así que
          // esto se dice con código para que la consola ofrezca ir a ella.
          if (otra) {
            throw Object.assign(new Error(`this device already has the account of that vault (profile ${otra.id})`),
              { code: 'ALREADY_PAIRED', detail: { profile: otra.id, name: otra.name || '' } })
          }
          born = await handlers.createProfile({ name: label || me?.nickname || '', forVault: true })
        }
      }
      if (join !== 'new') {
        const yaConEsta = loadVaultCert()?.master === qr?.iss
        if (loadActa() && !isPendingJoin() && !yaConEsta) {
          throw new Error('this device is already using an account: to also use your vault account, create a new account here (the open one is untouched)')
        }
      }
      try {
        return await pairWithVault({ qr, label })
      } catch (e) {
        // El intento falló (código vencido, la bóveda dijo que no, se agotó la espera): la
        // cuenta que nació para él se va con él. Si no, cada reintento dejaba una cuenta
        // fantasma —y encima puesta como activa—.
        if (born) await discardBornProfile(born.id, from)
        throw e
      }
    },

    /**
     * CAMINO A — «esta cuenta que tengo aquí, que la guarde mi computadora».
     *
     * La cuenta no se muda ni se copia: sigue siendo la misma (mismo `profileId`, misma
     * reputación, lo mismo firmado). Lo único que cambia es **quién sella el acta**. Este
     * aparato admite a la bóveda como miembro, le envuelve la clave de contenido para que
     * pueda leer lo que ya hay, y le traspasa el mando — los tres cambios en un **único
     * `seq`**, que es la regla que existe justamente para que no haya un momento raro en
     * el que la cuenta tenga dos sellador​es o ninguno.
     *
     * Requisito (§2 del doc): solo puede hacerlo el master. Si esta cuenta ya la manda otra
     * bóveda, este aparato no puede regalar lo que no tiene; el traspaso se hace desde la
     * que manda hoy.
     */
    async vaultAdopt ({ qr, label = '' } = {}) {
      const mine = loadActa()
      if (!mine) throw new Error('this device has no account to hand over yet')
      if (!amMaster()) throw new Error('not-the-master: another device or vault is in charge of this account; the handover is done from there')

      const device = { publickey: publickeyJwkStr, privateKey: masterKey() }
      const res = await remoteEnroll({
        qr,
        device,
        intent: 'adopt',
        profileId: mine.profileId,
        encPub: encPublickeyJwkStr,
        label: label || me?.nickname || '',
        onChallenge: (c) => emitVault({ phase: 'challenge', deviceId: c.deviceId, code: c.code }),
        // Admitir + envolver + traspasar, en UN solo sello. Se ejecuta cuando la bóveda ya
        // fue aprobada por un humano (el código de 6 dígitos volvió correcto).
        onAdopt: async ({ pub, encPub, label: vlabel }) => {
          const cambios = [{ op: 'admit', member: { pub, encPub, label: vlabel || 'bóveda', caps: ['sign', 'store', 'read'] } }]
          // Sin la clave de contenido envuelta, la bóveda entraría mandando pero sin poder
          // leer nada de lo que guarda la cuenta que acaba de recibir.
          const mine = await myCek()
          if (mine && encPub) {
            const wrap = await Content.wrapForMember({ cek: mine.cek, memberEncPub: encPub })
            cambios.push({ op: 'wrap', gen: mine.gen, pub, wrap })
          }
          cambios.push({ op: 'handover', to: pub })
          return sealChanges(cambios)
        }
      })
      // La bóveda devuelve el acta ya sellada por ella (y con los certs re-emitidos): se
      // adopta por las reglas de siempre (§2.4.1) — encaja porque el sellador es el que
      // este mismo aparato nombró hace un momento.
      // `misma-acta` = la bóveda guardó exactamente la que este aparato acababa de sellar
      // y no la cambió. No hay nada que adoptar, y es justo lo que se esperaba: el
      // traspaso ya iba dentro de esa acta.
      const r = await adoptActa(res.acta)
      const ok = r.adopted || r.reason === 'misma-acta'
      emitVault({ phase: 'adopted', master: res.master, seq: res.acta?.seq, ok })
      if (!ok) throw new Error('the vault returned a record that does not fit: ' + r.reason)
      return { ok: true, adopted: true, profileId: mine.profileId, seq: r.seq ?? res.acta?.seq, master: res.master, deviceId: res.deviceId }
    },

    /**
     * Marca este perfil como **nacido para adoptar** la cuenta de otro (la marca que
     * `joinProfile` exige, §5.1). Lo usa la BÓVEDA al abrir un perfil vacío para el camino
     * A: sin la marca, adoptar la cuenta del aparato se leería como pisar una cuenta con
     * datos y se rechazaría, que es exactamente lo que tiene que pasar cuando nadie lo pidió.
     */
    async prepareForAdoption () {
      kv.setItem(PENDING_JOIN_STORAGE, '1')
      const list = loadProfiles()
      const e = list.find((p) => p.id === currentPid)
      if (e) { e.pendingJoin = true; saveProfiles(list) }
      return { ok: true, pending: true }
    },

    async vaultStatus () {
      const v = loadVaultCert()
      if (!v?.cert) return { paired: false }
      maybeRenewVaultCert()
      return { paired: true, deviceId: v.deviceId, master: v.master, proxy: v.proxy, scope: v.cert.scope, seq: v.cert.seq, pairedAt: v.pairedAt }
    },

    async vaultUnpair () {
      kv.removeItem(VAULT_DEVICE_STORAGE)
      kv.removeItem(VAULT_CERT_STORAGE)
      emitVault({ phase: 'unpaired' })
      return { ok: true }
    },

    // Firma DELEGADA: pide a la maestra del vault que firme `payload` (con el cert de
    // este dispositivo). Aditivo y explícito — NO cambia `signData` (que sigue local),
    // así nada se rompe si no estás emparejado o si el vault está apagado.
    async vaultSign ({ payload }) {
      const v = loadVaultCert(); const device = loadVaultDevice()
      if (!v?.cert || !device) throw new Error('this device is not paired with a vault')
      maybeRenewVaultCert()
      try { return await remoteSign({ master: v.master, proxy: v.proxy, device, cert: v.cert, payload, onRevoked: wipeVaultLink }) }
      catch (e) { return handleVaultError(e) }
    },

    // Store DELEGADO: lee/escribe el store de hilos+aperturas EN tu vault (con el cert).
    // Reusa el MISMO emparejamiento (no hay un pairing aparte para el store).
    /**
     * Store DELEGADO, CIFRADO de punta a punta. Los argumentos y el resultado viajan
     * cifrados con la clave de contenido del perfil: el proxy transporta pero no ve nada
     * de lo que guardas. Si todavía no tengo la clave (nadie me la ha envuelto), va en
     * claro como antes — y se dice en el resultado en vez de fallar en silencio.
     */
    async vaultStore ({ method, args }) {
      const v = loadVaultCert(); const device = loadVaultDevice()
      if (!v?.cert || !device) throw new Error('this device is not paired with a vault')
      maybeRenewVaultCert()
      const mine = await myCek().catch(() => null)
      let payload = { method, args }
      if (mine) {
        payload = { method, enc: await Content.encryptWithCek({ cek: mine.cek, gen: mine.gen, plaintext: JSON.stringify(args ?? {}) }) }
      }
      try {
        const res = await remoteStore({ master: v.master, proxy: v.proxy, device, cert: v.cert, method: payload.method, args: payload.args, enc: payload.enc, onRevoked: wipeVaultLink })
        // La respuesta vuelve cifrada con la misma clave si la bóveda pudo.
        if (res && typeof res === 'object' && res.__enc && mine) {
          return JSON.parse(await Content.decryptWithKeyring({
            envelope: res.__enc, keyring: loadActa()?.keyring, myPub: publickeyJwkStr, myEncPrivateKey: encKeypair.privateKey
          }))
        }
        return res
      } catch (e) { return handleVaultError(e) }
    },

    /**
     * CONSOLA REMOTA: administrar el perfil desde este dispositivo (ver
     * `dotrino-vault/docs/consola-remota.md`). Requiere que el cert de este aparato
     * lleve `vault:admin`, que **no se recibe al emparejar**: se concede a mano en la
     * bóveda (`dotrino-vault caps <ID> +administra`).
     *
     * `op`: `pending` · `pair` · `approve` · `reject` · `revoke` · `audit`. Cambiar
     * permisos y traspasar el mando NO están, y no es un olvido: eso sigue siendo del
     * master, en su máquina.
     */
    async vaultAdmin ({ op, ...rest } = {}) {
      const v = loadVaultCert(); const device = loadVaultDevice()
      if (!v?.cert || !device) throw new Error('this device is not paired with a vault')
      maybeRenewVaultCert()
      try { return await remoteAdmin({ master: v.master, proxy: v.proxy, device, cert: v.cert, op, ...rest, onRevoked: wipeVaultLink }) }
      catch (e) { return handleVaultError(e) }
    },

    /**
     * PEDIDOS DE APROBACIÓN: lo que le toca al teléfono cuando un cajón de la bóveda exige
     * el visto bueno por uso. `op`: `approvals` (listar) · `approve` · `deny` (con `id`).
     * Requiere `vault:approve` en el cert, que se concede a mano (`caps <ID> +aprueba`).
     */
    async vaultApprovals ({ op, id } = {}) {
      const v = loadVaultCert(); const device = loadVaultDevice()
      if (!v?.cert || !device) throw new Error('this device is not paired with a vault')
      maybeRenewVaultCert()
      try { return await remoteApproval({ master: v.master, proxy: v.proxy, device, cert: v.cert, op, id, onRevoked: wipeVaultLink }) }
      catch (e) { return handleVaultError(e) }
    },

    /**
     * PUSH DE LA APP NATIVA: registra el token (FCM/APNs) de este aparato en el proxio,
     * bajo la llave del dispositivo, para que la bóveda pueda «timbrarlo» cuando haya
     * un pedido. La app nativa le pasa el token a la página; la página lo trae aquí.
     */
    async registerPush ({ kind = 'fcm', token } = {}) {
      const device = loadVaultDevice()
      if (!device) throw new Error('this device is not paired with a vault')
      if (typeof token !== 'string' || !token) throw new Error('registerPush requires a token')
      const v = loadVaultCert()
      const { WebSocketProxyClient } = await import('@dotrino/proxy-client')
      const client = new WebSocketProxyClient({ url: v?.proxy || 'wss://proxy.dotrino.com', enableWebRTC: false, autoReconnect: false })
      await client.connect()
      try {
        await client.registerPushToken({
          publicKey: device.publickey, token, kind,
          sign: async (data) => (await signWithDevice({ privateJwk: device.privateJwk, privateKey: device.privateKey, publickey: device.publickey, data })).signature
        })
        return { ok: true, kind }
      } finally { try { client.close() } catch (_) {} }
    },

    /** ¿Puede ESTE dispositivo aprobar pedidos? Mismo criterio que `canAdminVault`. */
    async canApproveVault () {
      if (certDesfasadoDelActa()) { try { await renovarCert() } catch (_) {} }
      const v = loadVaultCert()
      return !!v?.cert && (v.cert.scope || []).includes('vault:approve')
    },

    /**
     * ¿Puede ESTE dispositivo administrar el perfil a distancia? Sale del scope del
     * cert que le dio la bóveda, no de una preferencia: la interfaz pregunta para
     * saber qué pintar, pero quien decide es la bóveda al recibir la petición.
     */
    async canAdminVault () {
      // Si el acta ya dice que este aparato administra pero el cert todavía no, se ESPERA a
      // renovarlo aquí mismo. Disparar la renovación y contestar «no» dejaba la consola
      // escondida hasta la siguiente visita, y el dueño —que acababa de dar el permiso— no
      // tenía forma de saber que solo faltaba recargar.
      if (certDesfasadoDelActa()) { try { await renovarCert() } catch (_) {} }
      const v = loadVaultCert()
      return !!v?.cert && (v.cert.scope || []).includes('vault:admin')
    },

    // Lista (solo lectura) de dispositivos enrolados en tu vault.
    async listVaultDevices () {
      const v = loadVaultCert(); const device = loadVaultDevice()
      if (!v?.cert || !device) {
        // SOLO SE AVISA SI ES RARO. Un aparato que manda en su propia cuenta —o que aún no
        // entró en ninguna bóveda— no está paired y no pasa absolutamente nada: avisar ahí
        // es ensuciar la consola de todo el mundo con el estado normal. Lo que sí es raro,
        // y hasta ahora era mudo, es guardar el acta de OTRO y no tener con qué llamarle.
        const acta = loadActa()
        if (acta && acta.sealer !== publickeyJwkStr) {
          console.warn('[identity] cannot reach the vault that seals this account:', JSON.stringify({
            cert: !!v?.cert, device: !!device, acta: acta.seq
          }))
        }
        throw new Error('this device is not paired with a vault')
      }
      maybeRenewVaultCert()
      try {
        const res = await remoteDevices({ master: v.master, proxy: v.proxy, device, cert: v.cert, sinceSeq: loadActa()?.seq ?? 0, onRevoked: wipeVaultLink })
        // El acta viaja con la lista: así los cambios de política llegan sin canal aparte.
        // Si estuve apagado, viene la CADENA y se adopta eslabón a eslabón (§1.3).
        try {
          if (res.chain?.length && res.chain[0].profileId === loadActa()?.profileId) await adoptChain(res.chain)
          else if (res.acta) await (res.acta.profileId === loadActa()?.profileId ? adoptActa(res.acta) : joinProfile(res.acta))
        } catch (_) {}
        // El acta acaba de llegar: si trae permisos que el cert no lleva, se renueva YA. La
        // comprobación de arriba corrió ANTES de tenerla, así que sin esto haría falta una
        // segunda visita para estrenar un permiso recién concedido.
        maybeRenewVaultCert()
        return res
      } catch (e) { return handleVaultError(e) }
    },

    // El cert de delegación de este dispositivo (para presentarlo al proxy en `identify`
    // → "una identidad": el proxy bindea tu pubkey también bajo tu maestra M). Sin secretos.
    /**
     * Lo que este dispositivo presenta al identificarse ante el proxy: su cert de
     * delegación y su ACTA de perfil. Con el cert, el proxy enruta lo dirigido a la
     * maestra; con el acta, lo dirigido a la PERSONA (cualquiera de sus dispositivos).
     * Sin secretos: las dos cosas son públicas y auto-verificables.
     */
    async getVaultCert () {
      const v = loadVaultCert()
      const acta = loadActa()
      if (!v?.cert) return acta ? { cert: null, master: null, acta } : null
      return { cert: v.cert, master: v.master, acta }
    },

    async listContacts () {
      return Object.values(loadPeers()).filter(p => p && p.isContact).sort((a, b) => (b.lastSeen || 0) - (a.lastSeen || 0))
    },

    async setMyNickname ({ nickname }) {
      return { me: applyMeUpdate({ nickname }) }
    },

    // Perfil completo (avatar 250x250, links de redes, datos), cada ítem con `visible`
    // (oculto = no se comparte). Merge: no pisa lo que no venga en el patch.
    async updateMe ({ patch } = {}) {
      return { me: applyMeUpdate(patch || {}) }
    },
    async getMe () { return me },
    /**
     * CÓMO FUE EL ÚLTIMO EMPUJÓN del perfil a la bóveda. Existe para que la interfaz pueda
     * decir «esto no se guardó» en vez de enseñar tan tranquila un perfil que solo vive en
     * este aparato — que es lo que pasaba cuando el fallo se tragaba.
     * `{ ok, at, error }`.
     */
    async profilePushState () { return lastProfilePush },
    // Subconjunto PÚBLICO del perfil (solo lo marcado visible) — para compartir/publicar.
    async publicMe () {
      const m = me || {}
      const out = { publickey: m.publickey, encryptionPubkey: m.encryptionPubkey }
      if (m.nickname) out.nickname = m.nickname
      if (m.avatar && m.avatarVisible !== false) out.avatar = m.avatar
      // Campos estándar: sensibles (telefono/direccion) solo si su flag === true; el resto salvo flag === false.
      for (const [k] of STD_FIELD_CAPS) {
        if (!m[k]) continue
        const shown = STD_FIELDS_SENSITIVE.has(k) ? (m[k + 'Visible'] === true) : (m[k + 'Visible'] !== false)
        if (shown) out[k] = m[k]
      }
      if (Array.isArray(m.links)) { const v = m.links.filter((l) => l.visible !== false).map(({ visible, ...r }) => r); if (v.length) out.links = v }
      if (Array.isArray(m.fields)) { const v = m.fields.filter((f) => f.visible !== false).map(({ visible, ...r }) => r); if (v.length) out.fields = v }
      return out
    },

    async getEncryptionPubkey () { return encPublickeyJwkStr },

    /**
     * Cifra para uno o varios destinatarios. Dos cosas que cambian respecto de antes:
     *
     * 1. **El sobre va atado a la LLAVE, no a la conexión.** Cada envoltura se indexa por un
     *    id derivado de la llave de cifrado del destinatario, en vez del token del proxy: así
     *    puede abrirla también un dispositivo que no estaba conectado cuando se envió.
     * 2. **Se cifra a TODOS los dispositivos de esa persona**, si conocemos su tarjeta de
     *    perfil (§tarjeta). Le escribes a la persona, no al aparato desde el que te habló.
     */
    async encrypt ({ recipients, plaintext }) {
      if (!Array.isArray(recipients) || recipients.length === 0) throw new Error('recipients required')
      if (typeof plaintext !== 'string') throw new Error('plaintext required')
      const k = await crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, true, ['encrypt', 'decrypt'])
      const kRaw = await crypto.subtle.exportKey('raw', k)
      const iv = crypto.getRandomValues(new Uint8Array(12))
      const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, k, new TextEncoder().encode(plaintext))

      // Expandir cada destinatario a TODOS los dispositivos de su perfil que conozcamos.
      const encPubs = new Set()
      const peers = loadPeers()
      for (const r of recipients) {
        if (!r) continue
        if (r.encryptionPubkey) encPubs.add(r.encryptionPubkey)
        const card = (r.publickey && peers[r.publickey]?.card) || null
        for (const kk of (card?.keys || [])) if (kk.encPub) encPubs.add(kk.encPub)
      }

      const wrap = {}
      for (const encPub of encPubs) {
        try {
          const peerPub = await importPeerEncPubkey(encPub)
          const sharedKey = await deriveSharedAesKey(encKeypair.privateKey, peerPub)
          const wrapIv = crypto.getRandomValues(new Uint8Array(12))
          const wrappedCt = await crypto.subtle.encrypt({ name: 'AES-GCM', iv: wrapIv }, sharedKey, kRaw)
          wrap[await encKeyId(encPub)] = { iv: bufToBase64(wrapIv), ct: bufToBase64(new Uint8Array(wrappedCt)) }
        } catch (e) { /* destinatario omitido */ }
      }
      return { v: 2, iv: bufToBase64(iv), ct: bufToBase64(new Uint8Array(ct)), wrap }
    },

    /**
     * Descifra. Busca MI envoltura por el id de mi llave de cifrado (v2); `myToken` ya no
     * hace falta y se acepta solo por compatibilidad de llamada.
     */
    async decrypt ({ senderEncryptionPubkey, myToken, envelope }) {
      if (!senderEncryptionPubkey) throw new Error('senderEncryptionPubkey required')
      if (!envelope || (envelope.v !== 1 && envelope.v !== 2)) throw new Error('Unsupported envelope')
      const myId = await encKeyId(encPublickeyJwkStr)
      const myEntry = envelope.wrap && (envelope.wrap[myId] || (myToken ? envelope.wrap[myToken] : null))
      if (!myEntry) throw new Error('this device is not among the message recipients')
      const senderPub = await importPeerEncPubkey(senderEncryptionPubkey)
      const sharedKey = await deriveSharedAesKey(encKeypair.privateKey, senderPub)
      const kRaw = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: base64ToBuf(myEntry.iv) }, sharedKey, base64ToBuf(myEntry.ct))
      const k = await crypto.subtle.importKey('raw', kRaw, { name: 'AES-GCM', length: 256 }, false, ['decrypt'])
      const ptBytes = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: base64ToBuf(envelope.iv) }, k, base64ToBuf(envelope.ct))
      return { plaintext: new TextDecoder().decode(ptBytes) }
    },

    async exportIdentity () {
      const raw = kv.getItem(KEY_STORAGE)
      if (!raw) {
        throw new Error('This profile stores its key as NON-exportable (theft protection). ' +
          'To use this identity in another browser, link that browser to your vault from profile.dotrino.com.')
      }
      const keys = JSON.parse(raw)
      const encRaw = kv.getItem(ENC_KEY_STORAGE)
      const encKeys = encRaw ? JSON.parse(encRaw) : null
      return {
        version: 2,
        privateJwk: keys.privateJwk,
        publicJwk: keys.publicJwk,
        encPrivateJwk: encKeys?.privateJwk || null,
        encPublicJwk: encKeys?.publicJwk || null,
        me: loadMe(),
        peers: loadPeers(),
        exportedAt: new Date().toISOString()
      }
    },

    async syncConnect ({ clientId }) { if (!sync) throw new Error('sync not ready'); return sync.connectGoogle(clientId) },
    async syncDisconnect () { if (!sync) return; return sync.disconnectGoogle() },
    async syncUnlock ({ passphrase }) { if (!sync) throw new Error('sync not ready'); return sync.unlock(passphrase) },
    async syncLock () { if (!sync) return; return sync.lock() },
    async syncStatus () { return sync ? sync.getStatus() : { connected: false, unlocked: false, dirty: false } },
    async syncNow () { if (!sync) throw new Error('sync not ready'); await sync.pull(); await sync.push(); return sync.getStatus() },

    async importIdentity ({ privateJwk, publicJwk, encPrivateJwk, encPublicJwk, me: meIn, peers: peersIn }) {
      if (!privateJwk || !publicJwk) throw new Error('privateJwk and publicJwk required')
      await crypto.subtle.importKey('jwk', publicJwk, { name: 'ECDSA', namedCurve: 'P-256' }, true, ['verify'])
      await adoptJwkPair('sign', KEY_STORAGE, privateJwk, publicJwk)
      if (encPrivateJwk && encPublicJwk) {
        await adoptJwkPair('enc', ENC_KEY_STORAGE, encPrivateJwk, encPublicJwk)
      } else {
        kv.removeItem(ENC_KEY_STORAGE)
      }
      if (peersIn && typeof peersIn === 'object' && Object.keys(peersIn).length) {
        savePeers({ ...loadPeers(), ...peersIn })
      }
      keypair = await loadOrCreateKeypair()
      publickeyJwkStr = JSON.stringify(keypair.publicJwk)
      encKeypair = await loadOrCreateEncKeypair()
      encPublickeyJwkStr = JSON.stringify(encKeypair.publicJwk)
      const newMe = meIn && meIn.publickey === publickeyJwkStr
        ? { ...meIn, encryptionPubkey: encPublickeyJwkStr }
        : { publickey: publickeyJwkStr, encryptionPubkey: encPublickeyJwkStr, ...(meIn?.nickname ? { nickname: meIn.nickname } : {}) }
      saveMe(newMe)
      return { me: newMe }
    }
  }

  // ----- bootstrap -----

  // Cuentas que NACIERON para un emparejamiento que nunca llegó a término y se quedaron ahí:
  // se cerró la pestaña con el código en pantalla, o se recargó a mitad. No tienen bóveda y
  // no pueden llegar a tenerla —el intento vivía en la llamada que se cortó—, así que son
  // cuentas fantasma: vacías, sin dueño y ensuciando el conmutador. Aquí se recogen, y si la
  // activa era una de ellas se vuelve a la que estabas usando antes (`from`).
  //
  // Nunca se borra la última: quedarse sin ninguna es peor que quedarse con una vacía. Y solo
  // se van las marcadas `pendingJoin` SIN certificado: en cuanto una se une a la bóveda la
  // marca se consume, así que ninguna cuenta de verdad entra en este barrido.
  {
    const list = loadProfiles()
    const orphan = (p) => p.pendingJoin && !vaultCertOf(p.id)
    const dead = list.filter(orphan)
    const alive = list.filter((p) => !orphan(p))
    if (dead.length && alive.length) {
      const stored = rawKv.getItem(CURRENT_STORAGE)
      const back = dead.find((p) => p.id === stored)?.from
      for (const p of dead) {
        try { await purgeProfile(p.id) } catch (e) { console.warn('[identity] could not discard a ghost account:', e?.message || e) }
      }
      if (back && alive.some((p) => p.id === back)) rawKv.setItem(CURRENT_STORAGE, back)
    }
  }

  // Perfil activo (multi-perfil por dispositivo). Si no hay perfiles, se crea el primero; si
  // existe una identidad ÚNICA vieja (pre-multi-perfil, claves sin namespace), se ADOPTA como
  // "Perfil 1" — sin pérdida. A partir de acá `kv` está scopeado a `currentPid`.
  {
    let profiles = loadProfiles()
    currentPid = rawKv.getItem(CURRENT_STORAGE)
    if (!profiles.length) {
      const pid = 'p' + crypto.randomUUID().slice(0, 8)
      // Migración: adoptar la identidad única vieja (si la hay) copiando sus claves al namespace de pid.
      const legacy = rawKv.getItem(KEY_STORAGE)
      if (legacy) {
        for (const s of ['keypair', 'enc-keypair', 'me', 'nonces', 'delegations', 'revocations', 'vault.device', 'vault.cert']) {
          const v = rawKv.getItem('dotrino.identity.' + s)
          if (v != null) rawKv.setItem(`dotrino.identity.p.${pid}.${s}`, v)
        }
        try { await peers.adoptLegacy?.(pid) } catch (_) { /* peers viejos opcionales */ }
      }
      currentPid = pid
      profiles = [{ id: pid, name: '', pubkey: null }]
      saveProfiles(profiles)
      rawKv.setItem(CURRENT_STORAGE, pid)
    } else if (!currentPid || !profiles.find((p) => p.id === currentPid)) {
      currentPid = profiles[0].id
      rawKv.setItem(CURRENT_STORAGE, currentPid)
    }
  }
  await peers.setProfile?.(currentPid)

  keypair = await loadOrCreateKeypair()
  publickeyJwkStr = JSON.stringify(keypair.publicJwk)
  encKeypair = await loadOrCreateEncKeypair()
  encPublickeyJwkStr = JSON.stringify(encKeypair.publicJwk)

  // Purga del JWK legado SIN namespace (pre-multi-perfil): la migración a
  // perfiles lo COPIABA sin borrarlo. Con keyStore (llaves no extractables) no
  // puede quedar ninguna privada en claro: si la llave activa ya vive en el
  // keyStore y coincide con la legada, se elimina el plano.
  if (keyStore) {
    try {
      const legacy = JSON.parse(rawKv.getItem(KEY_STORAGE) || 'null')
      if (legacy && JSON.stringify(legacy.publicJwk) === publickeyJwkStr) {
        rawKv.removeItem(KEY_STORAGE)
        rawKv.removeItem(ENC_KEY_STORAGE)
      }
    } catch (_) {}
  }

  await initPeerStorage()

  const persistedMe = loadMe()
  if (persistedMe && persistedMe.publickey === publickeyJwkStr) {
    me = persistedMe
    if (me.encryptionPubkey !== encPublickeyJwkStr) {
      me = { ...me, encryptionPubkey: encPublickeyJwkStr }
      kv.setItem(ME_STORAGE, JSON.stringify(me))
    }
  } else {
    me = { publickey: publickeyJwkStr, encryptionPubkey: encPublickeyJwkStr }
    kv.setItem(ME_STORAGE, JSON.stringify(me))
  }
  // Acta de perfil: si no existe, nace ahora (un miembro, este dispositivo, que es el master).
  try { await ensureActa() } catch (e) { console.warn('[identity] could not create the profile record:', e.message) }

  // Perfil compartido: jalar del vault en background (gana el más nuevo).
  pullProfileFromVault()
  // Y, si a este aparato no le queda papel con el que llamar, preguntar si sigue siendo de
  // la casa. Es lo único que le queda por hacer, y hasta ahora no lo hacía nadie.
  askIfStillAMember()

  // Registrar el pubkey (y nombre) del perfil activo en su meta → para avatar/listado sin abrir cada perfil.
  {
    const list = loadProfiles(); const e = list.find((p) => p.id === currentPid)
    if (e && (e.pubkey !== publickeyJwkStr || (!e.name && me?.nickname))) {
      e.pubkey = publickeyJwkStr; if (!e.name && me?.nickname) e.name = me.nickname; saveProfiles(list)
    }
  }

  if (typeof makeSync === 'function') {
    sync = makeSync({
      fileName: 'dotrino-identity-backup.json',
      kind: 'identity',
      exportLocal: exportLocalForSync,
      applyMerged: applyMergedFromSync,
      mergeFn: mergeForSync
    })
    onDirty(() => { if (sync) sync.markDirty() })
  }

  // ----- gate del candado: TODO handler no exento exige perfil desbloqueado -----
  refreshLockState()
  for (const name of Object.keys(handlers)) {
    if (LOCK_EXEMPT.has(name)) continue
    const fn = handlers[name]
    handlers[name] = async (params) => {
      if (locked) refreshLockState() // otra pestaña pudo desbloquear… no: session es por pestaña; re-chequea por si se quitó el pwd
      if (locked) throw new Error('profile locked: unlock it with your password (unlockProfile)')
      return fn(params)
    }
  }

  return {
    handlers,
    get me () { return me },
    /** ¿Está la maestra bajo llave? Cerrada, esta identidad NO puede firmar nada. */
    get masterLocked () { return !keypair?.privateKey },
    /** Echa el candado a la maestra que ya existía (al abrir el perfil). Idempotente. */
    sealMasterKey,
    /** Recarga el par tras abrir el candado, sin reabrir la identidad entera. */
    async reloadMasterKey () {
      keypair = await loadOrCreateKeypair()
      publickeyJwkStr = JSON.stringify(keypair.publicJwk)
      return { locked: !keypair?.privateKey }
    },
    sync,
    onSyncStatus (fn) { if (sync) sync.onStatus(fn) },
    onVaultEvent (fn) { vaultListeners.add(fn); return () => vaultListeners.delete(fn) }
  }
}
