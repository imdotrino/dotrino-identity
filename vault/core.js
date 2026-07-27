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

import { signDelegationWith, MAX_DELEGATION_MS, DEFAULT_DELEGATION_MS } from './capabilities.js'
import * as Acta from './acta.js'
import * as Content from './content.js'
import { pubkeyId as pubkeyIdOf } from './capabilities.js'
import { enrollDevice as remoteEnroll, requestSign as remoteSign, requestStore as remoteStore, requestDevices as remoteDevices, requestRenew as remoteRenew } from './remote.js'

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

export async function createIdentityCore ({ kv: rawKv, peers, makeSync = null, keyStore = null, sessionKv = null }) {
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
  const isPendingJoin = (pid = currentPid) => !!loadProfiles().find((p) => p.id === pid)?.pendingJoin
  const clearPendingJoin = (pid = currentPid) => {
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
        const { privateJwk, publicJwk } = JSON.parse(raw)
        const privateKey = await crypto.subtle.importKey('jwk', privateJwk, algo, true, privUses)
        return { privateKey, publicKey: await importPub(publicJwk), publicJwk }
      } catch (_) {}
    }
    const pair = await crypto.subtle.generateKey(algo, true, pairUses)
    const privateJwk = await crypto.subtle.exportKey('jwk', pair.privateKey)
    const publicJwk = await crypto.subtle.exportKey('jwk', pair.publicKey)
    kv.setItem(storageKey, JSON.stringify({ privateJwk, publicJwk }))
    return { privateKey: pair.privateKey, publicKey: pair.publicKey, publicJwk }
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

  // PODA (los dos registros crecían para siempre): la renovación automática firma un cert
  // nuevo cada 30 días, así que sin podar cada dispositivo dejaba 12 entradas muertas al año.
  // Se tira lo que YA NO PUEDE SERVIR, nunca lo vivo:
  //   · delegación → cuando su `exp` ya pasó (un cert vencido no autoriza nada).
  //     OJO: no se poda «la anterior del mismo dispositivo» al renovar, porque el cert
  //     viejo SIGUE VIGENTE hasta su exp y hay que poder revocarlo si te roban el aparato.
  //   · revocación → 30 días después de revocar: para entonces el cert al que apunta está
  //     vencido seguro (el tope duro de vida es `MAX_DELEGATION_MS`, y exp ≤ iat + 30 días
  //     ≤ revokedAt + 30 días), y un cert vencido ya falla por `expired` sin mirar la lista.
  const DELEGATION_MAX_LIFE_MS = 30 * 24 * 60 * 60 * 1000 // espejo de MAX_DELEGATION_MS (capabilities.js)

  function loadDelegations () {
    const o = loadJson(DELEGATIONS_STORAGE)
    const now = Date.now()
    let changed = false
    for (const k of Object.keys(o)) {
      const exp = o[k]?.exp
      if (typeof exp === 'number' && exp < now) { delete o[k]; changed = true }
    }
    if (changed) kv.setItem(DELEGATIONS_STORAGE, JSON.stringify(o))
    return o
  }
  const saveDelegations = (o) => kv.setItem(DELEGATIONS_STORAGE, JSON.stringify(o))

  function loadRevocations () {
    const o = loadJson(REVOCATIONS_STORAGE)
    const now = Date.now()
    let changed = false
    for (const k of Object.keys(o)) {
      const at = o[k]
      if (typeof at === 'number' && now - at > DELEGATION_MAX_LIFE_MS) { delete o[k]; changed = true }
    }
    if (changed) kv.setItem(REVOCATIONS_STORAGE, JSON.stringify(o))
    return o
  }
  const saveRevocations = (o) => kv.setItem(REVOCATIONS_STORAGE, JSON.stringify(o))

  // ----- emparejamiento con el vault del usuario (este dispositivo enrolado) -----
  // Canal de eventos 'vault' (p.ej. el código a tipear durante el emparejamiento).
  const vaultListeners = new Set()
  const emitVault = (p) => { for (const fn of vaultListeners) { try { fn(p) } catch (_) {} } }

  /**
   * BORRADO por revocación. Solo lo dispara un `vault.revoked` FIRMADO por la maestra
   * pineada (lo verifica `remote.js` antes de llamar aquí). Emite 'revoked' →
   * `@dotrino/store` borra el store de ESTE perfil (los demás quedan intactos).
   */
  const wipeVaultLink = () => {
    try { kv.removeItem(VAULT_CERT_STORAGE); kv.removeItem(VAULT_DEVICE_STORAGE) } catch (_) {}
    emitVault({ phase: 'revoked' })
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
        return { publickey: publickeyJwkStr, privateKey: keypair.privateKey }
      }
      // MIGRACIÓN: el emparejamiento viejo persistía la privada del perfil en
      // claro aquí. Si es la misma llave del perfil, reemplazar por el marcador
      // (borra el último JWK plano) y firmar con la CryptoKey.
      if (d.privateJwk && d.publickey === publickeyJwkStr) {
        kv.setItem(VAULT_DEVICE_STORAGE, JSON.stringify({ useIdentityKey: true, publickey: publickeyJwkStr }))
        return { publickey: publickeyJwkStr, privateKey: keypair.privateKey }
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
  const pushHistory = (acta) => {
    if (!acta) return
    const h = loadHistory().filter((a) => a.seq !== acta.seq)
    h.push(acta)
    h.sort((a, b) => a.seq - b.seq)
    kv.setItem(ACTA_HISTORY_STORAGE, JSON.stringify(h.slice(-ACTA_WINDOW)))
  }

  const loadRenounces = () => { try { return JSON.parse(kv.getItem(RENOUNCE_STORAGE) || '[]') || [] } catch (_) { return [] } }
  const saveRenounces = (l) => kv.setItem(RENOUNCE_STORAGE, JSON.stringify(l))

  /** ¿Es ESTE dispositivo el master (el único que puede sellar)? */
  const amMaster = () => loadActa()?.sealer === publickeyJwkStr

  /** Sella con la llave del perfil (CryptoKey, puede ser no extractable). */
  const seal = (acta) => Acta.sealActa({ acta, privateKey: keypair.privateKey })

  /**
   * Aplica cambios, sella y guarda. Solo funciona si este dispositivo es el master: es la
   * regla 1 del modelo, y `applyChanges` la vuelve a comprobar por su cuenta.
   */
  async function sealChanges (changes) {
    const acta = loadActa()
    if (!acta) throw new Error('este perfil todavía no tiene acta')
    const next = await Acta.applyChanges(acta, changes, { by: publickeyJwkStr })
    const sealed = await seal(next)
    pushHistory(acta) // la que deja de ser vigente entra en la ventana de retención
    saveActa(sealed)
    emitVault({ phase: 'acta', seq: sealed.seq, sealer: sealed.sealer })
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
    } catch (e) { console.warn('[identity] no se pudo crear la clave de contenido:', e.message) }
    saveActa(await seal(base))
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
    emitVault({ phase: 'acta', seq: candidate.seq, sealer: candidate.sealer, joined: true })
    return { joined: true, profileId: candidate.profileId, seq: candidate.seq }
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

  async function adoptActa (candidate) {
    const current = loadActa()
    const r = await Acta.canAdopt({ candidate, current })
    if (!r.adopt) return { adopted: false, reason: r.reason, seq: current?.seq ?? null }
    saveActa(candidate)
    emitVault({ phase: 'acta', seq: candidate.seq, sealer: candidate.sealer, adopted: r.reason })
    return { adopted: true, reason: r.reason, seq: candidate.seq }
  }

  // ----- renovación AUTOMÁTICA del cert (sin QR ni aprobación) -----
  // Con el cert aún vigente y quedando <15 días, cualquier uso del vault dispara en
  // segundo plano un `vault.renew`: el vault firma un cert fresco (30 días) para la
  // misma sub-clave y scope. Mientras uses el ecosistema ~1 vez al mes, nunca vence.
  // Un cert YA vencido o revocado no puede renovarse (ahí sí, re-emparejar).
  const RENEW_WINDOW_MS = 15 * 24 * 60 * 60 * 1000
  const RENEW_RETRY_MS = 60 * 60 * 1000 // si falla (vault apagado), no insistir >1 vez/hora
  let renewLastTry = 0
  function maybeRenewVaultCert () {
    try {
      const v = loadVaultCert(); const device = loadVaultDevice()
      if (!v?.cert || !device) return
      const now = Date.now()
      if (v.cert.exp <= now || v.cert.exp - now > RENEW_WINDOW_MS) return
      if (now - renewLastTry < RENEW_RETRY_MS) return
      renewLastTry = now
      remoteRenew({ master: v.master, proxy: v.proxy, device, cert: v.cert, onRevoked: wipeVaultLink }).then(({ cert }) => {
        kv.setItem(VAULT_CERT_STORAGE, JSON.stringify({ ...v, cert, renewedAt: Date.now() }))
        emitVault({ phase: 'renewed', exp: cert.exp })
      }).catch(() => {}) // best-effort: el cert vigente sigue sirviendo mientras tanto
    } catch (_) {}
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
  let profilePushTimer = null
  function pushProfileToVault () {
    const v = loadVaultCert(); const device = loadVaultDevice()
    if (!v?.cert || !device || v.cert.exp <= Date.now()) return
    clearTimeout(profilePushTimer)
    profilePushTimer = setTimeout(() => {
      const { publickey, encryptionPubkey, ...content } = me || {}
      remoteStore({ master: v.master, proxy: v.proxy, device, cert: v.cert, method: 'profileSet', args: { me: content } })
        .catch(() => {}) // el vault puede estar apagado; se reintenta en la próxima edición
    }, 800) // debounce: ediciones seguidas = un solo push
  }
  async function pullProfileFromVault () {
    try {
      const v = loadVaultCert(); const device = loadVaultDevice()
      if (!v?.cert || !device || v.cert.exp <= Date.now()) return
      const res = await remoteStore({ master: v.master, proxy: v.proxy, device, cert: v.cert, method: 'profileGet', args: {} })
      const remoteMe = res?.me
      if (!remoteMe) {
        // el vault aún no tiene perfil: sembrar con el local (si tiene contenido)
        if (me?.nickname || me?.avatar) pushProfileToVault()
        return
      }
      if ((remoteMe.updatedAt || 0) > (me?.updatedAt || 0)) {
        const { publickey, encryptionPubkey, ...content } = remoteMe
        me = { ...(me || {}), ...content, publickey: publickeyJwkStr, encryptionPubkey: encPublickeyJwkStr }
        saveMe(me)
        if (typeof content.nickname === 'string') {
          const list = loadProfiles(); const e = list.find((p) => p.id === currentPid)
          if (e && e.name !== content.nickname) { e.name = content.nickname; saveProfiles(list) }
        }
        emitVault({ phase: 'profile-sync', updatedAt: remoteMe.updatedAt })
      }
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
    'profileActa', 'profileMembers', 'myMembership', 'isMaster'
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
      if (left > 0) throw new Error(`demasiados intentos: espera ${Math.ceil(left / 1000)} s`)
      const proof = await derivePwd(password, pwd.salt, pwd.iter)
      if (proof !== pwd.verifier) {
        kv.setItem('dotrino.identity.pwd.tries', JSON.stringify({ n: tries.n + 1, at: Date.now() }))
        throw new Error('contraseña incorrecta')
      }
      kv.removeItem('dotrino.identity.pwd.tries')
      try { sessionKv?.setItem(_scoped(PWD_SESSION), proof) } catch (_) {}
      locked = false
      return { ok: true, locked: false }
    },
    // Poner/cambiar contraseña (requiere estar desbloqueado; cambiar exige la actual vía unlock previo).
    async setProfilePassword ({ password }) {
      if (locked) throw new Error('perfil bloqueado')
      if (!password || String(password).length < 4) throw new Error('la contraseña debe tener al menos 4 caracteres')
      const salt = b64(crypto.getRandomValues(new Uint8Array(16)))
      const verifier = await derivePwd(password, salt, PWD_ITER)
      kv.setItem(PWD_STORAGE, JSON.stringify({ v: 1, salt, iter: PWD_ITER, verifier }))
      try { sessionKv?.setItem(_scoped(PWD_SESSION), verifier) } catch (_) {}
      return { ok: true }
    },
    async removeProfilePassword () {
      if (locked) throw new Error('perfil bloqueado')
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
      const signature = await signBytes(keypair.privateKey, bytes)
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
      const signature = await signBytes(keypair.privateKey, sigBytes)
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
        return { signature: await signBytes(keypair.privateKey, bytes), publickey: publickeyJwkStr }
      }
      const acta = loadActa()
      const puedeFirmar = !acta || Acta.memberCan(acta, publickeyJwkStr, 'sign', loadRenounces())
      if (puedeFirmar || data?.op === 'identify') return local()

      const v = loadVaultCert(); const device = loadVaultDevice()
      if (!v?.cert || !device) {
        throw new Error('perfil-sin-firmante: este dispositivo ya no firma por ti y no está conectado a ninguna bóveda que pueda hacerlo')
      }
      maybeRenewVaultCert()
      try { return await remoteSign({ master: v.master, proxy: v.proxy, device, cert: v.cert, payload: data, onRevoked: wipeVaultLink }) }
      catch (e) { return handleVaultError(e) }
    },

    // ----- delegación de capacidad: la maestra firma un cert para una sub-clave -----
    // de dispositivo `sub`, acotado por `scope` y `exp`, revocable por `nonce`.
    // Es la ÚNICA forma en que la autoridad sale de la clave maestra, y va limitada.

    async signDelegation ({ sub, scope, ttlMs, exp, nonce, label }) {
      if (!sub || typeof sub !== 'string') throw new Error('sub (device pubkey) required')
      if (!scope || (typeof scope !== 'string' && !Array.isArray(scope))) throw new Error('scope required')
      const iat = Date.now()
      const want = typeof exp === 'number' ? exp : iat + (Number(ttlMs) || DEFAULT_DELEGATION_MS)
      const cappedExp = Math.min(want, iat + MAX_DELEGATION_MS)   // tope duro de vida
      // `iss` se FUERZA a la propia maestra: el usuario no puede emitir cert para otro emisor.
      const cert = await signDelegationWith(keypair.privateKey, publickeyJwkStr, { sub, scope, iat, exp: cappedExp, nonce: nonce || crypto.randomUUID() })
      const store = loadDelegations()
      store[cert.nonce] = { nonce: cert.nonce, sub, scope, iat, exp: cappedExp, label: typeof label === 'string' ? label.slice(0, 60) : '' }
      saveDelegations(store)
      return { cert }
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

    async listDelegations () {
      const store = loadDelegations(); const rev = loadRevocations()
      return {
        issued: Object.values(store).sort((a, b) => (b.iat || 0) - (a.iat || 0)),
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
        // `pendingJoin`: nació para adoptar la cuenta de una bóveda y todavía no se unió.
        // La consola lo usa para no ofrecerlo como una cuenta normal a medio hacer.
        return { id: p.id, name: p.name || '', pubkey: p.pubkey || null, avatar, current: p.id === currentPid, pendingJoin: !!p.pendingJoin }
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
      currentPid = pid
      rawKv.setItem(CURRENT_STORAGE, pid)
      await peers.setProfile?.(pid)
      await initPeerStorage()
      keypair = await loadOrCreateKeypair(); publickeyJwkStr = JSON.stringify(keypair.publicJwk)
      encKeypair = await loadOrCreateEncKeypair(); encPublickeyJwkStr = JSON.stringify(encKeypair.publicJwk)
      me = { publickey: publickeyJwkStr, encryptionPubkey: encPublickeyJwkStr, nickname: String(name || '').slice(0, 40) }
      saveMe(me)
      const list = loadProfiles()
      list.push({ id: pid, name: me.nickname, pubkey: publickeyJwkStr, ...(forVault ? { pendingJoin: true } : {}) })
      saveProfiles(list)
      await ensureActa(me.nickname) // el perfil nuevo nace con su acta (él mismo es el master)
      return { id: pid, name: me.nickname, pubkey: publickeyJwkStr, pendingJoin: !!forVault }
    },
    async switchProfile ({ id } = {}) {
      if (!loadProfiles().find((p) => p.id === id)) throw new Error('perfil no existe')
      rawKv.setItem(CURRENT_STORAGE, id) // la app recarga la página → re-init con el nuevo perfil
      return { id }
    },
    async renameProfile ({ id, name } = {}) {
      const list = loadProfiles(); const e = list.find((p) => p.id === (id || currentPid))
      if (!e) throw new Error('perfil no existe')
      e.name = String(name || '').slice(0, 40); saveProfiles(list)
      if (e.id === currentPid) { me = { ...(me || {}), nickname: e.name }; saveMe(me) }
      return { id: e.id, name: e.name }
    },
    async deleteProfile ({ id } = {}) {
      let list = loadProfiles()
      if (list.length <= 1) throw new Error('no se puede borrar el único perfil')
      if (!list.find((p) => p.id === id)) throw new Error('perfil no existe')
      list = list.filter((p) => p.id !== id); saveProfiles(list)
      // Borrado directo del namespace del perfil (incluye su store del vault si lo tuviera).
      for (const s of ['keypair', 'enc-keypair', 'me', 'nonces', 'delegations', 'revocations', 'vault.device', 'vault.cert', 'acta', 'renounced']) {
        rawKv.removeItem(`dotrino.identity.p.${id}.${s}`)
      }
      // …y sus CryptoKeys no extractables del keyStore (IndexedDB).
      if (keyStore) {
        for (const s of ['keypair', 'enc-keypair']) {
          try { await keyStore.remove(`dotrino.identity.p.${id}.${s}`) } catch (_) {}
        }
      }
      if (currentPid === id) { currentPid = list[0].id; rawKv.setItem(CURRENT_STORAGE, currentPid) }
      return { ok: true, current: currentPid }
    },

    // ----- ACTA DE PERFIL -----
    // Quién es de este perfil y qué puede hacer cada uno. Solo el master sella; los demás
    // adoptan. Ver `dotrino-vault/docs/acta-de-perfil.md`.

    async profileActa () {
      const acta = loadActa()
      if (!acta) return null
      return { acta, isMaster: amMaster(), myCaps: Acta.effectiveCaps(acta, publickeyJwkStr, loadRenounces()) }
    },

    async profileMembers () {
      const acta = loadActa()
      if (!acta) return { members: [], profileId: null, seq: 0, sealer: null }
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
        isMaster: m.pub === acta.sealer
      })))
      return { members, profileId: acta.profileId, seq: acta.seq, sealer: acta.sealer, updatedAt: acta.updatedAt }
    },

    async myMembership () {
      const acta = loadActa()
      if (!acta) return { inProfile: false }
      const m = acta.members.find((x) => x.pub === publickeyJwkStr)
      return {
        inProfile: !!m,
        profileId: acta.profileId,
        seq: acta.seq,
        isMaster: acta.sealer === publickeyJwkStr,
        caps: Acta.effectiveCaps(acta, publickeyJwkStr, loadRenounces()),
        id: m ? await Acta.memberId(m.pub) : null
      }
    },

    async isMaster () { return amMaster() },

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

    async removeMember ({ pub } = {}) {
      const acta = await sealChanges([{ op: 'remove', pub }])
      // Expulsar rota la clave: el que sale no podrá abrir el contenido NUEVO. Lo que ya
      // leyó no vuelve — eso no se puede deshacer y no se promete.
      let rotated = null
      try { rotated = await rotateCek() } catch (_) {}
      return { ok: true, seq: acta.seq, rotated }
    },

    /**
     * Traspasa el master a otro miembro. Admitir y nombrar van en el MISMO seq: el nuevo
     * sellador tiene que ser miembro para poder serlo, y así no hay ventana intermedia.
     * Cubre igual dispositivo → bóveda y bóveda → bóveda (mudarse de PC).
     */
    async handoverMaster ({ to, member = null } = {}) {
      const changes = []
      if (member) changes.push({ op: 'admit', member: { ...member, pub: to } })
      changes.push({ op: 'handover', to })
      const acta = await sealChanges(changes)
      return { ok: true, seq: acta.seq, sealer: acta.sealer }
    },

    /**
     * RENUNCIA (§2.2): este dispositivo se quita capacidades a sí mismo. No pasa por el
     * master —por eso funciona con la bóveda apagada, que es justo cuando hace falta (te
     * robaron el aparato)— y solo puede QUITAR, así que cualquiera puede honrarla.
     */
    async renounceCaps ({ caps } = {}) {
      const acta = loadActa()
      if (!acta) throw new Error('este perfil todavía no tiene acta')
      const record = await Acta.makeRenounce({ member: publickeyJwkStr, caps, privateKey: keypair.privateKey })
      const pend = loadRenounces().filter((r) => r.member !== publickeyJwkStr)
      pend.push(record)
      saveRenounces(pend)
      emitVault({ phase: 'renounced', caps: record.caps })
      // Si además soy el master, la absorbo ya en el acta.
      if (amMaster()) { try { await sealChanges([{ op: 'renounce', record }]) } catch (_) {} }
      return { ok: true, record, caps: Acta.effectiveCaps(loadActa(), publickeyJwkStr, loadRenounces()) }
    },

    /** Absorbe en el acta una renuncia ajena ya verificada (solo el master). */
    async absorbRenounce ({ record } = {}) {
      if (!(await Acta.verifyRenounce(record))) throw new Error('renuncia inválida: la firma no es del propio miembro')
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
      if (!mine) throw new Error('este dispositivo todavía no tiene la clave de contenido del perfil')
      return Content.encryptWithCek({ cek: mine.cek, gen: mine.gen, plaintext: String(plaintext) })
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
     */
    async actaHistory ({ sinceSeq = 0 } = {}) {
      const cur = loadActa()
      const hist = loadHistory().filter((a) => a.seq > sinceSeq)
      const all = cur && cur.seq > sinceSeq ? [...hist, cur] : hist
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
      if (!card?.profileId) throw new Error('tarjeta inválida')
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
     *   · `'current'` → sigue con la cuenta abierta. Solo vale si nació para adoptar
     *                   (`forVault`) o si ya está emparejada con ESA misma bóveda
     *                   (re-emparejar). En cualquier otro caso falla **antes de tocar la
     *                   red**, en vez de traerse un acta ajena y pisar la tuya.
     */
    async vaultPair ({ qr, label = '', join = 'current' }) {
      if (join === 'new') {
        await handlers.createProfile({ name: label || me?.nickname || '', forVault: true })
      } else {
        const yaConEsta = loadVaultCert()?.master === qr?.iss
        if (loadActa() && !isPendingJoin() && !yaConEsta) {
          throw new Error('este aparato ya está usando una cuenta: para usar también la de tu bóveda, crea una cuenta nueva aquí (la que tienes abierta no se toca)')
        }
      }
      // Usa la PROPIA llave de identidad de este navegador como dispositivo: el cert delega
      // TU identidad (P) desde la maestra M → una sola identidad (signData/identify/cert = P).
      // La privada es la CryptoKey del perfil (no extractable): se pasa como `privateKey`
      // y NO se persiste ningún JWK del dispositivo (marcador useIdentityKey).
      const device = { publickey: publickeyJwkStr, privateKey: keypair.privateKey }
      // Si esta identidad ya existía por su cuenta, se lleva un certificado de continuidad
      // firmado por ella misma: es el puente para que su reputación previa siga contando.
      // Solo si esta llave tenía vida propia. Una recién creada para adoptar (camino B) no
      // tiene pasado que salvar: mandarle un puente de continuidad sería puro ruido.
      const mio = loadActa()
      const continuity = (mio && mio.members.length === 1 && !isPendingJoin())
        ? await Acta.makeContinuity({ member: publickeyJwkStr, from: mio.profileId, privateKey: keypair.privateKey })
        : null
      const res = await remoteEnroll({ qr, device, continuity, encPub: encPublickeyJwkStr, label: label || me?.nickname || '', onChallenge: (c) => emitVault({ phase: 'challenge', deviceId: c.deviceId, code: c.code }) })
      kv.setItem(VAULT_DEVICE_STORAGE, JSON.stringify({ useIdentityKey: true, publickey: publickeyJwkStr }))
      kv.setItem(VAULT_CERT_STORAGE, JSON.stringify({ cert: res.cert, master: res.master, proxy: res.proxy, deviceId: res.deviceId, pairedAt: Date.now() }))
      // Conectarse a una bóveda es ENTRAR A SU CUENTA: el acta viene con el cert.
      const unido = res.acta ? await joinProfile(res.acta) : { joined: false, reason: 'sin-acta' }
      emitVault({ phase: 'paired', deviceId: res.deviceId, master: res.master, join: unido })
      pullProfileFromVault() // adoptar el perfil que ya viva en el vault (si hay)
      return { ok: true, deviceId: res.deviceId, master: res.master, exp: res.cert.exp, scope: res.cert.scope, join: unido }
    },

    async vaultStatus () {
      const v = loadVaultCert()
      if (!v?.cert) return { paired: false }
      maybeRenewVaultCert()
      return { paired: true, deviceId: v.deviceId, master: v.master, proxy: v.proxy, scope: v.cert.scope, exp: v.cert.exp, pairedAt: v.pairedAt }
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
      if (!v?.cert || !device) throw new Error('este dispositivo no está emparejado con un vault')
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
      if (!v?.cert || !device) throw new Error('este dispositivo no está emparejado con un vault')
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

    // Lista (solo lectura) de dispositivos enrolados en tu vault.
    async listVaultDevices () {
      const v = loadVaultCert(); const device = loadVaultDevice()
      if (!v?.cert || !device) throw new Error('este dispositivo no está emparejado con un vault')
      maybeRenewVaultCert()
      try {
        const res = await remoteDevices({ master: v.master, proxy: v.proxy, device, cert: v.cert, sinceSeq: loadActa()?.seq ?? 0, onRevoked: wipeVaultLink })
        // El acta viaja con la lista: así los cambios de política llegan sin canal aparte.
        // Si estuve apagado, viene la CADENA y se adopta eslabón a eslabón (§1.3).
        try {
          if (res.chain?.length && res.chain[0].profileId === loadActa()?.profileId) await adoptChain(res.chain)
          else if (res.acta) await (res.acta.profileId === loadActa()?.profileId ? adoptActa(res.acta) : joinProfile(res.acta))
        } catch (_) {}
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
      if (!myEntry) throw new Error('este dispositivo no está entre los destinatarios del mensaje')
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
        throw new Error('Este perfil guarda su llave de forma NO exportable (protección contra robo). ' +
          'Para usar tu identidad en otro navegador, conecta ese navegador a tu bóveda (vault) desde profile.dotrino.com.')
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
  try { await ensureActa() } catch (e) { console.warn('[identity] no se pudo crear el acta de perfil:', e.message) }

  // Perfil compartido: jalar del vault en background (gana el más nuevo).
  pullProfileFromVault()

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
      if (locked) throw new Error('perfil bloqueado: desbloquéalo con tu contraseña (unlockProfile)')
      return fn(params)
    }
  }

  return {
    handlers,
    get me () { return me },
    sync,
    onSyncStatus (fn) { if (sync) sync.onStatus(fn) },
    onVaultEvent (fn) { vaultListeners.add(fn); return () => vaultListeners.delete(fn) }
  }
}
