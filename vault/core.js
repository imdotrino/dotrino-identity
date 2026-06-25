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
import { enrollDevice as remoteEnroll, requestSign as remoteSign, requestStore as remoteStore, requestDevices as remoteDevices } from './remote.js'

export const KEY_STORAGE = 'dotrino.identity.keypair'
export const ENC_KEY_STORAGE = 'dotrino.identity.enc-keypair'
export const ME_STORAGE = 'dotrino.identity.me'
export const NONCE_STORAGE = 'dotrino.identity.nonces' // replay window
export const DELEGATIONS_STORAGE = 'dotrino.identity.delegations'   // caps emitidas
export const REVOCATIONS_STORAGE = 'dotrino.identity.revocations'   // nonces revocados
export const VAULT_DEVICE_STORAGE = 'dotrino.identity.vault.device' // sub-clave D de ESTE dispositivo (custodia en el iframe)
export const VAULT_CERT_STORAGE = 'dotrino.identity.vault.cert'     // { cert, master, proxy, deviceId, pairedAt }

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
export async function createIdentityCore ({ kv, peers, makeSync = null }) {
  const {
    initPeerStorage, loadPeers, savePeers, setPeersDirect, upsertPeer, onDirty
  } = peers

  // ----- keypair loaders (kv-backed) -----

  async function loadOrCreateKeypair () {
    const raw = kv.getItem(KEY_STORAGE)
    if (raw) {
      try {
        const { privateJwk, publicJwk } = JSON.parse(raw)
        const privateKey = await crypto.subtle.importKey('jwk', privateJwk, { name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign'])
        const publicKey = await crypto.subtle.importKey('jwk', publicJwk, { name: 'ECDSA', namedCurve: 'P-256' }, true, ['verify'])
        return { privateKey, publicKey, publicJwk }
      } catch (_) {}
    }
    const pair = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify'])
    const privateJwk = await crypto.subtle.exportKey('jwk', pair.privateKey)
    const publicJwk = await crypto.subtle.exportKey('jwk', pair.publicKey)
    kv.setItem(KEY_STORAGE, JSON.stringify({ privateJwk, publicJwk }))
    return { privateKey: pair.privateKey, publicKey: pair.publicKey, publicJwk }
  }

  async function loadOrCreateEncKeypair () {
    const raw = kv.getItem(ENC_KEY_STORAGE)
    if (raw) {
      try {
        const { privateJwk, publicJwk } = JSON.parse(raw)
        const privateKey = await crypto.subtle.importKey('jwk', privateJwk, { name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveBits', 'deriveKey'])
        const publicKey = await crypto.subtle.importKey('jwk', publicJwk, { name: 'ECDH', namedCurve: 'P-256' }, true, [])
        return { privateKey, publicKey, publicJwk }
      } catch (_) {}
    }
    const pair = await crypto.subtle.generateKey({ name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveBits', 'deriveKey'])
    const privateJwk = await crypto.subtle.exportKey('jwk', pair.privateKey)
    const publicJwk = await crypto.subtle.exportKey('jwk', pair.publicKey)
    kv.setItem(ENC_KEY_STORAGE, JSON.stringify({ privateJwk, publicJwk }))
    return { privateKey: pair.privateKey, publicKey: pair.publicKey, publicJwk }
  }

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
  const loadDelegations = () => loadJson(DELEGATIONS_STORAGE)
  const saveDelegations = (o) => kv.setItem(DELEGATIONS_STORAGE, JSON.stringify(o))
  const loadRevocations = () => loadJson(REVOCATIONS_STORAGE)
  const saveRevocations = (o) => kv.setItem(REVOCATIONS_STORAGE, JSON.stringify(o))

  // ----- emparejamiento con el vault del usuario (este dispositivo enrolado) -----
  // Canal de eventos 'vault' (p.ej. el SAS a comparar durante el emparejamiento).
  const vaultListeners = new Set()
  const emitVault = (p) => { for (const fn of vaultListeners) { try { fn(p) } catch (_) {} } }
  const loadVaultCert = () => { try { return JSON.parse(kv.getItem(VAULT_CERT_STORAGE) || 'null') } catch (_) { return null } }
  const loadVaultDevice = () => { try { return JSON.parse(kv.getItem(VAULT_DEVICE_STORAGE) || 'null') } catch (_) { return null } }

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
    const raw = kv.getItem(KEY_STORAGE)
    const keys = raw ? JSON.parse(raw) : null
    const encRaw = kv.getItem(ENC_KEY_STORAGE)
    const encKeys = encRaw ? JSON.parse(encRaw) : null
    return {
      privateJwk: keys?.privateJwk || null,
      publicJwk: keys?.publicJwk || null,
      encPrivateJwk: encKeys?.privateJwk || null,
      encPublicJwk: encKeys?.publicJwk || null,
      me: loadMe(),
      peers: loadPeers()
    }
  }

  async function applyMergedFromSync (merged) {
    const localKeys = kv.getItem(KEY_STORAGE)
    if (!localKeys && merged.privateJwk && merged.publicJwk) {
      kv.setItem(KEY_STORAGE, JSON.stringify({ privateJwk: merged.privateJwk, publicJwk: merged.publicJwk }))
      if (merged.encPrivateJwk && merged.encPublicJwk) {
        kv.setItem(ENC_KEY_STORAGE, JSON.stringify({ privateJwk: merged.encPrivateJwk, publicJwk: merged.encPublicJwk }))
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

  const handlers = {
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

    async signData ({ data }) {
      if (data == null) throw new Error('data required')
      const bytes = new TextEncoder().encode(canonicalStringify(data))
      const signature = await signBytes(keypair.privateKey, bytes)
      return { signature, publickey: publickeyJwkStr }
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

    // ----- emparejar ESTE dispositivo con el vault del usuario (Fase 1) -----
    // Genera D aquí dentro (su privada NUNCA sale de la identidad), hace el enroll
    // endurecido por el proxy y guarda el cert. NO cambia signData todavía (Fase 2).
    async vaultPair ({ qr }) {
      // Usa la PROPIA llave de identidad de este navegador como dispositivo: el cert delega
      // TU identidad (P) desde la maestra M → una sola identidad (signData/identify/cert = P).
      let device
      try { const k = JSON.parse(kv.getItem(KEY_STORAGE)); device = { publickey: JSON.stringify(k.publicJwk), privateJwk: k.privateJwk } } catch (_) { device = undefined }
      const res = await remoteEnroll({ qr, device, onChallenge: (c) => emitVault({ phase: 'challenge', deviceId: c.deviceId, sas: c.sas }) })
      kv.setItem(VAULT_DEVICE_STORAGE, JSON.stringify(res.device))
      kv.setItem(VAULT_CERT_STORAGE, JSON.stringify({ cert: res.cert, master: res.master, proxy: res.proxy, deviceId: res.deviceId, pairedAt: Date.now() }))
      emitVault({ phase: 'paired', deviceId: res.deviceId, master: res.master })
      return { ok: true, deviceId: res.deviceId, master: res.master, exp: res.cert.exp, scope: res.cert.scope }
    },

    async vaultStatus () {
      const v = loadVaultCert()
      if (!v?.cert) return { paired: false }
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
      return remoteSign({ master: v.master, proxy: v.proxy, device, cert: v.cert, payload })
    },

    // Store DELEGADO: lee/escribe el store de hilos+aperturas EN tu vault (con el cert).
    // Reusa el MISMO emparejamiento (no hay un pairing aparte para el store).
    async vaultStore ({ method, args }) {
      const v = loadVaultCert(); const device = loadVaultDevice()
      if (!v?.cert || !device) throw new Error('este dispositivo no está emparejado con un vault')
      return remoteStore({ master: v.master, proxy: v.proxy, device, cert: v.cert, method, args })
    },

    // Lista (solo lectura) de dispositivos enrolados en tu vault.
    async listVaultDevices () {
      const v = loadVaultCert(); const device = loadVaultDevice()
      if (!v?.cert || !device) throw new Error('este dispositivo no está emparejado con un vault')
      return remoteDevices({ master: v.master, proxy: v.proxy, device, cert: v.cert })
    },

    // El cert de delegación de este dispositivo (para presentarlo al proxy en `identify`
    // → "una identidad": el proxy bindea tu pubkey también bajo tu maestra M). Sin secretos.
    async getVaultCert () {
      const v = loadVaultCert()
      return v?.cert ? { cert: v.cert, master: v.master } : null
    },

    async listContacts () {
      return Object.values(loadPeers()).filter(p => p && p.isContact).sort((a, b) => (b.lastSeen || 0) - (a.lastSeen || 0))
    },

    async setMyNickname ({ nickname }) {
      const next = { publickey: publickeyJwkStr, encryptionPubkey: encPublickeyJwkStr, nickname: String(nickname || '').slice(0, 40) }
      saveMe(next)
      return { me: next }
    },

    async getEncryptionPubkey () { return encPublickeyJwkStr },

    async encrypt ({ recipients, plaintext }) {
      if (!Array.isArray(recipients) || recipients.length === 0) throw new Error('recipients required')
      if (typeof plaintext !== 'string') throw new Error('plaintext required')
      const k = await crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, true, ['encrypt', 'decrypt'])
      const kRaw = await crypto.subtle.exportKey('raw', k)
      const iv = crypto.getRandomValues(new Uint8Array(12))
      const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, k, new TextEncoder().encode(plaintext))
      const wrap = {}
      for (const r of recipients) {
        if (!r || !r.token || !r.encryptionPubkey) continue
        try {
          const peerPub = await importPeerEncPubkey(r.encryptionPubkey)
          const sharedKey = await deriveSharedAesKey(encKeypair.privateKey, peerPub)
          const wrapIv = crypto.getRandomValues(new Uint8Array(12))
          const wrappedCt = await crypto.subtle.encrypt({ name: 'AES-GCM', iv: wrapIv }, sharedKey, kRaw)
          wrap[r.token] = { iv: bufToBase64(wrapIv), ct: bufToBase64(new Uint8Array(wrappedCt)) }
        } catch (e) { /* destinatario omitido */ }
      }
      return { v: 1, iv: bufToBase64(iv), ct: bufToBase64(new Uint8Array(ct)), wrap }
    },

    async decrypt ({ senderEncryptionPubkey, myToken, envelope }) {
      if (!senderEncryptionPubkey) throw new Error('senderEncryptionPubkey required')
      if (!myToken) throw new Error('myToken required')
      if (!envelope || envelope.v !== 1) throw new Error('Unsupported envelope')
      const myEntry = envelope.wrap && envelope.wrap[myToken]
      if (!myEntry) throw new Error('No wrap entry for this recipient')
      const senderPub = await importPeerEncPubkey(senderEncryptionPubkey)
      const sharedKey = await deriveSharedAesKey(encKeypair.privateKey, senderPub)
      const kRaw = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: base64ToBuf(myEntry.iv) }, sharedKey, base64ToBuf(myEntry.ct))
      const k = await crypto.subtle.importKey('raw', kRaw, { name: 'AES-GCM', length: 256 }, false, ['decrypt'])
      const ptBytes = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: base64ToBuf(envelope.iv) }, k, base64ToBuf(envelope.ct))
      return { plaintext: new TextDecoder().decode(ptBytes) }
    },

    async exportIdentity () {
      const raw = kv.getItem(KEY_STORAGE)
      if (!raw) throw new Error('No keypair to export')
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
      await crypto.subtle.importKey('jwk', privateJwk, { name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign'])
      await crypto.subtle.importKey('jwk', publicJwk, { name: 'ECDSA', namedCurve: 'P-256' }, true, ['verify'])
      kv.setItem(KEY_STORAGE, JSON.stringify({ privateJwk, publicJwk }))
      if (encPrivateJwk && encPublicJwk) {
        await crypto.subtle.importKey('jwk', encPrivateJwk, { name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveBits', 'deriveKey'])
        await crypto.subtle.importKey('jwk', encPublicJwk, { name: 'ECDH', namedCurve: 'P-256' }, true, [])
        kv.setItem(ENC_KEY_STORAGE, JSON.stringify({ privateJwk: encPrivateJwk, publicJwk: encPublicJwk }))
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

  keypair = await loadOrCreateKeypair()
  publickeyJwkStr = JSON.stringify(keypair.publicJwk)
  encKeypair = await loadOrCreateEncKeypair()
  encPublickeyJwkStr = JSON.stringify(encKeypair.publicJwk)

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

  return {
    handlers,
    get me () { return me },
    sync,
    onSyncStatus (fn) { if (sync) sync.onStatus(fn) },
    onVaultEvent (fn) { vaultListeners.add(fn); return () => vaultListeners.delete(fn) }
  }
}
