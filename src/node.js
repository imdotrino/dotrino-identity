/**
 * Dotrino Identity — adaptador headless para Node.js.
 *
 * Expone la MISMA API pública que el cliente de navegador (`./index.js`), pero
 * sin iframe ni postMessage: llama directamente a los handlers de
 * `../vault/core.js`. El keypair, `me`, los nonces y el peer book se persisten
 * en archivos JSON dentro de un directorio por identidad, de modo que cada
 * directorio es un "usuario" distinto y estable entre ejecuciones.
 *
 * La criptografía es byte-idéntica a la del vault del navegador (mismo core),
 * así que un bot Node es plenamente interoperable con usuarios reales:
 * firmas verificables por el proxy e `identify`, y cifrado E2E (ECDH+AES-GCM)
 * descifrable por la app web y viceversa.
 *
 * Requiere Node ≥ 20 (crypto.subtle, btoa/atob, TextEncoder globales).
 */

import fs from 'node:fs'
import path from 'node:path'
import os from 'node:os'
import { createIdentityCore } from '../vault/core.js'
import { IdentityFacade } from '../vault/facade.js'

/**
 * kv síncrono respaldado por un archivo JSON (estilo localStorage).
 *
 * `atRest` (opcional) cifra el archivo entero en disco: quien lo provee decide con qué
 * (el vault lo liga a la máquina, ver `dotrino-vault/src/atrest.js`). Si el archivo estaba
 * en claro se lee igual y queda cifrado en la primera escritura, sin pedir nada.
 */
function fileKv (filePath, atRest = null) {
  let data = {}
  try {
    if (fs.existsSync(filePath)) {
      const raw = fs.readFileSync(filePath, 'utf8')
      data = JSON.parse(atRest ? atRest.decrypt(raw) : raw) || {}
    }
  } catch (_) { data = {} }
  const flush = () => {
    fs.mkdirSync(path.dirname(filePath), { recursive: true })
    const text = JSON.stringify(data)
    fs.writeFileSync(filePath, atRest ? atRest.encrypt(text) : text, { mode: 0o600 })
  }
  return {
    getItem: (k) => (k in data ? data[k] : null),
    setItem: (k, v) => { data[k] = String(v); flush() },
    removeItem: (k) => { delete data[k]; flush() }
  }
}

/** Peer book respaldado por un archivo JSON (interfaz de vault/peerStore.js). */
function filePeers (filePath) {
  let peers = {}
  let markDirty = null
  let pid = null // multi-perfil: el peer book se namespacea por perfil
  const fileFor = () => pid ? path.join(path.dirname(filePath), `peers.${pid}.json`) : filePath
  const flush = () => {
    const f = fileFor()
    fs.mkdirSync(path.dirname(f), { recursive: true })
    fs.writeFileSync(f, JSON.stringify(peers))
  }
  return {
    setProfile (p) { pid = p || null },
    adoptLegacy (newPid) {
      // Migración: copia el peers.json viejo (sin namespace) al perfil newPid.
      try {
        if (!fs.existsSync(filePath)) return
        const legacy = JSON.parse(fs.readFileSync(filePath, 'utf8'))
        if (legacy && typeof legacy === 'object' && Object.keys(legacy).length) {
          fs.writeFileSync(path.join(path.dirname(filePath), `peers.${newPid}.json`), JSON.stringify(legacy))
        }
      } catch (_) { /* sin peers viejos */ }
    },
    async initPeerStorage () {
      const f = fileFor()
      try {
        peers = (fs.existsSync(f)) ? (JSON.parse(fs.readFileSync(f, 'utf8')) || {}) : {}
      } catch (_) { peers = {} }
      return peers
    },
    loadPeers: () => peers,
    savePeers: (next) => { peers = next; flush(); if (markDirty) markDirty() },
    setPeersDirect: (next) => { peers = next; flush() },
    upsertPeer: (publickey, patch) => {
      const existing = peers[publickey] || { publickey, firstSeen: Date.now() }
      peers[publickey] = { ...existing, ...patch, publickey, lastSeen: Date.now() }
      flush()
      if (markDirty) markDirty()
      return peers[publickey]
    },
    onDirty: (fn) => { markDirty = fn }
  }
}

const DEFAULT_DIR = path.join(os.homedir(), '.dotrino', 'identity')

export class Identity extends IdentityFacade {
  /**
   * @param {Object} [options]
   * @param {string} [options.dir]  Directorio de persistencia de esta identidad.
   *   Cada directorio = un usuario distinto. Default: ~/.dotrino/identity
   */
  constructor (options = {}) {
    super(null)
    this._dir = options.dir || DEFAULT_DIR
    this._atRest = options.atRest || null
    // CANDADO DE LA MAESTRA: `{ seal(jwkStr), open(blob) }`. Quien lo provee (el daemon
    // del vault) es el único que tiene la llave que sale de la contraseña. Sin candado,
    // la maestra se guarda como siempre — un perfil sin contraseña no cambia.
    this._keyLock = options.keyLock || null
  }

  /**
   * Crea/abre una identidad headless. A diferencia del navegador NO es singleton:
   * cada `dir` distinto devuelve una identidad independiente (para correr muchos
   * bots-usuario en el mismo proceso).
   */
  static async connect (options = {}) {
    const inst = new Identity(options)
    await inst.ready()
    return inst
  }

  async ready () {
    if (this._core) return this
    this._core = await createIdentityCore({
      kv: fileKv(path.join(this._dir, 'identity.json'), this._atRest),
      keyLock: this._keyLock,
      peers: filePeers(path.join(this._dir, 'peers.json')),
      makeSync: null,
      // Aquí las cuentas las lleva quien hospeda (el daemon del vault tiene su propio
      // registro de perfiles): que una expulsión borre una por debajo le dejaría el suyo
      // apuntando a algo que ya no existe. Se borra el enlace y el acta, nada más.
      removeAccountOnExpulsion: false
    })
    this._wire()
    return this
  }

}

export default Identity

// Helpers de capacidad SIN clave maestra (lado dispositivo + verificación), para que
// un bridge/bot Node pueda crear su clave, firmar acciones y verificar cadenas D←P.
export { makeDeviceKey, makeDeviceEncKey, importDeviceEncKey, signWithDevice, verifyDelegation, verifyChain, pubkeyId, deriveSAS, verifyDeviceSig, makePairingCode, commitCode, avatarSvg, avatarDataUri } from '../vault/capabilities.js'
