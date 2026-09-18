/**
 * @dotrino/opaque — OPAQUE (RFC 9807) para el ecosistema Dotrino.
 *
 * Comprueba una contraseña SIN que el servidor la vea nunca y sin entregar nada con qué
 * adivinarla desde fuera. Lo usan las tres versiones del vault (el binario, la pestaña y la
 * extensión) y el gestor, para el aparato que se abre con usuario y contraseña.
 *
 * Aquí no hay criptografía propia: el protocolo es `opaque-ke` (Meta, auditado por NCC
 * Group) compilado a WASM desde su código fuente en nuestro CI. Este archivo solo pone
 * nombres y comprueba lo que entra.
 *
 * Todo lo que entra y sale son cadenas base64url. Los errores llevan `code`:
 *   · `bad-input`    — falta un dato o no se puede leer
 *   · `login-failed` — contraseña equivocada, usuario inexistente, identificadores que no
 *                      casan o un mensaje alterado. A propósito son el MISMO código: distinguirlos
 *                      le diría a quien prueba qué usuarios existen.
 *   · `protocol`     — cualquier otro fallo del protocolo
 *   · `internal`     — un fallo que no viene del protocolo (no debería pasar)
 */
import * as wasm from '../build/opaque.js'
import wasmBytes from '../build/wasm-bytes.js'

export class OpaqueError extends Error {
  constructor (code, message) {
    super(message)
    this.name = 'OpaqueError'
    this.code = code
  }
}

let ready = false
function init () {
  if (ready) return
  const bin = Uint8Array.from(atob(wasmBytes), (c) => c.charCodeAt(0))
  wasm.initSync({ module: bin })
  ready = true
}

const CODE = /^(bad-input|login-failed|protocol): ([\s\S]*)$/

function call (fn, ...args) {
  init()
  try {
    return fn(...args)
  } catch (e) {
    const msg = String(e?.message ?? e)
    const m = CODE.exec(msg)
    if (m) throw new OpaqueError(m[1], m[2])
    throw new OpaqueError('internal', msg)
  }
}

function need (name, v) {
  if (typeof v !== 'string' || !v) throw new OpaqueError('bad-input', `${name} is required`)
  return v
}

/**
 * Los identificadores que se atan al intercambio. Si se usan, las DOS puntas tienen que
 * pasar los mismos; si no casan, el inicio falla como una contraseña equivocada.
 */
function idents (identifiers) {
  if (identifiers == null || typeof identifiers !== 'object') throw new OpaqueError('bad-input', 'identifiers must be an object')
  const { client, server } = identifiers
  for (const [k, v] of [['identifiers.client', client], ['identifiers.server', server]]) {
    if (v !== undefined && (typeof v !== 'string' || !v)) throw new OpaqueError('bad-input', `${k} must be a non-empty string`)
  }
  return [client, server]
}

/** La suite y sus parámetros. Se guarda junto a cada registro. */
export function suiteId () {
  return call(wasm.suiteId)
}

export const server = {
  /** La preparación del servidor: SECRETA, una por bóveda. Sin ella no se puede comprobar nada. */
  createSetup () {
    return call(wasm.serverCreateSetup)
  },
  publicKey ({ setup } = {}) {
    return call(wasm.serverPublicKey, need('setup', setup))
  },
  registrationResponse ({ setup, request, credentialId } = {}) {
    return call(wasm.serverRegistrationResponse, need('setup', setup), need('request', request), need('credentialId', credentialId))
  },
  /** Lo que se guarda del usuario (el «registro»). */
  registrationFinish ({ upload } = {}) {
    return call(wasm.serverRegistrationFinish, need('upload', upload))
  },
  /**
   * `record` tiene que venir SIEMPRE: el registro, o `null` si el usuario no existe. Con
   * `null` responde igual, así que desde fuera no se sabe qué usuarios hay.
   */
  loginStart ({ setup, record, request, credentialId, identifiers = {} } = {}) {
    if (record !== null && (typeof record !== 'string' || !record)) {
      throw new OpaqueError('bad-input', 'record must be the stored record, or null for an unknown user')
    }
    return call(wasm.serverLoginStart, need('setup', setup), record ?? undefined, need('request', request), need('credentialId', credentialId), ...idents(identifiers))
  },
  loginFinish ({ state, finalization, identifiers = {} } = {}) {
    return call(wasm.serverLoginFinish, need('state', state), need('finalization', finalization), ...idents(identifiers))
  },
}

export const client = {
  registrationStart ({ password } = {}) {
    return call(wasm.clientRegistrationStart, need('password', password))
  },
  /** Devuelve `upload` (para el servidor) y `exportKey`, que solo sale de la contraseña. */
  registrationFinish ({ state, response, password, identifiers = {} } = {}) {
    return call(wasm.clientRegistrationFinish, need('state', state), need('response', response), need('password', password), ...idents(identifiers))
  },
  loginStart ({ password } = {}) {
    return call(wasm.clientLoginStart, need('password', password))
  },
  /** Devuelve `finalization` (para el servidor), `sessionKey` y el mismo `exportKey` del registro. */
  loginFinish ({ state, response, password, identifiers = {} } = {}) {
    return call(wasm.clientLoginFinish, need('state', state), need('response', response), need('password', password), ...idents(identifiers))
  },
}

export default { suiteId, server, client, OpaqueError }
