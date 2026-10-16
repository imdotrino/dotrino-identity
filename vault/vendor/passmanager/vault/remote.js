// Bóveda remota: la que usa la extensión de Chrome por defecto (DISENO §2).
//
// No tiene la CEK y no guarda nada. Pregunta por un dominio, recibe metadatos, y
// pide UNA credencial cuando el usuario elige. Quién responde al otro lado del
// transporte —el vault del PC o el teléfono— le da igual.

import { VaultError, CODES } from './errors.js'

export class RemoteVault {
  /**
   * @param {object} transport `{ request(op, payload) }` — proxy, WebSocket o
   *   `chrome.runtime` según dónde corra. Devuelve la respuesta ya deserializada.
   */
  constructor (transport, opts = {}) {
    this.transport = transport
    this.needsApproval = opts.needsApproval !== false
  }

  get capabilities () {
    return { canWrite: true, canList: false, needsApproval: this.needsApproval }
  }

  async find (url) {
    return this.#request('find', { url })
  }

  /**
   * UNA credencial, y **solo los campos que se piden**.
   *
   * `keys` no es una optimización: es lo que hace que rellenar un nombre no saque de la
   * bóveda la contraseña. Al otro lado, pedir algo privado puede exigir la huella; pedir
   * lo público, no (DISENO §4.2).
   */
  async get (id, opts = {}) {
    return this.#request('get', { id, ...(Array.isArray(opts.keys) ? { keys: opts.keys } : {}) })
  }

  async put (entry) {
    return this.#request('put', { entry })
  }

  /**
   * CAMBIAR unos campos sin leer la entrada antes. Lo demás se queda como estaba, y la
   * fusión la hace quien tiene el dato — así guardar un teléfono no saca una contraseña.
   */
  async patch (id, changes) {
    return this.#request('patch', { id, changes })
  }

  /**
   * No se puede, y no es una limitación técnica: si la extensión pudiera listar la
   * bóveda entera, el "pide de a una" no significaría nada (DISENO §2).
   */
  /** Buscar por texto en toda la bóveda. Lo público, y con tope (ver `LocalVault`). */
  async search (q, opts = {}) {
    return this.#request('search', { q, limit: opts.limit })
  }

  /**
   * En qué sitios hay algo guardado, y cuántas entradas en cada uno. Ni un id ni un
   * nombre: el dominio, que ya viaja en claro para poder emparejar (§5).
   */
  async sites () {
    return this.#request('sites', {})
  }

  /** Quitar una entrada. La borra quien la tiene, no quien la pide. */
  async remove (id) {
    return this.#request('remove', { id })
  }

  async list () {
    throw new VaultError(CODES.NO_KEY, 'una bóveda remota no lista: pide de a una')
  }

  async #request (op, payload) {
    try {
      return await this.transport.request(op, payload)
    } catch (e) {
      // El transporte puede fallar de muchas formas; hacia arriba solo hay códigos.
      if (e instanceof VaultError) throw e
      throw new VaultError(e?.code || CODES.UNREACHABLE, e?.message || 'no hay bóveda al otro lado')
    }
  }
}
