// Recuerdo de lo YA entregado, durante esta sesión del navegador.
//
// No es la caché que se descartó (DISENO §3.1): aquella era una copia de la bóveda
// entera, y para abrirla hacía falta la llave. Esto guarda solo las credenciales que
// la bóveda ya entregó, en memoria de sesión, y muere al cerrar el navegador.
//
// Para qué: entrar tres veces al mismo sitio en una tarde no debería ser tres
// aprobaciones en el teléfono. Lo que nunca pediste, nunca estuvo aquí.

const DEFAULT_TTL = 5 * 60 * 1000

export class SessionCache {
  /**
   * @param {object} store  almacén de SESIÓN `{ get(k), set(k, v) }` — en la
   *   extensión, `chrome.storage.session`: memoria, nunca disco.
   * @param {object} opts   `{ ttlMs, now }`
   */
  constructor (store, { ttlMs = DEFAULT_TTL, now = () => Date.now() } = {}) {
    this.store = store
    this.ttlMs = ttlMs
    this.now = now
    this.key = 'passmanager/session/v1'
  }

  async #all () {
    return (await this.store.get(this.key)) || {}
  }

  /** Devuelve la entrada si sigue vigente. Una caducada se tira al pasar por ella. */
  async get (id) {
    const all = await this.#all()
    const hit = all[id]
    if (!hit) return null
    if (this.now() - hit.ts > this.ttlMs) {
      delete all[id]
      await this.store.set(this.key, all)
      return null
    }
    return hit.entry
  }

  /** Guarda lo entregado. */
  async put (id, entry) {
    if (!entry) return false
    const all = await this.#all()
    all[id] = { entry, ts: this.now() }
    await this.store.set(this.key, all)
    return true
  }

  async forget (id) {
    const all = await this.#all()
    if (id) delete all[id]
    await this.store.set(this.key, id ? all : {})
  }

  async size () {
    return Object.keys(await this.#all()).length
  }
}
