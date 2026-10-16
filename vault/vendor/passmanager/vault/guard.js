// Una bóveda con la puerta puesta: la misma de dentro, pero pidiendo autorización antes
// de soltar lo privado.
//
// Existe porque las tres bóvedas del ecosistema tienen que funcionar igual (dueño,
// 2026-08-29). Las dos de fuera —el daemon y la pestaña de `vault.dotrino.com/vault`—
// ya la tenían: se la pone `VaultResponder` al atender por el proxio. La de dentro de la
// extensión no pasaba por ahí, porque no hay transporte de por medio, y acababa siendo
// la única que entregaba una llave privada sin preguntar.
//
// **La política vive aquí, no en quien pide.** Un aparato que pide no decide nada, y en
// la extensión «quien pide» es el mismo proceso — razón de más para que la puerta esté
// delante de la bóveda y no repartida por cada pantalla que llama.

import { VaultError, CODES } from './errors.js'
import { privateKeysOf } from '../fields.js'
import { projectEntry } from '../model.js'

export class GuardedVault {
  /**
   * @param {object} inner  la bóveda de verdad (normalmente un `LocalVault` abierto)
   * @param {object} opts
   *   `gate`  una `ApprovalGate`
   */
  constructor (inner, { gate } = {}) {
    this.inner = inner
    this.gate = gate
  }

  /**
   * `needsApproval: true` no es cosmético: es lo que hace que el resto del gestor trate
   * a esta bóveda como a una de fuera —esperar a que el usuario pida ver un valor en vez
   * de abrirlo solo— sin una sola rama nueva.
   */
  get capabilities () {
    return { ...(this.inner.capabilities || {}), needsApproval: true }
  }

  async find (url) {
    return this.inner.find(url)
  }

  /**
   * UNA credencial, y **solo lo que se pide**.
   *
   * La regla, en una frase del dueño (2026-08-29): *«se pide autorización únicamente para
   * intentar llenar un dato privado»*. Así que:
   *
   * - se abre la entrada **aquí dentro**, que es la bóveda mirándose a sí misma;
   * - se mira qué de lo pedido es privado —la contraseña, el código de dos pasos, las
   *   notas, la llave de una passkey, y los campos que el usuario marcó (§4.2)—;
   * - si no hay nada privado entre lo pedido, **no se pregunta nada**: rellenar tu nombre
   *   en un formulario no es sacar un secreto de ningún sitio;
   * - y lo que sale es **solo lo pedido**. Sin esto, pedir el nombre devolvía la entrada
   *   entera y la contraseña viajaba de propina.
   *
   * Sin `keys` se pide todo, así que se autoriza todo: es lo que hace falta para firmar
   * una passkey o para copiar una contraseña desde el popup.
   */
  async get (id, opts = {}) {
    const open = await this.inner.get(id)
    const privadas = privateKeysOf(open)
    const keys = Array.isArray(opts.keys) ? opts.keys : null
    const pedidasPrivadas = keys ? keys.filter(k => privadas.has(k)) : [...privadas]

    if (pedidasPrivadas.length) {
      const ok = await this.gate.allow({ op: 'get', payload: { id, keys: pedidasPrivadas } })
      if (!ok) throw new VaultError(CODES.NOT_APPROVED, 'no aprobado')
    }
    return projectEntry(open, keys)
  }

  /** Escribir no saca nada de la bóveda, así que no se pregunta. */
  async put (entry) {
    return this.inner.put(entry)
  }

  /**
   * Cambiar unos campos tampoco: la fusión la hace la bóveda y no sale ni un valor. Es
   * además lo que evita el fallo que tenía guardar —leer la entrada entera para escribir
   * un campo, y perderla si esa lectura no salía—.
   */
  async patch (id, changes) {
    return this.inner.patch(id, changes)
  }

  async search (q, opts) {
    return this.inner.search(q, opts)
  }

  /** Los dominios ya viajan en claro: preguntarlos no saca nada que estuviera guardado. */
  async sites () {
    return this.inner.sites()
  }

  async remove (id) {
    return this.inner.remove(id)
  }

  async list () {
    return this.inner.list()
  }

  /**
   * EL RESUMEN DE UN VALOR, que existe justamente para no tener que abrir nada: dice si lo
   * que tienes escrito delante ya está guardado igual. Por eso no pasa por la puerta —no
   * saca de la bóveda ningún valor, solo compara— y por eso hay que reenviarlo: sin esto,
   * la bóveda sellada tenía el método y el gestor no lo veía, así que «¿ya está guardado
   * igual?» se contestaba que no siempre y el aviso de guardar salía en cada formulario.
   */
  async digest (id, key, value) {
    if (typeof this.inner.digest !== 'function') return null
    return this.inner.digest(id, key, value)
  }
}
