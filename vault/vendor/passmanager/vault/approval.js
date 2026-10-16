// LA APROBACIÓN, en un solo sitio.
//
// La piden dos bóvedas que parecen distintas y no lo son: la que responde por el proxio
// (`VaultResponder` — el daemon, la pestaña de `vault.dotrino.com/vault`) y la que la
// extensión lleva dentro (`GuardedVault`). Tienen que comportarse igual; que la de
// dentro fuera la excepción y entregara sin preguntar es justo lo que el dueño mandó
// arreglar el 2026-08-29.
//
// Lo que la puerta garantiza, venga de donde venga la petición (DISENO §2.0):
//
//   · una NEGATIVA no queda recordada como aprobación: la siguiente vuelve a preguntar
//   · dos peticiones a la vez producen UN aviso, no dos
//   · lo aprobado vive en memoria y muere con la bóveda: no se guarda en ninguna parte

export class ApprovalGate {
  /**
   * @param {object} opts
   *   `ask({ op, payload, ... })` → Promise<boolean>  cómo se le pregunta al humano.
   *      Por defecto NO: una puerta sin quien conteste no deja pasar.
   *   `scope(req)` → string|null  con qué llave se recuerda un sí, y con cuál se juntan
   *      dos peticiones simultáneas. El responder pasa el APARATO, porque ahí la
   *      aprobación es del aparato y no de cada credencial.
   *   `remember`  si un sí vale para los siguientes. En `false` la puerta sigue
   *      juntando las simultáneas, pero cada petición nueva vuelve a preguntar.
   */
  constructor ({ ask, scope, remember = true } = {}) {
    this.ask = ask || (async () => false)
    this.scope = scope || (() => null)
    this.remember = remember !== false
    this._granted = new Set()
    this._asking = new Map()
  }

  /** ¿Pasa? Pregunta si hace falta, y recuerda el sí si le toca recordarlo. */
  async allow (req = {}) {
    const key = this.scope(req)
    if (this.remember && key != null && this._granted.has(key)) return true

    // Dos pestañas abriendo el mismo sitio no deben hacer sonar el teléfono dos veces.
    const junta = key == null ? `${req.op || ''}:${req.payload?.id || ''}` : String(key)
    if (this._asking.has(junta)) return this._asking.get(junta)

    const p = Promise.resolve(this.ask(req))
      .then(ok => {
        if (ok && this.remember && key != null) this._granted.add(key)
        return !!ok
      })
      .finally(() => this._asking.delete(junta))

    this._asking.set(junta, p)
    return p
  }

  granted (key) {
    return this._granted.has(key)
  }

  /** Retirar lo aprobado sin apagar la bóveda. Sin argumento, todo. */
  revoke (key) {
    if (key == null) this._granted.clear()
    else this._granted.delete(key)
  }
}
