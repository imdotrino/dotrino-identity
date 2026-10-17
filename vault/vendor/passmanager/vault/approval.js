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
//   · y además CADUCA: una hora deslizante, como dotrino-env (dueño, 2026-10-16). Cada uso
//     la renueva; una hora sin usarla y se vuelve a preguntar. Antes duraba hasta reiniciar
//     la bóveda, o sea días, y un sí de la mañana servía para todo lo de la semana.

/** Cuánto vale un sí sin usarse: una hora, deslizante. */
export const GRANT_TTL_MS = 60 * 60 * 1000

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
   *   `ttlMs`  cuánto vale un sí sin usarse (deslizante: cada uso lo renueva). Una hora.
   *   `now`  el reloj, para las pruebas.
   */
  constructor ({ ask, scope, remember = true, ttlMs = GRANT_TTL_MS, now = Date.now } = {}) {
    this.ask = ask || (async () => false)
    this.scope = scope || (() => null)
    this.remember = remember !== false
    this.ttlMs = ttlMs
    this.now = now
    this._granted = new Map()   // llave → cuándo se usó por última vez
    this._asking = new Map()
  }

  /** ¿Sigue vivo el sí de esa llave? Si sí, se renueva (deslizante); si caducó, se olvida. */
  #fresh (key) {
    const last = this._granted.get(key)
    if (last == null) return false
    if (this.now() - last > this.ttlMs) { this._granted.delete(key); return false }
    this._granted.set(key, this.now())
    return true
  }

  /**
   * ¿Pasa? Pregunta si hace falta, y recuerda el sí si le toca recordarlo.
   *
   * `req.remember === false`: ESTA petición pregunta siempre, y su sí no vale para las
   * siguientes. Es la de lo que no se deshace (borrar o pisar una passkey): que el sí a
   * leer, o a borrar otra cosa, la dejara pasar es borrar sin que nadie lo vea
   * (pasó el 2026-10-16: un borrado aprobado dejó pasar el siguiente sin aviso).
   */
  async allow (req = {}) {
    const key = this.scope(req)
    const remember = this.remember && req.remember !== false
    if (remember && key != null && this.#fresh(key)) return true

    // Dos pestañas abriendo el mismo sitio no deben hacer sonar el teléfono dos veces.
    // Lo que pregunta siempre se junta solo con la MISMA petición, no con todo el aparato.
    const junta = key == null || !remember ? `${key ?? ''}:${req.op || ''}:${req.payload?.id || ''}` : String(key)
    if (this._asking.has(junta)) return this._asking.get(junta)

    const p = Promise.resolve(this.ask(req))
      .then(ok => {
        if (ok && remember && key != null) this._granted.set(key, this.now())
        return !!ok
      })
      .finally(() => this._asking.delete(junta))

    this._asking.set(junta, p)
    return p
  }

  granted (key) {
    const last = this._granted.get(key)
    return last != null && this.now() - last <= this.ttlMs
  }

  /** Retirar lo aprobado sin apagar la bóveda. Sin argumento, todo. */
  revoke (key) {
    if (key == null) this._granted.clear()
    else this._granted.delete(key)
  }
}
