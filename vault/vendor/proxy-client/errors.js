/**
 * Error con un `code` estable.
 *
 * El contrato es el CODE, no la frase: comprobar por el texto cruza procesos y
 * se rompe en silencio en cuanto alguien lo reescribe o lo traduce.
 *
 * @param {string} message
 * @param {string} code
 * @returns {Error & { code: string }}
 */
export function errorWithCode (message, code) {
  const e = /** @type {Error & { code: string }} */ (new Error(message))
  e.code = code
  return e
}
