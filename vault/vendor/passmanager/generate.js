// Generador de contraseñas.
//
// Un gestor que no genera contraseñas obliga a inventárselas, y ahí es donde la gente
// repite la de siempre. Es parte del producto, no un extra.
//
// Toda la aleatoriedad sale de `crypto.getRandomValues`, y la elección de carácter se
// hace SIN sesgo: `% alphabet.length` reparte de más los primeros caracteres cuando el
// alphabet no divide a 256, y en un generador de contraseñas eso es exactamente lo que
// no se quiere. Se descartan los valores que caen fuera del último bloque completo.

const MINUS = 'abcdefghijkmnopqrstuvwxyz'    // sin la ele
const MAYUS = 'ABCDEFGHJKLMNPQRSTUVWXYZ'     // sin la I ni la O
const DIGITOS = '23456789'                   // sin el cero ni el uno
const SIMBOLOS = '!#$%&*+-=?@_'
const AMBIGUOS = 'lIO01'

/** Un entero en [0, max) sin sesgo. */
function randomBelow (max) {
  const limite = Math.floor(256 / max) * max
  const b = new Uint8Array(1)
  for (;;) {
    globalThis.crypto.getRandomValues(b)
    if (b[0] < limite) return b[0] % max
  }
}

function pick (alphabet) {
  return alphabet[randomBelow(alphabet.length)]
}

/** Baraja en su sitio (Fisher-Yates), para que los obligatorios no queden al principio. */
function shuffle (arr) {
  for (let i = arr.length - 1; i > 0; i--) {
    const j = randomBelow(i + 1)
    ;[arr[i], arr[j]] = [arr[j], arr[i]]
  }
  return arr
}

/**
 * @param {object} opts
 *   `length`      size (por defecto 20)
 *   `upper`/`digits`/`symbols`  incluir mayúsculas, números, símbolos
 *   `ambiguous`   incluir los caracteres que se confunden al leer (l, I, O, 0, 1)
 */
export function generatePassword ({
  length = 20, upper = true, digits = true, symbols = true, ambiguous = false,
} = {}) {
  const groups = [ambiguous ? MINUS + 'l' : MINUS]
  if (upper) groups.push(ambiguous ? MAYUS + 'IO' : MAYUS)
  if (digits) groups.push(ambiguous ? DIGITOS + '01' : DIGITOS)
  if (symbols) groups.push(SIMBOLOS)

  const alphabet = groups.join('')
  const min = Math.max(groups.length, 4)
  const size = Math.max(min, Math.min(256, Math.floor(length) || 20))

  // Uno de cada grupo pedido, para que «con números» signifique que HAY un número y no
  // que podría haberlo. El resto, del alphabet entero.
  const chars = groups.map(g => pick(g))
  while (chars.length < size) chars.push(pick(alphabet))
  return shuffle(chars).join('')
}

/** Frase de varias palabras, más fácil de dictar o teclear a mano. */
export function generatePassphrase (words, { count = 4, separator = '-' } = {}) {
  if (!Array.isArray(words) || words.length < 16) {
    throw new Error('generatePassphrase: hace falta una lista de palabras')
  }
  return Array.from({ length: Math.max(2, count) }, () => words[randomBelow(words.length)])
    .join(separator)
}

export { AMBIGUOS }
