// LA LLAVE DEL PERFIL PARA LAS CONTRASEÑAS, y las dos que salen de ella.
//
// `sealed-passwords.md` §2.6. Una sola llave aleatoria, sellada a los aparatos con
// `passwords` como cualquier otro valor, y de ella se DERIVAN dos:
//
//   · `kidx` — el índice de sitios. La bóveda busca por huellas, no por dominios, así que
//     una copia de su disco no dice en qué sitios tienes cuenta.
//   · `kcmp` — comparar sin abrir. El gestor sabe si lo que acabas de escribir ya está
//     guardado igual sin pedir una autorización para mirarlo.
//
// **Son dos y no una**, y el motivo es que un uso no sirva para el otro: con una sola,
// quien viera un índice de sitios podría fabricar resúmenes de valores, y al revés. Salen
// de HKDF con etiquetas distintas, que es lo que separa dos llaves de una.
//
// Lo que NO protegen, dicho como en el diseño: un aparato que tenga `kcmp` puede adivinar
// un valor muy corto (un PIN de cuatro cifras) probando resúmenes. Por eso los resúmenes no
// salen del aparato que los calcula.

const subtle = () => {
  const c = globalThis.crypto
  if (!c?.subtle) throw new Error('webcrypto unavailable')
  return c.subtle
}

const enc = new TextEncoder()

const b64 = (bytes) => {
  let s = ''
  for (const b of new Uint8Array(bytes)) s += String.fromCharCode(b)
  return btoa(s)
}
const unb64 = (str) => {
  const bin = atob(str)
  const out = new Uint8Array(bin.length)
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i)
  return out
}

/** La llave base del perfil, en base64. Es lo que se sella y se reparte. */
export async function makePasswordKey () {
  return b64(globalThis.crypto.getRandomValues(new Uint8Array(32)))
}

/**
 * Deriva una de las dos llaves de uso. HKDF-SHA256 con `info` distinto por uso: es la
 * forma estándar de que dos usos no compartan llave aunque compartan origen.
 */
async function derive (base, use) {
  const material = await subtle().importKey('raw', unb64(base), 'HKDF', false, ['deriveKey'])
  return subtle().deriveKey(
    { name: 'HKDF', hash: 'SHA-256', salt: new Uint8Array(0), info: enc.encode('dotrino-passmanager/v2/' + use) },
    material,
    { name: 'HMAC', hash: 'SHA-256', length: 256 },
    false,
    ['sign']
  )
}

/**
 * Las dos llaves de uso, listas para firmar. Se derivan UNA vez por sesión: hacerlo en
 * cada huella multiplica el coste de abrir el gestor sin ganar nada.
 */
export async function profileKeys (base) {
  if (typeof base !== 'string' || !base) throw new Error('profileKeys: missing the profile password key')
  const [kidx, kcmp] = await Promise.all([derive(base, 'idx'), derive(base, 'cmp')])
  return { kidx, kcmp, base }
}

/** 128 bits: de sobra para no colisionar, y la mitad de bytes que el SHA-256 entero. */
async function hmac (key, text) {
  const sig = await subtle().sign('HMAC', key, enc.encode(text))
  return b64(new Uint8Array(sig).slice(0, 16))
}

/**
 * LA HUELLA DE UN SITIO. Lo que la bóveda guarda en claro de cada entrada, y con lo que
 * contesta «tengo algo para esto» sin saber para qué.
 *
 * El sitio se normaliza aquí y en un solo sitio: si quien guarda y quien pregunta lo
 * escriben distinto (`Google.com` y `google.com`), la huella no casa y la entrada no
 * aparece — un fallo mudo de los caros.
 */
export function siteIndex (kidx, site) {
  return hmac(kidx, 'site ' + String(site || '').trim().toLowerCase())
}

/**
 * LA HUELLA DEL NOMBRE DE UN CAMPO LIBRE.
 *
 * El nombre que el usuario le pone a un campo es SUYO —«cédula», «número de socio»— y decía
 * demasiado guardado en claro: la bóveda tiene que poder emparejar la clave que le piden con
 * el sobre que guarda, pero no tiene por qué saber de qué se trata. Compara huellas, como
 * con los sitios.
 *
 * Los campos FIJOS (`username`, `secret`, `totp`, `notes`, `wa.*`) no pasan por aquí a
 * propósito: son un vocabulario cerrado, iguales en todas las entradas y de todo el mundo, y
 * son los que dejan a la bóveda aplicar su propia regla —la contraseña es privada siempre—
 * sin fiarse de una lista que escribe el aparato.
 */
export function fieldIndex (kidx, key) {
  return hmac(kidx, 'field ' + String(key || ''))
}

/** La huella de una passkey: por el sitio que la pide y por el id de la credencial. */
export function passkeyIndex (kidx, kind, value) {
  return hmac(kidx, 'wa.' + kind + ' ' + String(value || ''))
}

/**
 * EL RESUMEN DE UN VALOR, para comparar sin abrir.
 *
 * El `id` de la entrada va DENTRO: así el mismo valor en dos entradas da dos resúmenes
 * distintos y un resumen no delata una contraseña repetida. Y el nombre del campo también,
 * para que el resumen de un usuario no se pueda comparar con el de una contraseña.
 */
export function valueDigest (kcmp, id, field, value) {
  return hmac(kcmp, `${id} ${field} ${value}`)
}

export default { makePasswordKey, profileKeys, siteIndex, fieldIndex, passkeyIndex, valueDigest }
