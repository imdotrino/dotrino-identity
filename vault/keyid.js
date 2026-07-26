/**
 * keyid.js — el identificador LEGIBLE de una llave.
 *
 * Una pubkey es un JWK: `{"crv":"P-256","kty":"EC","x":"…","y":"…"}`. Eso no se le enseña a
 * nadie — ni entero ni recortado, que es peor: parece un error. Para que una persona pueda
 * reconocer y comparar una llave se usa su huella corta, `AB12-CD34`, que es la misma que
 * ya se muestra al emparejar («aprueba el dispositivo AB12-CD34») y en el acta del perfil.
 *
 * Módulo aparte y sin dependencias a propósito: cualquier interfaz que necesite mostrar una
 * llave puede importarlo sin arrastrar el resto de la identidad. `capabilities.js` reexporta
 * `pubkeyId` desde aquí para que haya UNA sola implementación.
 */

const enc = (s) => new TextEncoder().encode(s)

/** Serialización canónica de los campos que identifican la llave (mismo orden siempre). */
function canonicalJwk (jwk) {
  return JSON.stringify({ crv: jwk.crv, kty: jwk.kty, x: jwk.x, y: jwk.y })
    .replace(/^{/, '{').replace(/}$/, '}')
}

/** id corto y estable de un pubkey (sha-256 hex de los campos canónicos del JWK). */
export async function pubkeyId (publicJwkStr) {
  const jwk = typeof publicJwkStr === 'string' ? JSON.parse(publicJwkStr) : publicJwkStr
  const h = await crypto.subtle.digest('SHA-256', enc(canonicalJwk(jwk)))
  return [...new Uint8Array(h)].map((b) => b.toString(16).padStart(2, '0')).join('')
}

/**
 * La huella que SÍ se le enseña a una persona: `AB12-CD34`. Corta, comparable de un vistazo
 * y la misma en todo el ecosistema (emparejamiento, acta, lista de dispositivos).
 */
export async function keyLabel (publicJwkStr) {
  if (!publicJwkStr) return ''
  try {
    const id = (await pubkeyId(publicJwkStr)).slice(0, 8).toUpperCase()
    return id.slice(0, 4) + '-' + id.slice(4, 8)
  } catch (_) { return '' }
}

export default { pubkeyId, keyLabel }
