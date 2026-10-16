// Comparar llaves públicas.
//
// **Nunca con `===` sobre el JSON.** Una misma llave se serializa de varias formas: el
// orden de las claves del JWK cambia según quién la escriba, y sobran campos como
// `ext` o `key_ops` que no son parte de la llave. Comparar cadenas hace que un aparato
// autorizado aparezca como desconocido, y eso se manifiesta como un «denegado» que no
// hay forma de explicar mirando los dos valores, porque *parecen* iguales.
//
// Es una lección que el ecosistema ya tenía escrita (en `@dotrino/reputation`: comparar
// con `samePubkey`, nunca con `===`) y que aquí se volvió a tropezar.

/** Los campos que IDENTIFICAN una llave EC; lo demás es adorno de la serialización. */
function canonical (jwkOrString) {
  let k = jwkOrString
  if (typeof k === 'string') {
    try { k = JSON.parse(k) } catch { return null }
  }
  if (!k || typeof k !== 'object') return null
  if (!k.kty || !k.crv || !k.x) return null
  return `${k.kty}|${k.crv}|${k.x}|${k.y || ''}`
}

/** ¿Son la misma llave, aunque vengan escritas distinto? */
export function samePubkey (a, b) {
  const ca = canonical(a)
  const cb = canonical(b)
  return !!ca && ca === cb
}

/** Una forma estable de la llave, para usarla como clave de un mapa o de un log. */
export function pubkeyId (jwkOrString) {
  return canonical(jwkOrString)
}
