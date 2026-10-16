// Campos sueltos para rellenar formularios: correo, teléfono, dirección, cédula, lo
// que sea. Son del usuario y no de un sitio concreto.
//
// Dos ideas, y las dos son deliberadamente simples:
//
// 1. **Los campos son libres.** Una lista de `{ label, value, kind }`, no un formulario
//    fijo. Cada quien guarda lo que necesita rellenar, y puede tener varios juegos —
//    la dirección de casa y la del trabajo son dos entradas, no dos campos.
//
// 2. **Cross-domain es no tener sitios**, no un tipo aparte. Una entrada sin `sites`
//    sirve en cualquier parte; con `sites`, solo ahí. Eso vale para cualquier tipo de
//    entrada, y así no hay dos reglas de emparejamiento que mantener.
//
// `kind` es opcional y solo sirve para el relleno automático: dice QUÉ ES el dato
// (un correo, un teléfono), para poder ponerlo en el hueco que le corresponde. Sin
// `kind`, el campo se guarda y se copia igual — solo no se rellena solo.

/** Clases de dato que el relleno automático sabe colocar. */
export const KINDS = [
  'email', 'tel', 'given-name', 'family-name', 'full-name',
  'street-address', 'city', 'region', 'postal-code', 'country',
  'organization', 'birthday', 'id-number', 'other',
]

/** Tokens de `autocomplete` del estándar HTML. Cuando el sitio los declara, mandan. */
export const AUTOCOMPLETE_BY_KIND = {
  email: ['email'],
  tel: ['tel', 'tel-national', 'tel-local'],
  'given-name': ['given-name'],
  'family-name': ['family-name'],
  'full-name': ['name'],
  'street-address': ['street-address', 'address-line1'],
  city: ['address-level2'],
  region: ['address-level1'],
  'postal-code': ['postal-code'],
  country: ['country', 'country-name'],
  organization: ['organization'],
  birthday: ['bday'],
}

/** Pistas por nombre/id/etiqueta, para los sitios que no declaran `autocomplete`. */
export const HINTS_BY_KIND = {
  email: ['email', 'correo', 'e-mail', 'mail'],
  tel: ['phone', 'telefono', 'teléfono', 'celular', 'movil', 'móvil', 'mobile', 'tel'],
  'given-name': ['firstname', 'first-name', 'first_name', 'givenname', 'nombre', 'nombres', 'fname'],
  'family-name': ['lastname', 'last-name', 'last_name', 'surname', 'apellido', 'apellidos', 'lname'],
  'full-name': ['fullname', 'full-name', 'nombrecompleto'],
  'street-address': ['address', 'direccion', 'dirección', 'street', 'calle', 'domicilio'],
  city: ['city', 'ciudad', 'localidad'],
  region: ['state', 'province', 'provincia', 'region', 'estado'],
  'postal-code': ['zip', 'zipcode', 'postal', 'postcode'],
  country: ['country', 'pais', 'país'],
  organization: ['company', 'empresa', 'organization', 'organizacion'],
  'id-number': ['cedula', 'cédula', 'dni', 'nif', 'rut', 'curp', 'documento'],
}

/**
 * Normaliza la lista de campos de una entrada.
 *
 * `private` marca lo que **solo sale de la bóveda con confirmación** (dueño,
 * 2026-08-28). Es la distinción que ya existía entre lo público y lo privado de un
 * registro, ahora dicha campo a campo: el teléfono que rellenas en veinte sitios no
 * pide lo mismo que el número de tu documento.
 */
export function normalizeFields (fields) {
  if (!Array.isArray(fields)) return []
  return fields
    .filter(f => f && (f.label || f.value))
    .map(f => ({
      label: String(f.label || '').trim(),
      value: String(f.value ?? ''),
      kind: KINDS.includes(f.kind) ? f.kind : undefined,
      ...(f.private ? { private: true } : {}),
    }))
}

/** ¿Esta entrada sirve en cualquier sitio? Sin sitios, sí. */
export function isCrossDomain (entry) {
  return !entry?.sites?.length
}

/** El primer campo de esa clase. */
export function fieldOfKind (entry, kind) {
  return (entry?.fields || []).find(f => f.kind === kind) || null
}

/** Un valor por etiqueta, para cuando se sabe qué se busca. */
export function fieldValue (entry, label) {
  const f = (entry?.fields || []).find(x => x.label === label)
  return f ? f.value : ''
}

/**
 * CÓMO SE LLAMA un campo para decir si dos son «el mismo».
 *
 * La clase si se reconoce, y si no la etiqueta que le puso el sitio. Vive aquí porque la
 * usan las dos puntas —la página, al mirar un formulario, y la bóveda, al decir qué
 * lleva una entrada— y dos ideas distintas de qué es el mismo campo serían un campo
 * duplicado en cada guardado. Su gemela para el DOM está en `extension/src/detect.js`,
 * que corre donde no llega esta librería; `offers.test.mjs` comprueba que dicen lo mismo.
 */
export function fieldKey (f = {}) {
  if (f.kind) return f.kind
  const l = String(f.label || '').trim()
  return l ? `label:${l}` : 'other'
}

/**
 * LO QUE NO SALE SIN AUTORIZACIÓN, pase lo que pase.
 *
 * La contraseña, el código de dos pasos, las notas y la llave de una passkey son privados
 * por lo que son, no por una marca: nadie los guarda para enseñarlos. El resto de campos
 * lo decide su marca `private` (§4.2), y el usuario es quien la pone al guardar.
 *
 * El **usuario** no está aquí a propósito: es el nombre visible de la entrada (§5), ya
 * viaja en la vista pública, y pedir permiso para escribirlo en el formulario donde lo
 * acabas de teclear no protege nada.
 */
export const ALWAYS_PRIVATE = ['secret', 'totp', 'notes', 'webauthn']

/** Las claves privadas de una entrada abierta: las de arriba, más las marcadas. */
export function privateKeysOf (open = {}) {
  const out = new Set()
  for (const k of ALWAYS_PRIVATE) if (open[k]) out.add(k)
  const campos = (() => {
    if (Array.isArray(open.fields)) return open.fields
    try { return JSON.parse(open.fields || '[]') } catch { return [] }
  })()
  for (const f of campos) if (f?.private && f?.value) out.add(fieldKey(f))
  return out
}

/**
 * TODOS los campos de una entrada abierta, como pares `{ key, value }`.
 *
 * Es la lista canónica de «qué lleva dentro»: el usuario, la contraseña, el código de dos
 * pasos y cada campo libre, **sin distinguir público de privado**. Esa distinción decide
 * qué se ENSEÑA (§4.2), no qué existe, y mezclar las dos preguntas fue lo que hizo falta
 * separar el 2026-08-29.
 */
export function entryFieldValues (open = {}) {
  const out = []
  const add = (key, value) => {
    if (!value) return
    if (out.some(f => f.key === key)) return
    out.push({ key, value: String(value) })
  }
  add('username', open.username)
  add('secret', open.secret)
  add('totp', open.totp)
  const campos = (() => {
    if (Array.isArray(open.fields)) return open.fields
    try { return JSON.parse(open.fields || '[]') } catch { return [] }
  })()
  for (const f of campos) if (f?.value) add(fieldKey(f), f.value)
  return out
}

/**
 * LO MISMO, MÁS LAS NOTAS. Solo para los resúmenes (§4.0.2).
 *
 * Las notas no están en `entryFieldValues` a propósito: eso es «qué se puede rellenar en
 * un formulario», y una nota no se rellena en ninguna parte. Pero sí se **edita** en el
 * gestor, y para decir ahí si lo escrito cambia algo hace falta su resumen como el de
 * cualquier otro campo. Un método de comparación, no dos (dueño, 2026-08-29).
 */
export function entryDigestValues (open = {}) {
  const out = entryFieldValues(open)
  if (open.notes && !out.some(f => f.key === 'notes')) out.push({ key: 'notes', value: String(open.notes) })
  return out
}

/**
 * QUÉ CAMPOS lleva una entrada abierta, por su nombre y sin un solo valor.
 *
 * Es lo que permite ofrecer «rellenar el número de socio» sin abrir nada: lo calcula
 * quien tiene la CEK y viaja en la vista pública (§4.0.2). Los NOMBRES no son los
 * valores — de la misma familia que `sites`, que ya va en claro para poder emparejar con
 * la página, y bastante menos que ellos.
 */
export function entryFieldKeys (open = {}) {
  return entryFieldValues(open).map(f => f.key)
}
