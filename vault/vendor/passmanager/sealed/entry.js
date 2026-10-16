// UNA ENTRADA SELLADA POR CAMPO (`sealed-passwords.md` §2.2 y §2.4).
//
// La diferencia con el formato de siempre (`../model.js`) no es criptográfica sino de
// QUIÉN PUEDE ABRIR: allí una sola llave de la bóveda cifraba todo, así que la bóveda leía
// las contraseñas —abierta o cerrada—. Aquí la bóveda guarda sobres dirigidos a los
// aparatos y **no tiene con qué abrir ninguno**.
//
// Tres consecuencias que cambian la forma del dato, y las tres están en el diseño:
//
//   · **La vista pública se GUARDA sellada**, no se calcula. Antes la calculaba quien tenía
//     la llave; ahora la escribe quien escribe la entrada.
//   · **Cada campo va en su propio sobre.** Es lo que permite entregar solo los campos
//     pedidos sin abrir la entrada, y lo que deja poner la privada de una passkey en un
//     sobre con OTROS destinatarios (§2.8).
//   · **Lo único en claro son huellas**: las del sitio, para poder buscar, y los resúmenes
//     para comparar. Ni un nombre de dominio.
//
// Este módulo es PURO: recibe las llaves ya resueltas y no sabe de red, de almacén ni de
// quién es miembro de nada.

import { encryptWithCek, decryptWithCek } from '@dotrino/identity/content'
import { normalizeFields, fieldKey, entryFieldKeys, privateKeysOf, entryDigestValues } from '../fields.js'
import { newEntry, normalizeSites, entryWho } from '../model.js'
import { siteIndex, fieldIndex, passkeyIndex, valueDigest } from './keys.js'

/** La privada de una passkey es el único campo que va a OTROS destinatarios (§2.8). */
export const PASSKEY_FIELD = 'wa.privateKey'

/**
 * Los campos de siempre. Su NOMBRE viaja en claro a propósito: es un vocabulario cerrado,
 * idéntico en todas las entradas de todo el mundo, así que no dice nada de nadie — y es lo
 * que deja a la bóveda saber que una contraseña es privada sin fiarse de ninguna lista.
 */
export const FIXED = ['name', 'username', 'secret', 'totp', 'notes']

const sealV = async (cek, gen, value) => encryptWithCek({ cek, gen, plaintext: String(value) })

/**
 * SELLA UNA ENTRADA ENTERA.
 *
 * @param {object} o
 *   `plain`  la entrada en claro (la misma forma de `newEntry`)
 *   `main`   `{ gen, cek }` la generación para todo lo normal
 *   `passkeys` `{ gen, cek }` la generación de la privada de la passkey. Solo hace falta
 *              si la entrada lleva una; si falta y la lleva, se para: guardar esa llave
 *              con los destinatarios de las contraseñas es justo lo que §2.8 prohíbe
 *   `keys`   `{ kidx, kcmp }` las llaves del perfil
 * @returns {Promise<object>} la entrada tal como se guarda
 */
export async function sealEntry ({ plain, main, passkeys = null, keys }) {
  if (!main?.cek || typeof main.gen !== 'number') throw new Error('sealEntry: missing the main generation')
  if (!keys?.kidx || !keys?.kcmp) throw new Error('sealEntry: missing the profile keys')
  const e = newEntry(plain)
  const campos = (() => {
    if (Array.isArray(e.fields)) return normalizeFields(e.fields)
    try { return normalizeFields(JSON.parse(e.fields || '[]')) } catch { return [] }
  })()
  const abierta = { ...e, fields: JSON.stringify(campos) }

  const fields = {}
  for (const f of FIXED) if (e[f]) fields[f] = await sealV(main.cek, main.gen, e[f])
  for (const f of campos) {
    if (!f?.value) continue
    // LA MARCA DE PRIVADO ES DEL SOBRE, con su valor (dueño, 2026-09-19). No es metadato
    // suelto: dice qué es ese dato, y separarla dejaba el sobre incompleto —quien lo abre
    // solo no sabría si es privado— y dos verdades que se pueden desincronizar. Lo que va
    // en la vista y en el índice de la bóveda son COPIAS derivadas, que se rehacen al
    // escribir.
    //
    // El precio, y se asume: cambiar la marca obliga a re-sellar el campo, o sea a tenerlo
    // delante. Marcar uno público como privado no cuesta aprobación (leerlo es gratis);
    // quitársela a uno privado sí la cuesta — y está bien, porque vas a exponerlo.
    fields['f:' + await fieldIndex(keys.kidx, fieldKey(f))] = await sealV(main.cek, main.gen, JSON.stringify(f))
  }

  if (e.webauthn) {
    if (e.webauthn.userHandle) fields['wa.userHandle'] = await sealV(main.cek, main.gen, e.webauthn.userHandle)
    if (e.webauthn.privateKey) {
      if (!passkeys?.cek || typeof passkeys.gen !== 'number') {
        throw Object.assign(
          new Error('this entry carries a passkey: it needs its own generation, wrapped only to devices with `passkeys`'),
          { code: 'passkeys-generation-missing' })
      }
      fields[PASSKEY_FIELD] = await sealV(passkeys.cek, passkeys.gen, e.webauthn.privateKey)
    }
  }

  // LA VISTA: lo que ve quien puede abrir la entrada pero no pidió ningún valor. Lleva los
  // NOMBRES de los campos y cuáles son privados —nunca sus valores—, que es lo que deja
  // ofrecer «rellenar el número de socio» sin sacar nada.
  const view = {
    type: e.type,
    title: e.title,
    sites: e.sites,
    hint: entryWho(abierta),
    fieldKeys: entryFieldKeys(abierta),
    privateKeys: [...privateKeysOf(abierta)],
    has: {
      secret: !!e.secret, totp: !!e.totp, notes: !!e.notes,
      fields: campos.length > 0, webauthn: !!e.webauthn
    },
    ...(e.webauthn
      ? { webauthn: { rpId: e.webauthn.rpId, credentialId: e.webauthn.credentialId, signCount: e.webauthn.signCount || 0 } }
      : {})
  }

  // LOS RESÚMENES, con la clave por huella igual que los sobres: los guarda la bóveda y
  // tampoco tiene por qué saber de qué campo son. Lo que se resume sigue siendo el NOMBRE
  // de verdad más el valor —es lo que compara quien escribe, que lo tiene delante.
  const digests = {}
  for (const f of entryDigestValues(abierta)) {
    const clave = FIXED.includes(f.key) || f.key.startsWith('wa.') ? f.key : 'f:' + await fieldIndex(keys.kidx, f.key)
    digests[clave] = await valueDigest(keys.kcmp, e.id, f.key, f.value)
  }

  return {
    id: e.id,
    createdAt: e.createdAt,
    updatedAt: e.updatedAt,
    // Sin sitios = sirve en cualquier parte, que es lo que ha significado siempre.
    idx: await Promise.all(normalizeSites(e.sites).map((s) => siteIndex(keys.kidx, s))),
    wa: e.webauthn
      ? {
          rp: await passkeyIndex(keys.kidx, 'rp', e.webauthn.rpId),
          cred: await passkeyIndex(keys.kidx, 'cred', e.webauthn.credentialId)
        }
      : null,
    view: await sealV(main.cek, main.gen, JSON.stringify(view)),
    fields,
    digests,
    // QUÉ CLAVES SON PRIVADAS, para que la bóveda sepa cuándo pedir un dedo encima. Es un
    // ÍNDICE derivado de las marcas de los sobres, no la fuente.
    //
    // Y va con las mismas huellas que las claves: de un campo libre, la bóveda ve
    // `f:<huella>` y no «cédula». Las fijas (`secret`, `totp`, …) sí van por su nombre, que
    // es un vocabulario cerrado e igual para todo el mundo — y son las que le dejan aplicar
    // su propia regla sin fiarse de esta lista, que la escribe el aparato.
    priv: await Promise.all([...privateKeysOf(abierta)].map(async (k) =>
      (FIXED.includes(k) || k.startsWith('wa.') ? k : 'f:' + await fieldIndex(keys.kidx, k))))
  }
}

/** Abre la vista de una entrada. `open({ envelope })` lo pone quien tiene la llave. */
export async function openView (sealed, open) {
  const v = JSON.parse(await open({ envelope: sealed.view }))
  return {
    id: sealed.id,
    type: v.type,
    title: v.title,
    sites: v.sites || [],
    hint: v.hint || '',
    fieldKeys: v.fieldKeys || [],
    privateKeys: v.privateKeys || [],
    hasSecret: !!v.has?.secret,
    hasTotp: !!v.has?.totp,
    hasNotes: !!v.has?.notes,
    hasFields: !!v.has?.fields,
    hasWebauthn: !!v.has?.webauthn,
    ...(v.webauthn ? { webauthn: v.webauthn } : {}),
    updatedAt: sealed.updatedAt,
    digests: sealed.digests || {}
  }
}

/**
 * ABRE LOS CAMPOS QUE VINIERON y los devuelve con la forma de siempre, para que la interfaz
 * no tenga que aprender un formato nuevo.
 *
 * Lo que no vino, no está: pedir el usuario y recibir la entrada entera es justo lo que se
 * quitó. `withheld` dice qué se quedó fuera —porque no se pidió, o porque este aparato no
 * puede abrirlo (una passkey sin el permiso)— para que la pantalla lo diga en vez de
 * enseñar un hueco.
 */
export async function openFields ({ sealed, envelopes, open, view = null }) {
  const out = {
    id: sealed?.id || view?.id,
    type: view?.type || 'login',
    title: view?.title || '',
    sites: view?.sites || [],
    name: '', username: '', secret: '', totp: '', notes: '',
    fields: '[]',
    webauthn: null,
    createdAt: sealed?.createdAt,
    updatedAt: sealed?.updatedAt || view?.updatedAt
  }
  const libres = []
  let wa = view?.webauthn ? { ...view.webauthn, userHandle: '', privateKey: '' } : null
  for (const [k, envelope] of Object.entries(envelopes || {})) {
    const valor = await open({ envelope, field: k })
    if (FIXED.includes(k)) { out[k] = valor; continue }
    if (k.startsWith('f:')) {
      // El campo viene entero: su etiqueta, su clase, su valor y su marca. La clave con la
      // que la bóveda lo guarda es una huella y no hace falta para nada aquí — el nombre
      // sale del propio sobre.
      try { libres.push(JSON.parse(valor)) } catch (_) {}
      continue
    }
    if (k === 'wa.userHandle') { wa = { ...(wa || {}), userHandle: valor }; continue }
    if (k === PASSKEY_FIELD) { wa = { ...(wa || {}), privateKey: valor }; continue }
  }
  out.fields = JSON.stringify(libres)
  out.webauthn = wa
  return out
}

/** Qué claves de campo lleva una entrada sellada. Sin abrir nada: son los nombres. */
export const fieldNames = (sealed) => Object.keys(sealed?.fields || {})

export default { sealEntry, openView, openFields, fieldNames, PASSKEY_FIELD }
