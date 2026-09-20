/**
 * EL APARATO QUE SE ABRE CON USUARIO Y CONTRASEÑA.
 *
 * Es un miembro del acta como cualquier otro —su llave de firma, su llave de cifrado, sus
 * permisos—, y lo único distinto es dónde vive su llave privada: aquí, **cifrada con algo
 * que solo sale de la contraseña**. Diseño en
 * `dotrino-passmanager/docs/temporary-access.md`.
 *
 * Lo que esta pieza guarda y lo que NO:
 *
 *   · el registro OPAQUE del usuario y la preparación del servidor — con ellos NO se puede
 *     comprobar una contraseña sin el protocolo, ni sacarla de ahí;
 *   · el paquete con las llaves privadas del aparato, **cerrado por quien lo creó** con la
 *     llave que sale de la contraseña (`exportKey`). La bóveda no lo abre nunca: lo guarda
 *     y lo devuelve cuando alguien demuestra saber la contraseña;
 *   · el certificado del aparato y su acta, que son públicos.
 *
 * **La bóveda nunca ve la contraseña.** OPAQUE (`@dotrino/opaque`, RFC 9807) la comprueba
 * sin recibirla y sin entregar nada con qué adivinarla desde fuera: solo se puede probar en
 * línea, contra el freno de abajo.
 *
 * El escritorio (`createLoginDesk`) es puro: recibe el estado, lo devuelve cambiado y no toca
 * el disco ni la red. Quien lo guarda y quien lo sirve es cada bóveda —`src/vault.js` en el
 * binario, `lib/src/index.js` en la pestaña—. Lo único que no es puro es `registerLogin`, al
 * final, porque hace falta la identidad que firma.
 */
import { server as opaque, suiteId } from '@dotrino/opaque'
import { pubkeyId } from '@dotrino/identity/capabilities'
import { deviceIdOf, scopeToCaps, scopeToCn } from './enroll.js'
import { SCOPE } from './protocol.js'
import { bytesToB64url, b64urlToBytes } from './b64.js'

/** Un usuario es la parte de antes de la `@` en `nombre@AB12-CD34-EF56`. */
export const isValidUser = (u) => typeof u === 'string' && /^[a-z0-9][a-z0-9._-]{0,31}$/.test(u)

/**
 * LA DIRECCIÓN: `nombre@AB12-CD34-EF56` (`temporary-access.md` §3.2). Lo de después de la
 * `@` son los primeros **48 bits de la huella de la cuenta** — el mismo `pubkeyId` que ya
 * identifica cualquier llave, con un grupo más que `keyLabel`.
 *
 * Se ata a la CUENTA y no a una máquina porque la cuenta no cambia nunca y la bóveda puede
 * mudarse o tener réplicas. Y son 48 bits y no 32 porque este código es lo único que ata la
 * dirección a la cuenta de verdad: fabricar otra cuenta con la misma huella corta cuesta
 * siglos con 48 bits y horas con los 32 de `keyLabel`.
 *
 * Vive aquí, y no en cada bóveda, porque una dirección que se escriba distinta en el binario
 * y en la extensión no es la misma dirección.
 */
export const ACCOUNT_CODE_HEX = 12
export function accountCode (fingerprint) {
  const hex = String(fingerprint || '').replace(/[^0-9a-fA-F]/g, '').toUpperCase()
  if (hex.length < ACCOUNT_CODE_HEX) throw err('bad-account', 'the account fingerprint is too short to build an address')
  return hex.slice(0, ACCOUNT_CODE_HEX).match(/.{4}/g).join('-')
}
export const loginAddress = (user, fingerprint) => `${user}@${accountCode(fingerprint)}`

/**
 * LA HUELLA DE LA CUENTA, que es de la CUENTA y no de la bóveda que la atiende.
 *
 * Sale del `profileId` del acta —la llave del génesis, la que no cambia nunca—, y por eso
 * la dirección sobrevive a que la bóveda se mude, se replique o adopte la cuenta de otro
 * aparato. Derivarla de la llave de la bóveda daba una dirección distinta en cada réplica
 * y ninguna en la segunda bóveda de un multivault.
 *
 * Es la MISMA cuenta para todas las bóvedas de esa cuenta, que es justo lo que hace que el
 * canal las junte a todas.
 */
export async function accountFingerprint (identity) {
  const pid = (await identity?.profileActa?.().catch(() => null))?.acta?.profileId
  if (!pid) throw err('no-acta', 'this vault has no account record yet: there is no address to build')
  return (await pubkeyId(pid)).slice(0, 16)
}

/**
 * Lee `nombre@AB12-CD34-EF56`. Es lo que TECLEA una persona en un equipo prestado, así que
 * se le perdona el formato —mayúsculas, espacios, guiones de más o de menos— pero no el
 * contenido: el código son 12 dígitos hexadecimales, ni uno más ni uno menos.
 *
 * Lo que NO se perdona tiene su razón: un código corto de menos no es «casi» la dirección,
 * es otra cuenta con la que se colisiona antes, y aceptarlo sería quitarle los bits que lo
 * atan a tu cuenta (§3.2 de `temporary-access.md`).
 */
export function parseLoginAddress (address) {
  const raw = String(address || '').trim()
  const at = raw.lastIndexOf('@')
  if (at <= 0) throw err('bad-address', 'an address looks like name@AB12-CD34-EF56')
  const user = raw.slice(0, at).trim().toLowerCase()
  const hex = raw.slice(at + 1).replace(/[^0-9a-fA-F]/g, '').toUpperCase()
  if (!isValidUser(user)) throw err('bad-user', 'a user name is lowercase letters, digits, dot, dash or underscore (1-32)')
  if (hex.length !== ACCOUNT_CODE_HEX) throw err('bad-address', `the account code is ${ACCOUNT_CODE_HEX} hex digits: AB12-CD34-EF56`)
  return { user, code: accountCode(hex), address: `${user}@${accountCode(hex)}` }
}

/**
 * EL CANAL DONDE SE ANUNCIA CADA BÓVEDA DE ESA CUENTA, réplicas incluidas.
 *
 * Quien entra con usuario y contraseña no tiene ninguna llave todavía, así que no puede
 * escribirle a la bóveda por su pubkey: no la sabe. Lo único que tiene es el código de la
 * dirección, y con él lista este canal y encuentra a quien atiende.
 *
 * **El canal no prueba nada**: cualquiera puede publicarse en uno. Lo que ata la bóveda a
 * la cuenta es el acta que enseña después — su huella tiene que empezar por ese mismo
 * código. Por eso son 48 bits, y por eso mirar este canal solo deja ver que detrás de un
 * código hay una bóveda encendida: ni de quién es, ni qué guarda.
 */
export const vaultChannel = (fingerprint) => `dotrino-vault-${accountCode(fingerprint)}`

/**
 * EL FRENO. Cinco intentos y, a partir de ahí, una espera que se DUPLICA con cada fallo
 * (decidido por el dueño el 2026-09-17). Se eligió frente a bloquear la cuenta porque un
 * bloqueo deja que cualquiera que sepa tu usuario te impida entrar a propósito.
 *
 * **Se cuenta al EMPEZAR el intento, no al terminarlo**, y no es un detalle: en OPAQUE quien
 * prueba una contraseña se entera ÉL SOLO al recibir la respuesta, sin mandar el último
 * mensaje. Contando al final, quien prueba contraseñas no gastaría ni un intento y el freno
 * no frenaría nada. Un inicio de sesión que termina bien reinicia la cuenta.
 *
 * El precio, dicho claro: quien sepa tu usuario puede gastarte los intentos y hacerte
 * esperar. Por eso hay tope de una hora y `clearBlock`, que lo quita desde la máquina de la
 * bóveda. No hay forma de evitarlo del todo: para saber si una contraseña es la buena hay
 * que dejar intentar.
 */
export const FREE_TRIES = 5
export const BACKOFF_BASE_MS = 60_000
export const BACKOFF_CAP_MS = 60 * 60_000
export const backoffFor = (fails) =>
  fails < FREE_TRIES ? 0 : Math.min(BACKOFF_BASE_MS * 2 ** (fails - FREE_TRIES), BACKOFF_CAP_MS)

/** Un intercambio de inicio de sesión a medias no puede quedarse abierto para siempre. */
export const EXCHANGE_TTL_MS = 2 * 60_000

const err = (code, message) => Object.assign(new Error(message), { code })

// ---------------------------------------------------------------------------
// EL PAQUETE DE LLAVES
//
// Lo cierra y lo abre QUIEN SABE LA CONTRASEÑA: la CLI al crear el aparato, y el
// navegador al entrar. La bóveda solo lo guarda y lo devuelve — nunca tiene con qué
// abrirlo, y por eso esto no está en ninguna de las tres bóvedas sino aquí, donde las
// tres lo importan y cierran el paquete EXACTAMENTE igual.
//
// AES-GCM con los primeros 32 bytes de la llave que sale de la contraseña (`exportKey`
// de OPAQUE). El formato lleva marca de versión porque este blob se guarda durante años
// y lo leen tres programas distintos: sin ella, cambiarlo sería adivinar.
// ---------------------------------------------------------------------------

const BLOB_V = 'k1'

/** La llave AES que sale del `exportKey` del intercambio. No se guarda en ningún sitio. */
async function keyFrom (exportKey, use) {
  const raw = b64urlToBytes(exportKey)
  if (!raw || raw.length < 32) throw err('bad-key', 'the key that opens the package is not valid')
  return crypto.subtle.importKey('raw', raw.subarray(0, 32), 'AES-GCM', false, [use])
}

/** Cierra las llaves privadas del aparato. `keys` es JSON: `{ sign, enc }` en JWK. */
export async function sealDeviceKeys (exportKey, keys) {
  const key = await keyFrom(exportKey, 'encrypt')
  const iv = crypto.getRandomValues(new Uint8Array(12))
  const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, new TextEncoder().encode(JSON.stringify(keys)))
  return [BLOB_V, bytesToB64url(iv), bytesToB64url(new Uint8Array(ct))].join('.')
}

/**
 * Abre el paquete. Una contraseña equivocada NO llega hasta aquí —OPAQUE la para antes—,
 * así que si esto falla es que el paquete está roto o es de otra versión, y se dice.
 */
export async function openDeviceKeys (exportKey, blob) {
  const [v, iv, ct] = String(blob || '').split('.')
  if (v !== BLOB_V || !iv || !ct) throw err('bad-blob', 'the key package is not in a format this version understands')
  const key = await keyFrom(exportKey, 'decrypt')
  let plain
  try {
    plain = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: b64urlToBytes(iv) }, key, b64urlToBytes(ct))
  } catch (_) { throw err('bad-blob', 'the key package did not open with that key') }
  return JSON.parse(new TextDecoder().decode(plain))
}

/**
 * @param {object} opts
 *   `load()`  devuelve el estado guardado (o `null` la primera vez)
 *   `save(s)` lo guarda
 *   `now()`   el reloj, para poder probar el freno sin esperar una hora
 */
export function createLoginDesk ({ load, save, now = () => Date.now() } = {}) {
  if (typeof load !== 'function' || typeof save !== 'function') throw new Error('createLoginDesk: load and save are required')

  /** Intercambios a medias: viven en memoria, y por eso un reinicio los tira. */
  const exchanges = new Map()

  const read = () => {
    const s = load()
    if (s && typeof s === 'object') return s
    return { v: 1, setup: null, users: {} }
  }

  /** La preparación del servidor nace con el primer usuario y no se toca nunca más. */
  function setupOf (state) {
    if (state.setup) return state.setup
    state.setup = opaque.createSetup()
    return state.setup
  }

  const userOf = (state, user) => {
    if (!isValidUser(user)) throw err('bad-user', 'a user name is lowercase letters, digits, dot, dash or underscore (1-32)')
    return state.users[user] || null
  }

  const sweepExchanges = () => {
    const t = now()
    for (const [lid, x] of exchanges) if (t - x.at > EXCHANGE_TTL_MS) exchanges.delete(lid)
  }

  return {
    /** Lo que se puede enseñar: ni el registro, ni el paquete de llaves, ni la preparación. */
    list () {
      const state = read()
      return Object.entries(state.users).map(([user, u]) => ({
        user,
        deviceId: u.deviceId || null,
        label: u.label || '',
        pub: u.pub,
        createdAt: u.createdAt || 0,
        passwordChangedAt: u.passwordChangedAt || u.createdAt || 0,
        fails: u.fails || 0,
        blockedUntil: u.nextTryAt || 0,
        sessions: Object.entries(u.sessions || {}).map(([sid, s]) => ({
          sid, openedAt: s.openedAt, lastUsedAt: s.lastUsedAt || s.openedAt, label: s.label || ''
        })).sort((a, b) => b.lastUsedAt - a.lastUsedAt)
      })).sort((a, b) => a.user.localeCompare(b.user))
    },

    /**
     * ALTA, primer paso. La contraseña no llega hasta aquí: lo que llega es el mensaje de
     * registro de OPAQUE, que no la lleva ni permite adivinarla.
     */
    registerBegin ({ user, request, replace = false } = {}) {
      const state = read()
      const existing = userOf(state, user)
      if (existing && !replace) throw err('user-exists', `there is already a login called "${user}"`)
      if (!existing && replace) throw err('no-user', `there is no login called "${user}"`)
      if (typeof request !== 'string' || !request) throw err('bad-input', 'request required')
      const setup = setupOf(state)
      const response = opaque.registrationResponse({ setup, request, credentialId: user })
      save(state)
      return { response, suite: suiteId() }
    },

    /**
     * ALTA, segundo paso. `blob` son las llaves privadas del aparato, ya cerradas por quien
     * creó el aparato con la llave que sale de la contraseña: aquí no se abre nunca.
     */
    registerFinish ({ user, upload, pub, encPub = null, deviceId = null, label = '', blob, replace = false } = {}) {
      const state = read()
      const existing = userOf(state, user)
      if (existing && !replace) throw err('user-exists', `there is already a login called "${user}"`)
      if (!existing && replace) throw err('no-user', `there is no login called "${user}"`)
      if (typeof blob !== 'string' || !blob) throw err('bad-input', 'blob required (the device keys, sealed with the password)')
      if (!replace && (typeof pub !== 'string' || !pub)) throw err('bad-input', 'pub required')
      const record = opaque.registrationFinish({ upload })
      const t = now()
      state.users[user] = {
        ...(existing || {}),
        pub: replace ? existing.pub : pub,
        encPub: replace ? existing.encPub : encPub,
        deviceId: replace ? existing.deviceId : deviceId,
        label: label || existing?.label || '',
        record,
        blob,
        suite: suiteId(),
        createdAt: existing?.createdAt || t,
        passwordChangedAt: t,
        // Cambiar la contraseña cierra lo abierto: si alguien entró con la vieja, deja de
        // valer. Y el freno se reinicia, que si no la cuenta vieja castigaría a la nueva.
        sessions: {},
        fails: 0,
        nextTryAt: 0
      }
      save(state)
      return { user, suite: suiteId() }
    },

    /** El certificado del aparato, que firma la bóveda al admitirlo en el acta. Es público. */
    setCert ({ user, cert, iss = null } = {}) {
      const state = read()
      const u = userOf(state, user)
      if (!u) throw err('no-user', `there is no login called "${user}"`)
      u.cert = cert
      if (iss) u.iss = iss
      save(state)
      return { ok: true }
    },

    /**
     * INICIO DE SESIÓN, primer paso.
     *
     * Un usuario que no existe recibe una respuesta **igual por fuera**, hecha con un
     * registro inventado: desde fuera no se puede averiguar qué usuarios hay. Y cuenta
     * contra el mismo freno, para que tampoco se pueda medir por el tiempo.
     */
    loginBegin ({ user, request } = {}) {
      sweepExchanges()
      const state = read()
      if (typeof request !== 'string' || !request) throw err('bad-input', 'request required')
      const u = isValidUser(user) ? state.users[user] || null : null
      const t = now()
      if (u?.nextTryAt && u.nextTryAt > t) {
        throw Object.assign(err('too-many-tries', 'too many tries: wait before trying again'), { waitMs: u.nextTryAt - t })
      }
      // EL INTENTO SE CUENTA AQUÍ. Ver el comentario del freno: quien prueba una contraseña
      // puede no mandar nunca el último mensaje, así que si se contara al final no se
      // contaría nada. `loginEnd` lo reinicia cuando el intento sale bien.
      if (u) {
        u.fails = (u.fails || 0) + 1
        u.nextTryAt = t + backoffFor(u.fails)
      }
      const setup = setupOf(state)
      const { state: serverState, response } = opaque.loginStart({
        setup,
        record: u?.record || null,
        request,
        credentialId: String(user || ''),
        identifiers: {}
      })
      const lid = crypto.randomUUID()
      exchanges.set(lid, { user: String(user || ''), known: !!u, state: serverState, at: t })
      save(state)
      return { lid, response }
    },

    /**
     * INICIO DE SESIÓN, segundo paso. Si la contraseña es la buena, devuelve el paquete de
     * llaves —que solo abre esa contraseña—, el certificado y el acta.
     */
    loginEnd ({ lid, finalization, label = '' } = {}) {
      sweepExchanges()
      const x = exchanges.get(lid)
      if (!x) throw err('no-exchange', 'that login is not in flight any more: start again')
      exchanges.delete(lid)
      const state = read()
      const u = x.known ? state.users[x.user] : null

      try {
        opaque.loginFinish({ state: x.state, finalization })
      } catch (e) {
        // Contraseña equivocada, usuario inexistente o mensaje alterado: el MISMO error.
        // Distinguirlos diría qué usuarios existen. El intento ya está contado desde
        // `loginBegin`, así que aquí no se vuelve a contar.
        throw err('login-failed', 'wrong user or password')
      }

      const t = now()
      const sid = crypto.randomUUID()
      u.fails = 0
      u.nextTryAt = 0
      u.sessions = { ...(u.sessions || {}), [sid]: { openedAt: t, lastUsedAt: t, label: String(label || '').slice(0, 60) } }
      save(state)
      return { sid, user: x.user, blob: u.blob, cert: u.cert || null, iss: u.iss || null, pub: u.pub }
    },

    /**
     * QUITAR LA ESPERA, desde la máquina de la bóveda. Existe porque el freno se cuenta al
     * empezar el intento (ver arriba): quien sepa tu usuario puede gastártelos, y el dueño
     * tiene que poder devolverte la entrada sin cambiar la contraseña.
     */
    clearBlock ({ user } = {}) {
      const state = read()
      const u = userOf(state, user)
      if (!u) throw err('no-user', `there is no login called "${user}"`)
      u.fails = 0
      u.nextTryAt = 0
      save(state)
      return { ok: true }
    },

    /**
     * Un inicio de sesión NO vence solo: lo decide el cliente (dueño, 2026-09-17). Se cierra
     * al salir, al cambiar la contraseña, al quitar el aparato, o desde la consola — que es
     * la única forma de cortar el que quedó abierto en un equipo prestado.
     */
    closeSession ({ user, sid } = {}) {
      const state = read()
      const u = userOf(state, user)
      if (!u || !u.sessions?.[sid]) return { ok: false }
      delete u.sessions[sid]
      save(state)
      return { ok: true }
    },

    /** «Se usó»: es lo que deja ver en la consola cuál sigue vivo y cuál se olvidó abierto. */
    touch ({ user, sid } = {}) {
      const state = read()
      const u = userOf(state, user)
      if (!u || !u.sessions?.[sid]) return { ok: false }
      u.sessions[sid].lastUsedAt = now()
      save(state)
      return { ok: true }
    },

    /** ¿Tiene esta llave algún inicio de sesión abierto? Lo pregunta quien sirve al aparato. */
    hasOpenSession ({ pub } = {}) {
      const state = read()
      for (const u of Object.values(state.users)) {
        if (u.pub === pub && Object.keys(u.sessions || {}).length) return true
      }
      return false
    },

    /** Quitar el aparato de aquí. Sacarlo del acta es aparte, y también hay que hacerlo. */
    remove ({ user } = {}) {
      const state = read()
      if (!userOf(state, user)) return { ok: false }
      delete state.users[user]
      save(state)
      return { ok: true }
    }
  }
}

/**
 * EL ALTA ENTERA: guardar el registro, firmar el certificado y meter al aparato en el acta.
 *
 * Vive aquí —y no en cada bóveda— porque las tres versiones tienen que crear exactamente el
 * mismo aparato: el binario, la pestaña y la extensión. Lo que cambia entre ellas es lo que
 * hacen DESPUÉS (la bitácora, avisar a los demás aparatos), y eso se queda fuera.
 *
 * `replace: true` es cambiar la contraseña: el aparato, su llave y su certificado siguen
 * siendo los mismos; lo que cambia es con qué se abre el paquete.
 *
 * @param {object} opts
 *   `identity` la identidad que firma (`signDelegation`, `admitMember`)
 *   `logins`   el escritorio de `createLoginDesk`
 *   `scope`    permisos del aparato; por defecto firmar, leer y guardar
 *   `unattended` si además puede trabajar sin que nadie apruebe
 */
export async function registerLogin ({
  identity, logins, user, upload, pub, encPub = null, label = '', blob,
  scope, unattended = false, replace = false
} = {}) {
  if (replace) {
    logins.registerFinish({ user, upload, blob, replace: true })
    return { ok: true, user, replaced: true }
  }
  // PERMISOS, no tipos: los del scope, más `unattended` si quien lo crea lo eligió
  // (temporary-access.md §3.1). `passwords` no entra todavía — hasta que existan las
  // contraseñas selladas, este aparato se llevaría TODAS (sealed-passwords.md).
  const scopes = Array.isArray(scope) && scope.length ? scope : [SCOPE.SIGN, SCOPE.READ, SCOPE.STORE]
  if (scopes.includes(SCOPE.PASSWORDS)) {
    throw Object.assign(new Error('a password login cannot take `contrasenas` yet: the sealed passwords come first'), { code: 'passwords-not-yet' })
  }
  if (typeof identity?.admitMember !== 'function') {
    throw Object.assign(new Error('this vault cannot add devices to the account record: no login was created'), { code: 'admit-unavailable' })
  }
  const deviceId = await deviceIdOf(pub)
  logins.registerFinish({ user, upload, pub, encPub, deviceId, label, blob })
  try {
    const { cert } = await identity.signDelegation(pub, scopes, { label: label || `login:${user}` })
    const cn = scopeToCn(scopes)
    const caps = [...new Set([...scopeToCaps(scopes), ...(unattended ? ['unattended'] : [])])]
    await identity.admitMember({ pub, encPub, label: label || `login:${user}`, cn, caps, cert })
    logins.setCert({ user, cert, iss: identity.me?.publickey || null })
    return { ok: true, user, deviceId, cert, caps }
  } catch (e) {
    // NADA DE MEDIAS ALTAS: si no entra en el acta, no queda un usuario que pueda entrar a
    // una cuenta que no lo reconoce. Se deshace y se dice.
    logins.remove({ user })
    throw e
  }
}
