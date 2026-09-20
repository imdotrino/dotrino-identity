/**
 * ENTRAR CON USUARIO Y CONTRASEÑA — EL LADO DEL QUE ENTRA.
 *
 * La otra mitad de `passwordLogins.js`: allí está la bóveda que atiende, aquí el equipo
 * prestado que llega sin ninguna llave y solo con una dirección escrita a mano. Diseño en
 * `dotrino-passmanager/docs/temporary-access.md` §3.2.
 *
 *     nombre@AB12-CD34-EF56 + contraseña
 *     lista el canal del código         ──►  las bóvedas de esa cuenta que estén encendidas
 *     OPAQUE (inicio)                  ◄──►  comprueba sin ver la contraseña
 *     abre el paquete de llaves        ◄──   { sid, blob, cert, iss, acta }
 *     desde aquí es un aparato del acta
 *
 * **Vive en el pilar y no en la página** porque lo van a hacer tres sitios distintos —la
 * pantalla de `profile.dotrino.com`, la extensión del gestor y cualquier app que ofrezca
 * entrar— y una dirección que se lea distinto, o una comprobación que uno se salte, no es
 * la misma puerta. Aquí no se abre ninguna conexión: el transporte se INYECTA, como en
 * `@dotrino/identity/session-flow`.
 *
 * QUÉ SE COMPRUEBA, Y EN QUÉ ORDEN (importa):
 *
 *   1. **OPAQUE autentica a las DOS partes.** Una bóveda falsa no tiene tu registro, así
 *      que no puede armar una respuesta que cuadre: `loginFinish` revienta en ESTE lado y
 *      la contraseña no se le ha dicho a nadie. Por eso mandarle el primer mensaje a un
 *      desconocido del canal no cuenta nada — es el único orden posible, porque el canal
 *      solo da tokens y un token no dice de quién es.
 *   2. **El acta tiene que ser de la cuenta que escribiste**: `pubkeyId(acta.profileId)`
 *      empieza por el código de la dirección. Esto es lo que ata la respuesta a TU cuenta
 *      y no a otra bóveda que también sepa contestar.
 *   3. **El papel y el acta se sostienen entre sí** (`checkVaultReply`).
 *   4. **La llave que acaba de salir del paquete es la del papel**: se firma un reto y se
 *      verifica contra `cert.sub`. Sin esto, una bóveda podría devolver el paquete de otro.
 *
 * Si algo de eso falla, se PARA con un `code` propio. No hay repliegue: entrar «a medias»
 * en una cuenta es peor que no entrar.
 */
import { client as opaque } from '@dotrino/opaque'
import { pubkeyId, verifyDeviceSig, signWithDevice } from '@dotrino/identity/capabilities'
import { checkVaultReply } from '@dotrino/identity/acta'
import { MSG } from './protocol.js'
import { accountCode, parseLoginAddress, vaultChannel, openDeviceKeys } from './passwordLogins.js'

const err = (code, message, extra = {}) => Object.assign(new Error(message), { code, ...extra })

/** Cuánto se espera a que una bóveda conteste antes de probar con la siguiente. */
export const REPLY_TIMEOUT_MS = 15_000

/**
 * Escucha UNA respuesta de un token concreto. El `off` se suelta siempre —también al
 * agotarse la espera—: un oyente que se queda pegado hace que el segundo intento vea la
 * respuesta del primero.
 */
function waitFor (transport, from, match, timeoutMs) {
  return new Promise((resolve, reject) => {
    let listo = false
    const fin = (fn, arg) => { if (!listo) { listo = true; clearTimeout(reloj); quitar(); fn(arg) } }
    const reloj = setTimeout(() => fin(reject, err('no-answer', 'the vault did not answer in time')), timeoutMs)
    const oyente = (quien, payload) => {
      if (from && quien !== from) return
      const p = typeof payload === 'string' ? parseJson(payload) : payload
      if (p && match(p)) fin(resolve, p)
    }
    const off = transport.on('message', oyente)
    const quitar = () => {
      if (typeof off === 'function') return off()
      transport.off?.('message', oyente)
    }
  })
}

const parseJson = (s) => { try { return JSON.parse(s) } catch (_) { return null } }

/**
 * ENTRAR. Devuelve el aparato entero —sus llaves privadas, su papel y el acta— para que
 * quien llama decida dónde vive eso: en el navegador lo adopta `@dotrino/identity` como una
 * cuenta más; en la extensión, su propio almacén.
 *
 * @param {object} opts
 * @param {object} opts.transport  cliente de `@dotrino/proxy-client` ya conectado. NO hace
 *   falta identificarse: quien entra todavía no tiene con qué.
 * @param {string} opts.address    `nombre@AB12-CD34-EF56`, tal como lo teclea una persona.
 * @param {string} opts.password
 * @param {string} [opts.label]    de dónde se entra («el cyber de la esquina»): es lo que
 *   el dueño va a leer en su consola para decidir si cerrarlo.
 * @returns {Promise<{user:string,address:string,code:string,sid:string,cert:object,
 *   iss:string,acta:object,vaultToken:string,publickey:string,encPublickey:(string|null),
 *   keys:{sign:object,enc:(object|null)}}>}
 */
export async function loginWithPassword ({ transport, address, password, label = '', timeoutMs = REPLY_TIMEOUT_MS } = {}) {
  if (!transport || typeof transport.on !== 'function' || typeof transport.send !== 'function') {
    throw err('no-transport', 'loginWithPassword: a connected transport is required')
  }
  if (typeof password !== 'string' || !password) throw err('no-password', 'loginWithPassword: password required')
  const { user, code, address: dir } = parseLoginAddress(address)

  const tokens = await transport.list(vaultChannel(code))
  if (!tokens.length) {
    throw err('no-vault', 'no vault is answering for that address right now: turn yours on, or check the address')
  }

  // De una en una, y parando en cuanto la contraseña resulte estar mal: cada intento GASTA
  // uno del freno en la bóveda que lo atiende (`passwordLogins.js`), así que repartir el
  // mismo error entre las réplicas solo sirve para bloquearse en todas a la vez.
  let ultimo = null
  for (const token of tokens) {
    try {
      return await unIntento({ transport, token, user, code, dir, password, label, timeoutMs })
    } catch (e) {
      // Se para: son cosas del que entra, y probar con otra bóveda no las arregla.
      if (e?.code === 'login-failed' || e?.code === 'too-many-tries' || e?.code === 'wrong-account' ||
          e?.code === 'bad-blob' || e?.code === 'bad-keys' || e?.code === 'bad-reply') throw e
      ultimo = e   // «esa no atiende inicios de sesión», «no contestó»: quizá la siguiente sí
    }
  }
  throw ultimo || err('no-vault', 'none of the vaults on that address could let you in')
}

async function unIntento ({ transport, token, user, code, dir, password, label, timeoutMs }) {
  const start = opaque.loginStart({ password })
  transport.send(token, { type: MSG.LOGIN_START, user, request: start.request })
  const r1 = await waitFor(transport, token, (p) => p.type === MSG.LOGIN_RESPONSE || p.type === MSG.ERROR, timeoutMs)
  if (r1.type === MSG.ERROR) throw deVuelta(r1)

  let fin
  try {
    fin = opaque.loginFinish({ state: start.state, response: r1.response, password })
  } catch (_) {
    // OPAQUE comprueba a las dos partes: aquí se sabe que el otro lado NO conoce el
    // registro de este usuario. Contraseña equivocada, usuario que no existe o una bóveda
    // que no es la tuya — y son el mismo error a propósito, porque distinguirlos diría
    // desde fuera qué usuarios hay.
    throw err('login-failed', 'wrong address or password')
  }

  transport.send(token, { type: MSG.LOGIN_FINISH, lid: r1.lid, finalization: fin.finalization, label })
  const ok = await waitFor(transport, token, (p) => p.type === MSG.LOGIN_OK || p.type === MSG.ERROR, timeoutMs)
  if (ok.type === MSG.ERROR) throw deVuelta(ok)

  const acta = ok.acta
  const cert = ok.cert
  if (!acta || !cert?.sub) throw err('bad-reply', 'the vault let you in without saying which account this is')

  // 2. ¿ES LA CUENTA QUE ESCRIBISTE? Es la única comprobación que ata todo esto a lo que la
  //    persona tecleó: el canal no prueba nada y el acta viene de quien contesta.
  if (accountCode((await pubkeyId(acta.profileId)).slice(0, 16)) !== code) {
    throw err('wrong-account', 'that vault serves a different account than the address says')
  }
  // 3. El papel lo firmó esa bóveda, esa bóveda puede sellar esta acta, y el papel vale
  //    según ella. Una sola llamada, la misma que usa el enrolamiento.
  const v = await checkVaultReply({ acta, cert, vault: ok.iss, sub: cert.sub })
  if (!v.ok) throw err('bad-reply', 'the vault reply does not hold together: ' + v.reason)

  const keys = await openDeviceKeys(fin.exportKey, ok.blob)   // `bad-blob` si no es el paquete
  if (!keys?.sign) throw err('bad-blob', 'the key package does not carry a signing key')

  // 4. La llave que salió del paquete tiene que SER la del papel. Se prueba firmando.
  const reto = { op: 'login.proof', sub: cert.sub, sid: ok.sid, ts: Date.now() }
  const { signature } = await signWithDevice({ privateJwk: keys.sign, data: reto })
  if (!(await verifyDeviceSig({ publickey: cert.sub, data: reto, signature }))) {
    throw err('bad-keys', 'the keys in the package are not the ones this certificate is for')
  }

  const member = (acta.members || []).find((m) => m?.pub === cert.sub)
  if (!member) throw err('bad-reply', 'that certificate names a key the account record does not list')

  return {
    user,
    address: dir,
    code,
    sid: ok.sid,
    cert,
    iss: ok.iss,
    acta,
    vaultToken: token,
    publickey: cert.sub,
    // La pública de CIFRADO la dice el acta, no el paquete: es lo que los demás miran para
    // envolverle un secreto a este aparato, y tiene que ser la misma que ellos ven.
    encPublickey: member.encPub || null,
    caps: [...(member.caps || [])],
    keys: { sign: keys.sign, enc: keys.enc || null }
  }
}

/** Un error de la bóveda con su `code` intacto: `too-many-tries` se arregla esperando. */
function deVuelta (p) {
  const code = p.code || 'login-error'
  const e = err(code, p.error || 'the vault refused the login')
  if (typeof p.waitMs === 'number') e.waitMs = p.waitMs
  return e
}

/**
 * SALIR. Va firmado con la llave que acabas de abrir —cerrar el inicio de sesión de otro
 * sería echarlo de su cuenta— y es lo que suelta la plaza en la bóveda; lo que se borre en
 * este navegador es cosa de quien llama.
 *
 * Es «mejor esfuerzo» a propósito: si la bóveda está apagada, salir de este equipo no puede
 * quedarse bloqueado esperándola. La sesión sigue abierta allí hasta que se cierre desde la
 * consola, y eso ya está dicho en el diseño (§3.2).
 */
export async function closeLogin ({ transport, token, user, sid, publickey, privateJwk, privateKey, timeoutMs = REPLY_TIMEOUT_MS } = {}) {
  if (!transport || typeof transport.send !== 'function') throw err('no-transport', 'closeLogin: transport required')
  if (!token || !user || !sid || !publickey) throw err('bad-input', 'closeLogin: token, user, sid and publickey are required')
  const data = { op: 'login.close', publickey, user, sid, ts: Date.now() }
  const { signature } = await signWithDevice({ privateJwk, privateKey, publickey, data })
  transport.send(token, { type: MSG.LOGIN_CLOSE, data, signature })
  try {
    const r = await waitFor(transport, token, (p) => p.type === MSG.LOGIN_CLOSED || p.type === MSG.ERROR, timeoutMs)
    if (r.type === MSG.ERROR) return { ok: false, reason: r.code || 'login-error' }
    return { ok: !!r.ok }
  } catch (e) {
    return { ok: false, reason: e?.code || 'no-answer' }
  }
}

export default { loginWithPassword, closeLogin, REPLY_TIMEOUT_MS }
