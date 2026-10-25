/**
 * LA BÓVEDA EN EL NAVEGADOR: la pestaña (`vault.dotrino.com`, dentro del iframe de
 * identidad) y la extensión del gestor de contraseñas corren el MISMO núcleo que el
 * binario (`./core/vault.js`). Lo único distinto es lo que pone la plataforma:
 *
 *   · el disco es IndexedDB cifrado (`./core/browserDisk.js`), uno por perfil;
 *   · la identidad es la que ya tiene abierta la pestaña o la extensión;
 *   · no hay `/proc` ni socket de archivo: lo que declara quien pide se queda como
 *     declarado, y los servicios de la misma máquina llegan por el proxio.
 *
 * Y lo que sí suma: la consola que corre en este mismo navegador administra esta bóveda
 * por un canal local (`core.setSelfVault`), con el MISMO protocolo y las mismas
 * comprobaciones que contra el binario.
 *
 * Lo que el binario tiene y el navegador no, por su contexto: actualizarse solo (la pestaña
 * se sirve siempre al día y la extensión la actualiza su tienda), las llaves de hardware
 * como puerta del perfil y el candado que cifra la maestra con la contraseña. Ver
 * `docs/three-versions.md`.
 */
import { startVault } from './core/vault.js'
import { openBrowserDisk } from './core/browserDisk.js'
import { LIB_VERSION } from './core/libVersion.js'
import { IdentityFacade } from '@dotrino/identity/facade'
import { memberScopes } from '@dotrino/identity/acta'
import { deviceIdOf } from './enroll.js'

const DEFAULT_PROXY = 'wss://proxy.dotrino.com'
/**
 * Cada cuánto se MIRA si el papel de la consola local sigue al día. Solo se vuelve a firmar
 * cuando el acta cambió (ver `selfCert`).
 */
const SELF_CERT_EVERY_MS = 60_000

/**
 * EL PAPEL DE LA CONSOLA LOCAL, firmado solo cuando hace falta. Un certificado muere con el
 * acta (`seq`), así que mientras ni el `seq` ni los permisos de `master` cambien, el de antes
 * sigue valiendo y no se vuelve a firmar: la bóveda no firma sola sin que nadie haga nada.
 * Devuelve una función que da el papel vigente, o `null` si el acta no le deja nada.
 */
export function selfCertIssuer ({ identity, master }) {
  let issued = null // { key, cert }
  return async () => {
    const acta = (await identity.profileActa().catch(() => null))?.acta || null
    if (!acta) { issued = null; return null }
    const scope = memberScopes(acta, master)
    if (!scope.length) { issued = null; return null }
    const key = acta.seq + '|' + [...scope].sort().join(',')
    if (issued?.key === key) return issued.cert
    const cert = (await identity.signDelegation(master, scope, { label: 'self' })).cert
    issued = { key, cert }
    return cert
  }
}

/**
 * @param {object} opts
 * @param {object} opts.core  el núcleo de identidad ya abierto (`createIdentityCore`)
 * @param {string} [opts.proxyUrl]
 * @param {Function} [opts.makeClient]  quién crea el cliente del proxio. La extensión lo
 *   pasa siempre: un service worker no puede hacer `import()`.
 * @param {Function} [opts.legacyLogins]  los inicios de sesión que esta pestaña guardaba
 *   antes de correr el núcleo (`{ state, drop }` o `null`). Se traen UNA vez.
 * @param {Function} [opts.onPendingChange]  un aparato espera aprobación, o dejó de esperar
 * @param {Function} [opts.onAdopted]
 * @param {Function} [opts.onStopped]  `(error)`: la bóveda se paró sola (la cuenta de la pestaña cambió)
 * @param {Function} [opts.log]
 * @param {object} [opts.opaque]  el servidor de OPAQUE, si el del paquete no se puede cargar aquí
 *   (la extensión: su CSP no deja WASM en la página de la bóveda).
 * @param {boolean} [opts.servePasswords]  `false` si las contraseñas las atiende quien monta
 *   la bóveda (la extensión, con su worker); decide con `passwordsNeedApproval`/`approvePasswordRequest`.
 * @param {Function} [opts.openDisk]  `(name) => disk`. Solo para las pruebas (Node no tiene
 *   IndexedDB); por defecto, `openBrowserDisk`.
 */
export async function startBrowserVault ({ core, proxyUrl = DEFAULT_PROXY, makeClient = null, legacyLogins = null, onPendingChange = () => {}, onAdopted = () => {}, onStopped = () => {}, log = console.log, openDisk = openBrowserDisk, opaque = null, servePasswords = true } = {}) {
  if (!core?.handlers) throw Object.assign(new Error('startBrowserVault: the identity core is required'), { code: 'no-identity' })
  const identity = new IdentityFacade(core)
  if (!identity.me?.publickey) throw Object.assign(new Error('no identity: create or unlock your profile before using this browser as a vault'), { code: 'no-identity' })
  const { id: pid } = await identity.currentProfile()
  if (!pid) throw Object.assign(new Error('no profile: the vault belongs to an account'), { code: 'no-profile' })
  // UNA BÓVEDA QUE NO PUEDE SELLAR SU ACTA NO ES UNA BÓVEDA. Arrancaba igual —un aparato
  // entrado con usuario y contraseña es miembro, no selladora— y el fallo salía después, al
  // aprobar a alguien («not the master, nor a co-sealer»), con el código ya en pantalla.
  const info = await identity.profileActa()
  if (!info?.acta) throw Object.assign(new Error('this account has no record yet: open the profile first'), { code: 'no-record' })
  if (!info.isMaster) throw Object.assign(new Error('this browser cannot be the vault of the account open here: its key does not seal the account record'), { code: 'not-sealer' })

  const disk = await openDisk(`dotrino-vault.${pid}`)

  // LOS INICIOS DE SESIÓN QUE YA HABÍA. Antes de correr el núcleo, la pestaña guardaba los
  // usuarios y contraseñas de la cuenta en su propio almacén. Se traen una vez —si el disco
  // ya tiene los suyos, mandan esos— y después se borra lo viejo: dos copias acaban diciendo
  // cosas distintas.
  if (legacyLogins && !disk.exists('logins.json')) {
    const old = await legacyLogins()
    if (old?.state) {
      disk.write('logins.json', disk.atRest.encrypt(JSON.stringify(old.state)))
      await disk.flush()
      try { await old.drop?.() } catch (_) {}
      log('[vault] password logins moved into the vault storage')
    }
  }

  const notify = () => { try { onPendingChange() } catch (_) {} }
  const vault = await startVault({
    platform: {
      disk,
      product: 'vault',
      version: LIB_VERSION,
      openIdentity: async () => identity,
      makeClient,
      noticeGroupMs: 3000,
      ...(opaque ? { opaque } : {}),
      servePasswords
    },
    proxyUrl,
    log,
    isLocked: () => !!core.masterLocked,
    // El navegador no tiene la contraseña del perfil con la que el binario cierra la copia
    // de recuperación: se cierra con la llave de este almacén, y el núcleo lo dice.
    hasPassword: () => false,
    onEnrollChallenge: notify,
    onAdopted: (info) => { try { onAdopted(info) } catch (_) {} }
  })

  // EL PAPEL CON EL QUE LA CONSOLA DE ESTE NAVEGADOR ADMINISTRA ESTA BÓVEDA: la llave del
  // perfil firmándose a sí misma con lo que el acta le deja hoy. Se mira cada minuto porque
  // el acta cambia (un permiso que te quitas, un sellado nuevo), pero se FIRMA solo cuando
  // cambió: la bóveda no firma sola sin que nadie haga nada (dueño, 2026-10-25). Antes se
  // rehacía cada minuto, y cada vez retiraba el anterior en el registro de papeles.
  const master = identity.me.publickey
  // LA BÓVEDA ES DE UNA CUENTA. Si en esta pestaña se abre otra (crear perfil, entrar con
  // contraseña), la identidad cambia por debajo y la bóveda firmaría como la nueva con el
  // disco de la vieja: se para antes de firmar nada.
  const sameAccount = async () => {
    const { id } = await identity.currentProfile()
    if (id !== pid || identity.me?.publickey !== master) {
      throw Object.assign(new Error('the account open in this tab changed: this vault was started for another one; reload the tab'), { code: 'profile-changed' })
    }
  }
  const selfCert = selfCertIssuer({ identity, master })
  /**
   * EL DUEÑO EN SU MÁQUINA ADMINISTRA. En el binario eso es la TUI, que no necesita ningún
   * permiso del acta; aquí la consola habla el protocolo de la consola remota, que exige
   * `admin`. Así que la llave de la cuenta se lo da a sí misma, una vez y a la vista en el
   * acta: es verdad que este navegador administra la cuenta. `aprueba` NO, a propósito: con
   * él los servicios pasarían a esperar el visto bueno de una pestaña que puede no estar.
   */
  const ensureAdmin = async () => {
    if (core.masterLocked) return
    const acta = (await identity.profileActa().catch(() => null))?.acta || null
    const yo = (acta?.members || []).find((m) => m.pub === master)
    if (!yo || (yo.caps || []).includes('admin')) return
    if (!(await identity.isMaster().catch(() => false))) return
    await identity.setCaps(master, [...yo.caps, 'admin'])
    log('[vault] this browser administers the account: admin added to its own key')
  }
  const open = (onReply) => vault.localChannel(onReply)
  let stopped = false
  let refresh = null
  const shutdown = async () => {
    if (stopped) return
    stopped = true
    clearInterval(refresh)
    try { core.setSelfVault?.(null) } catch (_) {}
    vault.close()
    try { await disk.flush() } catch (e) { log('[vault] some changes could not be saved: ' + (e?.message || e)) }
    disk.close()
  }
  const present = async () => {
    if (stopped) return
    try {
      await sameAccount()
      await ensureAdmin()
      const cert = await selfCert()
      core.setSelfVault?.(cert ? { cert, proxy: proxyUrl, open } : null)
    } catch (e) {
      if (e?.code === 'profile-changed') {
        log('[vault] ' + e.message)
        await shutdown()
        try { onStopped(e) } catch (_) {}
        return
      }
      log('[vault] the console in this browser cannot administer this vault yet: ' + (e?.message || e))
    }
  }
  await present()
  if (!stopped) refresh = setInterval(present, SELF_CERT_EVERY_MS)

  return {
    ...vault,
    iss: master,
    proxy: proxyUrl,
    disk,
    /** Aprueba TIPEANDO el código que muestra el aparato (el núcleo comprueba el compromiso). */
    approve: async (_deviceId, code) => { try { await sameAccount(); return await vault.approveDevice(code) } finally { notify() } },
    reject: (deviceId) => { try { return vault.rejectDevice(deviceId) } finally { notify() } },
    /**
     * Las máquinas con papel de firma de esta cuenta (excluye los navegadores enrolados con
     * etiqueta `cli`, que no atienden pedidos). Se queda el papel del acta más nueva.
     */
    async listMachines () {
      const { issued } = await identity.listDelegations()
      const bySub = new Map()
      for (const x of (issued || [])) {
        if (!x.sub || x.revokedAt) continue
        if (!Array.isArray(x.scope) || !x.scope.includes('vault:sign')) continue
        if (!x.label || x.label === 'cli' || x.label === 'self') continue
        if (!bySub.has(x.sub) || (x.seq || 0) > (bySub.get(x.sub).seq || 0)) bySub.set(x.sub, x)
      }
      return Promise.all([...bySub.values()].map(async (x) => ({ ...x, deviceId: await deviceIdOf(x.sub) })))
    },
    revokeDevice: (sub) => vault.revokeDevice({ sub }),
    revoke: (nonce) => vault.revokeDevice(nonce),
    close: shutdown
  }
}

export default { startBrowserVault }
