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
/** Cada cuánto se rehace el papel con el que la consola local administra esta bóveda. */
const SELF_CERT_EVERY_MS = 60_000

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
 * @param {Function} [opts.log]
 * @param {object} [opts.opaque]  el servidor de OPAQUE, si el del paquete no se puede cargar aquí
 *   (la extensión: su CSP no deja WASM en la página de la bóveda).
 * @param {boolean} [opts.servePasswords]  `false` si las contraseñas las atiende quien monta
 *   la bóveda (la extensión, con su worker); decide con `passwordsNeedApproval`/`approvePasswordRequest`.
 * @param {Function} [opts.openDisk]  `(name) => disk`. Solo para las pruebas (Node no tiene
 *   IndexedDB); por defecto, `openBrowserDisk`.
 */
export async function startBrowserVault ({ core, proxyUrl = DEFAULT_PROXY, makeClient = null, legacyLogins = null, onPendingChange = () => {}, onAdopted = () => {}, log = console.log, openDisk = openBrowserDisk, opaque = null, servePasswords = true } = {}) {
  if (!core?.handlers) throw Object.assign(new Error('startBrowserVault: the identity core is required'), { code: 'no-identity' })
  const identity = new IdentityFacade(core)
  if (!identity.me?.publickey) throw Object.assign(new Error('no identity: create or unlock your profile before using this browser as a vault'), { code: 'no-identity' })
  const { id: pid } = await identity.currentProfile()
  if (!pid) throw Object.assign(new Error('no profile: the vault belongs to an account'), { code: 'no-profile' })

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

  const avisar = () => { try { onPendingChange() } catch (_) {} }
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
    onEnrollChallenge: avisar,
    onAdopted: (info) => { try { onAdopted(info) } catch (_) {} }
  })

  // EL PAPEL CON EL QUE LA CONSOLA DE ESTE NAVEGADOR ADMINISTRA ESTA BÓVEDA: la llave del
  // perfil firmándose a sí misma con lo que el acta le deja hoy. Se rehace cada minuto
  // porque el acta cambia (un permiso que te quitas, un sellado nuevo).
  const master = identity.me.publickey
  const selfCert = async () => {
    const acta = (await identity.profileActa().catch(() => null))?.acta || null
    if (!acta) return null
    const scope = memberScopes(acta, master)
    if (!scope.length) return null
    return (await identity.signDelegation(master, scope, { label: 'self' })).cert
  }
  /**
   * EL DUEÑO EN SU MÁQUINA ADMINISTRA. En el binario eso es la TUI, que no necesita ningún
   * permiso del acta; aquí la consola habla el protocolo de la consola remota, que exige
   * `admin`. Así que la llave de la cuenta se lo da a sí misma, una vez y a la vista en el
   * acta: es verdad que este navegador administra la cuenta. `aprueba` NO, a propósito: con
   * él los servicios pasarían a esperar el visto bueno de una pestaña que puede no estar.
   */
  const asegurarAdmin = async () => {
    if (core.masterLocked) return
    const acta = (await identity.profileActa().catch(() => null))?.acta || null
    const yo = (acta?.members || []).find((m) => m.pub === master)
    if (!yo || (yo.caps || []).includes('admin')) return
    if (!(await identity.isMaster().catch(() => false))) return
    await identity.setCaps(master, [...yo.caps, 'admin'])
    log('[vault] this browser administers the account: admin added to its own key')
  }
  const open = (onReply) => vault.localChannel(onReply)
  const presentar = async () => {
    try {
      await asegurarAdmin()
      const cert = await selfCert()
      core.setSelfVault?.(cert ? { cert, proxy: proxyUrl, open } : null)
    } catch (e) { log('[vault] the console in this browser cannot administer this vault yet: ' + (e?.message || e)) }
  }
  await presentar()
  const refresco = setInterval(presentar, SELF_CERT_EVERY_MS)

  return {
    ...vault,
    iss: master,
    proxy: proxyUrl,
    disk,
    /** Aprueba TIPEANDO el código que muestra el aparato (el núcleo comprueba el compromiso). */
    approve: async (_deviceId, code) => { try { return await vault.approveDevice(code) } finally { avisar() } },
    reject: (deviceId) => { try { return vault.rejectDevice(deviceId) } finally { avisar() } },
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
    async close () {
      clearInterval(refresco)
      try { core.setSelfVault?.(null) } catch (_) {}
      vault.close()
      try { await disk.flush() } catch (e) { log('[vault] some changes could not be saved: ' + (e?.message || e)) }
      disk.close()
    }
  }
}

export default { startBrowserVault }
