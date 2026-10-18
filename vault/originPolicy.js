/**
 * QUIÉN PUEDE PEDIR QUÉ al iframe de identidad, por el origen que pone el navegador.
 *
 * El iframe habla con todo el ecosistema (`*.dotrino.com`, el espejo de GitHub y, en desarrollo,
 * localhost y la red local). Eso está bien para firmar, cifrar o leer el perfil: es para lo que
 * está. Pero hay pedidos que deciden QUIÉN ES de tu cuenta o se llevan la llave, y esos no los
 * puede hacer cualquier página que se cargue en esos orígenes. Regla del dueño (2026-10-18):
 * **ningún aparato entra a una cuenta sin invitación**, y una app cualquiera llamando a
 * `admitMember` es justo eso.
 *
 * Esos pedidos solo los atiende la CONSOLA: `vault.dotrino.com` y `profile.dotrino.com`. Los
 * orígenes locales valen únicamente si el propio iframe corre en local (desarrollo y pruebas):
 * en producción, una página de localhost de tu máquina no administra tu cuenta.
 */
const LOCAL = /^https?:\/\/(localhost|127\.0\.0\.1|192\.168\.\d{1,3}\.\d{1,3}|10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3})(:\d+)?$/
const CONSOLE = /^https:\/\/(vault|profile)\.dotrino\.com$/

/**
 * Lo que solo pide la consola: entrar y salir del acta, cambiar permisos, la llave en crudo,
 * borrar un perfil, la bóveda de esta pestaña (sus emparejamientos, sus altas con contraseña,
 * sus respaldos) y la contraseña del perfil.
 */
export const CONSOLE_ONLY = Object.freeze([
  'admitMember', 'removeMember', 'setCaps', 'setCapsMany', 'setLabel', 'setMemberEncPub', 'handoverMaster',
  'renounceCaps', 'absorbRenounce', 'adoptActa', 'adoptActaChain', 'joinProfile', 'rotateSealKey', 'setSealKeyProvider',
  'revokeDevice', 'vaultPair', 'vaultAdopt', 'vaultUnpair', 'prepareForAdoption', 'setSelfVault',
  'exportIdentity', 'importIdentity', 'deleteProfile', 'setProfilePassword', 'removeProfilePassword',
  'selfVaultPairing', 'selfVaultApprove', 'selfVaultLoginAdd',
  'selfVaultBackupDrawers', 'selfVaultBackupExport', 'selfVaultBackupPlan', 'selfVaultBackupImport'
])

/** Además de la consola, quién más puede pedir uno de esos (su herramienta lo necesita). */
const ALSO = Object.freeze({
  // El gestor de contraseñas vuelve a envolver sus llaves para los aparatos que entran.
  rewrapFor: /^https:\/\/pass\.dotrino\.com$/
})

export function originPolicy ({ selfOrigin }) {
  const selfIsLocal = LOCAL.test(String(selfOrigin || ''))
  const isConsole = (origin) => CONSOLE.test(String(origin || '')) || (selfIsLocal && LOCAL.test(String(origin || '')))
  const only = new Set(CONSOLE_ONLY)

  /**
   * Lanza `console-only` si `origin` no puede pedir `method` con estos parámetros. Lo demás pasa.
   * `me` es la llave pública del perfil activo (para el certificado de uno mismo).
   */
  function check (method, params, origin, { me = null } = {}) {
    if (isConsole(origin)) return
    const deny = (why) => { throw Object.assign(new Error(`${method}: ${why}`), { code: 'console-only' }) }
    if (only.has(method)) deny('only the vault console (vault.dotrino.com, profile.dotrino.com) can ask for this')
    if (ALSO[method] && !ALSO[method].test(String(origin || ''))) deny('this origin cannot ask for this')
    if (method === 'signDelegation') {
      // Un certificado con poder sobre la bóveda (`vault:*`) es meter un aparato: eso es de la
      // consola, con su invitación. Una app sí firma lo suyo (geo: los aparatos de here) y su
      // propio certificado (`sub` = el perfil: el de terminal y el de ia).
      const scopes = Array.isArray(params?.scope) ? params.scope : [params?.scope]
      const vaultPower = scopes.some((s) => typeof s !== 'string' || s.startsWith('vault:'))
      if (vaultPower && !(me && params?.sub === me)) deny('a certificate with vault powers is issued from the vault console, with an invitation')
    }
  }

  return { check, isConsole }
}

export default { originPolicy, CONSOLE_ONLY }
