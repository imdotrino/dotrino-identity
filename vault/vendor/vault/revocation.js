/**
 * revocation.js — CUÁNDO se le dice a un aparato que ya no es de casa.
 *
 * Módulo PURO (sin red, sin disco, sin `node:*`), como `enroll.js` y `admin.js`: la regla
 * vive en un solo sitio, se lee entera y se prueba sin levantar nada.
 *
 * EL PROBLEMA QUE RESUELVE. Un dispositivo al que quitaron del perfil no se entera por su
 * cuenta: lo único que le borra la cuenta es un aviso FIRMADO por la maestra
 * (`vault.revoked`). Un «unauthorized» suelto no vale y no debe valer — no va firmado, así
 * que cualquiera podría destruir datos ajenos con un mensaje (el wipe-DoS de
 * `docs/pairing-protocol.md §2.3`). Por eso la bóveda tiene que **atender** la conexión de
 * un aparato que fue suyo, aunque su papel ya no sirva, precisamente para poder mandarlo a
 * paseo. Si no lo hace, el aparato se queda enseñando una cuenta que ya no existe.
 *
 * LA REGLA, en una línea: papel nuestro + ya no está en el acta ⇒ se le avisa.
 */

/**
 * Motivos de rechazo de `verifyChain` que significan «este papel ya no sirve».
 *
 * Los tres se producen DESPUÉS de que `verifyChain` haya comprobado la firma del propio
 * aparato y la del certificado, así que quien llega hasta aquí demostró tener la llave que
 * el certificado nombra. El resto de motivos (`shape`, `bad-signature`,
 * `bad-action-signature`, `cert-device-mismatch`, `untrusted-issuer`…) son ruido o gente
 * ajena: ahí no hay a quién avisar de nada.
 */
export const STALE_PAPER = Object.freeze(['revoked', 'expired', 'scope'])
const STALE = new Set(STALE_PAPER)

/** ¿El motivo del rechazo es «tu papel ya no sirve»? */
export const isStalePaper = (reason) => STALE.has(reason)

/**
 * ¿Hay que mandarle el aviso firmado de expulsión?
 *
 * @param {Object} o
 * @param {string} o.reason      por qué falló `verifyChain`.
 * @param {string} o.pubkey      la llave del aparato que acaba de escribir.
 * @param {string} o.master      la maestra de ESTA bóveda.
 * @param {string|null} [o.certIss]  quién firmó el certificado que presentó.
 * @param {Array<{pub:string}>|null} [o.members]  miembros del acta; `null` = no hay acta.
 * @param {boolean} [o.knownRevoked]  consta explícitamente como revocado en las
 *   delegaciones. Es el único criterio que queda cuando no hay acta.
 * @returns {boolean}
 */
export function shouldNotifyRevoked ({ reason, pubkey, master, certIss = null, members = null, knownRevoked = false } = {}) {
  if (typeof pubkey !== 'string' || !pubkey) return false
  if (!isStalePaper(reason)) return false
  // Que el papel sea NUESTRO. No hace falta que siga siendo válido —justo por eso estamos
  // aquí— pero sí que lo haya firmado esta maestra: es lo que separa a un aparato que fue
  // de casa de uno que pasaba por ahí.
  if (certIss && master && certIss !== master) return false
  // El aparato no puede echarse a sí mismo, y la maestra tampoco se echa.
  if (master && pubkey === master) return false

  // EL ACTA MANDA, y es lo único que manda. Un certificado retirado o vencido NO significa
  // «estás fuera»: renovar retira el anterior y cambiar permisos obliga a renovar, así que
  // un aparato de casa con un papel viejo solo tiene que renovar. Decirle «estás fuera»
  // ahí lo borraba solo: dabas «administra» y el dispositivo desaparecía.
  if (Array.isArray(members)) return !members.some((m) => m?.pub === pubkey)

  // Sin acta (bóveda anterior al acta) no se puede saber quién es del perfil: solo se
  // avisa a quien conste explícitamente como revocado.
  return !!knownRevoked
}

export default { STALE_PAPER, isStalePaper, shouldNotifyRevoked }
