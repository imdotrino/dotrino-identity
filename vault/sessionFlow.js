/**
 * sessionFlow.js — LAS DOS PUNTAS DE «ENTRAR».
 *
 * El papel de sesión lo define `session.js`; aquí está cómo se consigue: un navegador que
 * no te conoce enseña una invitación, un aparato tuyo la lee y le da el papel.
 *
 *     navegador nuevo                         aparato que respalda (con cámara)
 *     ──────────────────                      ─────────────────────────────────
 *     genera su llave S
 *     muestra QR + código  ──── escanea ────►  ve qué aplicación y qué pide
 *                                              [Permitir] → firma el papel
 *                          ◄──── sellado ────  { paper, chain }
 *     comprueba y entra
 *
 * TRES COSAS QUE NO SON DETALLE:
 *
 *   · **El QR va al revés que en el emparejamiento.** Allí lo muestra la bóveda; aquí lo
 *     muestra QUIEN QUIERE ENTRAR, porque quien entra puede no tener cámara y el teléfono
 *     siempre la tiene.
 *   · **El código corto es el freno del reenvío**, igual que el SAS del emparejamiento:
 *     quien intercepte la invitación no puede enseñar el código correcto en la pantalla que
 *     el dueño está mirando.
 *   · **Va sellado.** Es un mensaje dirigido y el proxio no cifra (CONVENCIONES §4.1). El
 *     papel no es un secreto —lo verifica cualquiera—, pero decir en claro «esta persona
 *     acaba de entrar en tal aplicación» sí cuenta algo.
 *
 * El transporte se INYECTA (`@dotrino/proxy-client`), como en geo y en reputación: este
 * pilar no abre conexiones ni sabe de proxios.
 */
import { signSession, verifySession, newSessionId, cleanSessionScopes, SESSION_DEFAULT_TTL_MS } from './session.js'

export const SESSION_OP = Object.freeze({
  GRANT: 'session.grant',   // aparato → navegador: aquí tienes tu papel
  DENY: 'session.deny',     // aparato → navegador: no
  CLOSE: 'session.close'    // aparato → navegador: se acabó, bórrala
})

/** El código corto que el humano compara. Seis dígitos, como el del emparejamiento. */
export function sessionCode (sid) {
  let h = 0
  for (const c of String(sid)) h = (h * 31 + c.charCodeAt(0)) >>> 0
  return String(h % 1000000).padStart(6, '0')
}

/**
 * Lo que viaja en el QR. Corto a propósito: un QR más denso se lee peor con poca luz, que
 * es justo cuando alguien intenta entrar desde un aparato prestado.
 */
export function buildInvite ({ sid, s, encPub, origin, scopes, proxy }) {
  return { v: 1, t: 'session', sid, s, encPub, origin, scopes: cleanSessionScopes(scopes), proxy }
}

/** Lee una invitación, venga del QR o pegada a mano. `null` si no es una. */
export function parseInvite (raw) {
  try {
    const o = typeof raw === 'string' ? JSON.parse(raw) : raw
    if (!o || o.t !== 'session' || o.v !== 1) return null
    if (typeof o.sid !== 'string' || typeof o.s !== 'string' || typeof o.origin !== 'string') return null
    return { ...o, scopes: cleanSessionScopes(o.scopes) }
  } catch (_) { return null }
}

/**
 * LADO DEL QUE ENTRA. Genera la sesión, publica la invitación y espera el papel.
 *
 * `transport` es un cliente ya conectado e identificado bajo la llave de sesión (`s`): así
 * el aparato que responde puede escribirle por pubkey. `onInvite` recibe lo que hay que
 * enseñar —la invitación y el código— para que la app pinte el QR con `@dotrino/qr`.
 *
 * Devuelve `{ paper, chain, profileId }` cuando alguien concede, o lanza si se deniega o
 * se agota la espera. No guarda nada: dónde vive la sesión lo decide quien llama.
 */
export async function openSession ({ transport, sessionPubkey, encPub, origin, scopes, onInvite, timeoutMs = 5 * 60 * 1000, sid = newSessionId() } = {}) {
  if (!transport || typeof transport.on !== 'function') throw new Error('openSession: transport required')
  if (typeof sessionPubkey !== 'string' || !sessionPubkey) throw new Error('openSession: sessionPubkey required')
  if (typeof origin !== 'string' || !origin.trim()) throw new Error('openSession: origin required')

  const invite = buildInvite({ sid, s: sessionPubkey, encPub, origin: origin.trim(), scopes, proxy: transport.url })
  onInvite?.({ invite, code: sessionCode(sid), qr: JSON.stringify(invite) })

  return await new Promise((resolve, reject) => {
    let listo = false
    const fin = (fn, arg) => { if (!listo) { listo = true; clearTimeout(reloj); off?.(); fn(arg) } }
    const reloj = setTimeout(() => fin(reject, Object.assign(new Error('nadie abrió la sesión a tiempo'), { code: 'session-timeout' })), timeoutMs)
    const off = transport.on('message', async (_from, payload, meta) => {
      const p = typeof payload === 'string' ? (() => { try { return JSON.parse(payload) } catch (_) { return null } })() : payload
      if (!p || p.sid !== sid) return
      if (p.op === SESSION_OP.DENY) return fin(reject, Object.assign(new Error('la sesión no se concedió'), { code: 'session-denied' }))
      if (p.op !== SESSION_OP.GRANT) return
      // NO SE ACEPTA LO QUE VENGA EN CLARO. El sellado es del pilar del transporte; aquí
      // solo se comprueba que llegó sellado, que es lo que la app puede saber.
      if (meta && meta.sealed === false) return
      const v = await verifySession(p.paper, { chain: p.chain, origin: origin.trim() })
      if (!v.ok) return fin(reject, Object.assign(new Error('el papel de sesión no vale: ' + v.reason), { code: 'session-invalid' }))
      if (p.paper.s !== sessionPubkey) return fin(reject, Object.assign(new Error('el papel es para otra llave'), { code: 'session-invalid' }))
      fin(resolve, { paper: p.paper, chain: p.chain, profileId: v.profileId, sid, scopes: v.scopes, exp: v.exp })
    })
  })
}

/**
 * LADO DEL QUE RESPALDA. Firma el papel y se lo manda al que espera.
 *
 * `sign` firma con la llave de ESTE aparato (la que el acta nombra) y `chain` es la cadena
 * del perfil: las dos cosas viajan juntas porque por separado no sirven.
 *
 * `scopes` acota lo que se concede: por omisión, lo que pidió la invitación. Quien llama
 * puede recortarlo —nunca ampliarlo, que de eso ya se encarga `verifySession`.
 */
export async function grantSession ({ transport, invite, by, sign, chain, scopes, ttlMs = SESSION_DEFAULT_TTL_MS, now = Date.now() } = {}) {
  const inv = parseInvite(invite)
  if (!inv) throw new Error('grantSession: invitación ilegible')
  if (typeof by !== 'string' || !by) throw new Error('grantSession: by (this device pubkey) required')
  if (typeof sign !== 'function') throw new Error('grantSession: sign(body) required')
  if (!Array.isArray(chain) || !chain.length) throw new Error('grantSession: chain required')

  const pedidos = cleanSessionScopes(scopes ?? inv.scopes)
  const paper = await signSession({ sid: inv.sid, s: inv.s, by, origin: inv.origin, scopes: pedidos, ttlMs, now }, sign)
  await enviar(transport, inv, { op: SESSION_OP.GRANT, sid: inv.sid, paper, chain })
  return paper
}

/** Decir que no, en vez de dejar al otro mirando una pantalla que no avanza. */
export async function denySession ({ transport, invite } = {}) {
  const inv = parseInvite(invite)
  if (!inv) throw new Error('denySession: invitación ilegible')
  await enviar(transport, inv, { op: SESSION_OP.DENY, sid: inv.sid })
}

/**
 * CERRARLA. Se avisa a la sesión para que se borre en el acto; lo que la corta de verdad es
 * que el papel vence y nadie lo renueva —y que quitar el aparato se lleva todos los suyos.
 */
export async function closeSession ({ transport, sessionPubkey, encPub, sid } = {}) {
  if (typeof sessionPubkey !== 'string' || !sessionPubkey) throw new Error('closeSession: sessionPubkey required')
  await enviar(transport, { s: sessionPubkey, encPub }, { op: SESSION_OP.CLOSE, sid })
}

/** Sellado siempre que se pueda: el proxio no cifra (CONVENCIONES §4.1). */
async function enviar (transport, inv, payload) {
  if (!transport || typeof transport.sendByPubkey !== 'function') throw new Error('sessionFlow: transport required')
  if (inv.encPub && typeof transport.sendSealed === 'function') {
    return transport.sendSealed([inv.s], payload, { peerEncPub: inv.encPub })
  }
  // Sin llave de cifrado del otro lado no se puede sellar. Se dice en vez de mandarlo en
  // claro por su cuenta: quien llama decide si eso le vale.
  if (!inv.encPub) throw Object.assign(new Error('sessionFlow: la invitación no trae encPub; no se puede sellar'), { code: 'unsealed' })
  return transport.sendByPubkey(inv.s, payload)
}

export default { SESSION_OP, sessionCode, buildInvite, parseInvite, openSession, grantSession, denySession, closeSession }
