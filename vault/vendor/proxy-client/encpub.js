/**
 * LA LLAVE DE CIFRADO DE UN DESCONOCIDO, Y DE QUIÉN ES.
 *
 * Sellar un mensaje dirigido necesita la llave de cifrado del otro lado. Hasta ahora el
 * pilar la exigía (`sendSealed({ peerEncPub })`) y no ofrecía ninguna forma de
 * conseguirla, así que solo podían sellar dos puntas que se hubieran emparejado antes y
 * se la hubieran intercambiado a mano. Todo lo demás —una sala, una invitación, un acuse
 * a alguien que está apagado— viajaba en claro, que es exactamente lo que el proxio ve.
 *
 * Lo que hay aquí es el ANUNCIO: una frase corta, firmada por la misma llave con la que
 * uno se identifica en el cable, que dice «mi llave de cifrado es ésta».
 *
 *     { v:1, op:'encpub', aud:'dotrino:encpub', publickey, encpub, ts }  + signature
 *
 * LO IMPORTANTE NO ES DÓNDE SE GUARDA, ES QUIÉN LO FIRMA. El proxio hace de buzón: se lo
 * queda y se lo da a quien pregunte. Pero quien pregunta **no se fía de él**: verifica la
 * firma contra la pubkey a la que va a escribir, que es la misma que el proxio usa para
 * enrutar y la misma que `identify` comprueba. Si el proxio cambia la llave por la suya
 * para poder leer, la firma no cuadra y no sale nada — ni sellado ni en claro.
 *
 * De ahí sale la regla dura de este módulo: **`readEncPubStatement` no devuelve nunca
 * `null`.** O devuelve una llave verificada o lanza con un `code`. Un valor por defecto
 * aquí sería una llave de cifrado que no es de nadie.
 *
 * `aud` es un propósito y no una URL a propósito: el mismo anuncio vale en cualquier nodo
 * de la malla, y con la URL del proxio delante un anuncio hecho en `proxy1` no se podría
 * verificar desde `proxy2`.
 */
import { canonicalStringify } from './canonical.js'
import { verifyData, samePubkey } from './signature.js'

export const ENCPUB_V = 1

/** Para quién vale este anuncio: un propósito, no un servidor. */
export const ENCPUB_AUD = 'dotrino:encpub'

/** Cuerpo canónico del anuncio. Lo que se firma, ni un campo más. */
export function encPubBody ({ publickey, encPub, ts = Date.now() }) {
  return { v: ENCPUB_V, op: 'encpub', aud: ENCPUB_AUD, publickey, encpub: encPub, ts }
}

/**
 * ¿Es esto una llave de cifrado P-256 y no cualquier string? Se comprueba de verdad
 * —igual que hace el acta— porque una llave mal formada no falla al guardarla: falla
 * mucho después, al intentar sellarle algo a alguien.
 */
export function isEncPub (v) {
  if (typeof v !== 'string' || !v) return false
  try {
    const j = JSON.parse(v)
    return j?.kty === 'EC' && j?.crv === 'P-256' && typeof j?.x === 'string' && typeof j?.y === 'string'
  } catch (_) {
    return false
  }
}

/**
 * @param {string} mensaje
 * @param {string} code
 * @returns {Error & { code: string }}
 */
function errorCon (mensaje, code) {
  const e = /** @type {Error & { code: string }} */ (new Error(mensaje))
  e.code = code
  return e
}

/**
 * Firma el anuncio con lo que firma la identidad (`identity.signData`, o la llave local
 * del cliente). No genera llaves ni cifra nada: solo dice de quién es la que ya tienes.
 *
 * @param {{ publickey:string, encPub:string, sign:(data:any)=>Promise<string|{signature:string}> }} args
 * @returns {Promise<{data:any, signature:string}>}
 */
export async function buildEncPubStatement ({ publickey, encPub, sign } = /** @type {any} */ ({})) {
  if (typeof publickey !== 'string' || !publickey) throw errorCon('buildEncPubStatement: missing publickey', 'encpub-shape')
  if (!isEncPub(encPub)) throw errorCon('buildEncPubStatement: encPub is not a P-256 public JWK', 'encpub-shape')
  if (typeof sign !== 'function') throw errorCon('buildEncPubStatement: missing sign(data)', 'encpub-shape')
  const data = encPubBody({ publickey, encPub })
  const firmado = await sign(data)
  const signature = typeof firmado === 'string' ? firmado : firmado?.signature
  // «No pude firmar» no es «se cayó la red», y aquí es donde se separan: quien llama
  // decide una cosa u otra según el `code`, nunca según la frase.
  if (typeof signature !== 'string') throw errorCon('buildEncPubStatement: sign() returned no signature', 'no-signature')
  return { data, signature }
}

/**
 * Abre un anuncio ajeno y devuelve la llave de cifrado, o LANZA.
 *
 * `publickey` es a quién le vas a escribir, y es el ancla entera: se comprueba que el
 * anuncio hable de ESA llave y que lo haya firmado ESA llave. Sin ese argumento esto
 * solo diría «alguien firmó esto», que no sirve para decidir a quién le sellas.
 *
 * @param {{data:any, signature:string}} statement
 * @param {{ publickey:string }} expected
 * @returns {Promise<string>} la `encpub` verificada
 */
export async function readEncPubStatement (statement, { publickey } = /** @type {any} */ ({})) {
  if (typeof publickey !== 'string' || !publickey) {
    throw errorCon('readEncPubStatement: missing the publickey to check against', 'encpub-shape')
  }
  const data = statement?.data
  const signature = statement?.signature
  if (!data || typeof signature !== 'string') throw errorCon('encpub statement: malformed', 'encpub-unverified')
  if (data.v !== ENCPUB_V || data.op !== 'encpub') throw errorCon('encpub statement: not an encpub announcement', 'encpub-unverified')
  if (data.aud !== ENCPUB_AUD) throw errorCon('encpub statement: wrong audience', 'encpub-unverified')
  // `samePubkey` y no `===`: un JWK serializado no es canónico y la misma llave escrita
  // por dos piezas distintas da dos strings distintos.
  if (!samePubkey(data.publickey, publickey)) throw errorCon('encpub statement: announces another identity', 'encpub-unverified')
  if (!isEncPub(data.encpub)) throw errorCon('encpub statement: not a P-256 public JWK', 'encpub-unverified')
  // Se verifica con la llave que ANUNCIA el sobre, que ya se comprobó que es la misma que
  // la pedida: así el texto firmado y la llave que lo comprueba salen del mismo sitio.
  if (!(await verifyData(data.publickey, data, signature))) {
    throw errorCon('encpub statement: bad signature — the key is not bound to that identity', 'encpub-unverified')
  }
  return data.encpub
}

/** Lo firmado, en texto canónico. Mismo orden en las dos puntas o las firmas no cuadran. */
export const encPubSigningText = (data) => canonicalStringify(data)
