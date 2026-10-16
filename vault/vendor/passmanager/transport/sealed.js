// El sellado extremo a extremo vive en el PILAR del transporte
// (`@dotrino/proxy-client/sealing`, desde 0.13.0), no aquí.
//
// Se escribió primero en este repo y se movió en cuanto quedó claro que la garantía
// —que lo del usuario no llegue a los servidores de Dotrino, ni de paso— no puede ser
// de una sola app. Este módulo queda como el punto por el que pasa el gestor, para no
// repetir el import por todos lados.

export {
  seal, open, isSealed,
  makeEncKeypair, importEncPrivate, exportEncPrivate,
  setSealingPrimitives,
} from '@dotrino/proxy-client/sealing'

/**
 * EL SOBRE que se pasan la bóveda y quien pide, en UN solo sitio.
 *
 * Estaba escrito dos veces —en la extensión y en la bóveda-en-pestaña de
 * `vault.dotrino.com/vault`—, y son las dos puntas del MISMO sobre: si una cambia de
 * forma, la otra deja de abrirlo. No falla ruidosamente, que es lo peor: la petición sale,
 * al otro lado «no es para mí», y desde fuera se ve como que nadie respondió.
 *
 * Lo que sí cambia entre las dos es el DIALECTO de `@dotrino/identity`, porque no es el
 * mismo objeto: la clase `Identity` (la que habla con el iframe) expone
 * `getEncryptionPubkey()` y un `decrypt(remitente, miToken, sobre)` que devuelve
 * `{ plaintext }`; el núcleo que corre dentro del service worker de la extensión expone
 * `encryptionPubkey()` y un `decrypt(remitente, sobre)` que devuelve la cadena. Los dos
 * son correctos y los dos se quedan; lo que no puede haber es dos ideas del sobre.
 *
 * @param {object} identity  cualquiera de los dos dialectos
 * @param {object} [opts]
 * @param {string} [opts.app='passmanager']  la marca del sobre: quien recibe lo que no es
 *   suyo lo descarta por aquí.
 * @returns {{seal:Function, open:Function, isSealed:Function}} el `sealing` de
 *   `@dotrino/proxy-client` (≥ 0.13.0)
 */
export function identitySealing (identity, { app = 'passmanager' } = {}) {
  // El dialecto se decide UNA vez, por lo que el objeto expone, y no por el resultado de
  // cada llamada: así, si mañana llega un tercero que no es ninguno de los dos, revienta
  // aquí y con nombre, en vez de devolver sobres que nadie abre.
  const iframe = typeof identity?.getEncryptionPubkey === 'function'
  if (!iframe && typeof identity?.encryptionPubkey !== 'function') {
    throw new Error('identitySealing: this identity exposes neither getEncryptionPubkey() nor encryptionPubkey()')
  }

  const myEncPub = () => (iframe ? identity.getEncryptionPubkey() : identity.encryptionPubkey())
  const openEnvelope = async (from, envelope) => {
    const r = iframe
      ? await identity.decrypt(from, null, envelope)
      : await identity.decrypt(from, envelope)
    // Un dialecto devuelve `{ plaintext }` y el otro la cadena. Nada más se admite: si
    // llega otra cosa, se para — un `?? ''` aquí sería un sobre vacío haciéndose pasar
    // por un mensaje.
    if (typeof r === 'string') return r
    if (typeof r?.plaintext === 'string') return r.plaintext
    throw new Error('identitySealing: decrypt returned neither a string nor { plaintext }')
  }

  return {
    async seal (msg, peerEncPub) {
      if (!peerEncPub) throw Object.assign(new Error('no encryption key for the other side'), { code: 'unsealed' })
      return {
        app,
        // Destinatarios como OBJETOS: `encrypt` expande cada uno a todos los aparatos de
        // esa persona, y una llave suelta se le cae sin envolver nada — el sobre salía
        // vacío, sin error, y al otro lado era «no es para mí».
        sealed: await identity.encrypt([{ encryptionPubkey: peerEncPub }], JSON.stringify(msg)),
        from: await myEncPub(),
      }
    },
    async open (env) { return JSON.parse(await openEnvelope(env.from, env.sealed)) },
    isSealed: (m) => !!m && m.app === app && !!m.sealed,
  }
}
