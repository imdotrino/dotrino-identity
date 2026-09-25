/**
 * LLAVES QUE NO VIVEN AQUÍ: el chip del teléfono, dentro de la app de Dotrino.
 *
 * En la app de Android el iframe corre en un WebView, y el teléfono ya tiene su llave de
 * cada cuenta en el Keystore (la que aprueba en la pantalla nativa de Pedidos). Si el
 * WebView se hiciera la suya, el teléfono serían DOS aparatos en el acta: uno con perfil y
 * sin aprobar, otro aprobando y sin perfil (dueño, 2026-09-25: «es como si el perfil viviera
 * solo en nativo y no en el webview»). Con esto hay UNA llave: el WebView firma y descifra
 * con la del chip, y la privada nunca entra en esta página.
 *
 * Este módulo envuelve el `keyStore` de IndexedDB. Lo que guarda por llave es un registro
 * sin nada secreto: `{ external: kid, kind, publicJwk }`. Al leerlo lo convierte en un ASA,
 * que es lo que `core.js` trata como privada: `{ external: true, sign, deriveBits }`. Las
 * cuatro funciones que usan una privada (`rawSign`, `signBytes`, `sharedKey`,
 * `deriveSharedAesKey`) saben qué hacer con ella.
 *
 * `bridge.call(method, params)` habla con la app: `create`, `open`, `sign`, `deriveBits`,
 * `save`, `remove`. La app solo le enseña el puente a `https://id.dotrino.com`.
 */

const b64 = (buf) => {
  const bytes = buf instanceof Uint8Array ? buf : new Uint8Array(buf)
  let s = ''
  for (let i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i])
  return btoa(s)
}
const fromB64 = (str) => {
  const bin = atob(str)
  const out = new Uint8Array(bin.length)
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i)
  return out
}

const SIGN_SUFFIX = '.keypair'
const ENC_SUFFIX = '.enc-keypair'

/** El nombre de la OTRA mitad del mismo perfil: firma y cifrado comparten llave en el chip. */
function siblingName (name) {
  if (name.endsWith(ENC_SUFFIX)) return name.slice(0, -ENC_SUFFIX.length) + SIGN_SUFFIX
  if (name.endsWith(SIGN_SUFFIX)) return name.slice(0, -SIGN_SUFFIX.length) + ENC_SUFFIX
  return null
}

/** El asa de una llave del chip. Lo que la app no pueda hacer sale con su `code`, sin plan B. */
export function externalHandle (bridge, kid) {
  return {
    external: true,
    kid,
    async sign (bytes) {
      const { signature } = await bridge.call('sign', { kid, data: b64(bytes) })
      return signature
    },
    async deriveBits (peerPubJwkStr) {
      const { bits } = await bridge.call('deriveBits', { kid, peer: peerPubJwkStr })
      return fromB64(bits).buffer
    },
    /** Tras emparejar: la app guarda la cuenta para su pantalla de Pedidos. */
    async paired (account) { return bridge.call('save', { kid, ...account }) }
  }
}

/**
 * Envuelve `keyStore` para que las llaves NUEVAS nazcan en el chip. Las que ya existían
 * (CryptoKey de IndexedDB) siguen igual: una llave no extraíble no se puede mover.
 */
export function withExternalKeys (keyStore, bridge) {
  const toHandle = (rec) => (rec && rec.external
    ? { privateKey: externalHandle(bridge, rec.external), publicJwk: rec.publicJwk }
    : rec)
  return {
    async get (name) { return toHandle(await keyStore.get(name)) },
    set: (name, pair) => keyStore.set(name, pair),
    async remove (name) {
      const rec = await keyStore.get(name)
      await keyStore.remove(name)
      // Se borra del chip cuando ya no queda ninguna de las dos mitades del perfil.
      const sib = siblingName(name)
      const other = sib ? await keyStore.get(sib) : null
      if (rec?.external && !(other?.external === rec.external)) await bridge.call('remove', { kid: rec.external })
    },
    async create (kind, name) {
      // Las dos mitades del perfil van bajo la MISMA llave del chip: si la otra ya nació
      // allí, se reutiliza; si no, se crea una nueva.
      const sib = siblingName(name)
      const other = sib ? await keyStore.get(sib) : null
      const k = other?.external
        ? await bridge.call('open', { kid: other.external })
        : await bridge.call('create', {})
      const publicJwk = kind === 'enc' ? k.encPub : k.publickey
      if (!k?.kid || !publicJwk) throw Object.assign(new Error('the phone did not return a key'), { code: 'native-no-key' })
      const rec = { external: k.kid, kind, publicJwk: typeof publicJwk === 'string' ? JSON.parse(publicJwk) : publicJwk }
      await keyStore.set(name, rec)
      return { privateKey: externalHandle(bridge, k.kid), publicJwk: rec.publicJwk }
    }
  }
}

/**
 * El puente de la app visto desde la página: `window.DotrinoIdentityKeys` (un
 * `addWebMessageListener` de Android). Mensajes `{ id, method, params }` → `{ id, result }`
 * o `{ id, error, code }`.
 */
export function appBridge (port, { timeoutMs = 20000 } = {}) {
  let seq = 0
  const waiting = new Map()
  port.onmessage = (ev) => {
    let m
    try { m = JSON.parse(ev.data) } catch (_) { return }
    const w = waiting.get(m?.id)
    if (!w) return
    waiting.delete(m.id)
    clearTimeout(w.t)
    if (m.error) w.reject(Object.assign(new Error(m.error), { code: m.code || 'native-error' }))
    else w.resolve(m.result)
  }
  return {
    call (method, params = {}) {
      const id = 'k' + (++seq)
      return new Promise((resolve, reject) => {
        const t = setTimeout(() => {
          waiting.delete(id)
          reject(Object.assign(new Error(`the phone did not answer ${method}`), { code: 'native-no-reply' }))
        }, timeoutMs)
        waiting.set(id, { resolve, reject, t })
        port.postMessage(JSON.stringify({ id, method, params }))
      })
    }
  }
}
