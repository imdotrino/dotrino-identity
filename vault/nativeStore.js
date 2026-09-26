/**
 * TODO LO DE LA IDENTIDAD EN LA APP, NO EN LA PÁGINA (app de iOS, 2026-09-26).
 *
 * WebKit guarda el localStorage y el IndexedDB de un iframe de otro origen APARTE por cada
 * página que lo contiene. Dentro de la app de iOS eso partía la identidad en tantas como
 * páginas: `dotrino.com`, `profile.dotrino.com` y `vault.dotrino.com` veían cada una un
 * perfil distinto, recién inventado (dueño: «todas deberían tener el perfil/perfiles
 * cargados nativamente»). El WebView de Android no separa así, y por eso allí no pasaba.
 *
 * Con esto, cuando la app lo ofrece (`bridge.storage`), las tres piezas que la identidad
 * guarda —el `kv` síncrono, los registros de llaves y el libro de contactos— viven en UN
 * almacén de la app, el mismo para todas las páginas. Nada secreto viaja: las llaves son del
 * chip (el registro es `{ external: kid, kind, publicJwk }`) y el resto es lo que ya se
 * guardaba en el disco de la página.
 *
 * Cómo: al arrancar se trae TODO de una vez (`storeLoad`) y se sirve desde memoria, que es
 * lo que el `kv` necesita para seguir siendo síncrono. Cada cambio se escribe en la app al
 * momento, en orden. Solo hay un iframe de identidad vivo a la vez (la app tiene un solo
 * WebView), así que no hay dos memorias que se pisen.
 */

const KV = 'kv:'
const KEY = 'key:'
const PEERS = 'peers:'

/** El asa de una llave no se puede guardar en la app: solo su registro, que no tiene nada secreto. */
function plainKeyRecord (rec) {
  if (rec && typeof rec.external === 'string' && rec.publicJwk && (rec.kind === 'sign' || rec.kind === 'enc')) {
    return { external: rec.external, kind: rec.kind, publicJwk: rec.publicJwk }
  }
  // Una llave de SOFTWARE (adoptar un perfil, entrar con contraseña) no cabe en el chip, y
  // guardarla a medias sería perder la cuenta sin decirlo. Se para aquí y se dice.
  throw Object.assign(new Error('this app keeps keys in the phone chip only: a software key cannot be stored here'), { code: 'native-no-import' })
}

export async function nativeBackends (bridge) {
  const { items } = await bridge.call('storeLoad', {})
  if (!items || typeof items !== 'object') {
    throw Object.assign(new Error('the app did not return its store'), { code: 'native-no-store' })
  }
  const mem = new Map(Object.entries(items))

  // Escrituras EN ORDEN: un `remove` que adelantara a su `set` resucitaría el dato. Una que
  // falla se dice en la consola con su código (sin tragársela) y no frena a las siguientes.
  let chain = Promise.resolve()
  const write = (method, params) => {
    chain = chain.then(() => bridge.call(method, params)).catch((e) => {
      console.error(`[cc-identity] native store ${method} failed (${e?.code || 'error'}): ${e?.message}`)
    })
    return chain
  }
  const set = (k, v) => { mem.set(k, v); return write('storeSet', { k, v }) }
  const del = (k) => { mem.delete(k); return write('storeRemove', { k }) }

  const kv = {
    getItem: (k) => (mem.has(KV + k) ? mem.get(KV + k) : null),
    setItem: (k, v) => { set(KV + k, String(v)) },
    removeItem: (k) => { del(KV + k) }
  }

  const keyStore = {
    async get (name) {
      const raw = mem.get(KEY + name)
      return raw ? JSON.parse(raw) : null
    },
    async set (name, rec) { await set(KEY + name, JSON.stringify(plainKeyRecord(rec))) },
    async remove (name) { await del(KEY + name) }
  }

  // El libro de contactos por perfil (`peerStore.useBackend`).
  const peers = {
    async get (key) {
      const raw = mem.get(PEERS + key)
      return raw ? JSON.parse(raw) : null
    },
    async put (key, val) { await set(PEERS + key, JSON.stringify(val)) }
  }

  return { kv, keyStore, peers, flush: () => chain }
}

