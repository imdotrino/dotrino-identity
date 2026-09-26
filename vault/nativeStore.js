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

const PROFILES = 'dotrino.identity.profiles'
const CURRENT = 'dotrino.identity.current'
const scopedKey = (pid, k) => `dotrino.identity.p.${pid}.${k}`

/**
 * LOS PERFILES QUE SE QUEDARON EN LA PÁGINA pasan a la app (dueño, 2026-09-26: «todas las
 * pestañas usan el mismo perfil, pero NO es el de Dotrino que está en Pedidos»).
 *
 * Antes de `nativeStore` cada página guardaba la identidad aparte, así que la cuenta que se
 * emparejó en `vault.dotrino.com/d` quedó en el almacén de ESA página: su llave está en el
 * chip (Pedidos la usa), pero su acta, su papel y su nombre no llegaron a la app, y la app
 * estrenó un perfil vacío. Esto la trae.
 *
 * Solo se trae un perfil cuya llave VIVE en el chip (`open` contesta): uno de software no
 * cabe, y uno cuya llave ya se borró no sirve para nada. Lo que la app ya tiene no se pisa.
 * Y si el perfil activo de la app no está emparejado y el traído sí, pasa a ser el activo:
 * el vacío se inventó justo porque faltaba este.
 *
 * `page`: lo que hay en el almacén de ESTA página — `kv` (entradas del localStorage),
 * `keys` (registros del IndexedDB de llaves) y `peers` (libros de contactos).
 */
export async function adoptPageProfiles (native, bridge, page) {
  const mine = JSON.parse(native.kv.getItem(PROFILES) || '[]')
  const theirs = JSON.parse(page.kv.get(PROFILES) || '[]')
  const adopted = []
  for (const p of theirs) {
    if (!p?.id || mine.some((m) => m.id === p.id)) continue
    const sign = page.keys.get(scopedKey(p.id, 'keypair'))
    const enc = page.keys.get(scopedKey(p.id, 'enc-keypair'))
    if (!sign?.external) continue
    try { await bridge.call('open', { kid: sign.external }) } catch (_) { continue }
    const prefix = `dotrino.identity.p.${p.id}.`
    for (const [k, v] of page.kv) if (k.startsWith(prefix)) native.kv.setItem(k, v)
    await native.keyStore.set(scopedKey(p.id, 'keypair'), sign)
    if (enc?.external) await native.keyStore.set(scopedKey(p.id, 'enc-keypair'), enc)
    const book = page.peers.get(`peers.${p.id}.v1`)
    if (book) await native.peers.put(`peers.${p.id}.v1`, book)
    mine.push(p)
    adopted.push(p.id)
  }
  if (!adopted.length) return adopted
  native.kv.setItem(PROFILES, JSON.stringify(mine))
  const cur = native.kv.getItem(CURRENT)
  const paired = (pid) => !!native.kv.getItem(scopedKey(pid, 'vault.cert'))
  if (!cur || !paired(cur)) {
    const next = adopted.find(paired)
    if (next) native.kv.setItem(CURRENT, next)
  }
  console.info(`[cc-identity] adopted ${adopted.length} profile(s) from this page's storage into the app: ${adopted.join(', ')}`)
  return adopted
}

/** Todo lo que la identidad guardó en el almacén de ESTA página (localStorage + sus dos IndexedDB). */
export async function readPageStorage () {
  const kv = new Map()
  for (let i = 0; i < localStorage.length; i++) {
    const k = localStorage.key(i)
    if (k && k.startsWith('dotrino.identity.')) kv.set(k, localStorage.getItem(k))
  }
  return { kv, keys: await idbAll('dotrino-identity-keys', 'keys'), peers: await idbAll('cc-identity', 'kv') }
}

function idbAll (dbName, store) {
  return new Promise((resolve, reject) => {
    const req = indexedDB.open(dbName)
    req.onupgradeneeded = () => { if (!req.result.objectStoreNames.contains(store)) req.result.createObjectStore(store) }
    req.onerror = () => reject(req.error)
    req.onsuccess = () => {
      const db = req.result
      if (!db.objectStoreNames.contains(store)) { db.close(); resolve(new Map()); return }
      const out = new Map()
      const cur = db.transaction(store, 'readonly').objectStore(store).openCursor()
      cur.onsuccess = () => {
        const c = cur.result
        if (c) { out.set(String(c.key), c.value); c.continue() } else { db.close(); resolve(out) }
      }
      cur.onerror = () => reject(cur.error)
    }
  })
}
