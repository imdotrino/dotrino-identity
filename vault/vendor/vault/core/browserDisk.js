/**
 * EL DISCO DE LA BÓVEDA EN EL NAVEGADOR (pestaña y extensión).
 *
 * El núcleo lee y escribe de forma síncrona (`./disk.js`), y en el navegador el único
 * almacén que aguanta es IndexedDB, que es asíncrono. Así que al abrir se cargan TODOS los
 * archivos del perfil a memoria, y cada escritura se guarda por detrás. Son una docena de
 * archivos pequeños: caben de sobra.
 *
 * NADA EN CLARO EN EL DISCO. Cada archivo se guarda cifrado con AES-GCM bajo una llave que
 * se crea aquí NO EXTRAÍBLE y vive en la misma base: el navegador la puede usar y nadie la
 * puede leer, que es lo más parecido que hay en un navegador a la llave ligada a la máquina
 * del binario. Por eso el cifrado en reposo del núcleo (`atRest`) aquí no hace nada: lo hace
 * el almacén entero, archivo por archivo.
 *
 * LO QUE NO PROMETE, dicho: una escritura que no llegó a IndexedDB antes de cerrar la
 * pestaña se pierde. Se guarda en cuanto se escribe (sin esperar a juntar), y `flush()`
 * espera a que todo esté guardado.
 */
import { memoryDisk } from './disk.js'

const STORE = 'files'
const KEY_ID = '\u0000key'

function idb (req) {
  return new Promise((resolve, reject) => {
    req.onsuccess = () => resolve(req.result)
    req.onerror = () => reject(req.error)
  })
}

function openDb (name) {
  const req = indexedDB.open(name, 1)
  req.onupgradeneeded = () => { req.result.createObjectStore(STORE) }
  return idb(req)
}

const tx = (db, mode) => db.transaction(STORE, mode).objectStore(STORE)

/**
 * @param {string} name  la base de este perfil (`dotrino-vault.<perfil>`)
 * @returns {Promise<object>} un disco (`./disk.js`) con `flush()` y `close()`
 */
export async function openBrowserDisk (name) {
  if (typeof indexedDB === 'undefined') throw Object.assign(new Error('this browser has no IndexedDB: the vault cannot keep anything here'), { code: 'no-indexeddb' })
  const db = await openDb(name)

  let key = await idb(tx(db, 'readonly').get(KEY_ID))
  if (!key) {
    key = await crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt'])
    await idb(tx(db, 'readwrite').put(key, KEY_ID))
  }

  // Todo a memoria. Un archivo que está y no se abre NO se salta: el núcleo decidiría con
  // un archivo vacío (una lista de bloqueados vacía, un acta sin cajones), y eso es justo
  // el repliegue que no se pone. Se para y se dice cuál.
  const files = new Map()
  const names = await idb(tx(db, 'readonly').getAllKeys())
  for (const n of names) {
    if (n === KEY_ID) continue
    const rec = await idb(tx(db, 'readonly').get(n))
    try {
      const plain = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: rec.iv }, key, rec.ct)
      files.set(n, new TextDecoder().decode(plain))
    } catch (e) {
      throw Object.assign(new Error(`vault storage: ${n} cannot be opened (${e?.message || e})`), { code: 'disk-unreadable', file: n })
    }
  }

  // Las escrituras van en orden y una detrás de otra: la última manda.
  let queue = Promise.resolve()
  let lastError = null
  const persist = (n) => {
    queue = queue.then(async () => {
      if (!files.has(n)) { await idb(tx(db, 'readwrite').delete(n)); return }
      const iv = crypto.getRandomValues(new Uint8Array(12))
      const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, new TextEncoder().encode(files.get(n)))
      await idb(tx(db, 'readwrite').put({ iv, ct }, n))
    }).catch((e) => {
      lastError = e
      console.error(`[vault] could not save ${n} in this browser: ${e?.message || e}`)
    })
  }

  // LA LLAVE DE LA MÁQUINA (`machineKey`): 32 bytes al azar, creados una vez. Es con lo que
  // el núcleo cierra lo que tiene que abrirse con el perfil cerrado; aquí vale lo que vale
  // este almacén, igual que en el binario vale lo que vale su disco.
  const MACHINE = 'machine.key'
  if (!files.has(MACHINE)) {
    const raw = crypto.getRandomValues(new Uint8Array(32))
    let s = ''; for (const b of raw) s += String.fromCharCode(b)
    files.set(MACHINE, btoa(s))
    persist(MACHINE)
  }
  const machineKey = () => Uint8Array.from(atob(files.get(MACHINE)), (c) => c.charCodeAt(0))

  const disk = memoryDisk({ files, machineKey, onChange: persist })
  return {
    ...disk,
    name,
    /** Espera a que lo escrito esté en IndexedDB. Lanza si algo no se pudo guardar. */
    async flush () {
      await queue
      if (lastError) { const e = lastError; lastError = null; throw e }
    },
    close () { try { db.close() } catch (_) {} }
  }
}

export default { openBrowserDisk }
