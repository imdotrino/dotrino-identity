/**
 * EL DISCO DE UNA BÓVEDA, el mismo para el binario y para el navegador.
 *
 * La bóveda guarda una docena de archivos pequeños (`vault.json`, `secrets.json`,
 * `blocked.json`, la bitácora…) y los lee y escribe de forma SÍNCRONA: se consultan por
 * cada mensaje que entra, y convertir cada lectura en un `await` cambiaría el orden en que
 * pasan las cosas en todo el núcleo. Por eso el disco es una interfaz síncrona, y quien
 * monta la bóveda pone la suya:
 *
 *   · el binario, archivos de verdad bajo el directorio del perfil (`src/disk.js`);
 *   · el navegador, una copia en memoria que se guarda cifrada en IndexedDB por detrás
 *     (`./browserDisk.js`).
 *
 * Interfaz (nombres relativos al perfil, nunca rutas):
 *
 *   read(name)          → el texto, o `null` si no existe. Otro fallo LANZA: un archivo
 *                         que está y no se puede leer no es un archivo vacío.
 *   write(name, text)   → reemplaza entero, de golpe (a medio escribir no queda nada).
 *   append(name, text)  → añade al final.
 *   exists(name), remove(name), rename(from, to), size(name)
 *   atRest              → `{ encrypt(text), decrypt(text) }`, síncronos: el cifrado en
 *                         reposo de ESTE disco. En el binario va ligado a la máquina; en el
 *                         navegador el cifrado lo hace el almacén entero y aquí no se toca.
 *   machineKey()        → 32 bytes: la llave de la máquina (`kekFor`). Es con lo que se
 *                         cierra lo que tiene que abrirse con el perfil cerrado.
 */

/** Lee un JSON cifrado en reposo. Lo que no está o no se puede leer devuelve `fallback`. */
export function readJson (disk, name, fallback) {
  try {
    const raw = disk.read(name)
    if (raw == null) return fallback
    return JSON.parse(disk.atRest.decrypt(raw))
  } catch (_) { return fallback }
}

/** Escribe un JSON cifrado en reposo, entero y de golpe. */
export function writeJson (disk, name, obj) {
  disk.write(name, disk.atRest.encrypt(JSON.stringify(obj, null, 2)))
}

/**
 * Un disco en memoria, sin nada detrás. Es la base del del navegador (que lo vuelca a
 * IndexedDB) y el de las pruebas. `files` es un `Map` nombre → texto.
 */
export function memoryDisk ({ files = new Map(), atRest = null, machineKey = null, onChange = () => {} } = {}) {
  const key = machineKey || (() => { throw Object.assign(new Error('this disk has no machine key'), { code: 'no-machine-key' }) })
  return {
    files,
    read: (name) => (files.has(name) ? files.get(name) : null),
    write: (name, text) => { files.set(name, String(text)); onChange(name) },
    append: (name, text) => { files.set(name, (files.get(name) || '') + String(text)); onChange(name) },
    exists: (name) => files.has(name),
    remove: (name) => { if (files.delete(name)) onChange(name) },
    rename: (from, to) => {
      if (!files.has(from)) throw Object.assign(new Error(`rename: ${from} does not exist`), { code: 'ENOENT' })
      files.set(to, files.get(from)); files.delete(from); onChange(from); onChange(to)
    },
    size: (name) => (files.has(name) ? new TextEncoder().encode(files.get(name)).length : 0),
    atRest: atRest || { encrypt: (t) => t, decrypt: (t) => t },
    machineKey: key
  }
}

export default { readJson, writeJson, memoryDisk }
