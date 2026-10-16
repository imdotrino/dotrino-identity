/**
 * Store del árbol de contenidos del vault (`vault.json`). **Cifrado en reposo**
 * con la misma clave ligada a la máquina que la identidad (`atrest.js`): el
 * contenido del usuario no es menos sensible que la maestra. NO guarda
 * identidad/dispositivos/certs: de eso se encarga
 * `@dotrino/identity` dentro del mismo dir (keypair, contactos, delegaciones,
 * revocaciones). Aquí vive solo lo del usuario: el árbol y los settings.
 */
import { readJson, writeJson } from './disk.js'

const SCHEMA_VERSION = 1

function newTree () {
  return { id: 'root', name: '', type: 'folder', children: [] }
}

function findNode (node, id) {
  if (!node) return null
  if (node.id === id) return node
  if (Array.isArray(node.children)) {
    for (const c of node.children) {
      const r = findNode(c, id)
      if (r) return r
    }
  }
  return null
}

export function openStore (disk) {
  const file = 'vault.json'
  let data = readJson(disk, file, null)
  if (!data || data.schemaVersion !== SCHEMA_VERSION) {
    data = { schemaVersion: SCHEMA_VERSION, tree: newTree(), settings: {} }
  }
  // Se reescribe SIEMPRE al abrir: así un archivo de una instalación anterior
  // (en claro) queda cifrado sin pedirle nada al usuario.
  writeJson(disk, file, data)
  const save = () => writeJson(disk, file, data)

  return {
    get raw () { return data },
    getTree () { return data.tree },
    getNode (id) { return findNode(data.tree, id || 'root') },
    addNode (parentId, node) {
      const parent = findNode(data.tree, parentId || 'root')
      if (!parent) throw new Error('parent node not found: ' + parentId)
      if (!Array.isArray(parent.children)) parent.children = []
      parent.children.push(node)
      save()
      return node
    },
    removeNode (id) {
      const remove = (node) => {
        if (!Array.isArray(node.children)) return false
        const i = node.children.findIndex((c) => c.id === id)
        if (i >= 0) { node.children.splice(i, 1); return true }
        return node.children.some(remove)
      }
      const ok = remove(data.tree)
      if (ok) save()
      return ok
    },
    getSetting (k) { return data.settings[k] },
    setSetting (k, v) { if (v === undefined) delete data.settings[k]; else data.settings[k] = v; save() },
    /** Todos los ajustes (copia). Para quien necesita buscar por prefijo. */
    listSettings () { return { ...data.settings } }
  }
}
