/**
 * RESOLVER COMO EL NAVEGADOR: los nombres de paquete (`@dotrino/...`) se resuelven con el
 * import map de `vault/index.html`, no con `node_modules`. Así una prueba en Node carga
 * exactamente los archivos que se descarga quien abre `vault.dotrino.com/vault`, y un
 * nombre que falte en el import map revienta aquí igual que allí.
 *
 *   import { register } from 'node:module'
 *   register('./helpers/importmap-hooks.mjs', import.meta.url)
 */
import { readFileSync } from 'node:fs'
import { fileURLToPath, pathToFileURL } from 'node:url'
import { join, dirname } from 'node:path'

const vaultDir = join(dirname(fileURLToPath(import.meta.url)), '..', '..', 'vault')
const html = readFileSync(join(vaultDir, 'index.html'), 'utf8')
const MAP = JSON.parse(html.match(/<script type="importmap">\s*([\s\S]*?)<\/script>/)[1]).imports

export async function resolve (specifier, context, next) {
  if (specifier.startsWith('@dotrino/')) {
    const dest = MAP[specifier]
    // Lo que el navegador no podría resolver tampoco se resuelve aquí.
    if (!dest) throw Object.assign(new Error(`the import map of vault/index.html does not resolve "${specifier}"`), { code: 'ERR_MODULE_NOT_FOUND' })
    return { url: pathToFileURL(join(vaultDir, dest)).href, shortCircuit: true }
  }
  return next(specifier, context)
}
