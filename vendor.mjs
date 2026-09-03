/**
 * RE-VENDORIZAR lo que sirve el iframe (`vault/vendor/`).
 *
 * `id.dotrino.com` se sirve ESTÁTICO —vanilla, sin bundler—, así que las dos piezas que
 * el iframe importa de fuera viajan copiadas dentro del repo: `@dotrino/vault` (el
 * device-vault que atiende enrolamientos) y `@dotrino/proxy-client` (su transporte).
 *
 * Copiarlas a mano es lo que hizo que el iframe corriera un vault de hace DIECIOCHO
 * versiones sin que nadie lo notara: se subía el pilar, se olvidaba la copia, y la
 * bóveda-en-pestaña se quedaba con un protocolo viejo — sin `vault:passwords` en el mapa
 * de permisos, o sea con el gestor de contraseñas incapaz de emparejarse contra ella.
 * Ha pasado tres veces (0.18, 0.24, 0.34).
 *
 * Por eso son dos piezas y no una: este script COPIA, y `test/vendor-up-to-date.test.mjs`
 * FALLA si alguien no lo corrió. Sin la prueba, el script se olvida igual que la copia.
 *
 *   node vendor.mjs
 */
import { readFile, writeFile, copyFile } from 'node:fs/promises'
import { existsSync } from 'node:fs'
import { join, dirname } from 'node:path'
import { fileURLToPath } from 'node:url'

const here = dirname(fileURLToPath(import.meta.url))
const eco = join(here, '..')

/**
 * Qué se copia y de dónde. `files` son los ÚNICOS archivos que el iframe necesita: el
 * device-vault no arrastra el resto del paquete (la CLI, los secretos, el cliente de
 * servicio).
 */
export const VENDORED = [
  {
    name: '@dotrino/vault',
    repo: 'dotrino-vault',
    pkg: 'dotrino-vault/lib/package.json',
    from: 'dotrino-vault/lib/src',
    to: 'vault/vendor/vault',
    files: ['index.js', 'enroll.js', 'protocol.js'],
    note: [
      'index.js importa ./enroll.js y ./protocol.js (relativos, van en esta misma copia),',
      '@dotrino/identity/{capabilities,acta} (= ../../{capabilities,acta}.js) y',
      '@dotrino/proxy-client (= ../proxy-client/), todos por el import map de index.html.',
    ],
  },
  {
    name: '@dotrino/proxy-client',
    repo: 'dotrino-proxy-client',
    pkg: 'dotrino-proxy-client/package.json',
    from: 'dotrino-proxy-client/src',
    to: 'vault/vendor/proxy-client',
    files: ['index.js', 'client.js', 'signature.js', 'canonical.js', 'sealing.js', 'webrtc.js'],
    note: [
      'sealing.js resuelve @dotrino/identity/content de forma PEREZOSA (= ../../content.js',
      'por el import map): solo se carga si de verdad se sella algo.',
    ],
  },
]

/** La ruta de un repo hermano, o null si esta copia del ecosistema no lo tiene. */
export const siblingPath = (rel) => {
  const p = join(eco, rel)
  return existsSync(p) ? p : null
}

async function version (rel) {
  return JSON.parse(await readFile(join(eco, rel), 'utf8')).version
}

async function main () {
  for (const v of VENDORED) {
    if (!siblingPath(v.from)) {
      // Sin el repo hermano no hay de dónde copiar. Se para y se dice: dejar la copia
      // vieja «porque no estaba la fuente» es exactamente el fallo que esto evita.
      console.error(`falta el repo hermano ${v.repo}/ — clónalo al lado y vuelve a correr`)
      process.exitCode = 1
      continue
    }
    const ver = await version(v.pkg)
    for (const f of v.files) await copyFile(join(eco, v.from, f), join(here, v.to, f))
    await writeFile(join(here, v.to, 'VERSION.txt'),
      `Copia vendorizada de ${v.name}@${ver} (${v.from}/{${v.files.map((f) => f.replace(/\.js$/, '')).join(',')}}.js).\n` +
      'NO se edita a mano: la escribe `node vendor.mjs` y la vigila test/vendor-up-to-date.test.mjs.\n' +
      v.note.join('\n') + '\n')
    console.log(`vendor: ${v.name}@${ver} → ${v.to}/`)
  }
}

if (process.argv[1] === fileURLToPath(import.meta.url)) await main()
