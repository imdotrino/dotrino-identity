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
import { readFile, writeFile, copyFile, mkdir } from 'node:fs/promises'
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
    files: ['index.js', 'enroll.js', 'protocol.js', 'passwordLogins.js', 'loginClient.js', 'b64.js'],
    note: [
      'index.js importa ./enroll.js y ./protocol.js (relativos, van en esta misma copia),',
      '@dotrino/identity/{capabilities,acta} (= ../../{capabilities,acta}.js) y',
      '@dotrino/proxy-client (= ../proxy-client/), todos por el import map de index.html.',
      'passwordLogins.js es el aparato que se abre con usuario y contraseña: lo carga',
      'vault.js SOLO cuando esta pestaña es bóveda, porque arrastra el OPAQUE en WASM.',
      'loginClient.js es la otra mitad —el que ENTRA con esa contraseña— y lo carga core.js',
      'solo al entrar, por lo mismo: arrastra el OPAQUE.',
    ],
  },
  // OPAQUE: comprobar una contraseña sin verla nunca. Solo lo carga la pestaña que es
  // bóveda — son ~270 KB de WASM incrustado, y el iframe lo cargan las ~30 apps.
  {
    name: '@dotrino/opaque',
    repo: 'dotrino-opaque',
    pkg: 'dotrino-opaque/package.json',
    from: 'dotrino-opaque',
    to: 'vault/vendor/opaque',
    files: ['src/index.js', 'build/opaque.js', 'build/wasm-bytes.js'],
    note: [
      'src/index.js importa ../build/{opaque,wasm-bytes}.js, así que la copia CONSERVA',
      'esas dos carpetas: aplanarla rompería el import relativo.',
      'El WASM viaja dentro del JS (base64) porque el binario del vault es un ejecutable',
      'único; aquí eso significa que se baja como script, sin un fetch aparte.',
    ],
  },
  {
    name: '@dotrino/proxy-client',
    repo: 'dotrino-proxy-client',
    pkg: 'dotrino-proxy-client/package.json',
    from: 'dotrino-proxy-client/src',
    to: 'vault/vendor/proxy-client',
    files: ['index.js', 'client.js', 'signature.js', 'canonical.js', 'sealing.js', 'encpub.js', 'webrtc.js'],
    note: [
      'sealing.js resuelve @dotrino/identity/content de forma PEREZOSA (= ../../content.js',
      'por el import map): solo se carga si de verdad se sella algo.',
      'encpub.js (≥ 0.20) es el anuncio firmado de la llave de cifrado; no importa nada de',
      'fuera, solo ./signature.js y ./canonical.js de esta misma copia.',
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
    for (const f of v.files) {
      // `f` puede llevar carpetas (`build/opaque.js`): la copia conserva la forma del
      // paquete, porque sus imports relativos cuentan con ella.
      const dest = join(here, v.to, f)
      await mkdir(dirname(dest), { recursive: true })
      await copyFile(join(eco, v.from, f), dest)
    }
    await writeFile(join(here, v.to, 'VERSION.txt'),
      `Copia vendorizada de ${v.name}@${ver} (${v.from}/{${v.files.map((f) => f.replace(/\.js$/, '')).join(',')}}.js).\n` +
      'NO se edita a mano: la escribe `node vendor.mjs` y la vigila test/vendor-up-to-date.test.mjs.\n' +
      v.note.join('\n') + '\n')
    console.log(`vendor: ${v.name}@${ver} → ${v.to}/`)
  }
}

if (process.argv[1] === fileURLToPath(import.meta.url)) await main()
