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
import { readFile, writeFile, copyFile, mkdir, readdir } from 'node:fs/promises'
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
    files: ['index.js', 'enroll.js', 'protocol.js', 'passwordLogins.js', 'loginClient.js', 'b64.js',
      // LA BÓVEDA ENTERA: el mismo núcleo que el binario (`browser.js` → `core/`).
      'browser.js', 'procContext.js', 'sealed.js', 'admin.js', 'revocation.js', 'core/'],
    note: [
      'browser.js es la bóveda de esta pestaña: el MISMO núcleo que el binario (core/), con',
      'el disco en IndexedDB. Importa @dotrino/{compat,roadmap,passmanager,store/core} y',
      '@dotrino/identity/{facade,machine,content}, todos por el import map de index.html.',
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
    files: ['index.js', 'client.js', 'signature.js', 'canonical.js', 'sealing.js', 'encpub.js', 'webrtc.js', 'stats.js', 'stats-log.js', 'parts.js', 'binpack.js'],
    note: [
      'sealing.js resuelve @dotrino/identity/content de forma PEREZOSA (= ../../content.js',
      'por el import map): solo se carga si de verdad se sella algo.',
      'encpub.js (≥ 0.20) es el anuncio firmado de la llave de cifrado; no importa nada de',
      'fuera, solo ./signature.js y ./canonical.js de esta misma copia.',
    ],
  },
]

// LO QUE IMPORTA EL NÚCLEO DE LA BÓVEDA (`@dotrino/vault/browser`). Solo lo carga la
// pestaña que es bóveda, como el OPAQUE.
VENDORED.push(
  {
    name: '@dotrino/compat',
    repo: 'dotrino-compat',
    pkg: 'dotrino-compat/package.json',
    from: 'dotrino-compat/src',
    to: 'vault/vendor/compat',
    files: ['index.js', 'ranges.js', 'advisory.js'],
    note: ['Qué versión es cada pieza y si pueden hablar (CONVENCIONES §14).'],
  },
  {
    name: '@dotrino/roadmap',
    repo: 'dotrino-roadmap',
    pkg: 'dotrino-roadmap/package.json',
    from: 'dotrino-roadmap/src',
    to: 'vault/vendor/roadmap',
    files: ['index.js', 'manifests.js'],
    note: ['El registro de versiones rotas que viaja con cada versión. Importa @dotrino/compat/ranges.'],
  },
  {
    name: '@dotrino/passmanager',
    repo: 'dotrino-passmanager',
    pkg: 'dotrino-passmanager/lib/package.json',
    from: 'dotrino-passmanager/lib/src',
    to: 'vault/vendor/passmanager',
    files: ['./'],
    note: ['El sobre de las contraseñas, el mismo que usan el binario y la extensión. Importa @dotrino/identity/content.'],
  },
  {
    name: '@dotrino/store/core',
    repo: 'dotrino-store',
    pkg: 'dotrino-store/package.json',
    from: 'dotrino-store/store',
    to: 'vault/vendor/store',
    files: ['core.js'],
    note: ['Las reglas del almacén (lápidas, páginas): las mismas en el store y en la bóveda.'],
  },
)

/**
 * Los archivos de una entrada. Una que acaba en `/` es una CARPETA: se copian todos sus
 * `.js`, con sus subcarpetas, porque sus imports relativos cuentan con la forma.
 */
export async function filesOf (v) {
  const out = []
  for (const f of v.files) {
    if (!f.endsWith('/')) { out.push(f); continue }
    const base = join(eco, v.from, f)
    const walk = async (rel) => {
      for (const e of await readdir(join(base, rel), { withFileTypes: true })) {
        const r = rel ? `${rel}/${e.name}` : e.name
        if (e.isDirectory()) await walk(r)
        else if (e.name.endsWith('.js') && !e.name.endsWith('.d.ts')) out.push(join(f, r).replace(/^\.\//, ''))
      }
    }
    await walk('')
  }
  return out.sort()
}

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
    const files = await filesOf(v)
    for (const f of files) {
      // `f` puede llevar carpetas (`build/opaque.js`): la copia conserva la forma del
      // paquete, porque sus imports relativos cuentan con ella.
      const dest = join(here, v.to, f)
      await mkdir(dirname(dest), { recursive: true })
      await copyFile(join(eco, v.from, f), dest)
    }
    await writeFile(join(here, v.to, 'VERSION.txt'),
      `Copia vendorizada de ${v.name}@${ver} (${v.from}/{${files.map((f) => f.replace(/\.js$/, '')).join(',')}}.js).\n` +
      'NO se edita a mano: la escribe `node vendor.mjs` y la vigila test/vendor-up-to-date.test.mjs.\n' +
      v.note.join('\n') + '\n')
    console.log(`vendor: ${v.name}@${ver} → ${v.to}/`)
  }
}

if (process.argv[1] === fileURLToPath(import.meta.url)) await main()
