/**
 * LA COPIA DEL IFRAME NO SE QUEDA ATRÁS.
 *
 * `id.dotrino.com` es estático, así que `@dotrino/vault` y `@dotrino/proxy-client` viajan
 * copiados en `vault/vendor/`. Esa copia se ha quedado vieja TRES veces (0.18, 0.24,
 * 0.34) y la última costó cara: el iframe corría un device-vault sin `vault:passwords` en
 * su mapa de permisos, así que un aparato emparejado contra la bóveda-en-pestaña nunca
 * salía del acta con esa capacidad — y la pestaña, que solo atiende a quien la tiene, no
 * le contestaba nunca. Desde fuera se veía como «nadie respondió».
 *
 * Nadie se acuerda de correr un script. Esta prueba es la que se acuerda.
 *
 * Se SALTA si el repo hermano no está al lado —no hay con qué comparar, y esto también
 * corre en CI, donde solo se clona este repo—. No es un repliegue: no da por buena la
 * copia, dice que no pudo mirarla.
 */
import test from 'node:test'
import assert from 'node:assert/strict'
import { readFile } from 'node:fs/promises'
import { join, dirname } from 'node:path'
import { fileURLToPath } from 'node:url'

import { VENDORED, siblingPath } from '../vendor.mjs'

const here = join(dirname(fileURLToPath(import.meta.url)), '..')

for (const v of VENDORED) {
  const src = siblingPath(v.from)
  test(`vendor: ${v.name} está al día`, { skip: src ? false : `sin ${v.repo}/ al lado` }, async () => {
    for (const f of v.files) {
      const [fuente, copia] = await Promise.all([
        readFile(join(src, f), 'utf8'),
        readFile(join(here, v.to, f), 'utf8'),
      ])
      assert.equal(copia, fuente,
        `${v.to}/${f} no es ${v.from}/${f}. Corre \`node vendor.mjs\` y commitea la copia.`)
    }
  })

  test(`vendor: ${v.name} declara la versión que copió`, { skip: src ? false : `sin ${v.repo}/ al lado` }, async () => {
    const { version } = JSON.parse(await readFile(join(here, '..', v.pkg), 'utf8'))
    const stamp = await readFile(join(here, v.to, 'VERSION.txt'), 'utf8')
    assert.ok(stamp.includes(`${v.name}@${version}`),
      `VERSION.txt dice otra cosa que ${v.name}@${version}. Corre \`node vendor.mjs\`.`)
  })
}

/**
 * Lo que el iframe importa por nombre tiene que estar en su import map, o el navegador
 * falla en tiempo de carga y no lo ve nadie hasta que alguien empareja. `sealing.js`
 * (proxy-client ≥ 0.13) añadió `@dotrino/identity/content` y por poco entra sin él.
 */
test('el import map resuelve todo lo que el vendor importa por nombre', async () => {
  const html = await readFile(join(here, 'vault/index.html'), 'utf8')
  const map = JSON.parse(html.match(/<script type="importmap">\s*([\s\S]*?)<\/script>/)[1]).imports

  const desnudos = new Set()
  for (const v of VENDORED) {
    for (const f of v.files) {
      const code = await readFile(join(here, v.to, f), 'utf8')
      for (const m of code.matchAll(/(?:from|import)\s*\(?\s*['"](@[^'"]+)['"]/g)) desnudos.add(m[1])
    }
  }

  for (const spec of desnudos) {
    assert.ok(map[spec], `el import map de vault/index.html no resuelve "${spec}"`)
  }
})
