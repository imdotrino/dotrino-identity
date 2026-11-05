/**
 * LOS TIPOS PUBLICADOS DE LOS SUBPATHS SALEN DEL CÓDIGO (`npm run types`), y esta prueba
 * comprueba que no se quedaron atrás: se generan otra vez en un directorio aparte y se
 * comparan con los de `types/`. Un tipo que no casa con el código es peor que ninguno.
 */
import test from 'node:test'
import assert from 'node:assert/strict'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import { execFileSync } from 'node:child_process'
import { fileURLToPath } from 'node:url'

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), '..')
const tsc = path.join(root, 'node_modules', 'typescript', 'bin', 'tsc')

test('types/ está al día con el código', { skip: fs.existsSync(tsc) ? false : 'sin typescript instalado' }, () => {
  const out = fs.mkdtempSync(path.join(os.tmpdir(), 'identity-types-'))
  execFileSync(process.execPath, [tsc, '-p', path.join(root, 'tsconfig.types.json'), '--outDir', out], { cwd: root, stdio: 'pipe' })
  for (const f of fs.readdirSync(out)) {
    assert.equal(fs.readFileSync(path.join(root, 'types', f), 'utf8'), fs.readFileSync(path.join(out, f), 'utf8'), `types/${f} desactualizado: npm run types`)
  }
})
