/**
 * Al ECHAR a un dispositivo, la cuenta se va del aparato — y el aparato NO se queda sin
 * cuenta.
 *
 * Antes se borraba el enlace con la bóveda y el acta, pero la cuenta seguía ahí: un
 * cascarón sin acta, sin certificado y sin poder hacer nada, que seguía saliendo en el
 * conmutador de perfiles con su nombre y su foto. Ahora se borra entera y queda otra
 * puesta: una que ya tuvieras, o una nueva si esa era la única.
 *
 * Lo que se fija aquí son las DOS reglas sobre las que se apoya ese paso (`wipeVaultLink`
 * → `removeThisAccount` en `vault/core.js`). Si alguna cambiara, el aparato acabaría sin
 * ninguna cuenta activa, que es peor que el cascarón.
 */
import test from 'node:test'
import assert from 'node:assert/strict'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import { Identity } from '../src/node.js'

const tmp = () => fs.mkdtempSync(path.join(os.tmpdir(), 'cuenta-'))

test('borrar la ÚNICA cuenta se niega: por eso primero se estrena otra', async () => {
  const dir = tmp()
  const id = await Identity.connect({ dir })
  const sola = (await id.currentProfile()).id

  await assert.rejects(() => id.deleteProfile(sola), /only profile/)

  // El orden que usa la expulsión: crear (queda activa) y luego borrar la que se fue.
  const nueva = await id.createProfile('')
  await id.deleteProfile(sola)

  const list = await id.listProfiles()
  assert.equal(list.length, 1, 'queda exactamente una')
  assert.equal(list[0].id, nueva.id)
  assert.equal((await id.currentProfile()).id, nueva.id, 'y es la activa: el aparato es usable')
  assert.notEqual(list[0].pubkey, null, 'con su propia llave, recién nacida')

  id.destroy(); fs.rmSync(dir, { recursive: true, force: true })
})

test('si había otras, borrar la echada deja una de ellas ACTIVA (sin crear ninguna)', async () => {
  const dir = tmp()
  const id = await Identity.connect({ dir })
  const otra = (await id.currentProfile()).id
  const echada = (await id.createProfile('la de la bóveda')).id
  assert.equal((await id.currentProfile()).id, echada, 'crear deja la nueva activa')

  await id.deleteProfile(echada)

  const list = await id.listProfiles()
  assert.deepEqual(list.map((p) => p.id), [otra], 'no se estrena ninguna de más')
  assert.equal((await id.currentProfile()).id, otra, 'y la que queda pasa a ser la activa')

  id.destroy(); fs.rmSync(dir, { recursive: true, force: true })
})

test('la cuenta borrada se va con lo suyo: llave, acta y enlace', async () => {
  const dir = tmp()
  const id = await Identity.connect({ dir })
  const echada = (await id.currentProfile()).id
  const suPub = (await id.currentProfile()).pubkey
  await id.createProfile('otra')
  await id.deleteProfile(echada)

  const list = await id.listProfiles()
  assert.equal(list.some((p) => p.id === echada), false)
  assert.equal(list.some((p) => p.pubkey === suPub), false, 'su llave no sobrevive en ninguna otra')

  id.destroy(); fs.rmSync(dir, { recursive: true, force: true })
})
