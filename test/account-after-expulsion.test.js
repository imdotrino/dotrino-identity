/**
 * Al ECHAR a un dispositivo, la cuenta se va del aparato — y el aparato no se queda sin
 * cuenta.
 *
 * Antes se borraba el enlace con la bóveda y el acta, pero la cuenta seguía ahí: un
 * cascarón sin acta, sin certificado y sin poder hacer nada, que seguía saliendo en el
 * conmutador de perfiles con su nombre y su foto.
 *
 * QUIÉN DECIDE QUÉ CUENTA QUEDA PUESTA: el ARRANQUE, que ya lo hacía. Si no queda
 * ninguna estrena la primera; si quedan, entra en la primera de la lista. Por eso
 * `removeThisAccount` solo borra: decidirlo también ahí sería la misma regla en dos
 * sitios, y de esas dos una acaba mintiendo.
 */
import test from 'node:test'
import assert from 'node:assert/strict'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import { Identity } from '../src/node.js'

const tmp = () => fs.mkdtempSync(path.join(os.tmpdir(), 'cuenta-'))

/** Cierra y vuelve a abrir la identidad sobre el mismo disco: eso es «recargar». */
async function reabrir (id, dir) {
  id.destroy()
  return Identity.connect({ dir })
}

test('sin ninguna cuenta, al arrancar se estrena una — y es la activa', async () => {
  const dir = tmp()
  let id = await Identity.connect({ dir })
  const primera = (await id.currentProfile()).id

  // Se borra el registro de perfiles a mano: es el estado en el que queda un aparato al
  // que echaron y del que se fue su única cuenta.
  id.destroy()
  const f = path.join(dir, 'identity.json')
  const kv = JSON.parse(fs.readFileSync(f, 'utf8'))
  delete kv['dotrino.identity.profiles']
  delete kv['dotrino.identity.current']
  fs.writeFileSync(f, JSON.stringify(kv))

  id = await Identity.connect({ dir })
  const list = await id.listProfiles()
  assert.equal(list.length, 1, 'el arranque estrena la primera')
  assert.notEqual(list[0].id, primera, 'y es una cuenta nueva, no la que se fue')
  assert.equal((await id.currentProfile()).id, list[0].id, 'queda activa: el aparato es usable')
  assert.ok((await id.currentProfile()).pubkey, 'con su propia llave')

  id.destroy(); fs.rmSync(dir, { recursive: true, force: true })
})

test('si quedan otras, al arrancar entra en la primera (sin estrenar ninguna)', async () => {
  const dir = tmp()
  let id = await Identity.connect({ dir })
  const otra = (await id.currentProfile()).id
  const echada = (await id.createProfile('la de la bóveda')).id
  assert.equal((await id.currentProfile()).id, echada, 'crear deja la nueva activa')

  await id.deleteProfile(echada)
  id = await reabrir(id, dir)

  const list = await id.listProfiles()
  assert.deepEqual(list.map((p) => p.id), [otra], 'no se estrena ninguna de más')
  assert.equal((await id.currentProfile()).id, otra, 'y es la activa')

  id.destroy(); fs.rmSync(dir, { recursive: true, force: true })
})

test('la cuenta borrada se va con lo suyo: no queda su llave en ninguna otra', async () => {
  const dir = tmp()
  const id = await Identity.connect({ dir })
  const echada = (await id.currentProfile()).id
  const suPub = (await id.currentProfile()).pubkey
  await id.createProfile('otra')
  await id.deleteProfile(echada)

  const list = await id.listProfiles()
  assert.equal(list.some((p) => p.id === echada), false)
  assert.equal(list.some((p) => p.pubkey === suPub), false)

  id.destroy(); fs.rmSync(dir, { recursive: true, force: true })
})

/**
 * BORRAR LA ÚNICA CUENTA (dueño, 2026-10-05): se puede, porque borrar tu cuenta es un derecho
 * y la App Store lo exige. La alerta es de la interfaz. Lo que se comprueba aquí es que el
 * aparato no queda roto: el siguiente arranque estrena una cuenta NUEVA, con otra llave.
 */
test('borrar la única cuenta: se va entera y el arranque estrena una nueva', async () => {
  const dir = tmp()
  const id = await Identity.connect({ dir })
  const sola = await id.currentProfile()

  const r = await id.deleteProfile(sola.id)
  assert.equal(r.wasCurrent, true)
  assert.equal((await id.listProfiles()).length, 0, 'no queda ninguna')
  id.destroy()

  const otra = await Identity.connect({ dir })
  const nueva = await otra.currentProfile()
  const lista = await otra.listProfiles()
  assert.equal(lista.length, 1, 'el arranque estrenó una')
  assert.notEqual(nueva.pubkey, sola.pubkey, 'con otra llave: la borrada no vuelve')
  otra.destroy(); fs.rmSync(dir, { recursive: true, force: true })
})
