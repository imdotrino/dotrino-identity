/**
 * EMPAREJARSE CON UNA BÓVEDA NO PUEDE DEJAR CUENTAS DE MÁS.
 *
 * El camino B (`enrollDevice(qr, { join: 'new' })`) crea aquí una cuenta más para meterla
 * al acta de la bóveda. Hasta 2026-08-17 la creaba ANTES de hablar con nadie y no la
 * deshacía nunca, así que:
 *
 *   · un intento que falla (código vencido, la bóveda apagada, se agotó la espera) dejaba
 *     una cuenta vacía —y encima puesta como activa—: tres reintentos, tres fantasmas;
 *   · volver a emparejar con la bóveda que YA te tiene (el papel venció, lo retiraron)
 *     creaba otra cuenta con otra llave: la misma cuenta dos veces en el conmutador.
 *
 * Aquí se comprueban las tres salidas: descartar la que nació para un intento fallido,
 * no duplicar la que ya está emparejada, y recoger al arrancar las que se quedaron a
 * medias porque se cerró la pestaña.
 */
import test from 'node:test'
import assert from 'node:assert/strict'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import { Identity } from '../src/node.js'

const tmp = () => fs.mkdtempSync(path.join(os.tmpdir(), 'pair-'))

/** Un QR con toda la pinta de bueno cuyo proxy no contesta: el enroll falla sí o sí. */
const qrMuerto = (iss = 'MASTER-QUE-NO-ESTA') => ({
  v: 2, iss, proxy: 'ws://127.0.0.1:9', token: 'tok', sn: 'sn-1'
})

const kvFile = (dir) => path.join(dir, 'identity.json')
const readKv = (dir) => JSON.parse(fs.readFileSync(kvFile(dir), 'utf8'))
const writeKv = (dir, data) => fs.writeFileSync(kvFile(dir), JSON.stringify(data))

test('un emparejamiento que falla no deja una cuenta fantasma', async () => {
  const dir = tmp()
  const id = await Identity.connect({ dir })
  const antes = await id.currentProfile()

  await assert.rejects(() => id.enrollDevice(qrMuerto(), { join: 'new' }))

  const perfiles = await id.listProfiles()
  assert.equal(perfiles.length, 1, 'la cuenta que nació para el intento se fue con él')
  assert.equal((await id.currentProfile()).id, antes.id, 'y sigue abierta la que estabas usando')
  assert.equal((await id.currentProfile()).pubkey, antes.pubkey, 'con su llave, no con la del intento')
  id.destroy()
  fs.rmSync(dir, { recursive: true, force: true })
})

test('si esa bóveda ya vive en OTRA cuenta de este aparato, se avisa en vez de duplicar', async () => {
  const dir = tmp()
  let id = await Identity.connect({ dir })
  const primera = (await id.currentProfile()).id
  const segunda = (await id.createProfile('Bóveda de casa')).id
  id.destroy()

  // La segunda cuenta ya está emparejada con MASTER-X, y la abierta es la primera.
  const kv = readKv(dir)
  kv[`dotrino.identity.p.${segunda}.vault.cert`] = JSON.stringify({ cert: {}, master: 'MASTER-X' })
  kv['dotrino.identity.current'] = primera
  writeKv(dir, kv)

  id = await Identity.connect({ dir })
  await assert.rejects(
    () => id.enrollDevice(qrMuerto('MASTER-X'), { join: 'new' }),
    (e) => {
      assert.equal(e.code, 'ALREADY_PAIRED', 'con código: la consola tiene que poder ofrecer ir a esa cuenta')
      assert.equal(e.detail.profile, segunda, 'y con CUÁL, para poder llevarte a ella')
      return true
    }
  )
  assert.equal((await id.listProfiles()).length, 2, 'no nació ninguna cuenta')
  assert.equal((await id.currentProfile()).id, primera, 'ni se cambió la abierta')
  id.destroy()
  fs.rmSync(dir, { recursive: true, force: true })
})

test('re-emparejar con la bóveda que ya tiene ESTA cuenta no crea otra', async () => {
  const dir = tmp()
  let id = await Identity.connect({ dir })
  const sola = (await id.currentProfile()).id
  id.destroy()

  const kv = readKv(dir)
  kv[`dotrino.identity.p.${sola}.vault.cert`] = JSON.stringify({ cert: {}, master: 'MASTER-X' })
  writeKv(dir, kv)

  id = await Identity.connect({ dir })
  // Falla igual (el proxy no contesta), pero por la red: no por haberse inventado una cuenta.
  await assert.rejects(() => id.enrollDevice(qrMuerto('MASTER-X'), { join: 'new' }))
  assert.equal((await id.listProfiles()).length, 1, 'sigue habiendo UNA cuenta, no dos iguales')
  id.destroy()
  fs.rmSync(dir, { recursive: true, force: true })
})

test('al arrancar se recogen las cuentas que se quedaron a medio emparejar', async () => {
  const dir = tmp()
  let id = await Identity.connect({ dir })
  const primera = (await id.currentProfile()).id
  // Lo que deja una pestaña cerrada con el código en pantalla: la cuenta creada para el
  // intento, marcada `pendingJoin`, sin bóveda y activa.
  const huerfana = await id.createProfile('Bóveda', { forVault: true })
  assert.equal(huerfana.pendingJoin, true)
  assert.equal((await id.listProfiles()).length, 2)
  id.destroy()

  id = await Identity.connect({ dir })
  const perfiles = await id.listProfiles()
  assert.equal(perfiles.length, 1, 'la fantasma no sobrevive al arranque')
  assert.equal(perfiles[0].id, primera)
  assert.equal((await id.currentProfile()).id, primera, 'y se vuelve a la que estabas usando')
  id.destroy()
  fs.rmSync(dir, { recursive: true, force: true })
})

test('la única cuenta no se barre aunque quedara marcada', async () => {
  const dir = tmp()
  let id = await Identity.connect({ dir })
  const sola = (await id.currentProfile()).id
  id.destroy()

  // Sin `alive` a la que volver, quedarse sin ninguna es peor que quedarse con una vacía.
  const kv = readKv(dir)
  const list = JSON.parse(kv['dotrino.identity.profiles'])
  kv['dotrino.identity.profiles'] = JSON.stringify(list.map((p) => ({ ...p, pendingJoin: true })))
  writeKv(dir, kv)

  id = await Identity.connect({ dir })
  const perfiles = await id.listProfiles()
  assert.equal(perfiles.length, 1)
  assert.equal(perfiles[0].id, sola)
  id.destroy()
  fs.rmSync(dir, { recursive: true, force: true })
})
