/**
 * QUÉ PERFIL ESTÁ CONECTADO A UNA BÓVEDA, Y CUÁL APRUEBA — sin cambiar el activo.
 *
 * En un teléfono con varios perfiles, el timbre de la bóveda llega a la llave de UNO de
 * ellos, y puede no ser el que está abierto. La pantalla de Pedidos abría con el activo y,
 * si no era ese, decía «este aparato no aprueba pedidos»: falso, y encima manda a conceder
 * un permiso que ya estaba concedido en otro perfil.
 *
 * Para llevarte al correcto hay que poder mirar el certificado de CADA perfil sin abrirlo
 * —abrirlo obliga a recargar la página, que es justo lo que no se puede hacer para
 * averiguar algo—. El cert está en claro en el kv y dice qué puede este aparato, no cómo:
 * leerlo no es firmar ni descifrar nada.
 *
 * El timbre NO dice a qué perfil llamó, y así se queda: viaja por FCM, o sea por Google.
 * La elección se resuelve en el aparato, con lo que ya hay.
 */
import test from 'node:test'
import assert from 'node:assert/strict'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import { Identity } from '../src/node.js'
import { VAULT_CERT_STORAGE } from '../vault/core.js'

const tmp = () => fs.mkdtempSync(path.join(os.tmpdir(), 'perfiles-'))

/** El cert que la bóveda le dio a este aparato, tal como queda guardado. */
const certDe = (scope) => JSON.stringify({
  cert: { v: 1, iss: 'MAESTRA', sub: 'APARATO', scope, iat: Date.now(), seq: 1, nonce: 'n1' },
  master: 'MAESTRA', proxy: 'wss://proxy.dotrino.com', deviceId: 'AB12-CD34', pairedAt: Date.now()
})

test('listProfiles dice cuál está conectado y cuál aprueba, sin tocar el activo', async () => {
  const dir = tmp()
  const archivo = path.join(dir, 'identity.json')

  // Tres perfiles: el primero es el que nace con la identidad.
  let id = await Identity.connect({ dir })
  const p1 = (await id.currentProfile()).id
  const p2 = (await id.createProfile('Trabajo')).id
  const p3 = (await id.createProfile('Suelto')).id
  id.destroy()

  // Los papeles que la bóveda le dio a este aparato EN CADA PERFIL, tal como quedan
  // guardados. Se escriben a mano porque emparejar de verdad pide una bóveda encendida y
  // lo que se prueba aquí es la lectura, no el emparejamiento.
  const kv = JSON.parse(fs.readFileSync(archivo, 'utf8'))
  const scoped = (pid, k) => k.replace(/^dotrino\.identity\./, `dotrino.identity.p.${pid}.`)
  kv[scoped(p1, VAULT_CERT_STORAGE)] = certDe(['vault:approve', 'vault:sign'])  // aprueba
  kv[scoped(p2, VAULT_CERT_STORAGE)] = certDe(['vault:sign'])                   // emparejado, no aprueba
  //  p3: ni emparejado.
  fs.writeFileSync(archivo, JSON.stringify(kv))

  id = await Identity.connect({ dir })
  const lista = await id.listProfiles()
  const por = (n) => lista.find((p) => p.name === n)

  assert.equal(lista.length, 3)
  assert.equal(por('Trabajo').vault, true, 'está emparejado')
  assert.equal(por('Trabajo').approve, false, 'pero su papel no aprueba')
  assert.equal(por('Suelto').vault, false, 'sin bóveda no hay nada que aprobar')
  assert.equal(por('Suelto').approve, false)
  assert.equal(por('Suelto').current, true, 'el último creado quedó activo')

  // El que aprueba se ve DESDE OTRO perfil: es lo que permite llevarte a él.
  const aprueban = lista.filter((p) => p.approve)
  assert.equal(aprueban.length, 1, 'exactamente uno aprueba')
  assert.equal(aprueban[0].id, p1)
  assert.equal(aprueban[0].current, false, 'y no es el que está abierto — por eso hay que saltar')

  // Y mirar no cambió nada: el activo sigue siendo el mismo.
  assert.equal((await id.currentProfile()).id, p3)
  id.destroy()
  fs.rmSync(dir, { recursive: true, force: true })
})
