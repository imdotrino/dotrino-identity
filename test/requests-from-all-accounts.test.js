/**
 * LOS PEDIDOS DE TODAS TUS CUENTAS, SIN CAMBIARTE DE CUENTA.
 *
 * El timbre de la bóveda llega a la llave de UNA cuenta, y el aviso no dice a cuál: viaja
 * por FCM —o sea por Google— y ahí no se mete nada que identifique al dueño. Así que la
 * pantalla de Pedidos tiene que mirar en todas las cuentas que aprueban.
 *
 * La primera versión lo hacía cambiando la cuenta activa y recargando la página una vez por
 * cuenta. Funcionaba, y era insufrible: el avatar y el icono de la app cambiaban dos o tres
 * veces por abrir la pantalla (dueño, 2026-09-10: «rotan los perfiles, cambia el icono y es
 * molesto»). Y era innecesario, porque este iframe tiene las llaves de todas las cuentas.
 *
 * Lo que se prueba aquí es exactamente eso: a quién se le pregunta, y que preguntar NO
 * mueva la cuenta activa — que es el bug que esta función viene a matar.
 *
 * No hace falta una bóveda encendida: los certs se escriben a mano (emparejar de verdad
 * pide una bóveda) y el `proxy` apunta a un puerto muerto, así que cada respuesta vuelve con
 * su `error`. Lo que importa es el reparto, no lo que contesta la bóveda.
 */
import test from 'node:test'
import assert from 'node:assert/strict'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import { Identity } from '../src/node.js'
import { VAULT_CERT_STORAGE } from '../vault/core.js'

const tmp = () => fs.mkdtempSync(path.join(os.tmpdir(), 'pedidos-'))
/** Un puerto muerto: conectar falla en el acto y la prueba no toca la red de verdad. */
const PROXY_MUERTO = 'ws://127.0.0.1:1'

const certDe = (scope) => ({
  cert: { v: 1, iss: 'MAESTRA', sub: 'APARATO', scope, iat: Date.now(), seq: 1, nonce: 'n1' },
  master: 'MAESTRA', proxy: PROXY_MUERTO, deviceId: 'AB12-CD34', pairedAt: Date.now()
})

/** Escribe el papel de la bóveda en el cajón de un perfil concreto, sin abrirlo. */
function ponCert (archivo, pid, scope) {
  const d = JSON.parse(fs.readFileSync(archivo, 'utf8'))
  d[VAULT_CERT_STORAGE.replace(/^dotrino\.identity\./, `dotrino.identity.p.${pid}.`)] = JSON.stringify(certDe(scope))
  fs.writeFileSync(archivo, JSON.stringify(d))
}

test('pregunta a TODAS las cuentas que aprueban y no cambia la activa', async () => {
  const dir = tmp()
  const archivo = path.join(dir, 'identity.json')

  let id = await Identity.connect({ dir })
  const p1 = (await id.currentProfile()).id
  const p2 = (await id.createProfile('Trabajo')).id
  const p3 = (await id.createProfile('Solo lee')).id
  const p4 = (await id.createProfile('Sin bóveda')).id
  // `createProfile` deja activo el último: se vuelve al primero, que es donde se abre la app.
  await id.switchProfile(p1)
  id.destroy()

  ponCert(archivo, p1, ['vault:sign', 'vault:approve'])
  ponCert(archivo, p2, ['vault:sign', 'vault:approve'])
  ponCert(archivo, p3, ['vault:sign'])              // emparejada, pero NO aprueba
  // p4 no tiene cert: no está emparejada con ninguna bóveda

  id = await Identity.connect({ dir })
  const antes = (await id.currentProfile()).id
  const todo = await id.vaultApprovalsAll()
  const despues = (await id.currentProfile()).id
  id.destroy()

  const ids = todo.map((e) => e.profile).sort()
  assert.deepEqual(ids, [p1, p2].sort(), 'solo las que aprueban: ni la de solo lectura ni la sin bóveda')

  // LO QUE DE VERDAD IMPORTA: preguntar no te mueve de cuenta.
  assert.equal(despues, antes, 'preguntar por los pedidos NO puede cambiar la cuenta activa')
  assert.equal(despues, p1)

  // Cada entrada se identifica, y la activa se sabe cuál es (la pantalla la marca).
  const mia = todo.find((e) => e.profile === p1)
  assert.equal(mia.current, true)
  assert.equal(todo.find((e) => e.profile === p2).current, false)
  assert.equal(todo.find((e) => e.profile === p2).name, 'Trabajo', 'el nombre viaja: es como se reconocen')

  // Sin bóveda al otro lado, cada una vuelve con su motivo y con la lista vacía — pero
  // vuelve: un fallo de una cuenta no puede llevarse por delante a las demás.
  for (const e of todo) {
    assert.deepEqual(e.items, [])
    assert.ok(e.error, 'si no se pudo preguntar, se dice')
  }
})

test('aprobar un pedido de OTRA cuenta se niega si esa cuenta no aprueba', async () => {
  const dir = tmp()
  const archivo = path.join(dir, 'identity.json')

  let id = await Identity.connect({ dir })
  const p1 = (await id.currentProfile()).id
  const p2 = (await id.createProfile('Solo lee')).id
  await id.switchProfile(p1)
  id.destroy()

  ponCert(archivo, p1, ['vault:sign', 'vault:approve'])
  ponCert(archivo, p2, ['vault:sign'])

  id = await Identity.connect({ dir })
  await assert.rejects(
    () => id.vaultApprovals('approve', { id: 'x1', profile: p2 }),
    (e) => /does not approve/.test(e.message),
    'el permiso lo dice el cert de ESA cuenta, no la pantalla que pulsa el botón'
  )
  // Y una cuenta que no existe en este aparato tampoco cuela.
  await assert.rejects(
    () => id.vaultApprovals('approve', { id: 'x1', profile: 'pNoExiste' }),
    (e) => /does not exist/.test(e.message)
  )
  assert.equal((await id.currentProfile()).id, p1, 'ni siquiera al fallar se mueve la activa')
  id.destroy()
})
