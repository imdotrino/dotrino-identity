/**
 * Unirse a la cuenta de una bóveda NO puede llevarse por delante la cuenta que ya estabas
 * usando (camino B de `dotrino-vault/docs/vinculacion-de-cuentas.md` §5.1).
 *
 * Hasta 2026-07-27 bastaba con ser el único miembro del acta propia para que `joinProfile`
 * la sobrescribiera sin preguntar: una cuenta con su contenido pasaba a colgar de otra en
 * silencio — justo la fusión de cuentas que el modelo prohíbe. Ahora unirse exige que el
 * perfil haya NACIDO para eso (`createProfile(nombre, { forVault: true })`), y sin esa
 * marca no se escribe nada.
 */
import test from 'node:test'
import assert from 'node:assert/strict'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import { Identity } from '../src/node.js'

const tmp = () => fs.mkdtempSync(path.join(os.tmpdir(), 'join-'))

/** Una bóveda cualquiera: otra identidad, en su propio directorio, con su propia cuenta. */
async function otraCuenta (invitado) {
  const dir = tmp()
  const vault = await Identity.connect({ dir })
  if (invitado) await vault.admitMember({ pub: invitado, label: 'Invitado', caps: ['store', 'read'] })
  const { acta } = await vault.profileActa()
  vault.destroy()
  fs.rmSync(dir, { recursive: true, force: true })
  return acta
}

test('sin la marca no se une: la cuenta abierta queda INTACTA', async () => {
  const dir = tmp()
  const id = await Identity.connect({ dir })
  const mia = (await id.profileActa()).acta
  const acta = await otraCuenta(id.me.publickey)

  const r = await id.joinProfile(acta)

  assert.equal(r.joined, false)
  assert.equal(r.reason, 'perfil-con-datos', 'dice por qué, para que la consola ofrezca crear una cuenta nueva')
  assert.equal(r.profileId, mia.profileId)

  const despues = (await id.profileActa()).acta
  assert.deepEqual(despues, mia, 'cero escrituras: el acta guardada es la misma de antes')
  assert.equal((await id.myMembership()).profileId, mia.profileId, 'sigue siendo su propia cuenta')
  id.destroy()
  fs.rmSync(dir, { recursive: true, force: true })
})

test('con la marca sí se une, y la marca se consume', async () => {
  const dir = tmp()
  const id = await Identity.connect({ dir })
  const primera = (await id.myMembership()).profileId

  // Camino B: se crea una cuenta MÁS, nacida para adoptar la de la bóveda.
  const nueva = await id.createProfile('Bóveda de casa', { forVault: true })
  assert.equal(nueva.pendingJoin, true)

  const acta = await otraCuenta(id.me.publickey)
  const r = await id.joinProfile(acta)

  assert.equal(r.joined, true)
  assert.equal(r.profileId, acta.profileId)
  assert.equal((await id.myMembership()).profileId, acta.profileId)

  // La marca es de un solo uso: ya adoptó, ya no es adoptable.
  const otra = await otraCuenta(id.me.publickey)
  assert.equal((await id.joinProfile(otra)).reason, 'perfil-con-datos')

  // Y la PRIMERA cuenta sigue ahí, con lo suyo.
  const perfiles = await id.listProfiles()
  assert.equal(perfiles.length, 2, 'quedan las dos cuentas')
  assert.equal(perfiles.find((p) => p.current).pendingJoin, false, 'la marca se consumió')
  await id.switchProfile(perfiles.find((p) => !p.current).id)
  id.destroy()

  const otra2 = await Identity.connect({ dir })
  assert.equal((await otra2.myMembership()).profileId, primera, 'la cuenta que ya usabas, intacta')
  otra2.destroy()
  fs.rmSync(dir, { recursive: true, force: true })
})

test('no me uno a una cuenta en la que no soy miembro', async () => {
  const dir = tmp()
  const id = await Identity.connect({ dir })
  await id.createProfile('Para la bóveda', { forVault: true })

  const ajena = await otraCuenta(null) // no me admitió
  const r = await id.joinProfile(ajena)

  assert.equal(r.joined, false)
  assert.equal(r.reason, 'no-soy-miembro')
  id.destroy()
  fs.rmSync(dir, { recursive: true, force: true })
})

test('la misma cuenta no es «unirse» sino ponerse al día', async () => {
  const dir = tmp()
  const id = await Identity.connect({ dir })
  const mia = (await id.profileActa()).acta

  // Mi propia acta, tal cual: no hay nada que adoptar y NO puede contar como conflicto.
  const r = await id.joinProfile(mia)
  assert.equal(r.joined, false)
  assert.equal(r.reason, 'misma-acta', 'va por las reglas de adopción, no por las de unirse')
  assert.equal((await id.myMembership()).profileId, mia.profileId)
  id.destroy()
  fs.rmSync(dir, { recursive: true, force: true })
})
