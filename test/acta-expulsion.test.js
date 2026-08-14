/**
 * SI EL ACTA NUEVA YA NO ME NOMBRA, ME BORRO. Sin botón y sin preguntar.
 *
 * El aviso firmado de expulsión (`vault.revoked`) es un mensaje suelto: si el aparato estaba
 * apagado se queda en la cola del proxy, que dura 24 h, y después no llega nunca. Hasta
 * ahora ESE era el único camino, así que un aparato al que echaron podía quedarse enseñando
 * la cuenta para siempre — incluso después de recibir de la propia bóveda un acta nueva que
 * ya no lo nombraba, porque nadie miraba si seguía dentro.
 *
 * El acta sirve para enterarse, y sirve igual de bien: va FIRMADA por el master, así que un
 * tercero no puede fabricar una para destruir datos ajenos (el wipe-DoS que cierra la regla
 * de «solo un aviso firmado borra»). Lo que no vale es un error suelto, y eso no cambia.
 */
import test from 'node:test'
import assert from 'node:assert/strict'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import { Identity } from '../src/node.js'

const tmp = () => fs.mkdtempSync(path.join(os.tmpdir(), 'expulsion-'))

/**
 * Una bóveda: otra identidad con su cuenta, que admite a `invitado` y luego —si se le
 * pide— lo echa. Devuelve las dos actas: la de cuando estaba dentro y la de después.
 */
async function bovedaQueEcha (invitado) {
  const dir = tmp()
  const vault = await Identity.connect({ dir })
  await vault.admitMember({ pub: invitado, label: 'Portátil', caps: ['sign', 'store', 'read'] })
  const dentro = (await vault.profileActa()).acta
  await vault.removeMember(invitado)
  const fuera = (await vault.profileActa()).acta
  vault.destroy()
  fs.rmSync(dir, { recursive: true, force: true })
  return { dentro, fuera }
}

test('un acta nueva en la que ya no estoy BORRA la cuenta de este aparato', async () => {
  const dir = tmp()
  const id = await Identity.connect({ dir })
  await id.createProfile('Bóveda de casa', { forVault: true })
  const { dentro, fuera } = await bovedaQueEcha(id.me.publickey)

  assert.equal((await id.joinProfile(dentro)).joined, true, 'primero entra, como siempre')
  assert.equal((await id.myMembership()).profileId, dentro.profileId)

  // Y ahora llega la siguiente versión del acta, sellada por la misma bóveda, sin él.
  const r = await id.adoptActa(fuera)
  assert.equal(r.adopted, true, 'el acta se adopta: es la buena, va firmada y encadena')
  assert.equal(r.expelled, true, 'y se ve que ya no lo nombra')

  // La cuenta se fue del aparato: no queda acta de ese perfil que enseñar.
  const ahora = await id.myMembership().catch(() => null)
  assert.notEqual(ahora?.profileId, fuera.profileId, 'deja de estar en la cuenta de la que lo echaron')
  id.destroy()
  fs.rmSync(dir, { recursive: true, force: true })
})

test('un acta nueva en la que SÍ estoy no borra nada (lo normal: cambió otra cosa)', async () => {
  const dir = tmp()
  const id = await Identity.connect({ dir })
  await id.createProfile('Bóveda de casa', { forVault: true })

  const vdir = tmp()
  const vault = await Identity.connect({ dir: vdir })
  await vault.admitMember({ pub: id.me.publickey, label: 'Portátil', caps: ['sign', 'store', 'read'] })
  const primera = (await vault.profileActa()).acta
  assert.equal((await id.joinProfile(primera)).joined, true)

  // La bóveda admite a OTRO aparato: el acta avanza y este sigue dentro.
  const tercero = await Identity.connect({ dir: tmp() })
  await vault.admitMember({ pub: tercero.me.publickey, label: 'Teléfono', caps: ['read'] })
  const segunda = (await vault.profileActa()).acta

  const r = await id.adoptActa(segunda)
  assert.equal(r.adopted, true)
  assert.notEqual(r.expelled, true, 'no lo echaron: no se borra nada')
  assert.equal((await id.myMembership()).profileId, segunda.profileId, 'sigue en su cuenta')

  id.destroy(); vault.destroy(); tercero.destroy()
  fs.rmSync(dir, { recursive: true, force: true }); fs.rmSync(vdir, { recursive: true, force: true })
})
