/**
 * El acta a través de la identidad real (adaptador Node, con su kv en disco): que nazca
 * sola, que persista, que solo el master pueda cambiarla y que el traspaso funcione.
 */
import test from 'node:test'
import assert from 'node:assert/strict'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import { Identity, makeDeviceKey } from '../src/node.js'

const tmp = () => fs.mkdtempSync(path.join(os.tmpdir(), 'acta-'))

test('el acta nace sola con el perfil: un miembro, master, todas las capacidades', async () => {
  const dir = tmp()
  const id = await Identity.connect({ dir })
  const mine = await id.myMembership()

  assert.equal(mine.inProfile, true)
  assert.equal(mine.isMaster, true)
  assert.deepEqual(mine.caps.sort(), ['read', 'sign', 'store'])
  assert.equal(mine.profileId, id.me.publickey, 'el perfil se llama como esta llave')
  assert.equal(mine.seq, 1)
  assert.match(mine.id, /^[0-9A-F]{4}-[0-9A-F]{4}$/)

  const { members, sealer } = await id.profileMembers()
  assert.equal(members.length, 1)
  assert.equal(members[0].isMe, true)
  assert.equal(sealer, id.me.publickey)
  fs.rmSync(dir, { recursive: true, force: true })
})

test('persiste entre arranques', async () => {
  const dir = tmp()
  const a = await Identity.connect({ dir })
  const dev = await makeDeviceKey({ label: 'Celular' })
  await a.admitMember({ pub: dev.publickey, label: 'Celular', caps: ['store', 'read'] })
  a.destroy()

  const b = await Identity.connect({ dir })
  const { members, seq } = await b.profileMembers()
  assert.equal(seq, 2, 'el seq avanzó y se guardó')
  assert.equal(members.length, 2)
  assert.deepEqual(members.find((m) => !m.isMe).caps, ['read', 'store'])
  fs.rmSync(dir, { recursive: true, force: true })
})

test('traspaso del master: quien lo cede deja de poder cambiar el acta', async () => {
  const dir = tmp()
  const id = await Identity.connect({ dir })
  const vault = await makeDeviceKey({ label: 'Bóveda' })

  // Admitir y nombrar master, en el mismo seq.
  const r = await id.handoverMaster(vault.publickey, { label: 'Bóveda', caps: ['sign', 'store', 'read'] })
  assert.equal(r.sealer, vault.publickey)

  assert.equal(await id.isMaster(), false)
  const mine = await id.myMembership()
  assert.equal(mine.isMaster, false)
  assert.equal(mine.inProfile, true, 'sigue siendo miembro, solo que ya no manda')

  const tercero = await makeDeviceKey({ label: 'Otro' })
  await assert.rejects(() => id.admitMember({ pub: tercero.publickey }), /no lo es/)
  fs.rmSync(dir, { recursive: true, force: true })
})

test('renuncia: el dispositivo se quita `sign` y el acta lo refleja', async () => {
  const dir = tmp()
  const id = await Identity.connect({ dir })
  const otro = await makeDeviceKey({ label: 'Bóveda' })
  await id.admitMember({ pub: otro.publickey, label: 'Bóveda', caps: ['sign', 'store', 'read'] })

  const res = await id.renounceCaps(['sign'])
  assert.deepEqual(res.caps.sort(), ['read', 'store'], 'ya no firma')
  assert.equal(res.record.member, id.me.publickey)

  const mine = await id.myMembership()
  assert.deepEqual(mine.caps.sort(), ['read', 'store'])
  fs.rmSync(dir, { recursive: true, force: true })
})

test('no se puede renunciar a `sign` si eres el único que firma', async () => {
  const dir = tmp()
  const id = await Identity.connect({ dir })
  // Como master, absorber la renuncia dejaría el perfil sin firmante → se rechaza…
  const res = await id.renounceCaps(['sign'])
  // …pero el registro suelto sí existe (es unilateral) y NO entra en el acta.
  assert.equal(res.record.member, id.me.publickey)
  const { members } = await id.profileMembers()
  assert.equal(members[0].caps.includes('sign'), false, 'la renuncia local se honra igual')
  const acta = (await id.profileActa()).acta
  assert.equal(acta.members[0].caps.includes('sign'), true, 'el acta sigue teniendo un firmante')
  fs.rmSync(dir, { recursive: true, force: true })
})

test('cada perfil tiene su propia acta', async () => {
  const dir = tmp()
  const id = await Identity.connect({ dir })
  const p1 = await id.myMembership()

  await id.createProfile('Trabajo')
  const p2 = await id.myMembership()

  assert.notEqual(p2.profileId, p1.profileId, 'perfil nuevo = acta nueva')
  assert.equal(p2.isMaster, true)
  assert.equal(p2.seq, 1)
  fs.rmSync(dir, { recursive: true, force: true })
})
