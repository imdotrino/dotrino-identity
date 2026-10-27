/**
 * Al abrir, la clave de contenido llega a TODOS los miembros (`completeKeyring`).
 *
 * La segunda bóveda de una cuenta entró sin envoltura (2026-10-27) y nada se la daba
 * después: no podía cifrar ni la lista de variables que le pide la consola.
 */
import test from 'node:test'
import assert from 'node:assert/strict'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import { Identity, makeDeviceKey } from '../src/node.js'

const tmp = () => fs.mkdtempSync(path.join(os.tmpdir(), 'complete-keyring-'))

async function encPubOf () {
  const enc = await crypto.subtle.generateKey({ name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveBits'])
  const jwk = await crypto.subtle.exportKey('jwk', enc.publicKey)
  return JSON.stringify({ kty: jwk.kty, crv: jwk.crv, x: jwk.x, y: jwk.y })
}

test('un miembro con llave de cifrado y sin envoltura la recibe al abrir, en una sola acta', async () => {
  const dir = tmp()
  const id = await Identity.connect({ dir })
  const otra = await makeDeviceKey({ label: 'Nube' })
  // Entra sin llave de cifrado (no se le puede envolver) y la nombra después.
  const r = await id.admitMember({ pub: otra.publickey, label: 'Nube', caps: ['sealer', 'sign'] })
  assert.equal(r.wrapped, false)
  await id.setMemberEncPub({ pub: otra.publickey, encPub: await encPubOf() })
  const antes = (await id.profileActa()).acta
  assert.ok(!antes.keyring.at(-1).wraps[otra.publickey], 'todavía sin envoltura')

  const out = await id.completeKeyring()
  assert.deepEqual(out.wrapped, [otra.publickey])
  assert.equal(out.named, false)
  const despues = (await id.profileActa()).acta
  assert.equal(despues.seq, antes.seq + 1, 'una sola acta')
  assert.ok(despues.keyring.at(-1).wraps[otra.publickey], 'ya tiene su envoltura')
  assert.equal(despues.keyring.length, antes.keyring.length, 'no rota: envuelve la vigente')

  const otraVez = await id.completeKeyring()
  assert.equal(otraVez.seq, despues.seq, 'sin nada que hacer no sella otra acta')
  fs.rmSync(dir, { recursive: true, force: true })
})

test('si el acta tiene otra llave de cifrado para mí, nombra la mía', async () => {
  const dir = tmp()
  const id = await Identity.connect({ dir })
  const yo = id.me.publickey
  const mia = (await id.profileActa()).acta.members.find((m) => m.pub === yo).encPub
  await id.setMemberEncPub({ pub: yo, encPub: await encPubOf() })

  const out = await id.completeKeyring()
  assert.equal(out.named, true)
  const acta = (await id.profileActa()).acta
  assert.equal(acta.members.find((m) => m.pub === yo).encPub, mia)
  fs.rmSync(dir, { recursive: true, force: true })
})

test('un miembro sin llave de cifrado se queda sin envoltura: no hay a qué envolver', async () => {
  const dir = tmp()
  const id = await Identity.connect({ dir })
  const d = await makeDeviceKey({ label: 'Viejo' })
  await id.admitMember({ pub: d.publickey, label: 'Viejo', caps: ['read'] })
  const seq = (await id.profileActa()).acta.seq
  const out = await id.completeKeyring()
  assert.deepEqual(out.wrapped, [])
  assert.equal(out.seq, seq)
  fs.rmSync(dir, { recursive: true, force: true })
})
