/**
 * BLOQUEAR a alguien (dueño, 2026-10-05): un indicador privado, aparte de la calificación.
 * Se guarda en el libro de contactos, no se firma ni se publica, y desbloquear también es un
 * cambio que tiene que llegar a los demás aparatos.
 */
import test from 'node:test'
import assert from 'node:assert/strict'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import { Identity } from '../src/node.js'

const tmp = () => fs.mkdtempSync(path.join(os.tmpdir(), 'dotrino-blocked-'))
const PEER = '{"crv":"P-256","kty":"EC","x":"x","y":"y"}'

test('bloquear y desbloquear se guarda en la ficha, sin calificar a nadie', async () => {
  const dir = tmp()
  const id = await Identity.connect({ dir })
  await id.addContact({ publickey: PEER, nickname: 'Ana' })

  const b = await id.setBlocked(PEER, true)
  assert.equal(b.blocked, true)
  assert.ok(b.changedAt > 0, 'con fecha, para que gane en los demás aparatos')
  assert.equal(b.myRating, undefined, 'bloquear no es calificar: no se firma nada')
  assert.equal((await id.getPeer(PEER)).isContact, true, 'y sigue siendo contacto')

  const u = await id.setBlocked(PEER, false)
  assert.equal(u.blocked, false, 'desbloquear deja false, no borra el campo')

  id.destroy(); fs.rmSync(dir, { recursive: true, force: true })
})
