/**
 * El canal de sesión de los agentes remotos: las dos puntas acuerdan la MISMA llave y lo
 * que cifra una lo abre la otra. Si esto cambia, la terminal y las apps nativas dejan de
 * entenderse con los agentes ya instalados.
 */
import test from 'node:test'
import assert from 'node:assert/strict'
import { makeEphemeral, deriveKey, seal, open } from '../vault/channel.js'

test('las dos puntas derivan la misma llave y se entienden', async () => {
  const a = await makeEphemeral(); const b = await makeEphemeral()
  const ka = await deriveKey(a.privateKey, b.pub, 'sesion-1')
  const kb = await deriveKey(b.privateKey, a.pub, 'sesion-1')
  assert.deepEqual(await open(kb, await seal(ka, { op: 'hola', n: 1, t: 'ñ' })), { op: 'hola', n: 1, t: 'ñ' })
})

test('otra sesión (otro salt) no abre el sobre', async () => {
  const a = await makeEphemeral(); const b = await makeEphemeral()
  const ka = await deriveKey(a.privateKey, b.pub, 'sesion-1')
  const kb = await deriveKey(b.privateKey, a.pub, 'sesion-2')
  await assert.rejects(open(kb, await seal(ka, { x: 1 })))
})
