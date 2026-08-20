/**
 * La LLAVE DE SELLADO del acta (§8.9 de `dotrino-vault/docs/secretos-sellados.md`): con
 * ella la bóveda firma los sobres de los secretos, y rota con el acta.
 *
 * Lo que se prueba aquí es lo que hace que un sobre viejo siga verificando después de
 * rotar: el acta guarda el TRAMO de `seq` en el que mandó cada llave.
 */
import test from 'node:test'
import assert from 'node:assert/strict'
import { genesisActa, sealActa, verifyActa, applyChanges, sealKeyAt, checkShape, ACTA_V } from '../vault/acta.js'

async function key () {
  const pair = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify'])
  return {
    pub: JSON.stringify(await crypto.subtle.exportKey('jwk', pair.publicKey)),
    privateJwk: await crypto.subtle.exportKey('jwk', pair.privateKey)
  }
}
const step = async (acta, changes, who, opts = {}) =>
  sealActa({ acta: await applyChanges(acta, changes, { by: who.pub, ...opts }), privateJwk: who.privateJwk })

test('un perfil nace SIN llave de sellado: no todo perfil sella secretos', async () => {
  const a = await key()
  const acta = await sealActa({ acta: genesisActa({ pub: a.pub }), privateJwk: a.privateJwk })
  assert.equal(acta.v, ACTA_V)
  assert.equal(acta.sealPub, null)
  assert.deepEqual(acta.sealKeys, [])
  assert.equal(sealKeyAt(acta, 1), null)
  assert.equal((await verifyActa({ acta })).ok, true)
})

test('rotar: la llave nueva manda desde su acta, y la vieja sigue verificando su tramo', async () => {
  const a = await key(); const b = await key()
  const s1 = await key(); const s2 = await key()

  let acta = await sealActa({ acta: genesisActa({ pub: a.pub, sealPub: s1.pub }), privateJwk: a.privateJwk })
  assert.equal(acta.sealPub, s1.pub)
  assert.equal(acta.sealSince, 1)

  // Un acta más SIN llave nueva: la de antes sigue mandando y el registro no crece.
  acta = await step(acta, [{ op: 'label', pub: a.pub, label: 'PC' }], a)
  assert.equal(acta.seq, 2)
  assert.equal(acta.sealPub, s1.pub)
  assert.deepEqual(acta.sealKeys, [], 'sin rotación no hay nada que guardar')

  // Y ahora sí, entra un aparato y con él una llave de sellado nueva.
  acta = await step(acta, [{ op: 'admit', member: { pub: b.pub, label: 'Teléfono' } }], a, { sealPub: s2.pub })
  assert.equal(acta.seq, 3)
  assert.equal(acta.sealPub, s2.pub)
  assert.equal(acta.sealSince, 3)
  assert.deepEqual(acta.sealKeys, [{ pub: s1.pub, from: 1, to: 2 }])

  // Lo que importa: con qué llave se comprueba un sobre según el acta que lo selló.
  assert.equal(sealKeyAt(acta, 1), s1.pub, 'un sobre de cuando mandaba la primera')
  assert.equal(sealKeyAt(acta, 2), s1.pub)
  assert.equal(sealKeyAt(acta, 3), s2.pub, 'y uno de ahora')
  assert.equal(sealKeyAt(acta, 4), null, 'un sobre del futuro no puede ser bueno')
  assert.equal((await verifyActa({ acta })).ok, true)
})

test('un acta v1 se lee y ASCIENDE a v2 al sellar la siguiente', async () => {
  const a = await key(); const s = await key()
  const v1 = await sealActa({ acta: genesisActa({ pub: a.pub }), privateJwk: a.privateJwk })
  // Un acta tal como quedó escrita ANTES de que existiera la llave de sellado.
  delete v1.sealPub; delete v1.sealSince; delete v1.sealKeys
  v1.v = 1
  const revieja = await sealActa({ acta: v1, privateJwk: a.privateJwk })

  assert.equal(checkShape(revieja), null, 'una v1 se sigue leyendo: dentro están tus aparatos')
  assert.equal((await verifyActa({ acta: revieja })).ok, true)

  const next = await step(revieja, [{ op: 'label', pub: a.pub, label: 'PC' }], a, { sealPub: s.pub })
  assert.equal(next.v, 2)
  assert.equal(next.sealPub, s.pub)
  assert.equal(next.sealSince, 2)
  assert.deepEqual(next.sealKeys, [], 'no había llave anterior que guardar')
})

test('forma: una llave de sellado sin decir desde cuándo NO es un acta válida', async () => {
  const a = await key(); const s = await key()
  const acta = genesisActa({ pub: a.pub, sealPub: s.pub })
  assert.equal(checkShape({ ...acta, sealSince: 0 }), 'sealsince')
  assert.equal(checkShape({ ...acta, sealSince: 9 }), 'sealsince', 'ni desde un acta que no ha pasado')
  assert.equal(checkShape({ ...acta, sealKeys: [{ pub: s.pub, from: 3, to: 1 }] }), 'sealkey-rango')
})
