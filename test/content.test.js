/**
 * La llave de contenido del perfil: que todos los miembros lean lo mismo, que expulsar
 * corte el acceso al contenido futuro, y que el viejo se siga pudiendo leer.
 */
import test from 'node:test'
import assert from 'node:assert/strict'
import {
  makeContentKey, makeGeneration, myContentKey, openWrap,
  encryptWithCek, decryptWithKeyring
} from '../vault/content.js'

/** Un miembro con su llave de cifrado (ECDH), como la que tiene cada perfil. */
async function miembro (label) {
  const pair = await crypto.subtle.generateKey({ name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveBits'])
  const jwk = await crypto.subtle.exportKey('jwk', pair.publicKey)
  return {
    pub: 'pub-' + label,
    encPub: JSON.stringify({ kty: jwk.kty, crv: jwk.crv, x: jwk.x, y: jwk.y }),
    priv: pair.privateKey,
    label
  }
}

test('todos los miembros abren la misma llave de contenido', async () => {
  const a = await miembro('pc'); const b = await miembro('celular')
  const { generation, cek } = await makeGeneration({ members: [a, b] })

  for (const m of [a, b]) {
    const mio = await myContentKey({ keyring: [generation], myPub: m.pub, myEncPrivateKey: m.priv })
    assert.equal(mio.cek, cek, `${m.label} abre la llave del perfil`)
    assert.equal(mio.gen, 1)
  }
})

test('quien no es miembro no puede abrir ninguna envoltura', async () => {
  const a = await miembro('pc'); const ajeno = await miembro('ajeno')
  const { generation } = await makeGeneration({ members: [a] })

  const nada = await myContentKey({ keyring: [generation], myPub: ajeno.pub, myEncPrivateKey: ajeno.priv })
  assert.equal(nada, null, 'no tiene envoltura')
  // Y aunque intente abrir la de otro, la cripto no se lo permite.
  await assert.rejects(() => openWrap({ wrap: generation.wraps[a.pub], myEncPrivateKey: ajeno.priv }))
})

test('expulsar y rotar: pierde el contenido nuevo, no el que ya había', async () => {
  const a = await miembro('pc'); const b = await miembro('celular'); const c = await miembro('perdido')

  // Generación 1: los tres.
  const g1 = (await makeGeneration({ members: [a, b, c], gen: 1 })).generation
  const k1 = await myContentKey({ keyring: [g1], myPub: c.pub, myEncPrivateKey: c.priv })
  const viejo = await encryptWithCek({ cek: k1.cek, gen: 1, plaintext: 'nota de antes' })

  // Se expulsa a `c` y se rota: generación 2 solo para a y b.
  const g2 = (await makeGeneration({ members: [a, b], gen: 2 })).generation
  const llavero = [g1, g2]

  const nuevoK = await myContentKey({ keyring: llavero, myPub: a.pub, myEncPrivateKey: a.priv })
  assert.equal(nuevoK.gen, 2, 'los que siguen usan la generación nueva')
  const nuevo = await encryptWithCek({ cek: nuevoK.cek, gen: 2, plaintext: 'nota de después' })

  // El expulsado NO puede leer lo nuevo…
  await assert.rejects(
    () => decryptWithKeyring({ envelope: nuevo, keyring: llavero, myPub: c.pub, myEncPrivateKey: c.priv }),
    /does not hold the key/
  )
  // …y los que quedan siguen leyendo lo viejo (por eso se conservan las generaciones).
  const leido = await decryptWithKeyring({ envelope: viejo, keyring: llavero, myPub: b.pub, myEncPrivateKey: b.priv })
  assert.equal(leido, 'nota de antes')
})

test('un miembro sin llave de cifrado se reporta en vez de fallar en silencio', async () => {
  const a = await miembro('pc')
  const { generation, sinLlave } = await makeGeneration({ members: [a, { pub: 'pub-viejo', encPub: null }] })
  assert.deepEqual(sinLlave, ['pub-viejo'])
  assert.ok(!generation.wraps['pub-viejo'], 'no se le envuelve nada')
  assert.ok(generation.wraps[a.pub])
})

test('el contenido cifrado no revela nada sin la llave', async () => {
  const a = await miembro('pc')
  const { generation, cek } = await makeGeneration({ members: [a] })
  const sobre = await encryptWithCek({ cek, gen: 1, plaintext: 'secreto' })
  assert.ok(!JSON.stringify(sobre).includes('secreto'))
  const leido = await decryptWithKeyring({ envelope: sobre, keyring: [generation], myPub: a.pub, myEncPrivateKey: a.priv })
  assert.equal(leido, 'secreto')
})

test('cada clave de contenido es distinta', async () => {
  const [k1, k2] = [await makeContentKey(), await makeContentKey()]
  assert.notEqual(k1, k2)
  assert.equal(Buffer.from(k1, 'base64').length, 32, 'AES-256')
})
