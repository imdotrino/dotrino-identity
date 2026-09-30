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

test('solo el sobre de la CUENTA lleva la marca; encryptWithCek es genérica', async () => {
  const { isCekEnvelope, CEK_ENVELOPE, sealAccount } = await import('../vault/content.js')
  const a = await miembro('pc')
  const { cek } = await makeGeneration({ members: [a] })
  const cuenta = await sealAccount({ cek, gen: 1, plaintext: 'hola' })
  assert.equal(cuenta.t, CEK_ENVELOPE)
  assert.equal(cuenta.gen, 1)
  assert.ok(isCekEnvelope(cuenta))
  const generico = await encryptWithCek({ cek, gen: 0, plaintext: 'hola' })
  assert.equal(generico.t, undefined, 'un cajón o una contraseña no se hacen pasar por la cuenta')
  await assert.rejects(sealAccount({ cek, gen: 0, plaintext: 'x' }), /starts at 1/)
})

/** Una cuenta con dos generaciones: la bóveda en las dos, el aparato nuevo solo en la 2. */
async function rotada () {
  const { sealAccount } = await import('../vault/content.js')
  const boveda = await miembro('boveda'); const viejo = await miembro('viejo'); const nuevo = await miembro('nuevo')
  const g1 = await makeGeneration({ members: [boveda, viejo], gen: 1 })
  const g2 = await makeGeneration({ members: [boveda, nuevo], gen: 2 })
  const keyring = [g1.generation, g2.generation]
  const reseal = async (env) => sealAccount({
    cek: g2.cek, gen: 2,
    plaintext: await decryptWithKeyring({ envelope: env, keyring, myPub: boveda.pub, myEncPrivateKey: boveda.priv })
  })
  const abre = (m, env) => decryptWithKeyring({ envelope: env, keyring, myPub: m.pub, myEncPrivateKey: m.priv }).catch(() => null)
  return { g1, g2, keyring, reseal, abre, nuevo }
}

test('resealStale: lo marcado viejo pasa a la vigente y un aparato nuevo lo abre', async () => {
  const { resealStale, sealAccount } = await import('../vault/content.js')
  const { g1, reseal, abre, nuevo } = await rotada()
  const sobre = await sealAccount({ cek: g1.cek, gen: 1, plaintext: 'la firma' })
  const dato = { id: 'signature:x', info: { cn: 'yo' }, envelope: sobre, lista: [sobre] }
  assert.equal(await abre(nuevo, sobre), null, 'el aparato nuevo no abre la generación 1')

  const { value, changed, skipped } = await resealStale(dato, { gen: 2, reseal })
  assert.equal(changed, 2); assert.equal(skipped, 0)
  assert.equal(dato.envelope.gen, 1, 'no toca el original')
  assert.deepEqual(value.info, { cn: 'yo' }, 'lo que no es sobre queda igual')
  for (const env of [value.envelope, value.lista[0]]) {
    assert.equal(env.gen, 2)
    assert.equal(await abre(nuevo, env), 'la firma')
  }
  assert.equal((await resealStale(value, { gen: 2, reseal })).changed, 0, 'lo vigente no se toca')
})

test('MIGRACIÓN: un sobre de la cuenta SIN marca (antes de 0.107) se vuelve a cerrar y queda marcado', async () => {
  const { resealStale, isCekEnvelope } = await import('../vault/content.js')
  const { g1, g2, reseal, abre, nuevo } = await rotada()
  // Tal como salían antes: { gen, iv, ct } a secas. Uno de la generación vieja y otro de la
  // vigente: los dos necesitan la marca.
  const viejo = await encryptWithCek({ cek: g1.cek, gen: 1, plaintext: 'p12' })
  const vigente = await encryptWithCek({ cek: g2.cek, gen: 2, plaintext: 'otro' })
  const { value, changed, skipped } = await resealStale({ a: viejo, b: vigente }, { gen: 2, reseal })
  assert.equal(changed, 2); assert.equal(skipped, 0)
  assert.ok(isCekEnvelope(value.a) && isCekEnvelope(value.b))
  assert.equal(await abre(nuevo, value.a), 'p12')
  assert.equal(await abre(nuevo, value.b), 'otro')
})

test('MIGRACIÓN: un sobre sin marca que NO es de la cuenta se deja como está y no bloquea nada', async () => {
  const { resealStale, sealAccount } = await import('../vault/content.js')
  const { g1, reseal, abre, nuevo } = await rotada()
  const ajena = (await makeGeneration({ members: [await miembro('otro')], gen: 1 })).cek
  const deOtraLlave = await encryptWithCek({ cek: ajena, gen: 3, plaintext: 'no es tuyo' })
  const cajon = await encryptWithCek({ cek: ajena, gen: 0, plaintext: 'cajón' })
  const cuenta = await sealAccount({ cek: g1.cek, gen: 1, plaintext: 'sí es tuyo' })
  const { value, changed, skipped } = await resealStale({ deOtraLlave, cajon, cuenta }, { gen: 2, reseal })
  assert.equal(changed, 1, 'solo el de la cuenta')
  assert.equal(skipped, 1, 'el de otra llave se prueba, no abre y se cuenta')
  assert.deepEqual(value.deOtraLlave, deOtraLlave, 'intacto')
  assert.deepEqual(value.cajon, cajon, 'gen 0 no es de la cuenta: ni se prueba')
  assert.equal(await abre(nuevo, value.cuenta), 'sí es tuyo')
})

test('MIGRACIÓN: pasada la fecha, un sobre sin marca ya no se toca', async () => {
  const { resealStale, LEGACY_UNMARKED_UNTIL } = await import('../vault/content.js')
  const { g1, reseal } = await rotada()
  const viejo = await encryptWithCek({ cek: g1.cek, gen: 1, plaintext: 'x' })
  const r = await resealStale({ viejo }, { gen: 2, reseal, now: LEGACY_UNMARKED_UNTIL + 1 })
  assert.equal(r.changed, 0)
  assert.deepEqual(r.value.viejo, viejo)
})

test('resealStale para si un sobre MARCADO no se puede volver a cerrar', async () => {
  const { resealStale, sealAccount } = await import('../vault/content.js')
  const a = await miembro('pc')
  const g1 = await makeGeneration({ members: [a], gen: 1 })
  const sobre = await sealAccount({ cek: g1.cek, gen: 1, plaintext: 'x' })
  await assert.rejects(resealStale({ sobre }, { gen: 2, reseal: async () => { throw new Error('no abre') } }), /no abre/)
})
