// UNA LLAVE QUE NO VIVE EN ESTE PROCESO (la del chip del teléfono, en la app nativa).
//
// El pilar le pasa el texto canónico y recibe la firma P1363 en base64; la privada no entra
// nunca aquí. Lo que se prueba es que eso firma EXACTAMENTE lo mismo que la llave propia —
// una firma que no verificara en la bóveda se vería como «no me contesta».
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { signWithDevice, verifyDeviceSig } from '../vault/capabilities.js'
import { canonicalStringify } from '../vault/core.js'

const ECDSA = { name: 'ECDSA', namedCurve: 'P-256' }

/** Un «chip»: la privada no se puede exportar, y solo sabe firmar bytes. */
async function chip () {
  const pair = await crypto.subtle.generateKey(ECDSA, false, ['sign', 'verify'])
  const jwk = await crypto.subtle.exportKey('jwk', pair.publicKey)
  const publickey = JSON.stringify({ kty: jwk.kty, crv: jwk.crv, x: jwk.x, y: jwk.y })
  const vistos = []
  const sign = async (texto) => {
    vistos.push(texto)
    const sig = await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, pair.privateKey, new TextEncoder().encode(texto))
    return Buffer.from(sig).toString('base64')
  }
  return { publickey, sign, vistos }
}

test('con un firmador externo se firma lo canónico, y verifica igual que una llave propia', async () => {
  const c = await chip()
  const data = { z: 1, op: 'enroll', a: { y: 2, b: [3, { d: 4, c: 5 }] } }
  const { signature, publickey } = await signWithDevice({ publickey: c.publickey, sign: c.sign, data })
  assert.equal(publickey, c.publickey)
  assert.deepEqual(c.vistos, [canonicalStringify(data)], 'al chip le llega el texto canónico, nada más')
  assert.equal(await verifyDeviceSig({ publickey, data, signature }), true)
})

test('el firmador externo exige saber de quién es la llave', async () => {
  const c = await chip()
  await assert.rejects(signWithDevice({ sign: c.sign, data: { a: 1 } }), /publickey is required/)
})

test('un firmador externo que no devuelve firma se dice, con su code', async () => {
  const c = await chip()
  await assert.rejects(
    signWithDevice({ publickey: c.publickey, sign: async () => '', data: { a: 1 } }),
    (e) => e.code === 'no-signature'
  )
})
