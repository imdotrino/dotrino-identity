/**
 * El aviso de revocación es la ÚNICA puerta al autoborrado del dispositivo, así que
 * lo que se comprueba antes de abrirla importa más que casi nada del paquete.
 *
 * El fallo que motiva estas pruebas: un certificado se retira también cuando NO pasa
 * nada malo (renovar retira el anterior, y cambiar permisos obliga a renovar). Con
 * solo mirar «¿va firmado y es para mí?», el aviso de «tu papel viejo ya no vale»
 * borraba el enlace con la bóveda entero: le dabas «administra» a un aparato y el
 * aparato desaparecía solo, como si lo hubieran echado.
 */
import test from 'node:test'
import assert from 'node:assert/strict'
import { isAuthenticRevoke } from '../vault/remote.js'
import { makeDeviceKey, signWithDevice } from '../vault/capabilities.js'

const master = await makeDeviceKey({ label: 'maestra' })
const masterPub = master.publickey
const DEVICE = (await makeDeviceKey({ label: 'aparato' })).publickey

async function aviso ({ sub = DEVICE, nonce = 'n-actual', exp = Date.now() + 60000 } = {}) {
  const body = { op: 'revoke', sub, nonce, iat: Date.now(), exp }
  const { signature } = await signWithDevice({ privateJwk: master.privateJwk, publickey: masterPub, data: body })
  return { body, signature }
}

test('el aviso del certificado que el aparato tiene AHORA sí borra', async () => {
  const { body, signature } = await aviso({ nonce: 'n-actual' })
  assert.equal(await isAuthenticRevoke({ body, signature, master: masterPub, devicePubkey: DEVICE, currentNonce: 'n-actual' }), true)
})

test('el aviso de un certificado VIEJO no borra nada (renovar retira el anterior)', async () => {
  const { body, signature } = await aviso({ nonce: 'n-vieja' })
  assert.equal(await isAuthenticRevoke({ body, signature, master: masterPub, devicePubkey: DEVICE, currentNonce: 'n-actual' }), false)
})

test('sin firma de la maestra no borra, aunque nombre el certificado bueno', async () => {
  const otraPub = (await makeDeviceKey({ label: 'impostora' })).publickey
  const { body, signature } = await aviso({ nonce: 'n-actual' })
  assert.equal(await isAuthenticRevoke({ body, signature, master: otraPub, devicePubkey: DEVICE, currentNonce: 'n-actual' }), false)
})

test('un aviso para OTRO dispositivo no borra', async () => {
  const { body, signature } = await aviso({ sub: 'otro' })
  assert.equal(await isAuthenticRevoke({ body, signature, master: masterPub, devicePubkey: DEVICE, currentNonce: 'n-actual' }), false)
})

test('un aviso caducado no borra', async () => {
  const { body, signature } = await aviso({ exp: Date.now() - 1 })
  assert.equal(await isAuthenticRevoke({ body, signature, master: masterPub, devicePubkey: DEVICE, currentNonce: 'n-actual' }), false)
})
