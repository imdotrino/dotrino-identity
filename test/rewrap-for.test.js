/**
 * `rewrapFor`: completar a un aparato que entró tarde SIN la frase del perfil.
 *
 * Es la pieza que evita las dos malas salidas. Sin ella, un aparato nuevo solo se
 * completa (a) tecleando la frase del perfil en un navegador, o (b) guardando en la
 * bóveda un depósito de llaves privadas que cualquiera con el disco podría usar. Con
 * ella, lo hace quien YA podía leer ese cajón, con su propia llave y sin que nada
 * secreto salga de su dispositivo.
 */
import { test } from 'node:test'
import assert from 'node:assert/strict'
import * as Content from '../vault/content.js'
import { makeDeviceEncKey, importDeviceEncKey } from '../vault/capabilities.js'

const nuevoMiembro = async (pub) => {
  const { encPublickey, encPrivateJwk } = await makeDeviceEncKey()
  return { pub, encPub: encPublickey, priv: encPrivateJwk }
}

test('quien puede abrir un cajón puede envolvérselo a otro miembro', async () => {
  const admin = await nuevoMiembro('admin')
  const tarde = await nuevoMiembro('el-que-llego-tarde')

  // Un cajón escrito cuando el segundo aún no existía: la generación solo lo envuelve
  // para el primero. Es exactamente lo que pasa al enrolar un servicio nuevo.
  const { generation, cek } = await Content.makeGeneration({ members: [admin] })
  const sobre = await Content.encryptWithCek({ cek, gen: 1, plaintext: 'el token de R2' })

  assert.equal(generation.wraps[tarde.pub], undefined, 'el que llegó tarde no tiene envoltura')

  // El que administra abre con SU llave y re-envuelve para el otro. La CEK nunca sale
  // en claro de aquí, y la bóveda no ha abierto nada.
  const miPriv = await importDeviceEncKey(admin.priv)
  const cekAbierta = await Content.openWrap({ wrap: generation.wraps[admin.pub], myEncPrivateKey: miPriv })
  const nueva = await Content.wrapForMember({ cek: cekAbierta, memberEncPub: tarde.encPub })

  // Y con esa envoltura, el recién llegado ya lee lo que se escribió antes de existir.
  const suPriv = await importDeviceEncKey(tarde.priv)
  const suCek = await Content.openWrap({ wrap: nueva, myEncPrivateKey: suPriv })
  assert.equal(await Content.decryptWithCek({ cek: suCek, envelope: sobre }), 'el token de R2')
})

test('sin envoltura propia no se puede re-envolver: no hay atajo', async () => {
  const admin = await nuevoMiembro('admin')
  const ajeno = await nuevoMiembro('ajeno')
  const { generation } = await Content.makeGeneration({ members: [admin] })

  const suPriv = await importDeviceEncKey(ajeno.priv)
  await assert.rejects(
    () => Content.openWrap({ wrap: generation.wraps[admin.pub], myEncPrivateKey: suPriv }),
    'quien no era destinatario no abre la llave, así que tampoco puede repartirla')
})
