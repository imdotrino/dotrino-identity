/**
 * DISPOSITIVO O SERVICIO, Y SE PASA DE UNO A OTRO SIN RE-ENROLAR (dueño, 2026-10-28).
 *
 * La única diferencia es el `cn`: con él, el miembro abre ese cajón, firma solo dentro de él y
 * no recibe la clave de contenido; sin él, es un aparato tuyo. Un túnel emparejado como
 * servicio no podía firmar como aparato, y la única salida era revocarlo y volver a emparejarlo.
 */
import test from 'node:test'
import assert from 'node:assert/strict'
import { genesisActa, applyChanges, sealActa, memberCanSign, memberCanReadSecrets, VAULT_CN } from '../vault/acta.js'
import { makeDeviceKey } from '../vault/capabilities.js'

const sellar = (acta, k) => sealActa({ acta, privateJwk: k.privateJwk })

async function cuenta () {
  const A = await makeDeviceKey()
  const T = await makeDeviceKey()
  let acta = await sellar(genesisActa({ pub: A.publickey, label: 'bóveda' }), A)
  acta = await applyChanges(acta, [
    { op: 'admit', member: { pub: T.publickey, label: 'túnel', cn: 'fexa', caps: ['sign'] } },
    { op: 'keyring', generation: { gen: 1, wraps: { [A.publickey]: 'wa', [T.publickey]: 'wt' } } }
  ], { by: A.publickey })
  return { A, T, acta: await sellar(acta, A) }
}

test('de servicio a dispositivo: firma como tú y deja de abrir el cajón, con la misma llave', async () => {
  const { A, T, acta } = await cuenta()
  assert.equal(memberCanSign(acta, T.publickey), false, 'como servicio no firma por la persona')
  assert.equal(memberCanSign(acta, T.publickey, 'fexa'), true)
  const next = await applyChanges(acta, [{ op: 'cn', pub: T.publickey, cn: null }], { by: A.publickey })
  assert.equal(next.members.find((m) => m.pub === T.publickey).cn, null)
  assert.equal(memberCanSign(next, T.publickey), true)
  assert.equal(memberCanReadSecrets(next, T.publickey, 'fexa'), false)
})

test('de dispositivo a servicio: se le quitan las envolturas de la clave de contenido', async () => {
  const { A, T, acta } = await cuenta()
  let next = await applyChanges(acta, [{ op: 'cn', pub: T.publickey, cn: null }], { by: A.publickey })
  next = await applyChanges(await sellar(next, A), [{ op: 'cn', pub: T.publickey, cn: 'tunnel' }], { by: A.publickey })
  assert.equal(next.keyring[0].wraps[T.publickey], undefined, 'un servicio no ve lo tuyo')
  assert.equal(next.keyring[0].wraps[A.publickey], 'wa', 'las demás envolturas no se tocan')
  assert.equal(memberCanReadSecrets(next, T.publickey, 'tunnel'), true)
  assert.equal(memberCanSign(next, T.publickey), false)
})

test('la llave de comunicación de la bóveda no se convierte, y el cajón «vault» no existe', async () => {
  const { A, T, acta } = await cuenta()
  const C = await makeDeviceKey()
  const conComm = await sellar(await applyChanges(acta, [
    { op: 'admit', member: { pub: C.publickey, label: 'esta bóveda', cn: VAULT_CN, caps: ['sign'], vault: A.publickey } }
  ], { by: A.publickey }), A)
  await assert.rejects(applyChanges(conComm, [{ op: 'cn', pub: C.publickey, cn: null }], { by: A.publickey }), /communication key/)
  await assert.rejects(applyChanges(acta, [{ op: 'cn', pub: T.publickey, cn: VAULT_CN }], { by: A.publickey }), /invalid CN/)
  await assert.rejects(applyChanges(acta, [{ op: 'cn', pub: T.publickey, cn: 'Mal Nombre' }], { by: A.publickey }), /invalid CN/)
})
