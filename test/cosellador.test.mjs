/**
 * MULTIVAULT: dos bóvedas que pueden sellar la misma acta (dueño, 2026-08-30).
 *
 * Por qué se hace, con sus palabras: *«me resuelve el problema de un desastre que pierda
 * permanentemente un vault»*. Y por qué se puede hacer: *«usualmente no se abren los dos
 * al mismo tiempo»*.
 *
 * Lo que se paga a cambio, dicho sin adornos: con un solo sellador (D4), dos actas
 * legítimas al mismo `seq` eran **criptográficamente imposibles**. Con dos, dejan de
 * serlo: pasan a ser raras. Así que el empate deja de ser un caso que no puede ocurrir y
 * pasa a ser un caso que hay que resolver bien — y lo que lo resuelve ya estaba escrito
 * en `canAdopt`: gana el traspaso, y si no, la de hash menor. Determinista y sin relojes.
 *
 * Estas pruebas fijan las dos mitades: que un cosellador puede, y que quien NO está
 * nombrado sigue sin poder.
 */
import test from 'node:test'
import assert from 'node:assert/strict'
import {
  genesisActa, applyChanges, sealActa, verifyActa, canAdopt, canSeal, sealersOf,
  checkShape, actaHash, isHandover
} from '../vault/acta.js'
import { makeDeviceKey, signWithDevice } from '../vault/capabilities.js'

/** `sealActa` firma con la llave de `acta.sealedBy`, que `applyChanges` deja puesta. */
const sellar = (acta, k) => sealActa({ acta, privateJwk: k.privateJwk })

/** Una cuenta con su bóveda principal (A) y otra bóveda (B) ya dentro como miembro. */
async function cuentaConDosBovedas () {
  const A = await makeDeviceKey()
  const B = await makeDeviceKey()
  let acta = genesisActa({ pub: A.publickey, label: 'bóveda A' })
  acta = await sellar(acta, A)

  // B entra como miembro Y queda nombrada cosellador, en el MISMO seq: un sellador que
  // no es miembro no existe (checkShape), así que las dos cosas van juntas.
  acta = await applyChanges(acta, [
    { op: 'admit', member: { pub: B.publickey, label: 'bóveda B', caps: ['sign', 'read', 'store'] } },
    { op: 'cosealer', pub: B.publickey }
  ], { by: A.publickey })
  acta = await sellar(acta, A)
  return { A, B, acta }
}

test('un cosellador queda nombrado, y el acta sigue siendo válida', async () => {
  const { A, B, acta } = await cuentaConDosBovedas()
  assert.equal(checkShape(acta), null)
  assert.ok((await verifyActa({ acta })).ok)
  assert.deepEqual(sealersOf(acta).sort(), [A.publickey, B.publickey].sort())
  assert.ok(canSeal(acta, B.publickey))
  assert.equal(acta.sealer, A.publickey, 'nombrar un cosellador NO es un traspaso')
  assert.equal(isHandover(acta), false)
})

test('la bóveda B ya puede sellar: es lo que resuelve perder la A', async () => {
  const { A, B, acta } = await cuentaConDosBovedas()
  const nuevo = await makeDeviceKey()

  // A está perdida. B admite un aparato ella sola.
  let siguiente = await applyChanges(acta, { op: 'admit', member: { pub: nuevo.publickey, label: 'teléfono', caps: ['sign'] } }, { by: B.publickey })
  siguiente = await sellar(siguiente, B)

  assert.ok((await verifyActa({ acta: siguiente })).ok)
  assert.equal(siguiente.sealedBy, B.publickey)
  const r = await canAdopt({ candidate: siguiente, current: acta })
  assert.equal(r.adopt, true, 'los demás miembros lo adoptan: el acta lo autorizaba')
  assert.notEqual(A.publickey, siguiente.sealedBy)
})

test('quien NO está nombrado sigue sin poder sellar', async () => {
  const { A, acta } = await cuentaConDosBovedas()
  const intruso = await makeDeviceKey()

  await assert.rejects(
    () => applyChanges(acta, { op: 'admit', member: { pub: intruso.publickey, label: 'x', caps: ['sign'] } }, { by: intruso.publickey }),
    /not the master, nor a co-sealer/
  )
  assert.equal(canSeal(acta, intruso.publickey), false)
  assert.ok(canSeal(acta, A.publickey))
})

/**
 * EL CASO QUE ANTES ERA IMPOSIBLE. Las dos bóvedas sellan `seq` N con contenido distinto
 * —solo pasa si están las dos abiertas y sin verse—, y hay que resolverlo igual en todos
 * los aparatos, sin relojes y sin preguntarle a nadie.
 */
test('empate a igual seq: gana la de hash menor, y gana lo MISMO en los dos lados', async () => {
  const { A, B, acta } = await cuentaConDosBovedas()
  const unoA = await makeDeviceKey()
  const unoB = await makeDeviceKey()

  let ramaA = await applyChanges(acta, { op: 'admit', member: { pub: unoA.publickey, label: 'de A', caps: ['sign'] } }, { by: A.publickey })
  ramaA = await sellar(ramaA, A)
  let ramaB = await applyChanges(acta, { op: 'admit', member: { pub: unoB.publickey, label: 'de B', caps: ['sign'] } }, { by: B.publickey })
  ramaB = await sellar(ramaB, B)

  assert.equal(ramaA.seq, ramaB.seq, 'mismo seq: esto es el empate')

  const [hA, hB] = [await actaHash(ramaA), await actaHash(ramaB)]
  const ganadora = hA < hB ? ramaA : ramaB

  // Un aparato que tenía la de A y recibe la de B, y otro al revés: los dos acaban igual.
  const vieneB = await canAdopt({ candidate: ramaB, current: ramaA })
  const vieneA = await canAdopt({ candidate: ramaA, current: ramaB })
  assert.notEqual(vieneB.adopt, vieneA.adopt, 'exactamente una de las dos gana')
  assert.equal(vieneB.adopt, ganadora === ramaB)
  assert.equal(vieneA.adopt, ganadora === ramaA)

  // Y lo que hay que decir en voz alta (§2.4.1 punto 5): el cambio del que pierde SE
  // PIERDE. El aparato que admitió la rama muerta no está en la ganadora.
  const perdedor = ganadora === ramaA ? unoB : unoA
  assert.ok(!ganadora.members.some((m) => m.pub === perdedor.publickey),
    'el aparato admitido en la rama que pierde no queda en la cuenta: hay que avisarlo')
})

test('quitar a la bóveda B la quita también de selladores, no deja un fantasma', async () => {
  const { A, B, acta } = await cuentaConDosBovedas()
  let sinB = await applyChanges(acta, { op: 'remove', pub: B.publickey }, { by: A.publickey })
  sinB = await sellar(sinB, A)

  assert.equal(checkShape(sinB), null, 'un sellador que ya no es miembro dejaría el acta inválida')
  assert.equal(canSeal(sinB, B.publickey), false)
  assert.deepEqual(sealersOf(sinB), [A.publickey])
})

test('un cosellador que no es miembro no se puede nombrar', async () => {
  const { A, acta } = await cuentaConDosBovedas()
  const fuera = await makeDeviceKey()
  await assert.rejects(
    () => applyChanges(acta, { op: 'cosealer', pub: fuera.publickey }, { by: A.publickey }),
    /must be a member/
  )
})
