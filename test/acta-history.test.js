/**
 * La CADENA de actas solo viaja cuando resuelve algo.
 *
 * `canAdopt` adopta el acta actual de un salto siempre que la haya sellado quien el que
 * pregunta tiene por sellador, así que los eslabones intermedios sobran salvo que haya
 * habido un TRASPASO de master en el hueco. Mandarlos «por si acaso» costó caro: cada acta
 * es un snapshot completo de los miembros, la ventana llegó a 991 KB de una respuesta de
 * 1,03 MB, y el proxio —que corta el frame a 1 MB— dejó a la bóveda muda para todo el
 * ecosistema (2026-08-24).
 */
import test from 'node:test'
import assert from 'node:assert/strict'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import { Identity, makeDeviceKey } from '../src/node.js'
import { applyChanges, sealActa } from '../vault/acta.js'

const tmp = () => fs.mkdtempSync(path.join(os.tmpdir(), 'acta-hist-'))

test('sin acta previa (sinceSeq 0): cadena VACÍA — se adopta la actual por «sin-acta-previa»', async () => {
  const dir = tmp()
  const id = await Identity.connect({ dir })
  for (const label of ['A', 'B', 'C']) {
    const d = await makeDeviceKey({ label })
    await id.admitMember({ pub: d.publickey, label, caps: ['read'] })
  }

  const { chain } = await id.actaHistory({ sinceSeq: 0 })
  assert.deepEqual(chain, [], 'quien no tiene acta no necesita eslabones para nada')
  fs.rmSync(dir, { recursive: true, force: true })
})

test('mismo sellador tras un hueco: cadena VACÍA (el salto lo da él solo)', async () => {
  const dir = tmp()
  const id = await Identity.connect({ dir })
  const suSeq = (await id.myMembership()).seq

  for (const label of ['A', 'B', 'C', 'D']) {
    const d = await makeDeviceKey({ label })
    await id.admitMember({ pub: d.publickey, label, caps: ['read'] })
  }
  assert.ok((await id.myMembership()).seq > suSeq + 1, 'hay hueco de verdad')

  const { chain } = await id.actaHistory({ sinceSeq: suSeq })
  assert.deepEqual(chain, [], 'el sellador no cambió: la cadena no aporta nada')
  fs.rmSync(dir, { recursive: true, force: true })
})

test('traspaso de master en el hueco: SÍ viaja la cadena, desde su seq hasta la actual', async () => {
  const dir = tmp()
  const id = await Identity.connect({ dir })
  const suSeq = (await id.myMembership()).seq

  const otro = await makeDeviceKey({ label: 'Otro' })
  await id.admitMember({ pub: otro.publickey, label: 'Otro', caps: ['read'] })
  const nuevo = await makeDeviceKey({ label: 'Bóveda' })
  await id.handoverMaster(nuevo.publickey, { label: 'Bóveda', caps: ['sign', 'store', 'read'] })

  // El acta del TRASPASO la sella el master saliente (regla 1), así que quien se quedó en
  // su `seq` la reconoce y llega hasta ella de un salto: todavía no hace falta cadena.
  assert.deepEqual((await id.actaHistory({ sinceSeq: suSeq })).chain, [],
    'hasta el traspaso inclusive, el sellador sigue siendo el que él conoce')

  // Es el acta SIGUIENTE —la primera que sella el master entrante— la que él ya no puede
  // reconocer: ahí empiezan a hacer falta los eslabones.
  const traspaso = (await id.profileActa()).acta
  const despues = await sealActa({
    acta: await applyChanges(traspaso, [{ op: 'caps', pub: otro.publickey, caps: ['read', 'store'] }], { by: nuevo.publickey }),
    privateJwk: nuevo.privateJwk
  })
  assert.equal((await id.adoptActa(despues)).adopted, true)

  const { chain } = await id.actaHistory({ sinceSeq: suSeq })
  assert.ok(chain.length > 0, 'la actual la selló alguien que él no conoce: necesita el puente')
  assert.equal(chain[0].seq, suSeq + 1, 'empieza donde él se quedó')
  assert.equal(chain[chain.length - 1].seq, despues.seq, 'y termina en la actual')
  assert.ok(chain.every((a) => a.seq > suSeq), 'ni un eslabón que él ya tenga')
  fs.rmSync(dir, { recursive: true, force: true })
})

test('ya está al día: cadena vacía', async () => {
  const dir = tmp()
  const id = await Identity.connect({ dir })
  const seq = (await id.myMembership()).seq
  const { chain } = await id.actaHistory({ sinceSeq: seq })
  assert.deepEqual(chain, [])
  fs.rmSync(dir, { recursive: true, force: true })
})
