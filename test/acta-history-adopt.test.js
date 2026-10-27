/**
 * LO QUE SE ADOPTA TAMBIÉN DEJA HISTORIA (2026-10-27).
 *
 * El PC de Seyacat selló la #75 (entraba la Nube), adoptó la #76 y la #77 que selló ella, y se
 * quedó sin la #75 ni la #76: adoptar no pasaba al historial la que dejaba de ser vigente. Su
 * navegador, en la #74, recibía la #77 sola —sellada por alguien que la #74 no conoce— y la
 * rechazaba. Dos arreglos: adoptar guarda la anterior, y un hueco se rellena con actas que trae
 * otra bóveda, comprobadas por el hash que nombra cada una (`prev`).
 */
import test from 'node:test'
import assert from 'node:assert/strict'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import { Identity, makeDeviceKey } from '../src/node.js'
import { applyChanges, sealActa, canAdopt } from '../vault/acta.js'

const tmp = () => fs.mkdtempSync(path.join(os.tmpdir(), 'acta-hist-adopt-'))

// El PC admite a la Nube (#n) y ella sella dos más (#n+1, #n+2), como pasó.
async function escenario () {
  const dir = tmp()
  const pc = await Identity.connect({ dir })
  const tel = await makeDeviceKey({ label: 'Navegador' })
  await pc.admitMember({ pub: tel.publickey, label: 'Navegador', caps: ['read'] })
  const delNavegador = (await pc.profileActa()).acta
  const nube = await makeDeviceKey({ label: 'Nube' })
  await pc.admitMember({ pub: nube.publickey, label: 'Nube', caps: ['sealer', 'sign'] })
  const entra = (await pc.profileActa()).acta
  const a1 = await sealActa({ acta: await applyChanges(entra, [{ op: 'label', pub: tel.publickey, label: 'N1' }], { by: nube.publickey }), privateJwk: nube.privateJwk })
  const a2 = await sealActa({ acta: await applyChanges(a1, [{ op: 'label', pub: tel.publickey, label: 'N2' }], { by: nube.publickey }), privateJwk: nube.privateJwk })
  return { dir, pc, delNavegador, entra, a1, a2 }
}

test('adoptar lo que sella la hermana deja la anterior en el historial: el navegador atrasado llega', async () => {
  const { dir, pc, delNavegador, entra, a1, a2 } = await escenario()
  assert.equal((await pc.adoptActa(a1)).adopted, true)
  assert.equal((await pc.adoptActa(a2)).adopted, true)
  const { chain } = await pc.actaHistory({ sinceSeq: delNavegador.seq })
  assert.deepEqual(chain.map((a) => a.seq), [entra.seq, a1.seq, a2.seq], 'van los eslabones que el navegador no tiene')
  // Y con ellos el navegador llega, eslabón a eslabón.
  let cur = delNavegador
  for (const a of chain) { assert.equal((await canAdopt({ candidate: a, current: cur })).adopt, true, `#${a.seq}`); cur = a }
  pc.destroy()
  fs.rmSync(dir, { recursive: true, force: true })
})

test('un hueco del historial se rellena con las actas de otra bóveda, comprobadas por hash', async () => {
  const { dir, pc, delNavegador, entra, a1, a2 } = await escenario()
  await pc.adoptActa(a1)
  await pc.adoptActa(a2)
  pc.destroy()
  await new Promise((resolve) => setTimeout(resolve, 300))
  // Se le quitan al historial los eslabones, como le quedó al PC.
  const archivo = path.join(dir, 'identity.json')
  const kv = JSON.parse(fs.readFileSync(archivo, 'utf8'))
  const k = Object.keys(kv).find((x) => x.endsWith('.acta.history'))
  kv[k] = JSON.stringify(JSON.parse(kv[k]).filter((a) => a.seq !== entra.seq && a.seq !== a1.seq))
  fs.writeFileSync(archivo, JSON.stringify(kv))

  const de = await Identity.connect({ dir })
  assert.deepEqual((await de.actaHistory({ sinceSeq: delNavegador.seq })).chain.map((a) => a.seq), [a2.seq], 'roto: solo la vigente')

  // Una acta que no encadena no entra, aunque tenga el seq que falta.
  const falsa = { ...a1, members: a1.members.slice(0, -1) }
  assert.equal((await de.fillActaHistory([falsa])).added, 0, 'la que no es la que nombra la siguiente, fuera')

  // Las de verdad, sí: bajando desde la vigente.
  assert.equal((await de.fillActaHistory([entra, a1, a2])).added, 2)
  assert.deepEqual((await de.actaHistory({ sinceSeq: delNavegador.seq })).chain.map((a) => a.seq), [entra.seq, a1.seq, a2.seq])
  assert.equal((await de.profileActa()).acta.seq, a2.seq, 'la vigente no cambia')
  // Lo que se le manda a otra bóveda para que rellene: las últimas, con la vigente al final.
  const { actas } = await de.recentActas(3)
  assert.deepEqual(actas.map((a) => a.seq), [entra.seq, a1.seq, a2.seq])
  de.destroy()
  fs.rmSync(dir, { recursive: true, force: true })
})

test('la bóveda que contesta no guarda mi acta: se sube por la cadena de selladoras, sin las de en medio', async () => {
  const dir = tmp()
  const pc = await Identity.connect({ dir })
  const tel = await makeDeviceKey({ label: 'Navegador' })
  await pc.admitMember({ pub: tel.publickey, label: 'Navegador', caps: ['read'] })
  await new Promise((resolve) => setTimeout(resolve, 300))
  // El aparato se queda con el acta de este momento (la #74 de hoy).
  const dirAparato = tmp()
  fs.cpSync(dir, dirAparato, { recursive: true })

  const de = pc
  const nube = await makeDeviceKey({ label: 'Nube' })
  await de.admitMember({ pub: nube.publickey, label: 'Nube', caps: ['sealer', 'sign'] })
  const entra = (await de.profileActa()).acta
  const a1 = await sealActa({ acta: await applyChanges(entra, [{ op: 'label', pub: tel.publickey, label: 'N1' }], { by: nube.publickey }), privateJwk: nube.privateJwk })
  const a2 = await sealActa({ acta: await applyChanges(a1, [{ op: 'label', pub: tel.publickey, label: 'N2' }], { by: nube.publickey }), privateJwk: nube.privateJwk })
  de.destroy()

  const aparato = await Identity.connect({ dir: dirAparato })
  const suya = (await aparato.profileActa()).acta.seq
  // Lo que pasaba: la #77 sola no entra, y no había otro camino.
  assert.equal((await aparato.adoptActa(a2)).reason, 'unauthorized-sealer')
  // Lo que no viene de quien el aparato reconoce, fuera: una sellada por la Nube sin el eslabón
  // que la deja entrar, o una tocada después de sellar.
  assert.equal((await aparato.adoptActaBySealerChain([a2])).adopted, false, 'sin el eslabón que la autoriza no entra')
  const falsa = { ...a2, members: a2.members.slice(0, -1) }
  assert.equal((await aparato.adoptActaBySealerChain([entra, falsa])).adopted, false, 'ni colgada de un eslabón bueno')
  // La de verdad, como la manda la Nube: [la que la dejó entrar, la vigente].
  const r = await aparato.adoptActaBySealerChain([entra, a2])
  assert.equal(r.adopted, true, r.reason)
  assert.equal((await aparato.profileActa()).acta.seq, a2.seq)
  assert.ok(a2.seq > suya + 1, 'saltó las de en medio')
  aparato.destroy()
  fs.rmSync(dir, { recursive: true, force: true })
  fs.rmSync(dirAparato, { recursive: true, force: true })
})
