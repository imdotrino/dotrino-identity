/**
 * LA CADENA DE SELLADORAS SIGUE LAS ANCLAS (2026-10-27).
 *
 * A la historia del PC de Seyacat le faltaba la #54 (el acta donde entró la bóveda alojada):
 * la #68 apuntaba a ella, la cadena juntaba [#1, #68, #71] y caía con `link-1:not-chained`,
 * así que la bóveda alojada nueva no podía comprobar de qué cuenta era la invitación.
 */
import test from 'node:test'
import assert from 'node:assert/strict'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import { Identity, makeDeviceKey } from '../src/node.js'
import { verifySealerChain } from '../vault/acta.js'

test('falta un eslabón en la historia: la cadena llega hasta donde encadena, y verifica', async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'chain-gap-'))
  const id = await Identity.connect({ dir })
  // Entra una segunda selladora (eslabón), y después sale (otro eslabón, anclado al anterior).
  const nube = await makeDeviceKey({ label: 'Nube' })
  await id.admitMember({ pub: nube.publickey, label: 'Nube', caps: ['sealer', 'sign'] })
  const entra = (await id.profileActa()).acta.seq
  for (const label of ['A', 'B']) await id.admitMember({ pub: (await makeDeviceKey({ label })).publickey, label, caps: ['read'] })
  await id.removeMember(nube.publickey)
  await id.admitMember({ pub: (await makeDeviceKey({ label: 'C' })).publickey, label: 'C', caps: ['read'] })
  assert.equal((await verifySealerChain(await id.sealerChain())).ok, true, 'con la historia entera, verifica')
  id.destroy()
  await new Promise((resolve) => setTimeout(resolve, 300))

  // Se le quita a la historia el eslabón donde ENTRÓ la Nube, como le pasó al PC.
  const archivo = path.join(dir, 'identity.json')
  const kv = JSON.parse(fs.readFileSync(archivo, 'utf8'))
  const k = Object.keys(kv).find((x) => x.endsWith('.acta.history'))
  kv[k] = JSON.stringify(JSON.parse(kv[k]).filter((a) => a.seq !== entra))
  fs.writeFileSync(archivo, JSON.stringify(kv))

  const de = await Identity.connect({ dir })
  const chain = await de.sealerChain()
  assert.ok(!chain.some((a) => a.seq === entra), 'el eslabón que falta no está')
  assert.ok(!chain.some((a) => a.seq === 1), 'ni lo de antes, que ya no encadena')
  const v = await verifySealerChain(chain)
  assert.equal(v.ok, true, `verifica: ${v.reason}`)
  assert.equal(v.seq, (await de.profileActa()).acta.seq, 'hasta la cabeza')
  de.destroy()
})
