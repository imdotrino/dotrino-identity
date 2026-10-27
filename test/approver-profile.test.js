/**
 * QUÉ PERFIL ESTÁ CONECTADO A UNA BÓVEDA, Y CUÁL APRUEBA — sin cambiar el activo.
 *
 * En un teléfono con varios perfiles, el timbre de la bóveda llega a la llave de UNO de
 * ellos, y puede no ser el que está abierto. La pantalla de Pedidos abría con el activo y,
 * si no era ese, decía «este aparato no aprueba pedidos»: falso, y encima manda a conceder
 * un permiso que ya estaba concedido en otro perfil.
 *
 * Para llevarte al correcto hay que poder mirar el certificado de CADA perfil sin abrirlo
 * —abrirlo obliga a recargar la página, que es justo lo que no se puede hacer para
 * averiguar algo—. El cert está en claro en el kv y dice qué puede este aparato, no cómo:
 * leerlo no es firmar ni descifrar nada.
 *
 * El timbre NO dice a qué perfil llamó, y así se queda: viaja por FCM, o sea por Google.
 * La elección se resuelve en el aparato, con lo que ya hay.
 */
import test from 'node:test'
import assert from 'node:assert/strict'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import { Identity } from '../src/node.js'
import { VAULT_CERT_STORAGE } from '../vault/core.js'

const tmp = () => fs.mkdtempSync(path.join(os.tmpdir(), 'perfiles-'))

/** La maestra de la bóveda del fixture: una llave pública de verdad (`listProfiles` saca su ID). */
const MAESTRA = JSON.stringify(await crypto.subtle.exportKey('jwk',
  (await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify'])).publicKey))

/** El cert que la bóveda le dio a este aparato, tal como queda guardado. */
const certDe = (scope) => JSON.stringify({
  cert: { v: 1, iss: MAESTRA, sub: 'APARATO', scope, iat: Date.now(), seq: 1, nonce: 'n1' },
  master: MAESTRA, proxy: 'wss://proxy.dotrino.com', deviceId: 'AB12-CD34', pairedAt: Date.now()
})

test('listProfiles dice cuál está conectado y cuál aprueba, sin tocar el activo', async () => {
  const dir = tmp()
  const archivo = path.join(dir, 'identity.json')

  // Tres perfiles: el primero es el que nace con la identidad.
  let id = await Identity.connect({ dir })
  const p1 = (await id.currentProfile()).id
  const p2 = (await id.createProfile('Trabajo')).id
  const p3 = (await id.createProfile('Suelto')).id
  id.destroy()

  // Los papeles que la bóveda le dio a este aparato EN CADA PERFIL, tal como quedan
  // guardados. Se escriben a mano porque emparejar de verdad pide una bóveda encendida y
  // lo que se prueba aquí es la lectura, no el emparejamiento.
  const kv = JSON.parse(fs.readFileSync(archivo, 'utf8'))
  const scoped = (pid, k) => k.replace(/^dotrino\.identity\./, `dotrino.identity.p.${pid}.`)
  kv[scoped(p1, VAULT_CERT_STORAGE)] = certDe(['vault:approve', 'vault:sign'])  // aprueba
  kv[scoped(p2, VAULT_CERT_STORAGE)] = certDe(['vault:sign'])                   // emparejado, no aprueba
  //  p3: ni emparejado.
  fs.writeFileSync(archivo, JSON.stringify(kv))

  id = await Identity.connect({ dir })
  const lista = await id.listProfiles()
  const por = (n) => lista.find((p) => p.name === n)

  assert.equal(lista.length, 3)
  assert.equal(por('Trabajo').vault, true, 'está emparejado')
  assert.equal(por('Trabajo').approve, false, 'pero su papel no aprueba')
  assert.equal(por('Suelto').vault, false, 'sin bóveda no hay nada que aprobar')
  assert.equal(por('Suelto').approve, false)
  assert.equal(por('Suelto').current, true, 'el último creado quedó activo')

  // El que aprueba se ve DESDE OTRO perfil: es lo que permite llevarte a él.
  const aprueban = lista.filter((p) => p.approve)
  assert.equal(aprueban.length, 1, 'exactamente uno aprueba')
  assert.equal(aprueban[0].id, p1)
  assert.equal(aprueban[0].current, false, 'y no es el que está abierto — por eso hay que saltar')

  // Y mirar no cambió nada: el activo sigue siendo el mismo.
  assert.equal((await id.currentProfile()).id, p3)
  id.destroy()
  fs.rmSync(dir, { recursive: true, force: true })
})

// LAS BÓVEDAS DE CADA PERFIL (vault.dotrino.com/vault empieza eligiendo una, aunque sea de
// otro perfil: dueño, 2026-10-26). Salen del acta de cada uno, también sin tocar el activo.
test('listProfiles dice qué bóvedas tiene cada perfil, sin tocar el activo', async () => {
  const dir = tmp()
  const archivo = path.join(dir, 'identity.json')
  let id = await Identity.connect({ dir })
  const p1 = (await id.currentProfile()).id
  const p2 = (await id.createProfile('Trabajo')).id
  // Va en el perfil que NO está activo: en el activo, un acta que no lo nombra es una
  // expulsión y el arranque la borra (que es lo correcto).
  const activo = (await id.currentProfile()).id
  const otro = activo === p1 ? p2 : p1
  id.destroy()
  await new Promise((resolve) => setTimeout(resolve, 300)) // que acabe de escribir lo suyo

  const llave = async () => JSON.stringify(await crypto.subtle.exportKey('jwk',
    (await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify'])).publicKey))
  const [pc, commPc, nube, commNube, tel] = await Promise.all([llave(), llave(), llave(), llave(), llave()])
  const kv = JSON.parse(fs.readFileSync(archivo, 'utf8'))
  const suya = JSON.parse(kv['dotrino.identity.profiles']).find((p) => p.id === otro).pubkey
  const acta = {
    v: 5, seq: 3, profileId: pc, sealedBy: pc,
    members: [
      { pub: pc, label: 'PC', caps: ['sealer'] },
      { pub: commPc, cn: 'vault', vault: pc, caps: ['sign'] },
      { pub: nube, label: 'nube', caps: ['sealer'] },
      { pub: commNube, cn: 'vault', vault: nube, caps: ['sign'] },
      { pub: tel, label: 'teléfono', caps: ['sign'] },
      { pub: suya, label: 'este navegador', caps: ['sign'] }
    ]
  }
  kv[`dotrino.identity.p.${otro}.acta`] = JSON.stringify(acta)
  fs.writeFileSync(archivo, JSON.stringify(kv))

  id = await Identity.connect({ dir })
  const lista = await id.listProfiles()
  const trabajo = lista.find((p) => p.id === otro)
  assert.deepEqual(trabajo.vaults.map((v) => [v.comm, v.master, v.label]), [[commPc, pc, 'PC'], [commNube, nube, 'nube']])
  assert.match(trabajo.vaults[0].id, /^[0-9A-F]{4}-[0-9A-F]{4}/)
  assert.ok(Array.isArray(lista.find((p) => p.id === activo).vaults), 'el activo también lo trae')
  assert.equal((await id.currentProfile()).id, activo, 'y el activo no cambió')
  id.destroy()
})

test('listProfiles: la bóveda del CERTIFICADO sale aunque la copia del acta sea vieja', async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'vaults-cert-'))
  const archivo = path.join(dir, 'identity.json')
  let id = await Identity.connect({ dir })
  const p1 = (await id.currentProfile()).id
  const p2 = (await id.createProfile('Cepi')).id
  const activo = (await id.currentProfile()).id
  const otro = activo === p1 ? p2 : p1
  id.destroy()
  await new Promise((resolve) => setTimeout(resolve, 300))

  const llave = async () => JSON.stringify(await crypto.subtle.exportKey('jwk',
    (await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify'])).publicKey))
  const [boveda, comm] = await Promise.all([llave(), llave()])
  // Copia de antes de que la llave de comunicación llevara `vault`.
  const kv = JSON.parse(fs.readFileSync(archivo, 'utf8'))
  const suya = JSON.parse(kv['dotrino.identity.profiles']).find((p) => p.id === otro).pubkey
  const acta = { v: 5, seq: 2, profileId: boveda, sealedBy: boveda, members: [{ pub: boveda, label: 'Servidor', caps: ['sealer'] }, { pub: comm, cn: 'vault', caps: ['sign'] }, { pub: suya, caps: ['sign'] }] }
  kv[`dotrino.identity.p.${otro}.acta`] = JSON.stringify(acta)
  kv[`dotrino.identity.p.${otro}.vault.cert`] = JSON.stringify({ master: boveda, cert: { sub: suya, scope: ['vault:sign'] } })
  fs.writeFileSync(archivo, JSON.stringify(kv))

  id = await Identity.connect({ dir })
  const cepi = (await id.listProfiles()).find((p) => p.id === otro)
  assert.deepEqual(cepi.vaults.map((v) => [v.comm, v.master, v.label]), [[null, boveda, 'Servidor']])
  id.destroy()
})

test('listProfiles: un acta o un papel que no son de la cuenta del perfil no ponen bóvedas en él', async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'vaults-cruzadas-'))
  const archivo = path.join(dir, 'identity.json')
  let id = await Identity.connect({ dir })
  const p1 = (await id.currentProfile()).id
  const p2 = (await id.createProfile('Otra')).id
  const activo = (await id.currentProfile()).id
  const otro = activo === p1 ? p2 : p1
  id.destroy()
  await new Promise((resolve) => setTimeout(resolve, 300))

  const llave = async () => JSON.stringify(await crypto.subtle.exportKey('jwk',
    (await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify'])).publicKey))
  const [ajena, comm, alguien] = await Promise.all([llave(), llave(), llave()])
  // El acta de OTRA cuenta, que no nombra la llave de este perfil, y un papel emitido a otra llave.
  const acta = { v: 5, seq: 9, profileId: ajena, sealedBy: ajena, members: [{ pub: ajena, label: 'Ajena', caps: ['sealer'] }, { pub: comm, cn: 'vault', vault: ajena, caps: ['sign'] }, { pub: alguien, caps: ['sign'] }] }
  const kv = JSON.parse(fs.readFileSync(archivo, 'utf8'))
  kv[`dotrino.identity.p.${otro}.acta`] = JSON.stringify(acta)
  kv[`dotrino.identity.p.${otro}.vault.cert`] = JSON.stringify({ master: ajena, cert: { sub: alguien, scope: ['vault:sign'] } })
  fs.writeFileSync(archivo, JSON.stringify(kv))

  id = await Identity.connect({ dir })
  const p = (await id.listProfiles()).find((x) => x.id === otro)
  assert.deepEqual(p.vaults, [], 'ninguna bóveda ajena en este perfil')
  id.destroy()
})
