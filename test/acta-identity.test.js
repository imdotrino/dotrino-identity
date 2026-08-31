/**
 * El acta a través de la identidad real (adaptador Node, con su kv en disco): que nazca
 * sola, que persista, que solo el master pueda cambiarla y que el traspaso funcione.
 */
import test from 'node:test'
import assert from 'node:assert/strict'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import { Identity, makeDeviceKey } from '../src/node.js'

const tmp = () => fs.mkdtempSync(path.join(os.tmpdir(), 'acta-'))

test('el acta nace sola con el perfil: un miembro que puede todo lo suyo y SELLA', async () => {
  const dir = tmp()
  const id = await Identity.connect({ dir })
  const mine = await id.myMembership()

  assert.equal(mine.inProfile, true)
  assert.equal(mine.isMaster, true)
  assert.deepEqual(mine.caps.sort(), ['read', 'sealer', 'sign', 'store'], 'quien funda la cuenta es su primer sellador')
  assert.equal(mine.profileId, id.me.publickey, 'el perfil se llama como esta llave')
  assert.equal(mine.seq, 1)
  assert.match(mine.id, /^[0-9A-F]{4}-[0-9A-F]{4}$/)

  const { members, sealers } = await id.profileMembers()
  assert.equal(members.length, 1)
  assert.equal(members[0].isMe, true)
  assert.deepEqual(sealers, [id.me.publickey], 'y la lista de selladores es él')
  fs.rmSync(dir, { recursive: true, force: true })
})

test('persiste entre arranques', async () => {
  const dir = tmp()
  const a = await Identity.connect({ dir })
  const dev = await makeDeviceKey({ label: 'Celular' })
  await a.admitMember({ pub: dev.publickey, label: 'Celular', caps: ['store', 'read'] })
  a.destroy()

  const b = await Identity.connect({ dir })
  const { members, seq } = await b.profileMembers()
  assert.equal(seq, 2, 'el seq avanzó y se guardó')
  assert.equal(members.length, 2)
  assert.deepEqual(members.find((m) => !m.isMe).caps, ['read', 'store'])
  fs.rmSync(dir, { recursive: true, force: true })
})

/**
 * NO HAY TRASPASO: sellar es un permiso, así que ceder el mando es CONCEDERLO. Y quien lo
 * cede no deja de tenerlo en el mismo acto — nadie se quita el sello a sí mismo, porque
 * eso deja un acta que uno firma sin poder firmarla y no tiene vuelta atrás.
 */
test('ceder el mando es conceder `sella`: a partir de ahí mandan los dos', async () => {
  const dir = tmp()
  const id = await Identity.connect({ dir })
  const vault = await makeDeviceKey({ label: 'Bóveda' })

  const r = await id.handoverMaster(vault.publickey, { label: 'Bóveda', caps: ['sign', 'store', 'read'] })
  assert.deepEqual(r.sealers.sort(), [id.me.publickey, vault.publickey].sort())

  assert.equal(await id.isMaster(), true, 'sigue pudiendo sellar: cederlo no es perderlo')
  const mine = await id.myMembership()
  assert.equal(mine.isMaster, true)
  assert.equal(mine.inProfile, true)

  // Y puede seguir admitiendo, claro. Quitarle el sello es cosa de la bóveda, no suya.
  const tercero = await makeDeviceKey({ label: 'Otro' })
  await id.admitMember({ pub: tercero.publickey })
  const { members } = await id.profileMembers()
  assert.equal(members.length, 3)
  fs.rmSync(dir, { recursive: true, force: true })
})

test('renuncia: el dispositivo se quita `sign` y el acta lo refleja', async () => {
  const dir = tmp()
  const id = await Identity.connect({ dir })
  const otro = await makeDeviceKey({ label: 'Bóveda' })
  await id.admitMember({ pub: otro.publickey, label: 'Bóveda', caps: ['sign', 'store', 'read'] })

  const res = await id.renounceCaps(['sign'])
  assert.deepEqual(res.caps.sort(), ['read', 'sealer', 'store'], 'ya no firma, pero sigue sellando')
  assert.equal(res.record.member, id.me.publickey)

  const mine = await id.myMembership()
  assert.deepEqual(mine.caps.sort(), ['read', 'sealer', 'store'])

  // Y sellar NO se renuncia: es la auto-amputación que el acta impide, por otra puerta.
  await assert.rejects(() => id.renounceCaps(['sealer']), /cannot be renounced/)
  fs.rmSync(dir, { recursive: true, force: true })
})

test('no se puede renunciar a `sign` si eres el único que firma', async () => {
  const dir = tmp()
  const id = await Identity.connect({ dir })
  // Como master, absorber la renuncia dejaría el perfil sin firmante → se rechaza…
  const res = await id.renounceCaps(['sign'])
  // …pero el registro suelto sí existe (es unilateral) y NO entra en el acta.
  assert.equal(res.record.member, id.me.publickey)
  const { members } = await id.profileMembers()
  assert.equal(members[0].caps.includes('sign'), false, 'la renuncia local se honra igual')
  const acta = (await id.profileActa()).acta
  assert.equal(acta.members[0].caps.includes('sign'), true, 'el acta sigue teniendo un firmante')
  fs.rmSync(dir, { recursive: true, force: true })
})

test('cada perfil tiene su propia acta', async () => {
  const dir = tmp()
  const id = await Identity.connect({ dir })
  const p1 = await id.myMembership()

  await id.createProfile('Trabajo')
  const p2 = await id.myMembership()

  assert.notEqual(p2.profileId, p1.profileId, 'perfil nuevo = acta nueva')
  assert.equal(p2.isMaster, true)
  assert.equal(p2.seq, 1)
  fs.rmSync(dir, { recursive: true, force: true })
})

test('firma re-enrutada: sin `sign` y sin bóveda, error claro en vez de firmar igual', async () => {
  const dir = tmp()
  const id = await Identity.connect({ dir })
  const otro = await makeDeviceKey({ label: 'Bóveda' })
  await id.admitMember({ pub: otro.publickey, label: 'Bóveda', caps: ['sign', 'store', 'read'] })

  // Con `sign`, firma en local.
  const firma = await id.signData({ hola: 'mundo' })
  assert.equal(firma.publickey, id.me.publickey)

  await id.renounceCaps(['sign'])

  // Sin `sign` y sin bóveda a la que pedirle: falla con un mensaje que se entiende.
  await assert.rejects(() => id.signData({ hola: 'mundo' }), /profile-without-signer/)

  // …pero el identify del transporte SIEMPRE se firma en local, o el dispositivo
  // no podría ni hablar con la bóveda para pedirle que firme.
  const ident = await id.signData({ op: 'identify', publickey: id.me.publickey, token: 'x', ts: Date.now() })
  assert.equal(ident.publickey, id.me.publickey)
  fs.rmSync(dir, { recursive: true, force: true })
})

test('la clave de contenido: nace con el perfil, se comparte al admitir y rota al expulsar', async () => {
  const dir = tmp()
  const id = await Identity.connect({ dir })

  const mia = await id.contentKey()
  assert.ok(mia?.cek, 'el perfil nace con su clave de contenido')
  assert.equal(mia.gen, 1)

  // Un miembro con llave de cifrado propia entra y recibe la MISMA clave.
  const otro = await makeDeviceKey({ label: 'Celular' })
  const enc = await crypto.subtle.generateKey({ name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveBits'])
  const encJwk = await crypto.subtle.exportKey('jwk', enc.publicKey)
  const encPub = JSON.stringify({ kty: encJwk.kty, crv: encJwk.crv, x: encJwk.x, y: encJwk.y })

  const r = await id.admitMember({ pub: otro.publickey, encPub, label: 'Celular', caps: ['store', 'read'] })
  assert.equal(r.wrapped, true, 'entrar al perfil incluye poder leer lo que ya hay')

  const acta = (await id.profileActa()).acta
  assert.ok(acta.keyring.at(-1).wraps[otro.publickey], 'tiene su envoltura')

  // Al expulsarlo se rota: generación nueva, y él ya no está en ninguna.
  const out = await id.removeMember(otro.publickey)
  assert.equal(out.rotated.gen, 2, 'expulsar rota la clave')
  const acta2 = (await id.profileActa()).acta
  assert.ok(!acta2.keyring.some((g) => g.wraps[otro.publickey]), 'sus envolturas se van con él')
  const ahora = await id.contentKey()
  assert.equal(ahora.gen, 2, 'los que quedan usan la nueva')
  fs.rmSync(dir, { recursive: true, force: true })
})

test('tarjeta de perfil: un contacto puede cifrar a TODOS mis dispositivos', async () => {
  // Bob tiene dos dispositivos en su perfil; Alice es otra persona.
  const dirBob = tmp(); const dirBob2 = tmp(); const dirAlice = tmp()
  const bob = await Identity.connect({ dir: dirBob })
  const bob2 = await Identity.connect({ dir: dirBob2 })
  const alice = await Identity.connect({ dir: dirAlice })

  await bob.admitMember({
    pub: bob2.me.publickey,
    encPub: await bob2.getEncryptionPubkey(),
    label: 'Celular de Bob',
    caps: ['store', 'read']
  })

  // La tarjeta de Bob: solo perfil, versión y llaves.
  const card = await bob.profileCard()
  assert.ok(card, 'el acta trae su tarjeta firmada')
  assert.equal(card.keys.length, 2, 'las llaves de sus dos dispositivos')
  assert.equal(JSON.stringify(card).includes('Celular de Bob'), false, 'sin etiquetas: no es asunto de Alice')
  assert.equal(JSON.stringify(card).includes('caps'), false, 'ni permisos')

  // Alice la guarda y cifra "para Bob".
  const ok = await alice.adoptPeerCard(card)
  assert.equal(ok.adopted, true)
  assert.equal(ok.devices, 2)

  const sobre = await alice.encrypt([{ publickey: bob.me.publickey }], 'hola Bob')
  assert.equal(Object.keys(sobre.wrap).length, 2, 'una envoltura por dispositivo de Bob')

  // Los DOS dispositivos de Bob lo abren, incluido el que no habló con Alice nunca.
  const aliceEnc = await alice.getEncryptionPubkey()
  for (const [quien, dev] of [['bob', bob], ['bob2', bob2]]) {
    const { plaintext } = await dev.decrypt(aliceEnc, null, sobre)
    assert.equal(plaintext, 'hola Bob', quien + ' lo abre')
  }

  // Y alguien de fuera no.
  const dirX = tmp(); const x = await Identity.connect({ dir: dirX })
  await assert.rejects(() => x.decrypt(aliceEnc, null, sobre), /not among the message recipients/)

  for (const d of [dirBob, dirBob2, dirAlice, dirX]) fs.rmSync(d, { recursive: true, force: true })
})

test('tarjeta: no retrocede, y avisa si cambió el master', async () => {
  const dirB = tmp(); const dirA = tmp()
  const bob = await Identity.connect({ dir: dirB })
  const alice = await Identity.connect({ dir: dirA })

  const v1 = await bob.profileCard()
  await alice.adoptPeerCard(v1)

  const otro = await makeDeviceKey({ label: 'otro' })
  const enc = await crypto.subtle.generateKey({ name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveBits'])
  const jwk = await crypto.subtle.exportKey('jwk', enc.publicKey)
  await bob.admitMember({ pub: otro.publickey, encPub: JSON.stringify({ kty: jwk.kty, crv: jwk.crv, x: jwk.x, y: jwk.y }), caps: ['read'] })

  const v2 = await bob.profileCard()
  assert.equal((await alice.adoptPeerCard(v2)).reason, 'seq-mayor')
  // La vieja ya no la acepta.
  assert.equal((await alice.adoptPeerCard(v1)).adopted, false)

  for (const d of [dirB, dirA]) fs.rmSync(d, { recursive: true, force: true })
})
