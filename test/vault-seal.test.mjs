/**
 * LO QUE UN APARATO LE PIDE A SU BÓVEDA VA SELLADO (`vault/vaultSeal.js`).
 *
 * Con un cliente de mentira que apunta lo que sale: se comprueba que el payload ENTERO va
 * dentro de un sobre (lo que vería el proxio no lleva el tipo, el `machine` ni el cajón), un
 * sobre por bóveda del acta, enrutado a la cuenta; y la migración: en claro hasta el
 * 2026-12-15 y diciéndolo, y desde esa fecha nunca.
 */
import test from 'node:test'
import assert from 'node:assert/strict'
import { sendToVault, acceptReply, vaultKeysOf, latestActa, PLAIN_UNTIL } from '../vault/vaultSeal.js'
import { wrapForMember, openWrap } from '../vault/content.js'

async function encKeypair () {
  const kp = await crypto.subtle.generateKey({ name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveBits'])
  const j = await crypto.subtle.exportKey('jwk', kp.publicKey)
  return { privateKey: kp.privateKey, encPub: JSON.stringify({ kty: j.kty, crv: j.crv, x: j.x, y: j.y }) }
}

/** Un cliente con la forma del del proxio: sella como el pilar (`wrapForMember`) y apunta el cable. */
function fakeClient (encPubs, { actas = [] } = {}) {
  const wire = []
  return {
    wire,
    async encPubOf (pub) { if (!encPubs[pub]) throw Object.assign(new Error('no'), { code: 'no-encpub' }); return encPubs[pub] },
    async sendSealed (to, payload, { peerEncPub, ...opts }) {
      wire.push({ to, opts, message: { v: 1, sealed: await wrapForMember({ cek: JSON.stringify(payload), memberEncPub: peerEncPub }) } })
    },
    sendByPubkey (to, payload, opts) { wire.push({ to, opts, message: payload }) },
    async getActas () { return actas }
  }
}

const acta = (members, seq = 3) => ({ profileId: 'P', seq, members })
const payload = { type: 'vault.secrets', data: { op: 'secrets', ns: 'mi-cajon', machine: 'Portatil-XYZ', rek: 'R' }, signature: 's', cert: {} }

test('la petición entera va sellada, un sobre por bóveda, enrutada a la cuenta', async () => {
  const a = await encKeypair(); const b = await encKeypair()
  const c = fakeClient({ A: a.encPub, B: b.encPub })
  const r = await sendToVault(c, { dest: 'MASTER', acta: acta([{ pub: 'A', cn: 'vault' }, { pub: 'B', cn: 'vault' }, { pub: 'PHONE', caps: ['sign'] }]), payload, quiet: true })
  assert.equal(r.sealed, 2)
  assert.equal(c.wire.length, 2)
  const cable = JSON.stringify(c.wire)
  for (const plain of ['vault.secrets', 'mi-cajon', 'Portatil-XYZ', '"rek"']) assert.ok(!cable.includes(plain), `nada en claro: ${plain}`)
  assert.ok(c.wire.every((w) => w.to[0] === 'MASTER' && w.opts.quiet === true))
  assert.deepEqual(JSON.parse(await openWrap({ wrap: c.wire[0].message.sealed, myEncPrivateKey: a.privateKey })), payload)
  assert.deepEqual(JSON.parse(await openWrap({ wrap: c.wire[1].message.sealed, myEncPrivateKey: b.privateKey })), payload)
})

test('con `to`, solo a esa bóveda', async () => {
  const a = await encKeypair()
  const c = fakeClient({ A: a.encPub })
  await sendToVault(c, { dest: 'A', to: 'A', acta: null, payload })
  assert.equal(c.wire.length, 1)
  assert.equal(c.wire[0].to[0], 'A')
})

test('MIGRACIÓN: sin a quién sellar, en claro y se dice — hasta el 2026-12-15', async () => {
  const lines = []
  const c = fakeClient({})
  const r = await sendToVault(c, { dest: 'M', acta: acta([]), payload, warn: (l) => lines.push(l), now: PLAIN_UNTIL - 1 })
  assert.equal(r.sealed, 0)
  assert.equal(r.why, 'no-vault-key')
  assert.match(lines[0], /UNSEALED .* 2026-12-15/)
  await assert.rejects(() => sendToVault(fakeClient({}), { dest: 'M', acta: acta([]), payload, now: PLAIN_UNTIL }), { code: 'vault-unsealable' })
})

test('el socket local no sella: no toca la red', async () => {
  const sent = []
  await sendToVault({ local: true, sendByPubkey: (to, p) => sent.push(p) }, { dest: 'M', acta: null, payload })
  assert.deepEqual(sent, [payload])
})

test('la respuesta: sellada sí; en claro solo durante la migración', () => {
  assert.equal(acceptReply({ meta: { sealed: true }, now: PLAIN_UNTIL }), true)
  assert.equal(acceptReply({ meta: { local: true }, local: true, now: PLAIN_UNTIL }), true)
  const lines = []
  assert.equal(acceptReply({ meta: { sealed: false }, type: 'x', warn: (l) => lines.push(l), now: PLAIN_UNTIL - 1 }), true)
  assert.equal(lines.length, 1)
  assert.equal(acceptReply({ meta: { sealed: false }, now: PLAIN_UNTIL }), false)
})

test('vaultKeysOf: solo las llaves de comunicación de bóveda', () => {
  assert.deepEqual(vaultKeysOf(acta([{ pub: 'A', cn: 'vault' }, { pub: 'S', cn: 'proxy' }, { pub: 'A', cn: 'vault' }])), ['A'])
  assert.deepEqual(vaultKeysOf(null), [])
})

test('latestActa no se fía del proxio: un acta que no verifica no se adopta', async () => {
  const mine = acta([{ pub: 'A', cn: 'vault' }], 3)
  const c = fakeClient({}, { actas: [acta([{ pub: 'EVIL', cn: 'vault' }], 9)] })
  assert.equal(await latestActa(c, mine), mine)
  const sinCache = { getActas: async () => { throw Object.assign(new Error('old proxy'), { code: 'no-acta-cache' }) } }
  assert.equal(await latestActa(sinCache, mine), mine)
  await assert.rejects(() => latestActa({ getActas: async () => { throw new Error('boom') } }, mine), /boom/)
})
