/**
 * UNA SOLA LLAVE POR CUENTA EN EL TELÉFONO (dueño, 2026-09-25).
 *
 * En la app de Android la identidad del WebView firma y descifra con la llave del CHIP (la
 * misma que aprueba en la pantalla nativa), por un puente. Aquí el chip es una llave de
 * software detrás del mismo protocolo que habla la app (`create`, `open`, `sign`,
 * `deriveBits`, `save`, `remove`), y se prueba contra un núcleo NORMAL al otro lado: lo que
 * firma el chip lo verifica cualquiera, y lo que se le sella lo abre él.
 */
import test from 'node:test'
import assert from 'node:assert/strict'

import { createIdentityCore } from '../vault/core.js'
import { withExternalKeys } from '../vault/externalKeys.js'
import { verifyDeviceSig } from '../vault/capabilities.js'
import * as Content from '../vault/content.js'

const b64 = (buf) => Buffer.from(buf instanceof ArrayBuffer ? new Uint8Array(buf) : buf).toString('base64')
const pubStr = ({ kty, crv, x, y }) => JSON.stringify({ kty, crv, x, y })

/** El chip del teléfono, como lo ve la página: guarda las privadas y no las enseña nunca. */
function chip () {
  const llaves = new Map()
  const log = []
  let n = 0
  const call = async (method, p) => {
    log.push(method)
    if (method === 'create') {
      const kid = 'kid-' + (++n)
      const s = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, false, ['sign', 'verify'])
      const e = await crypto.subtle.generateKey({ name: 'ECDH', namedCurve: 'P-256' }, false, ['deriveBits'])
      const k = { s, e, publickey: pubStr(await crypto.subtle.exportKey('jwk', s.publicKey)), encPub: pubStr(await crypto.subtle.exportKey('jwk', e.publicKey)) }
      llaves.set(kid, k)
      return { kid, publickey: k.publickey, encPub: k.encPub }
    }
    if (method === 'import') {
      // La llave que entrega la bóveda al entrar con contraseña: la app la guarda y firma ella.
      const kid = 'kid-' + (++n)
      const s = { privateKey: await crypto.subtle.importKey('jwk', p.sign, { name: 'ECDSA', namedCurve: 'P-256' }, false, ['sign']) }
      const e = { privateKey: await crypto.subtle.importKey('jwk', p.enc, { name: 'ECDH', namedCurve: 'P-256' }, false, ['deriveBits']) }
      llaves.set(kid, { s, e, publickey: p.publickey, encPub: p.encPub })
      return { kid, publickey: p.publickey, encPub: p.encPub }
    }
    const k = llaves.get(p.kid)
    if (!k) throw Object.assign(new Error('that key is not on this phone'), { code: 'native-key-gone' })
    if (method === 'open') return { kid: p.kid, publickey: k.publickey, encPub: k.encPub }
    if (method === 'sign') {
      const sig = await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, k.s.privateKey, Buffer.from(p.data, 'base64'))
      return { signature: b64(sig) }
    }
    if (method === 'deriveBits') {
      const peer = await crypto.subtle.importKey('jwk', JSON.parse(p.peer), { name: 'ECDH', namedCurve: 'P-256' }, false, [])
      return { bits: b64(await crypto.subtle.deriveBits({ name: 'ECDH', public: peer }, k.e.privateKey, 256)) }
    }
    if (method === 'save') { k.saved = p; return { deviceId: 'X' } }
    if (method === 'remove') { llaves.delete(p.kid); return { ok: true } }
    throw new Error('unknown ' + method)
  }
  return { call, llaves, log }
}

async function nucleo ({ bridge } = {}) {
  const mem = new Map()
  const idb = new Map()
  let peers = {}
  const base = {
    get: async (name) => idb.get(name) || null,
    set: async (name, v) => { idb.set(name, v) },
    remove: async (name) => { idb.delete(name) }
  }
  const core = await createIdentityCore({
    kv: { getItem: (k) => (mem.has(k) ? mem.get(k) : null), setItem: (k, v) => mem.set(k, String(v)), removeItem: (k) => mem.delete(k) },
    keyStore: bridge ? withExternalKeys(base, bridge) : base,
    peers: {
      async initPeerStorage () {}, loadPeers: () => peers, savePeers: (m) => { peers = m },
      setPeersDirect: (m) => { peers = m || {} },
      upsertPeer: (pub, patch) => { peers[pub] = { ...(peers[pub] || {}), ...patch, publickey: pub }; return peers[pub] },
      onDirty () {}, setProfile () {}
    },
    makeSync: null
  })
  return { core, idb }
}

test('las llaves nuevas nacen en el chip: IndexedDB solo guarda la pública y el nombre de la llave', async () => {
  const c = chip()
  const { core, idb } = await nucleo({ bridge: c })
  const me = await core.handlers.getMe()
  assert.equal(c.llaves.size, 1, 'una sola llave del chip para las dos mitades (firma y cifrado)')
  const [kid, k] = [...c.llaves][0]
  assert.equal(me.publickey, JSON.stringify(JSON.parse(k.publickey)), 'la identidad ES la llave del chip')
  assert.equal(me.encryptionPubkey, JSON.stringify(JSON.parse(k.encPub)))
  for (const rec of idb.values()) {
    assert.equal(rec.external, kid)
    assert.equal(rec.privateKey, undefined, 'nada privado en IndexedDB')
  }
})

test('lo que firma el chip lo verifica cualquiera (signData)', async () => {
  const c = chip()
  const { core } = await nucleo({ bridge: c })
  const data = { op: 'hola', n: 1 }
  const r = await core.handlers.signData({ data })
  assert.ok(await verifyDeviceSig({ publickey: r.publickey, data, signature: r.signature }))
  assert.ok(c.log.includes('sign'), 'firmó el chip, no WebCrypto')
})

test('cifrado entre pares: un núcleo normal le escribe al del chip, y el chip le contesta', async () => {
  const c = chip()
  const { core: tel } = await nucleo({ bridge: c })
  const { core: pc } = await nucleo()
  const meTel = await tel.handlers.getMe(); const mePc = await pc.handlers.getMe()
  const ida = await pc.handlers.encrypt({ recipients: [{ encryptionPubkey: meTel.encryptionPubkey }], plaintext: 'para el teléfono' })
  assert.equal((await tel.handlers.decrypt({ senderEncryptionPubkey: mePc.encryptionPubkey, envelope: ida })).plaintext, 'para el teléfono')
  const vuelta = await tel.handlers.encrypt({ recipients: [{ encryptionPubkey: mePc.encryptionPubkey }], plaintext: 'desde el chip' })
  assert.equal((await pc.handlers.decrypt({ senderEncryptionPubkey: meTel.encryptionPubkey, envelope: vuelta })).plaintext, 'desde el chip')
  assert.ok(c.log.includes('deriveBits'))
})

test('un sobre sellado al chip (el perfil @me, los pedidos) se abre con él', async () => {
  const c = chip()
  const { core } = await nucleo({ bridge: c })
  const me = await core.handlers.getMe()
  const cek = await Content.makeContentKey()
  const wrap = await Content.wrapForMember({ cek, memberEncPub: me.encryptionPubkey })
  const [kid] = [...c.llaves.keys()]
  const { privateKey } = await withExternalKeys({ get: async () => ({ external: kid, publicJwk: {} }) }, c).get('x')
  assert.equal(await Content.openWrap({ wrap, myEncPrivateKey: privateKey }), cek)
})

test('si la llave ya no está en el teléfono, se dice con su código y NO se fabrica otra', async () => {
  const c = chip()
  const { core } = await nucleo({ bridge: c })
  const antes = (await core.handlers.getMe()).publickey
  c.llaves.clear()
  await assert.rejects(() => core.handlers.signData({ data: { a: 1 } }), (e) => e.code === 'native-key-gone')
  assert.equal((await core.handlers.getMe()).publickey, antes, 'la identidad no cambió')
})

test('sin puente (el navegador, las apps) todo sigue como siempre: CryptoKey en IndexedDB', async () => {
  const { core, idb } = await nucleo()
  const r = await core.handlers.signData({ data: { a: 1 } })
  assert.ok(r.signature)
  for (const rec of idb.values()) assert.ok(rec.privateKey && !rec.external)
})

test('la llave de entrar con contraseña la guarda la app: aquí queda solo su registro, y firma por el puente', async () => {
  const c = chip()
  const idb = new Map()
  const ks = withExternalKeys({
    get: async (name) => idb.get(name) || null, set: async (name, v) => { idb.set(name, v) }, remove: async (name) => { idb.delete(name) }
  }, { call: c.call })
  const s = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify'])
  const e = await crypto.subtle.generateKey({ name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveBits'])
  const sin = ({ key_ops: _o, ...r }) => r
  const publickey = pubStr(await crypto.subtle.exportKey('jwk', s.publicKey))
  const encPub = pubStr(await crypto.subtle.exportKey('jwk', e.publicKey))
  await ks.importPair({
    sign: { name: 'p.sign', privateJwk: sin(await crypto.subtle.exportKey('jwk', s.privateKey)), publickey },
    enc: { name: 'p.enc', privateJwk: sin(await crypto.subtle.exportKey('jwk', e.privateKey)), publickey: encPub }
  })
  const rec = idb.get('p.sign')
  assert.deepEqual(Object.keys(rec).sort(), ['external', 'kind', 'publicJwk'], 'ninguna privada en el almacén de la página')
  assert.equal(idb.get('p.enc').external, rec.external, 'las dos mitades bajo el mismo id')
  assert.equal(JSON.stringify(rec.publicJwk), publickey, 'la pública es la del acta, tal cual')
  const h = await ks.get('p.sign')
  const data = new TextEncoder().encode('hola')
  const sig = Buffer.from(await h.privateKey.sign(data), 'base64')
  assert.ok(await crypto.subtle.verify({ name: 'ECDSA', hash: 'SHA-256' }, s.publicKey, sig, data), 'lo que firma la app lo verifica la pública de la bóveda')
})
