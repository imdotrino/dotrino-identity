/**
 * El almacén de la identidad dentro de la app de iOS (`vault/nativeStore.js`): uno para
 * todas las páginas. Lo que importa es que lo que guarda una página lo vea la siguiente —
 * que es exactamente lo que WebKit rompía al partir el almacén del iframe por página.
 */
import test from 'node:test'
import assert from 'node:assert/strict'
import { nativeBackends, adoptPageProfiles } from '../vault/nativeStore.js'

/** La app, en pequeño: un mapa y los tres métodos que expone el puente. */
function fakeApp () {
  const store = new Map()
  const calls = []
  return {
    store,
    calls,
    bridge: {
      async call (method, params) {
        calls.push(method)
        if (method === 'storeLoad') return { items: Object.fromEntries(store) }
        if (method === 'storeSet') { store.set(params.k, params.v); return { ok: true } }
        if (method === 'storeRemove') { store.delete(params.k); return { ok: true } }
        if (method === 'open') {
          if (params.kid === 'kid-gone') throw Object.assign(new Error('that key is not on this phone'), { code: 'native-key-gone' })
          return { kid: params.kid }
        }
        throw new Error('unknown ' + method)
      }
    }
  }
}

test('lo que guarda una página lo ve la siguiente: kv, llaves y contactos', async () => {
  const app = fakeApp()
  const a = await nativeBackends(app.bridge)
  a.kv.setItem('dotrino.identity.profiles', '["p1"]')
  await a.keyStore.set('dotrino.identity.p.p1.keypair', { external: 'kid-1', kind: 'sign', publicJwk: { kty: 'EC' } })
  await a.peers.put('peers.p1.v1', { bob: { nick: 'Bob' } })
  await a.flush()

  const b = await nativeBackends(app.bridge)   // otra página: otro iframe, el mismo almacén
  assert.equal(b.kv.getItem('dotrino.identity.profiles'), '["p1"]')
  assert.deepEqual(await b.keyStore.get('dotrino.identity.p.p1.keypair'), { external: 'kid-1', kind: 'sign', publicJwk: { kty: 'EC' } })
  assert.deepEqual(await b.peers.get('peers.p1.v1'), { bob: { nick: 'Bob' } })
})

test('el kv sigue siendo síncrono y un borrado no lo resucita un set anterior', async () => {
  const app = fakeApp()
  const s = await nativeBackends(app.bridge)
  s.kv.setItem('x', '1')
  assert.equal(s.kv.getItem('x'), '1', 'se lee al momento, sin esperar a la app')
  s.kv.removeItem('x')
  assert.equal(s.kv.getItem('x'), null)
  await s.flush()
  assert.equal(app.store.has('kv:x'), false, 'las escrituras llegan en orden')
})

test('una llave de software no se guarda a medias: se para con su código', async () => {
  const s = await nativeBackends(fakeApp().bridge)
  await assert.rejects(() => s.keyStore.set('k', { privateKey: {}, publicJwk: { kty: 'EC' } }), (e) => e.code === 'native-no-import')
})

test('sin almacén de la app no se sigue con uno vacío', async () => {
  const bridge = { async call () { return {} } }
  await assert.rejects(() => nativeBackends(bridge), (e) => e.code === 'native-no-store')
})

/** El almacén de la página de antes: la cuenta emparejada en vault.dotrino.com/d. */
function pageWith ({ pid = 'pPaired', kid = 'kid-chip', paired = true } = {}) {
  const kv = new Map([
    ['dotrino.identity.profiles', JSON.stringify([{ id: pid, name: 'Dotrino', pubkey: 'x' }])],
    ['dotrino.identity.current', pid],
    [`dotrino.identity.p.${pid}.me`, '{"nickname":"Dotrino"}']
  ])
  if (paired) kv.set(`dotrino.identity.p.${pid}.vault.cert`, '{"seq":3}')
  return {
    kv,
    keys: new Map([
      [`dotrino.identity.p.${pid}.keypair`, { external: kid, kind: 'sign', publicJwk: { kty: 'EC' } }],
      [`dotrino.identity.p.${pid}.enc-keypair`, { external: kid, kind: 'enc', publicJwk: { kty: 'EC' } }]
    ]),
    peers: new Map([[`peers.${pid}.v1`, { bob: { nick: 'Bob' } }]])
  }
}

test('la cuenta emparejada en la página pasa a la app y queda ACTIVA en vez del perfil vacío', async () => {
  const app = fakeApp()
  const n = await nativeBackends(app.bridge)
  n.kv.setItem('dotrino.identity.profiles', JSON.stringify([{ id: 'pEmpty', name: '', pubkey: 'y' }]))
  n.kv.setItem('dotrino.identity.current', 'pEmpty')

  assert.deepEqual(await adoptPageProfiles(n, app.bridge, pageWith()), ['pPaired'])
  assert.deepEqual(JSON.parse(n.kv.getItem('dotrino.identity.profiles')).map((p) => p.id), ['pEmpty', 'pPaired'])
  assert.equal(n.kv.getItem('dotrino.identity.current'), 'pPaired')
  assert.equal(n.kv.getItem('dotrino.identity.p.pPaired.vault.cert'), '{"seq":3}')
  assert.equal((await n.keyStore.get('dotrino.identity.p.pPaired.keypair')).external, 'kid-chip')
  assert.deepEqual(await n.peers.get('peers.pPaired.v1'), { bob: { nick: 'Bob' } })

  await n.flush()
  const next = await nativeBackends(app.bridge)   // otra página ya lo ve
  assert.equal(next.kv.getItem('dotrino.identity.current'), 'pPaired')
  assert.deepEqual(await adoptPageProfiles(next, app.bridge, pageWith()), [], 'la segunda vez no trae nada')
})

test('no trae un perfil cuya llave ya no está en el chip, ni cambia el activo si ya está emparejado', async () => {
  const app = fakeApp()
  const n = await nativeBackends(app.bridge)
  assert.deepEqual(await adoptPageProfiles(n, app.bridge, pageWith({ kid: 'kid-gone' })), [])

  n.kv.setItem('dotrino.identity.profiles', JSON.stringify([{ id: 'pMine', name: 'Mía', pubkey: 'z' }]))
  n.kv.setItem('dotrino.identity.current', 'pMine')
  n.kv.setItem('dotrino.identity.p.pMine.vault.cert', '{"seq":1}')
  assert.deepEqual(await adoptPageProfiles(n, app.bridge, pageWith({ pid: 'pOther' })), ['pOther'])
  assert.equal(n.kv.getItem('dotrino.identity.current'), 'pMine', 'el activo emparejado se respeta')
})
