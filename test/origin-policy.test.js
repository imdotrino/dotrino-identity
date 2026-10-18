/**
 * Lo que decide quién es de la cuenta solo lo pide la consola (regla del dueño, 2026-10-18:
 * ningún aparato entra sin invitación). Una app del ecosistema —aunque sea de `*.dotrino.com`
 * o de localhost— no mete miembros, no cambia permisos, no se lleva la llave.
 */
import test from 'node:test'
import assert from 'node:assert/strict'
import { originPolicy, CONSOLE_ONLY } from '../vault/originPolicy.js'

const prod = originPolicy({ selfOrigin: 'https://id.dotrino.com' })
const dev = originPolicy({ selfOrigin: 'http://localhost:5173' })
const ME = '{"kty":"EC","x":"me"}'

test('la consola puede pedirlo todo; una app del ecosistema, no lo que mete aparatos', () => {
  for (const m of CONSOLE_ONLY) {
    assert.doesNotThrow(() => prod.check(m, {}, 'https://vault.dotrino.com'))
    assert.doesNotThrow(() => prod.check(m, {}, 'https://profile.dotrino.com'))
    assert.throws(() => prod.check(m, {}, 'https://chat.dotrino.com'), { code: 'console-only' }, m)
    assert.throws(() => prod.check(m, {}, 'https://imdotrino.github.io'), { code: 'console-only' }, m)
  }
})

test('localhost administra solo cuando el propio iframe corre en local', () => {
  assert.throws(() => prod.check('admitMember', {}, 'http://localhost:3000'), { code: 'console-only' })
  assert.throws(() => prod.check('admitMember', {}, 'http://192.168.1.20:8080'), { code: 'console-only' })
  assert.doesNotThrow(() => dev.check('admitMember', {}, 'http://localhost:3000'))
  assert.throws(() => dev.check('admitMember', {}, 'https://chat.dotrino.com'), { code: 'console-only' })
})

test('firmar, cifrar y leer el perfil siguen abiertos a cualquier app', () => {
  for (const m of ['signData', 'encrypt', 'decrypt', 'getMe', 'sealContent', 'openContent', 'listPeers', 'profileActa', 'switchProfile', 'createProfile']) {
    assert.doesNotThrow(() => prod.check(m, {}, 'https://chat.dotrino.com'), m)
  }
})

test('un certificado con poder sobre la bóveda es de la consola; una app firma lo suyo y el propio', () => {
  const app = 'https://here.dotrino.com'
  assert.doesNotThrow(() => prod.check('signDelegation', { sub: 'otra', scope: ['geo:publish', 'geo:read:x'] }, app))
  assert.doesNotThrow(() => prod.check('signDelegation', { sub: ME, scope: 'vault:sign' }, app, { me: ME }))
  assert.throws(() => prod.check('signDelegation', { sub: 'otra', scope: 'vault:sign' }, app, { me: ME }), { code: 'console-only' })
  assert.throws(() => prod.check('signDelegation', { sub: 'otra', scope: ['geo:publish', 'vault:admin'] }, app, { me: ME }), { code: 'console-only' })
  assert.throws(() => prod.check('signDelegation', { sub: ME, scope: 'vault:sign' }, app, { me: null }), { code: 'console-only' })
  assert.doesNotThrow(() => prod.check('signDelegation', { sub: 'otra', scope: 'vault:admin' }, 'https://vault.dotrino.com'))
})

test('rewrapFor: la consola y el gestor de contraseñas', () => {
  assert.doesNotThrow(() => prod.check('rewrapFor', {}, 'https://pass.dotrino.com'))
  assert.doesNotThrow(() => prod.check('rewrapFor', {}, 'https://vault.dotrino.com'))
  assert.throws(() => prod.check('rewrapFor', {}, 'https://chat.dotrino.com'), { code: 'console-only' })
})
