/**
 * DÓNDE CORRE CADA APARATO (`vault/machine.js`): se limpia igual en las dos puntas, se detecta
 * del navegador sin inventar lo que no se sabe, y el acta lo guarda al admitir.
 */
import test from 'node:test'
import assert from 'node:assert/strict'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import { Identity } from '../src/node.js'
import { cleanMachine, machineLine, browserMachine } from '../vault/machine.js'

const ua = {
  chromeLinux: 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36',
  edgeWin: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36 Edg/141.0.0.0',
  iphone: 'Mozilla/5.0 (iPhone; CPU iPhone OS 18_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/15E148',
  androidWv: 'Mozilla/5.0 (Linux; Android 14; Pixel 7 Build/UQ1A; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/141.0.0.0 Mobile Safari/537.36',
  ipad: 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Safari/605.1.15'
}

test('cleanMachine: recorta, quita lo que no es de la forma y no lanza nunca', () => {
  assert.equal(cleanMachine(null), null)
  assert.equal(cleanMachine('linux'), null)
  assert.equal(cleanMachine({}), null)
  assert.deepEqual(cleanMachine({ kind: 'robot', os: 'Linux', name: 'x'.repeat(200), extra: 1 }), { kind: '', os: 'Linux', name: 'x'.repeat(64) })
  assert.deepEqual(cleanMachine({ kind: 'node', os: 'Linux\n6.1', name: 'pc' }), { kind: 'node', os: 'Linux6.1', name: 'pc' })
  assert.equal(machineLine({ kind: 'node', os: 'Linux 7.0', name: 'pc' }), 'node · Linux 7.0 · pc')
  assert.equal(machineLine(null), '')
})

test('browserMachine: navegador, extensión y las dos apps nativas', () => {
  assert.deepEqual(browserMachine({ navigator: { userAgent: ua.chromeLinux } }), { kind: 'browser', os: 'Linux', name: 'Chrome' })
  assert.deepEqual(browserMachine({ navigator: { userAgent: ua.edgeWin } }), { kind: 'browser', os: 'Windows', name: 'Edge' })
  assert.deepEqual(browserMachine({ navigator: { userAgent: ua.chromeLinux }, chrome: { runtime: { id: 'abc' } } }), { kind: 'extension', os: 'Linux', name: 'Chrome' })
  assert.deepEqual(browserMachine({ navigator: { userAgent: ua.iphone }, DotrinoNative: { platform: () => 'ios' } }), { kind: 'ios', os: 'iOS 18', name: '' })
  assert.deepEqual(browserMachine({ navigator: { userAgent: ua.androidWv }, DotrinoNative: { platform: () => 'android' } }), { kind: 'android', os: 'Android 14', name: '' })
  assert.equal(browserMachine({ navigator: { userAgent: ua.ipad, maxTouchPoints: 5 } }).os, 'iPadOS')
  // Node tiene `navigator`, pero no es un navegador.
  assert.equal(browserMachine(globalThis), null)
  // Un puente que revienta no cambia qué es: sigue siendo un navegador.
  assert.equal(browserMachine({ navigator: { userAgent: ua.chromeLinux }, DotrinoNative: { platform: () => { throw new Error('x') } } }).kind, 'browser')
})

test('el acta guarda dónde corre el aparato al admitirlo, limpio', async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'machine-'))
  const vault = await Identity.connect({ dir })
  const otro = await Identity.connect({ dir: fs.mkdtempSync(path.join(os.tmpdir(), 'machine-b-')) })
  const pub = otro.me.publickey
  await vault.admitMember({ pub, label: 'Portátil', caps: ['read'], machine: { kind: 'node', os: 'Linux 7.0', name: 'mi-pc', sobra: true } })
  const m = (await vault.profileActa()).acta.members.find((x) => x.pub === pub)
  assert.deepEqual(m.machine, { kind: 'node', os: 'Linux 7.0', name: 'mi-pc' })
  // Sin nada que decir, el campo no aparece (no un objeto vacío).
  const tercero = await Identity.connect({ dir: fs.mkdtempSync(path.join(os.tmpdir(), 'machine-c-')) })
  await vault.admitMember({ pub: tercero.me.publickey, label: 'Otro', caps: ['read'] })
  assert.equal('machine' in (await vault.profileActa()).acta.members.find((x) => x.pub === tercero.me.publickey), false)
  vault.destroy(); otro.destroy(); tercero.destroy()
})
