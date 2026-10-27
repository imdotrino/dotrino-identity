/**
 * LA LLAVE DE CIFRADO NO VA BAJO LA CONTRASEÑA: solo la maestra.
 *
 * La bóveda sirve cerrada (dueño, 2026-10-25), y con la llave de cifrado abre la clave de
 * contenido. La alojada nace con el candado abierto, así que su llave de cifrado quedaba
 * sellada: cerrada no podía cifrar ni la lista de variables de la consola, y abrir tampoco
 * la recargaba (2026-10-27).
 */
import test from 'node:test'
import assert from 'node:assert/strict'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import crypto from 'node:crypto'
import { Identity } from '../src/node.js'

const tmp = () => fs.mkdtempSync(path.join(os.tmpdir(), 'enc-lock-'))
const file = (dir) => path.join(dir, 'identity.json')
const leer = (dir) => JSON.parse(fs.readFileSync(file(dir), 'utf8'))
const claveDe = (kv, fin) => Object.keys(kv).find((k) => k.endsWith(fin))

function candado () {
  const st = { abierto: true }
  const key = crypto.createHash('sha256').update('la-frase').digest()
  return {
    st,
    seal: async (texto) => {
      const iv = crypto.randomBytes(12)
      const c = crypto.createCipheriv('aes-256-gcm', key, iv)
      const ct = Buffer.concat([c.update(texto, 'utf8'), c.final(), c.getAuthTag()])
      return iv.toString('base64') + '.' + ct.toString('base64')
    },
    open: async (blob) => {
      if (!st.abierto) return null
      const [iv, ct] = String(blob).split('.')
      const buf = Buffer.from(ct, 'base64')
      const d = crypto.createDecipheriv('aes-256-gcm', key, Buffer.from(iv, 'base64'))
      d.setAuthTag(buf.subarray(buf.length - 16))
      return Buffer.concat([d.update(buf.subarray(0, buf.length - 16)), d.final()]).toString('utf8')
    }
  }
}

test('con el candado abierto al nacer, la maestra va sellada y la llave de cifrado no', async () => {
  const dir = tmp()
  await Identity.connect({ dir, keyLock: candado() })
  const kv = leer(dir)
  assert.ok(JSON.parse(kv[claveDe(kv, '.keypair')]).sealed, 'la maestra, sellada')
  const enc = JSON.parse(kv[claveDe(kv, '.enc-keypair')])
  assert.equal(enc.sealed, undefined, 'la de cifrado, bajo el cifrado en reposo y nada más')
  assert.ok(enc.privateJwk)
  fs.rmSync(dir, { recursive: true, force: true })
})

test('una llave de cifrado que quedó sellada sale de debajo del candado al abrir', async () => {
  const dir = tmp()
  const lock = candado()
  const id = await Identity.connect({ dir, keyLock: lock })
  const encPub = await id.getEncryptionPubkey()
  // Como la dejaban las versiones de antes: sellada con la contraseña.
  const kv = leer(dir); const k = claveDe(kv, '.enc-keypair')
  const { privateJwk, publicJwk } = JSON.parse(kv[k])
  kv[k] = JSON.stringify({ sealed: await lock.seal(JSON.stringify(privateJwk)), publicJwk })
  fs.writeFileSync(file(dir), JSON.stringify(kv))

  lock.st.abierto = false
  const cerrada = await Identity.connect({ dir, keyLock: lock })
  assert.equal(await cerrada.contentKey(), null, 'cerrada y sellada: no abre la clave de contenido')

  lock.st.abierto = true
  await cerrada.reloadMasterKey()
  assert.ok(await cerrada.contentKey(), 'al abrir ya la abre')
  assert.equal(await cerrada.getEncryptionPubkey(), encPub, 'es la MISMA llave: el acta no cambia')
  const despues = JSON.parse(leer(dir)[k])
  assert.equal(despues.sealed, undefined, 'y queda escrita fuera del candado')

  lock.st.abierto = false
  const otraVez = await Identity.connect({ dir, keyLock: lock })
  assert.ok(await otraVez.contentKey(), 'desde entonces, cerrada también la abre')
  fs.rmSync(dir, { recursive: true, force: true })
})
