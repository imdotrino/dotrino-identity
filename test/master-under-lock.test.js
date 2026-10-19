/**
 * LA MAESTRA BAJO LLAVE.
 *
 * Regla del dueño (2026-08-31): **una bóveda cerrada no puede firmar nada, y su llave no
 * se puede filtrar de ninguna manera.** Hasta aquí el candado era una bandera en memoria
 * con la maestra descifrada al lado: quien tuviera el proceso —o el disco— firmaba igual.
 *
 * Lo que fija esta prueba es que el candado sea la CRIPTOGRAFÍA y no una condición: con el
 * perfil cerrado la privada no existe en memoria, y lo que hay en el disco no se abre sin
 * la llave que sale de la contraseña.
 *
 * Y el fallo que más caro se paga: cerrada NO se genera otra. Una identidad que se
 * inventa un par nuevo porque no pudo abrir el suyo deja al dueño fuera de su cuenta para
 * siempre, y encima en silencio.
 */
import test from 'node:test'
import assert from 'node:assert/strict'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import crypto from 'node:crypto'
import { Identity } from '../src/node.js'

const tmp = () => fs.mkdtempSync(path.join(os.tmpdir(), 'candado-'))
const leer = (dir) => JSON.parse(fs.readFileSync(path.join(dir, 'identity.json'), 'utf8'))

/** Candado de mentira, con la misma forma que el de verdad: `abierto` decide si abre. */
function candado (llave = 'la-frase') {
  const st = { abierto: true }
  const kdf = (s) => crypto.createHash('sha256').update(llave + s).digest()
  return {
    st,
    seal: async (texto) => {
      const iv = crypto.randomBytes(12)
      const c = crypto.createCipheriv('aes-256-gcm', kdf('k'), iv)
      const ct = Buffer.concat([c.update(texto, 'utf8'), c.final(), c.getAuthTag()])
      return iv.toString('base64') + '.' + ct.toString('base64')
    },
    open: async (blob) => {
      if (!st.abierto) return null            // cerrado: no hay con qué
      const [iv, ct] = String(blob).split('.')
      const buf = Buffer.from(ct, 'base64')
      const d = crypto.createDecipheriv('aes-256-gcm', kdf('k'), Buffer.from(iv, 'base64'))
      d.setAuthTag(buf.subarray(buf.length - 16))
      return Buffer.concat([d.update(buf.subarray(0, buf.length - 16)), d.final()]).toString('utf8')
    }
  }
}

test('con candado, la privada NO queda en el disco en claro', async () => {
  const dir = tmp()
  const lock = candado()
  const id = await Identity.connect({ dir, keyLock: lock })
  await id.setMyNickname('yo')
  const pub = id.me.publickey

  const guardado = leer(dir)
  const entrada = JSON.parse(guardado[Object.keys(guardado).find((k) => k.endsWith('keypair'))])
  assert.ok(entrada.sealed, 'la privada va sellada')
  assert.equal(entrada.privateJwk, undefined, 'y no queda una copia en claro al lado')
  assert.ok(entrada.publicJwk, 'la pública sí: es pública')
  // Y en el archivo entero no aparece la mitad privada de una P-256 (`d` de la JWK).
  assert.ok(!JSON.stringify(guardado).includes('"d"'), 'ni rastro de la privada en el archivo')
  assert.ok(pub)
})

test('CERRADA no firma: ni datos, ni certificados, ni el acta', async () => {
  const dir = tmp()
  const lock = candado()
  let id = await Identity.connect({ dir, keyLock: lock })
  await id.setMyNickname('yo')
  const pub = id.me.publickey
  id.destroy()

  lock.st.abierto = false                      // echar el candado y reabrir el perfil
  id = await Identity.connect({ dir, keyLock: lock })

  assert.equal(id.masterLocked, true)
  assert.equal(id.me.publickey, pub, 'se sigue sabiendo QUIÉN eres: la pública está en claro')

  for (const [que, fn] of [
    ['firmar datos', () => id.signData({ hola: 1 })],
    ['emitir un certificado', () => id.signDelegation(pub, ['vault:sign'])]
  ]) {
    await assert.rejects(fn, (e) => e.code === 'vault-locked', `${que} tiene que negarse con código`)
  }
})

test('cerrada NO se inventa otra identidad (lo que dejaría al dueño fuera para siempre)', async () => {
  const dir = tmp()
  const lock = candado()
  let id = await Identity.connect({ dir, keyLock: lock })
  await id.setMyNickname('yo')
  const pub = id.me.publickey
  const antes = leer(dir)
  id.destroy()

  lock.st.abierto = false
  id = await Identity.connect({ dir, keyLock: lock })
  assert.equal(id.me.publickey, pub, 'la misma llave, no una nueva')
  assert.deepEqual(leer(dir), antes, 'y el disco no se tocó')
})

test('abrir el candado devuelve la firma, sin reabrir la identidad', async () => {
  const dir = tmp()
  const lock = candado()
  let id = await Identity.connect({ dir, keyLock: lock })
  await id.setMyNickname('yo')
  id.destroy()

  lock.st.abierto = false
  id = await Identity.connect({ dir, keyLock: lock })
  await assert.rejects(() => id.signData({ a: 1 }), (e) => e.code === 'vault-locked')

  lock.st.abierto = true
  const r = await id.reloadMasterKey()
  assert.equal(r.locked, false)
  const { signature } = await id.signData({ a: 1 })
  assert.ok(signature, 'y vuelve a firmar')
})

test('un perfil SIN contraseña se queda como estaba (y se puede sellar después)', async () => {
  const dir = tmp()
  let id = await Identity.connect({ dir })          // sin candado
  await id.setMyNickname('yo')
  const pub = id.me.publickey
  let entrada = JSON.parse(leer(dir)[Object.keys(leer(dir)).find((k) => k.endsWith('keypair'))])
  assert.ok(entrada.privateJwk, 'sin contraseña, como siempre: la llave de máquina y nada más')
  id.destroy()

  // Le pone contraseña: al abrir el perfil se sella la maestra que ya existía.
  const lock = candado()
  id = await Identity.connect({ dir, keyLock: lock })
  const r = await id.sealMasterKey()
  assert.equal(r.ok, true)
  entrada = JSON.parse(leer(dir)[Object.keys(leer(dir)).find((k) => k.endsWith('keypair'))])
  assert.ok(entrada.sealed && !entrada.privateJwk, 'ahora sí está bajo llave')
  assert.equal(id.me.publickey, pub, 'y sigue siendo la misma cuenta')
})
