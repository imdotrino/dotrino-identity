/**
 * LOS APARATOS MUERTOS SALEN DEL ACTA al abrir la bóveda, en UNA sola acta (dueño,
 * 2026-09-22). Muerto = todos sus certificados de esta bóveda son del modelo viejo y ya no
 * valen; renovar no los salva, porque la renovación va firmada con ese mismo papel.
 */
import test from 'node:test'
import assert from 'node:assert/strict'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import crypto from 'node:crypto'
import { Identity, makeDeviceKey } from '../src/node.js'
import { LEGACY_CERTS_UNTIL } from '../vault/capabilities.js'

const tmp = () => fs.mkdtempSync(path.join(os.tmpdir(), 'muertos-'))

/** Candado de mentira, como el de `maestra-bajo-llave.test.js`: `abierto` decide si abre. */
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
      if (!st.abierto) return null
      const [iv, ct] = String(blob).split('.')
      const buf = Buffer.from(ct, 'base64')
      const d = crypto.createDecipheriv('aes-256-gcm', kdf('k'), Buffer.from(iv, 'base64'))
      d.setAuthTag(buf.subarray(buf.length - 16))
      return Buffer.concat([d.update(buf.subarray(0, buf.length - 16)), d.final()]).toString('utf8')
    }
  }
}

/**
 * Convierte en papel del MODELO VIEJO los certificados de `sub`, como los dejaba la
 * bóveda antes de identity 0.73: sin `seq` y con `exp`. Se toca el archivo en disco
 * porque ya no hay forma de emitirlos así — que es justo el motivo de la prueba.
 */
function aLegado (dir, sub, exp) {
  for (const f of fs.readdirSync(dir).filter((x) => x.endsWith('.json'))) {
    const file = path.join(dir, f)
    let data
    try { data = JSON.parse(fs.readFileSync(file, 'utf8')) } catch (_) { continue }
    let tocado = false
    for (const [k, v] of Object.entries(data)) {
      if (!k.endsWith('delegations')) continue
      const store = JSON.parse(v)
      for (const d of Object.values(store)) {
        if (d.sub !== sub) continue
        delete d.seq
        d.exp = exp
        tocado = true
      }
      data[k] = JSON.stringify(store)
    }
    if (tocado) { fs.writeFileSync(file, JSON.stringify(data)); return }
  }
  throw new Error('no delegations file found for the test')
}

async function conDosAparatos () {
  const dir = tmp()
  const id = await Identity.connect({ dir })
  const muerto = await makeDeviceKey({ label: 'Teléfono viejo' })
  const vivo = await makeDeviceKey({ label: 'Portátil' })
  await id.admitMember({ pub: muerto.publickey, label: 'Teléfono viejo', caps: ['store', 'read'] })
  await id.admitMember({ pub: vivo.publickey, label: 'Portátil', caps: ['store', 'read'] })
  await id.signDelegation(muerto.publickey, ['vault:read'], { label: 'Teléfono viejo' })
  await id.signDelegation(vivo.publickey, ['vault:read'], { label: 'Portátil' })
  return { dir, id, muerto, vivo }
}

test('un papel viejo y vencido saca al aparato del acta; uno vigente no se toca', async () => {
  const { dir, id, muerto, vivo } = await conDosAparatos()
  id.destroy()
  aLegado(dir, muerto.publickey, Date.now() - 1000)
  const b = await Identity.connect({ dir })

  const antes = await b.profileMembers()
  const r = await b.pruneExpiredDevices()

  assert.deepEqual(r.removed.map((m) => m.pub), [muerto.publickey])
  assert.equal(r.removed[0].label, 'Teléfono viejo')
  const { members, seq } = await b.profileMembers()
  assert.equal(seq, antes.seq + 1, 'las bajas y la clave nueva van en UNA acta')
  assert.ok(!members.some((m) => m.pub === muerto.publickey), 'el muerto ya no es miembro')
  assert.ok(members.some((m) => m.pub === vivo.publickey), 'el vivo sigue')
  const { issued } = await b.listDelegations()
  assert.ok(!issued.some((d) => d.sub === muerto.publickey), 'y su papel ya no sale como vigente')
  assert.ok(issued.some((d) => d.sub === vivo.publickey))
  fs.rmSync(dir, { recursive: true, force: true })
})

test('un papel viejo que TODAVÍA vale no se quita (se renueva, no se poda)', async () => {
  const { dir, id, muerto } = await conDosAparatos()
  id.destroy()
  aLegado(dir, muerto.publickey, Date.now() + 86400000)
  const b = await Identity.connect({ dir })
  const antes = await b.profileMembers()
  const r = await b.pruneExpiredDevices(Math.min(Date.now(), LEGACY_CERTS_UNTIL - 1))
  assert.deepEqual(r.removed, [])
  assert.equal((await b.profileMembers()).seq, antes.seq, 'sin nada que quitar, no se sella nada')
  fs.rmSync(dir, { recursive: true, force: true })
})

test('pasado el corte, todo papel viejo está muerto aunque su fecha diga otra cosa', async () => {
  const { dir, id, muerto, vivo } = await conDosAparatos()
  id.destroy()
  aLegado(dir, muerto.publickey, LEGACY_CERTS_UNTIL + 30 * 86400000)
  const b = await Identity.connect({ dir })
  const r = await b.pruneExpiredDevices(LEGACY_CERTS_UNTIL + 1000)
  assert.deepEqual(r.removed.map((m) => m.pub), [muerto.publickey])
  assert.ok((await b.profileMembers()).members.some((m) => m.pub === vivo.publickey),
    'un papel del modelo nuevo no caduca por el corte')
  fs.rmSync(dir, { recursive: true, force: true })
})

test('con la maestra cerrada no se firma nada', async () => {
  const lock = candado()
  const dir = tmp()
  const id = await Identity.connect({ dir, keyLock: lock })
  const muerto = await makeDeviceKey({ label: 'Teléfono viejo' })
  await id.admitMember({ pub: muerto.publickey, label: 'Teléfono viejo', caps: ['store', 'read'] })
  await id.signDelegation(muerto.publickey, ['vault:read'], { label: 'Teléfono viejo' })
  id.destroy()
  aLegado(dir, muerto.publickey, Date.now() - 1000)

  lock.st.abierto = false
  const b = await Identity.connect({ dir, keyLock: lock })
  assert.equal(b.masterLocked, true)
  const antes = await b.profileMembers()
  const r = await b.pruneExpiredDevices()
  assert.deepEqual(r.removed, [], 'cerrada no quita nada')
  assert.equal((await b.profileMembers()).seq, antes.seq)

  // Y al abrir, sí.
  lock.st.abierto = true
  await b.reloadMasterKey()
  const r2 = await b.pruneExpiredDevices()
  assert.deepEqual(r2.removed.map((m) => m.pub), [muerto.publickey])
  fs.rmSync(dir, { recursive: true, force: true })
})
