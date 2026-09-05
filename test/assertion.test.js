/**
 * PARA QUIÉN vale una firma, y hasta cuándo.
 *
 * Lo que estas pruebas fijan es lo que motivó la pieza: que una prueba emitida para un
 * servicio NO sirva ante otro (el cruce de destinatario, que la ventana de repetición no
 * cubría), y que no haya forma de que el verificador diga «vale» sin haber comprobado.
 */
import test from 'node:test'
import assert from 'node:assert/strict'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import { Identity } from '../src/node.js'
import {
  verifyAssertion, newAssertionNonce, assertionBody, cleanScopes, claimsAllowed,
  ASSERTION_MAX_TTL_MS, ASSERTION_DEFAULT_TTL_MS
} from '../vault/assertion.js'

const tmp = () => fs.mkdtempSync(path.join(os.tmpdir(), 'assertion-'))
const PROXIO = 'https://proxy.dotrino.com'
const GEO = 'https://geo.dotrino.com'

/** Una identidad de usar y tirar, con su directorio. */
async function conIdentidad (fn) {
  const dir = tmp()
  const id = await Identity.connect({ dir })
  try { return await fn(id) } finally { id.destroy?.(); fs.rmSync(dir, { recursive: true, force: true }) }
}

test('una prueba vale ante su destinatario', async () => {
  await conIdentidad(async (id) => {
    const nonce = newAssertionNonce()
    const a = await id.requestAssertion({ audience: PROXIO, nonce })

    assert.equal(a.aud, PROXIO)
    assert.equal(a.nonce, nonce)
    assert.deepEqual(a.scopes, ['id:whoami'], 'el mínimo es saber quién eres, y es el defecto')
    assert.deepEqual(a.claims, {}, 'el mínimo no lleva ningún dato')
    assert.equal(a.exp - a.iat, ASSERTION_DEFAULT_TTL_MS)

    const v = await verifyAssertion(a, { audience: PROXIO, nonce })
    assert.equal(v.ok, true, v.reason)
    assert.equal(v.profileId, a.sub)
    assert.equal(v.signer, id.me.publickey)
  })
})

/** El agujero que esto vino a tapar, escrito como prueba. */
test('la MISMA prueba NO vale ante otro servicio', async () => {
  await conIdentidad(async (id) => {
    const nonce = newAssertionNonce()
    const a = await id.requestAssertion({ audience: PROXIO, nonce })

    const v = await verifyAssertion(a, { audience: GEO, nonce })
    assert.equal(v.ok, false)
    assert.equal(v.reason, 'otro-destinatario')
  })
})

test('el reto ata la prueba a UNA petición', async () => {
  await conIdentidad(async (id) => {
    const a = await id.requestAssertion({ audience: PROXIO, nonce: newAssertionNonce() })
    const v = await verifyAssertion(a, { audience: PROXIO, nonce: newAssertionNonce() })
    assert.equal(v.ok, false)
    assert.equal(v.reason, 'otro-reto')
  })
})

test('sin destinatario o sin reto NO se puede juzgar, y se dice', async () => {
  await conIdentidad(async (id) => {
    const nonce = newAssertionNonce()
    const a = await id.requestAssertion({ audience: PROXIO, nonce })

    assert.equal((await verifyAssertion(a, { nonce })).reason, 'no-audience')
    assert.equal((await verifyAssertion(a, { audience: PROXIO })).reason, 'no-nonce')
    assert.equal((await verifyAssertion(a, {})).reason, 'no-audience')
    assert.equal((await verifyAssertion(a)).reason, 'no-audience', 'ni llamándola a secas')
  })
})

test('vencida es vencida: el margen de reloj es para el arranque, no para el final', async () => {
  await conIdentidad(async (id) => {
    const nonce = newAssertionNonce()
    const a = await id.requestAssertion({ audience: PROXIO, nonce, ttlMs: 60000 })

    const justo = await verifyAssertion(a, { audience: PROXIO, nonce, now: a.exp - 1 })
    assert.equal(justo.ok, true, justo.reason)

    const tarde = await verifyAssertion(a, { audience: PROXIO, nonce, now: a.exp })
    assert.equal(tarde.ok, false)
    assert.equal(tarde.reason, 'vencida')

    const muyTarde = await verifyAssertion(a, { audience: PROXIO, nonce, now: a.exp + 10 * 60 * 1000 })
    assert.equal(muyTarde.reason, 'vencida')
  })
})

test('una prueba del futuro se rechaza pasado el margen de reloj', async () => {
  await conIdentidad(async (id) => {
    const nonce = newAssertionNonce()
    const a = await id.requestAssertion({ audience: PROXIO, nonce })

    const conMargen = await verifyAssertion(a, { audience: PROXIO, nonce, now: a.iat - 30 * 1000 })
    assert.equal(conMargen.ok, true, 'medio minuto de desfase entre dos máquinas honestas')

    const lejos = await verifyAssertion(a, { audience: PROXIO, nonce, now: a.iat - 5 * 60 * 1000 })
    assert.equal(lejos.ok, false)
    assert.equal(lejos.reason, 'del-futuro')
  })
})

test('la vigencia tiene tope, y lo comprueba TAMBIÉN quien recibe', async () => {
  await conIdentidad(async (id) => {
    const nonce = newAssertionNonce()
    // Quien emite no puede pasarse aunque lo pida: se recorta al tope.
    const a = await id.requestAssertion({ audience: PROXIO, nonce, ttlMs: 365 * 24 * 3600 * 1000 })
    assert.equal(a.exp - a.iat, ASSERTION_MAX_TTL_MS)

    // Y si alguien fabricara una más larga, el que recibe la rechaza igual: fiarse del
    // `exp` del otro es fiarse de su buena fe.
    const estirada = { ...a, exp: a.iat + 400 * 24 * 3600 * 1000 }
    const v = await verifyAssertion(estirada, { audience: PROXIO, nonce })
    assert.equal(v.ok, false)
    assert.equal(v.reason, 'vigencia-excesiva')
  })
})

test('tocar el cuerpo invalida la firma', async () => {
  await conIdentidad(async (id) => {
    const nonce = newAssertionNonce()
    const a = await id.requestAssertion({ audience: PROXIO, nonce })

    // Cambiar el destinatario para que «valga» ante geo: la firma deja de cuadrar.
    const falsa = { ...a, aud: GEO }
    const v = await verifyAssertion(falsa, { audience: GEO, nonce })
    assert.equal(v.ok, false)
    assert.match(v.reason, /^firma:/)
  })
})

test('una prueba no puede atribuirse a otro perfil', async () => {
  await conIdentidad(async (id) => {
    const nonce = newAssertionNonce()
    const a = await id.requestAssertion({ audience: PROXIO, nonce })
    const suplantada = { ...a, sub: 'otra-identidad' }
    const v = await verifyAssertion(suplantada, { audience: PROXIO, nonce })
    assert.equal(v.ok, false)
    // El cuerpo cambió, así que salta ya en la firma; y si alguien resellara el cuerpo con
    // SU llave, el `sub` seguiría sin coincidir con el perfil de la cadena.
    assert.match(v.reason, /^firma:|^otro-sujeto$/)
  })
})

test('la cadena tiene que ser del perfil que se espera', async () => {
  await conIdentidad(async (id) => {
    const nonce = newAssertionNonce()
    const a = await id.requestAssertion({ audience: PROXIO, nonce })

    const propio = await verifyAssertion(a, { audience: PROXIO, nonce, expectedProfileId: a.sub })
    assert.equal(propio.ok, true, propio.reason)

    const ajeno = await verifyAssertion(a, { audience: PROXIO, nonce, expectedProfileId: 'otro' })
    assert.equal(ajeno.ok, false)
    assert.match(ajeno.reason, /^firma:cadena:/)
  })
})

test('los alcances son una lista cerrada, y los datos no salen sin el suyo', async () => {
  assert.deepEqual(cleanScopes(['profile:name', 'inventado', 'profile:name']), ['profile:name'])
  assert.deepEqual(cleanScopes(['inventado']), ['id:whoami'], 'sin nada pedible queda el mínimo')
  assert.deepEqual([...claimsAllowed(['id:whoami'])], [], 'el mínimo no permite ningún dato')

  const base = { sub: 'p', aud: PROXIO, nonce: 'n', iat: 1000, exp: 2000 }
  assert.throws(
    () => assertionBody({ ...base, scopes: ['id:whoami'], claims: { email: 'yo@ejemplo.com' } }),
    /claim "email" has no scope/,
    'llevar un dato sin su alcance no se recorta en silencio: revienta'
  )
  const ok = assertionBody({ ...base, scopes: ['profile:email'], claims: { email: 'yo@ejemplo.com' } })
  assert.deepEqual(ok.claims, { email: 'yo@ejemplo.com' })
})

test('un dato colado sin su alcance se rechaza al verificar', async () => {
  await conIdentidad(async (id) => {
    const nonce = newAssertionNonce()
    const a = await id.requestAssertion({ audience: PROXIO, nonce })
    const colada = { ...a, claims: { email: 'yo@ejemplo.com' } }
    const v = await verifyAssertion(colada, { audience: PROXIO, nonce })
    assert.equal(v.ok, false)
    assert.equal(v.reason, 'claim-sin-alcance')
  })
})

test('lo que se pide es lo que se firma, y viaja lo que el perfil ya comparte', async () => {
  await conIdentidad(async (id) => {
    await id.updateMe({ nickname: 'Ada', email: 'ada@ejemplo.com' })
    const nonce = newAssertionNonce()
    const a = await id.requestAssertion({ audience: PROXIO, nonce, scopes: ['profile:name', 'profile:email'] })

    assert.deepEqual(a.scopes, ['profile:email', 'profile:name'], 'orden estable: se firma canónicamente')
    assert.equal(a.claims.name, 'Ada')
    assert.equal(a.claims.email, 'ada@ejemplo.com')
    assert.equal(a.claims.avatar, undefined, 'lo que no se pidió no va')

    const v = await verifyAssertion(a, { audience: PROXIO, nonce })
    assert.equal(v.ok, true, v.reason)
    assert.equal(v.claims.name, 'Ada')
  })
})

test('emitir sin destinatario o sin reto no es posible', async () => {
  await conIdentidad(async (id) => {
    await assert.rejects(() => id.requestAssertion({ nonce: newAssertionNonce() }), /audience required/)
    await assert.rejects(() => id.requestAssertion({ audience: PROXIO }), /nonce required/)
    await assert.rejects(() => id.requestAssertion({ audience: '   ', nonce: 'n' }), /audience required/)
  })
})

test('basura no pasa por prueba', async () => {
  const args = { audience: PROXIO, nonce: 'n' }
  for (const mala of [null, undefined, 42, 'texto', {}, { v: 1 }, { v: 2, op: 'assertion' }]) {
    const v = await verifyAssertion(/** @type {any} */ (mala), args)
    assert.equal(v.ok, false)
    assert.equal(v.reason, 'shape', JSON.stringify(mala))
  }
})
