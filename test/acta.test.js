/**
 * El acta de perfil: sellador único, cadena `seq`/`prev`, capacidades, renuncia y el
 * caso feo del master obsoleto. Todo sin red ni disco (módulo puro).
 */
import test from 'node:test'
import assert from 'node:assert/strict'
import {
  genesisActa, sealActa, verifyActa, applyChanges, actaHash, canAdopt, isHandover,
  makeRenounce, verifyRenounce, effectiveCaps, memberCan, CAPS, DEVICE_CAPS,
  memberCanReadSecrets, memberScopes, isService
} from '../vault/acta.js'

/** Una llave de miembro (extractable, para poder firmar en el test con privateJwk). */
async function key () {
  const pair = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify'])
  const privateJwk = await crypto.subtle.exportKey('jwk', pair.privateKey)
  const publicJwk = await crypto.subtle.exportKey('jwk', pair.publicKey)
  return { pub: JSON.stringify(publicJwk), privateJwk }
}

/** Atajo: aplica cambios y sella con la llave de quien es master. */
async function step (acta, changes, who) {
  const next = await applyChanges(acta, changes, { by: who.pub })
  return sealActa({ acta: next, privateJwk: who.privateJwk })
}

test('génesis: un miembro, es el master, y verifica', async () => {
  const a = await key()
  const acta = await sealActa({ acta: genesisActa({ pub: a.pub, label: 'PC' }), privateJwk: a.privateJwk })

  assert.equal((await verifyActa({ acta })).ok, true)
  assert.equal(acta.profileId, a.pub, 'el perfil se llama como su primera llave')
  assert.equal(acta.sealer, a.pub)
  assert.equal(acta.sealedBy, a.pub)
  assert.equal(acta.seq, 1)
  assert.deepEqual(acta.members[0].caps, [...DEVICE_CAPS], 'el dueño nace como dispositivo: acceso a todo lo suyo')
  assert.equal(acta.members[0].cn, null, 'y sin CN, porque no es un servicio')
  assert.equal(isHandover(acta), false)
})

test('admitir: solo el master puede, y la cadena encadena', async () => {
  const a = await key(); const b = await key()
  const g = await sealActa({ acta: genesisActa({ pub: a.pub }), privateJwk: a.privateJwk })

  const dos = await step(g, [{ op: 'admit', member: { pub: b.pub, label: 'Celular', caps: ['store', 'read'] } }], a)
  assert.equal((await verifyActa({ acta: dos })).ok, true)
  assert.equal(dos.seq, 2)
  assert.equal(dos.prev, await actaHash(g), 'prev apunta al acta anterior')
  assert.deepEqual(effectiveCaps(dos, b.pub), ['read', 'store'])
  assert.equal(memberCan(dos, b.pub, 'sign'), false)

  // …y quien no es master no puede cambiar nada.
  await assert.rejects(
    () => applyChanges(dos, [{ op: 'caps', pub: b.pub, caps: [...CAPS] }], { by: b.pub }),
    /no lo es/
  )
})

test('no se puede dejar el perfil sin nadie que firme, ni expulsar al master', async () => {
  const a = await key(); const b = await key()
  const g = await sealActa({ acta: genesisActa({ pub: a.pub }), privateJwk: a.privateJwk })
  const dos = await step(g, [{ op: 'admit', member: { pub: b.pub, caps: ['read'] } }], a)

  await assert.rejects(() => applyChanges(dos, [{ op: 'caps', pub: a.pub, caps: ['read'] }], { by: a.pub }), /sin ningún miembro que pueda firmar/)
  await assert.rejects(() => applyChanges(dos, [{ op: 'remove', pub: a.pub }], { by: a.pub }), /no puedes expulsar al master/)
})

test('traspaso: admitir y nombrar master van en el MISMO seq', async () => {
  const disp = await key(); const vault = await key()
  const g = await sealActa({ acta: genesisActa({ pub: disp.pub, label: 'Celular' }), privateJwk: disp.privateJwk })

  const traspaso = await step(g, [
    { op: 'admit', member: { pub: vault.pub, label: 'Bóveda', caps: [...CAPS] } },
    { op: 'handover', to: vault.pub }
  ], disp)

  assert.equal((await verifyActa({ acta: traspaso })).ok, true, 'la firma es del SALIENTE y verifica')
  assert.equal(traspaso.sealedBy, disp.pub, 'la firmó el master saliente')
  assert.equal(traspaso.sealer, vault.pub, 'el master pasa a ser la bóveda')
  assert.equal(isHandover(traspaso), true)
  assert.equal(traspaso.profileId, disp.pub, 'el perfil sigue llamándose igual')

  // El saliente ya no puede sellar nada.
  await assert.rejects(() => applyChanges(traspaso, [{ op: 'caps', pub: disp.pub, caps: ['read'] }], { by: disp.pub }), /no lo es/)
  // El entrante sí.
  const cuatro = await step(traspaso, [{ op: 'caps', pub: disp.pub, caps: ['store', 'read'] }], vault)
  assert.deepEqual(effectiveCaps(cuatro, disp.pub), ['read', 'store'])
})

test('MASTER OBSOLETO: a igual seq gana el acta que traspasa', async () => {
  const a = await key(); const b = await key()
  const g = await sealActa({ acta: genesisActa({ pub: a.pub }), privateJwk: a.privateJwk })

  // La buena: A traspasa a B.
  const traspaso = await step(g, [
    { op: 'admit', member: { pub: b.pub, caps: [...CAPS] } },
    { op: 'handover', to: b.pub }
  ], a)
  // La mala: A restaurado de un respaldo sella su propio seq 2, creyéndose master.
  const fantasma = await step(g, [{ op: 'admit', member: { pub: b.pub, caps: ['read'] } }], a)

  assert.equal(traspaso.seq, fantasma.seq, 'mismo seq: es el empate que hay que romper')

  const gana = await canAdopt({ candidate: traspaso, current: fantasma })
  assert.equal(gana.adopt, true)
  assert.equal(gana.reason, 'traspaso-gana')

  const pierde = await canAdopt({ candidate: fantasma, current: traspaso })
  assert.equal(pierde.adopt, false)
  assert.equal(pierde.reason, 'traspaso-gana')
})

test('adopción: nunca hacia atrás, ni sin encadenar, ni de un sellador no autorizado', async () => {
  const a = await key(); const b = await key(); const intruso = await key()
  const g = await sealActa({ acta: genesisActa({ pub: a.pub }), privateJwk: a.privateJwk })
  const dos = await step(g, [{ op: 'admit', member: { pub: b.pub, caps: ['read'] } }], a)

  assert.equal((await canAdopt({ candidate: dos, current: g })).adopt, true)
  assert.equal((await canAdopt({ candidate: g, current: dos })).adopt, false, 'seq menor: jamás')
  assert.equal((await canAdopt({ candidate: dos, current: dos })).reason, 'misma-acta')

  // Un acta bien formada y bien firmada… pero por alguien que no es el master vigente.
  const falsa = await sealActa({ acta: { ...dos, seq: 3, prev: await actaHash(dos), sealedBy: intruso.pub }, privateJwk: intruso.privateJwk })
  assert.equal((await verifyActa({ acta: falsa })).ok, true, 'la firma cuadra con quien dice haberla sellado…')
  assert.equal((await canAdopt({ candidate: falsa, current: dos })).reason, 'sellador-no-autorizado', '…pero ese no era el master')

  // Contigua pero con `prev` que no corresponde.
  const rota = await sealActa({ acta: { ...dos, seq: 3, prev: 'a'.repeat(64) }, privateJwk: a.privateJwk })
  assert.equal((await canAdopt({ candidate: rota, current: dos })).reason, 'no-encadena')
})

test('firma manipulada: el acta deja de verificar', async () => {
  const a = await key(); const b = await key()
  const g = await sealActa({ acta: genesisActa({ pub: a.pub }), privateJwk: a.privateJwk })
  const dos = await step(g, [{ op: 'admit', member: { pub: b.pub, caps: ['read'] } }], a)

  const manipulada = { ...dos, members: dos.members.map((m) => m.pub === b.pub ? { ...m, caps: [...CAPS] } : m) }
  assert.equal((await verifyActa({ acta: manipulada })).ok, false, 'darse capacidades a mano rompe la firma')
})

test('renuncia: unilateral, solo quita, y no la puede falsificar otro', async () => {
  const a = await key(); const b = await key()
  const g = await sealActa({ acta: genesisActa({ pub: a.pub }), privateJwk: a.privateJwk })
  const dos = await step(g, [{ op: 'admit', member: { pub: b.pub, caps: [...CAPS] } }], a)

  const r = await makeRenounce({ member: b.pub, caps: ['sign'], privateJwk: b.privateJwk })
  assert.equal(await verifyRenounce(r), true)
  assert.deepEqual(effectiveCaps(dos, b.pub, [r]), ['read', 'store'], 'se honra sin tocar el acta')

  // Falsificada por otro miembro: no vale.
  const falsa = await makeRenounce({ member: b.pub, caps: ['sign'], privateJwk: a.privateJwk })
  assert.equal(await verifyRenounce(falsa), false)

  // El master la absorbe: queda en el acta y el seq avanza.
  const tres = await step(dos, [{ op: 'renounce', record: r }], a)
  assert.deepEqual(effectiveCaps(tres, b.pub), ['read', 'store'])
  assert.equal(tres.renounced.length, 1)
})

test('una renuncia no puede dejar al perfil sin firmante al absorberse', async () => {
  const a = await key()
  const g = await sealActa({ acta: genesisActa({ pub: a.pub }), privateJwk: a.privateJwk })
  const r = await makeRenounce({ member: a.pub, caps: ['sign'], privateJwk: a.privateJwk })
  await assert.rejects(() => applyChanges(g, [{ op: 'renounce', record: r }], { by: a.pub }), /sin ningún miembro que pueda firmar/)
})

test('revocaciones: se apuntan y se podan solas al vencer', async () => {
  const a = await key(); const b = await key()
  const g = await sealActa({ acta: genesisActa({ pub: a.pub }), privateJwk: a.privateJwk })
  const dos = await step(g, [
    { op: 'admit', member: { pub: b.pub, caps: ['read'] } },
    { op: 'revoke', nonce: 'viva', until: Date.now() + 60000 },
    { op: 'revoke', nonce: 'vencida', until: Date.now() - 60000 }
  ], a)
  assert.deepEqual(dos.revoked.map((r) => r.nonce), ['viva'])
})

test('CN: un servicio solo abre SU cajón, y no puede tener permisos de dispositivo', async () => {
  const a = await key(); const proxy = await key(); const geo = await key()
  const g = await sealActa({ acta: genesisActa({ pub: a.pub, label: 'PC' }), privateJwk: a.privateJwk })

  // Se admiten dos servicios, cada uno con su nombre.
  const dos = await step(g, [
    { op: 'admit', member: { pub: proxy.pub, cn: 'proxy', label: 'proxy', caps: ['secrets'] } },
    { op: 'admit', member: { pub: geo.pub, cn: 'geo', label: 'geo', caps: ['secrets'] } }
  ], a)

  assert.equal(isService(dos, proxy.pub), true)
  assert.equal(isService(dos, a.pub), false, 'el dueño es un dispositivo, no un servicio')

  // La frontera: el proxy solo ve lo del proxy.
  assert.equal(memberCanReadSecrets(dos, proxy.pub, 'proxy'), true)
  assert.equal(memberCanReadSecrets(dos, proxy.pub, 'geo'), false, 'no ve el cajón de otro')
  assert.equal(memberCanReadSecrets(dos, a.pub, 'proxy'), false, 'un dispositivo no tiene cajón')
  assert.deepEqual(memberScopes(dos, proxy.pub), ['vault:secrets:proxy'])

  // Y no se le pueden dar permisos de dispositivo, ni al admitirlo ni después.
  const tres = await step(dos, [{ op: 'caps', pub: proxy.pub, caps: ['sign', 'store', 'read', 'secrets'] }], a)
  assert.deepEqual(effectiveCaps(tres, proxy.pub), ['secrets'], 'un servicio no se asciende cambiándole permisos')

  const cuatro = await step(tres, [{ op: 'admit', member: { pub: (await key()).pub, cn: 'bot', caps: ['sign', 'secrets'] } }], a)
  assert.deepEqual(cuatro.members.at(-1).caps, ['secrets'])
})

test('CN inválido o mezclado: el acta no cuadra', async () => {
  const a = await key(); const x = await key()
  const g = await sealActa({ acta: genesisActa({ pub: a.pub }), privateJwk: a.privateJwk })

  await assert.rejects(
    () => applyChanges(g, [{ op: 'admit', member: { pub: x.pub, cn: 'Proxy Mayúsculas', caps: ['secrets'] } }], { by: a.pub }),
    /CN inválido/
  )
  // Un acta escrita a mano que mezcle las dos cosas no pasa la comprobación de forma.
  const mezclada = { ...g, members: [...g.members, { pub: x.pub, cn: 'proxy', caps: ['sign', 'secrets'], addedAt: Date.now() }] }
  assert.equal((await verifyActa({ acta: mezclada })).reason, 'servicio-con-capacidades-de-dispositivo')
  // Y `secrets` sin CN tampoco.
  const sinCn = { ...g, members: [...g.members, { pub: x.pub, cn: null, caps: ['secrets'], addedAt: Date.now() }] }
  assert.equal((await verifyActa({ acta: sinCn })).reason, 'secretos-sin-cn')
})
