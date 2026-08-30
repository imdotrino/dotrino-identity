/**
 * El acta de perfil: sellador único, cadena `seq`/`prev`, capacidades, renuncia y el
 * caso feo del master obsoleto. Todo sin red ni disco (módulo puro).
 */
import test from 'node:test'
import assert from 'node:assert/strict'
import {
  genesisActa, sealActa, verifyActa, applyChanges, actaHash, canAdopt, isHandover,
  makeRenounce, verifyRenounce, effectiveCaps, memberCan, CAPS, DEVICE_CAPS,
  memberCanReadSecrets, memberScopes, isService, PAIRED_CAPS, capScope, checkShape
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
  assert.deepEqual(acta.members[0].caps, [...PAIRED_CAPS], 'el dueño nace como dispositivo: acceso a todo lo suyo')
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
    /not the master/
  )
})

test('no se puede dejar el perfil sin nadie que firme, ni expulsar al master', async () => {
  const a = await key(); const b = await key()
  const g = await sealActa({ acta: genesisActa({ pub: a.pub }), privateJwk: a.privateJwk })
  const dos = await step(g, [{ op: 'admit', member: { pub: b.pub, caps: ['read'] } }], a)

  await assert.rejects(() => applyChanges(dos, [{ op: 'caps', pub: a.pub, caps: ['read'] }], { by: a.pub }), /no member able to sign/)
  await assert.rejects(() => applyChanges(dos, [{ op: 'remove', pub: a.pub }], { by: a.pub }), /cannot remove the master/)
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
  await assert.rejects(() => applyChanges(traspaso, [{ op: 'caps', pub: disp.pub, caps: ['read'] }], { by: disp.pub }), /not the master/)
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
  // `sealer` entra en la lista desde 2026-08-30: sellar es un permiso de aparato, y este
  // miembro los tiene todos. De paso queda probado que una bóveda puede RENUNCIAR a sellar.
  assert.deepEqual(effectiveCaps(dos, b.pub, [r]), ['admin', 'approve', 'passwords', 'read', 'sealer', 'store'], 'se honra sin tocar el acta')

  // Falsificada por otro miembro: no vale.
  const falsa = await makeRenounce({ member: b.pub, caps: ['sign'], privateJwk: a.privateJwk })
  assert.equal(await verifyRenounce(falsa), false)

  // El master la absorbe: queda en el acta y el seq avanza.
  const tres = await step(dos, [{ op: 'renounce', record: r }], a)
  assert.deepEqual(effectiveCaps(tres, b.pub), ['admin', 'approve', 'passwords', 'read', 'sealer', 'store'])
  assert.equal(tres.renounced.length, 1)
})

test('una renuncia no puede dejar al perfil sin firmante al absorberse', async () => {
  const a = await key()
  const g = await sealActa({ acta: genesisActa({ pub: a.pub }), privateJwk: a.privateJwk })
  const r = await makeRenounce({ member: a.pub, caps: ['sign'], privateJwk: a.privateJwk })
  await assert.rejects(() => applyChanges(g, [{ op: 'renounce', record: r }], { by: a.pub }), /no member able to sign/)
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

test('CN: un miembro con cajón abre SU cajón; lo demás son permisos que se le dan o no', async () => {
  const a = await key(); const proxy = await key(); const geo = await key()
  const g = await sealActa({ acta: genesisActa({ pub: a.pub, label: 'PC' }), privateJwk: a.privateJwk })

  // Se admiten dos servicios, cada uno con su nombre y solo su cajón.
  const dos = await step(g, [
    { op: 'admit', member: { pub: proxy.pub, cn: 'proxy', label: 'proxy', caps: ['secrets'] } },
    { op: 'admit', member: { pub: geo.pub, cn: 'geo', label: 'geo', caps: ['secrets'] } }
  ], a)

  assert.equal(isService(dos, proxy.pub), true)
  assert.equal(isService(dos, a.pub), false, 'el dueño es un dispositivo, no un servicio')

  // La frontera del cajón: el proxy solo ve lo del proxy.
  assert.equal(memberCanReadSecrets(dos, proxy.pub, 'proxy'), true)
  assert.equal(memberCanReadSecrets(dos, proxy.pub, 'geo'), false, 'no ve el cajón de otro')
  assert.equal(memberCanReadSecrets(dos, a.pub, 'proxy'), false, 'un dispositivo no tiene cajón')
  assert.deepEqual(memberScopes(dos, proxy.pub), ['vault:secrets:proxy'])

  // PERMISOS, no tipos (2026-08-22): el cajón no recorta lo demás. Un miembro con CN puede
  // llevar además capacidades de aparato — al admitirlo o después —, y siguen siendo
  // exactamente las que se le dieron, ni una más.
  const tres = await step(dos, [{ op: 'caps', pub: proxy.pub, caps: ['sign', 'secrets'] }], a)
  assert.deepEqual([...effectiveCaps(tres, proxy.pub)].sort(), ['secrets', 'sign'])
  assert.deepEqual([...memberScopes(tres, proxy.pub)].sort(), ['vault:secrets:proxy', 'vault:sign'])
  assert.equal(memberCanReadSecrets(tres, proxy.pub, 'geo'), false, 'firmar no le abre otros cajones')

  const bot = await key()
  const cuatro = await step(tres, [{ op: 'admit', member: { pub: bot.pub, cn: 'bot', caps: ['sign', 'secrets'] } }], a)
  assert.deepEqual([...cuatro.members.at(-1).caps].sort(), ['secrets', 'sign'])
})

test('CN inválido o mezclado: el acta no cuadra', async () => {
  const a = await key(); const x = await key()
  const g = await sealActa({ acta: genesisActa({ pub: a.pub }), privateJwk: a.privateJwk })

  await assert.rejects(
    () => applyChanges(g, [{ op: 'admit', member: { pub: x.pub, cn: 'Proxy Mayúsculas', caps: ['secrets'] } }], { by: a.pub }),
    /invalid CN/
  )
  // Un acta escrita a mano que mezcle las dos cosas no pasa la comprobación de forma.
  // Un miembro con cajón SÍ puede llevar permisos de aparato (permisos, no tipos): eso cuadra.
  const mezclada = { ...g, members: [...g.members, { pub: x.pub, cn: 'proxy', caps: ['sign', 'secrets'], addedAt: Date.now() }] }
  assert.notEqual((await verifyActa({ acta: mezclada })).reason, 'servicio-con-capacidades-de-dispositivo')
  // Y `secrets` sin CN tampoco.
  const sinCn = { ...g, members: [...g.members, { pub: x.pub, cn: null, caps: ['secrets'], addedAt: Date.now() }] }
  assert.equal((await verifyActa({ acta: sinCn })).reason, 'secretos-sin-cn')
})

// --- La capacidad `admin` (consola remota, dotrino-vault/docs/consola-remota.md) ---

test('admin: es de dispositivo, tiene su scope y no se empareja sola', async () => {
  const a = await key(); const b = await key()
  const g = await sealActa({ acta: genesisActa({ pub: a.pub }), privateJwk: a.privateJwk })

  assert.equal(capScope('admin'), 'vault:admin')
  assert.ok(DEVICE_CAPS.includes('admin'), 'un dispositivo puede administrar')
  assert.ok(!PAIRED_CAPS.includes('admin'), 'pero NO se recibe al emparejar: se concede después')
  assert.deepEqual([...g.members[0].caps], [...PAIRED_CAPS], 'la génesis nace sin admin explícita')

  const dos = await step(g, [{ op: 'admit', member: { pub: b.pub, caps: ['read', 'admin'] } }], a)
  assert.ok(memberCan(dos, b.pub, 'admin'))
  assert.ok(memberScopes(dos, b.pub).includes('vault:admin'))
})

/**
 * `passwords` — el gestor de contraseñas. Es un permiso del acta y no una lista aparte
 * de la bóveda: quitar un aparato tiene que ser un solo acto, en un solo sitio.
 */
test('passwords: es de dispositivo, tiene su scope y NO viene con el emparejamiento por defecto', async () => {
  const a = await key(); const b = await key()
  const g = await sealActa({ acta: genesisActa({ pub: a.pub }), privateJwk: a.privateJwk })

  assert.equal(capScope('passwords'), 'vault:passwords')
  assert.ok(DEVICE_CAPS.includes('passwords'), 'un aparato puede pedir contraseñas')
  assert.ok(!PAIRED_CAPS.includes('passwords'), 'pero no lo recibe cualquier aparato por emparejarse')

  // Estar en el acta NO basta: hay que tener el permiso.
  const soloLee = await step(g, [{ op: 'admit', member: { pub: b.pub, caps: ['read'] } }], a)
  assert.equal(memberCan(soloLee, b.pub, 'passwords'), false, 'estar en el acta bastaba para pedir contraseñas')

  const conPermiso = await step(g, [{ op: 'admit', member: { pub: b.pub, caps: ['read', 'passwords'] } }], a)
  assert.ok(memberCan(conPermiso, b.pub, 'passwords'))
  assert.ok(memberScopes(conPermiso, b.pub).includes('vault:passwords'))
})

test('admin: un miembro con cajón solo administra si el master se lo da, como cualquier aparato', async () => {
  const a = await key(); const x = await key()
  const g = await sealActa({ acta: genesisActa({ pub: a.pub }), privateJwk: a.privateJwk })

  // Es un permiso más: entra solo si el master lo sella, y se ve en el acta.
  const dos = await step(g, [{ op: 'admit', member: { pub: x.pub, cn: 'proxy', caps: ['secrets'] } }], a)
  assert.deepEqual(dos.members.at(-1).caps, ['secrets'])
  const tres = await step(dos, [{ op: 'caps', pub: x.pub, caps: ['secrets', 'admin'] }], a)
  assert.deepEqual([...effectiveCaps(tres, x.pub)].sort(), ['admin', 'secrets'])

  // Lo que NO pasa la forma es una capacidad que no existe.
  const rara = { ...g, members: [...g.members, { pub: x.pub, cn: 'proxy', caps: ['secrets', 'vuela'], addedAt: Date.now() }] }
  assert.equal((await verifyActa({ acta: rara })).reason, 'cap-desconocida')
})

test('admin: se puede renunciar (solo quita) y quitar desde el master', async () => {
  const a = await key(); const b = await key()
  const g = await sealActa({ acta: genesisActa({ pub: a.pub }), privateJwk: a.privateJwk })
  const dos = await step(g, [{ op: 'admit', member: { pub: b.pub, caps: ['read', 'admin'] } }], a)

  const r = await makeRenounce({ member: b.pub, caps: ['admin'], privateJwk: b.privateJwk })
  assert.deepEqual(effectiveCaps(dos, b.pub, [r]), ['read'], 'renunciar a administrar es unilateral')

  const tres = await step(dos, [{ op: 'caps', pub: b.pub, caps: ['read'] }], a)
  assert.ok(!memberCan(tres, b.pub, 'admin'), 'el master se la quita')
})

test('renombrar un miembro: cambia el nombre y no toca nada más', async () => {
  const a = await key(); const b = await key()
  const g = await sealActa({ acta: genesisActa({ pub: a.pub }), privateJwk: a.privateJwk })
  const dos = await step(g, [{ op: 'admit', member: { pub: b.pub, label: 'Seyacat', caps: ['store', 'read'] } }], a)
  const antes = dos.members.find((m) => m.pub === b.pub)
  assert.equal(antes.label, 'Seyacat', 'entró con el apodo que tenía el usuario ese día')

  const tres = await step(dos, [{ op: 'label', pub: b.pub, label: 'Teléfono de casa' }], a)
  const m = tres.members.find((m) => m.pub === b.pub)
  assert.equal(m.label, 'Teléfono de casa', 'el nombre cambió')
  assert.deepEqual(m.caps, antes.caps, 'los permisos NO se tocan')
  assert.equal(m.cn, antes.cn, 'ni si es un servicio')
  assert.equal((await verifyActa({ acta: tres })).ok, true, 'y el acta sigue verificando')
})

test('renombrar: tope de 60, y a quien no está en el acta se le dice que no', async () => {
  const a = await key(); const b = await key()
  const g = await sealActa({ acta: genesisActa({ pub: a.pub }), privateJwk: a.privateJwk })
  const dos = await step(g, [{ op: 'admit', member: { pub: b.pub, label: 'x', caps: ['read'] } }], a)
  const tres = await step(dos, [{ op: 'label', pub: b.pub, label: 'z'.repeat(200) }], a)
  assert.equal(tres.members.find((m) => m.pub === b.pub).label.length, 60)
  await assert.rejects(
    () => applyChanges(tres, [{ op: 'label', pub: 'no-existe', label: 'x' }], { by: a.pub }),
    /not in the record/
  )
})

test('renombrar: solo el master', async () => {
  const a = await key(); const b = await key()
  const g = await sealActa({ acta: genesisActa({ pub: a.pub }), privateJwk: a.privateJwk })
  const dos = await step(g, [{ op: 'admit', member: { pub: b.pub, label: 'x', caps: ['read'] } }], a)
  await assert.rejects(() => applyChanges(dos, [{ op: 'label', pub: a.pub, label: 'mio' }], { by: b.pub }), /not the master/)
})

test('conceder de nuevo LIMPIA la renuncia (o sería irreversible)', async () => {
  const a = await key(); const b = await key()
  const g = await sealActa({ acta: genesisActa({ pub: a.pub }), privateJwk: a.privateJwk })
  const dos = await step(g, [{ op: 'admit', member: { pub: b.pub, label: 'móvil', caps: ['sign', 'store', 'read'] } }], a)

  // El miembro renuncia a firmar (no pasa por el master: funciona con la bóveda apagada).
  const rec = await makeRenounce({ member: b.pub, caps: ['sign'], privateJwk: b.privateJwk })
  const tres = await step(dos, [{ op: 'renounce', record: rec }], a)
  assert.ok(!effectiveCaps(tres, b.pub).includes('sign'), 'ya no firma')

  // Y el master se lo devuelve. Antes esto NO servía de nada: effectiveCaps seguía
  // restando la renuncia y el permiso no volvía nunca.
  const cuatro = await step(tres, [{ op: 'caps', pub: b.pub, caps: ['sign', 'store', 'read'] }], a)
  assert.ok(effectiveCaps(cuatro, b.pub).includes('sign'), 'el master puede devolvérselo')
  assert.equal(cuatro.renounced.filter((r) => r.member === b.pub).length, 0, 'y la renuncia se limpia')
  assert.equal((await verifyActa({ acta: cuatro })).ok, true)
})

test('conceder OTRA cosa no borra una renuncia que sigue en pie', async () => {
  const a = await key(); const b = await key()
  const g = await sealActa({ acta: genesisActa({ pub: a.pub }), privateJwk: a.privateJwk })
  const dos = await step(g, [{ op: 'admit', member: { pub: b.pub, caps: ['sign', 'read'] } }], a)
  const rec = await makeRenounce({ member: b.pub, caps: ['sign'], privateJwk: b.privateJwk })
  const tres = await step(dos, [{ op: 'renounce', record: rec }], a)
  // Le dan `store`, que no es lo que renunció: la renuncia a firmar sigue.
  const cuatro = await step(tres, [{ op: 'caps', pub: b.pub, caps: ['read', 'store'] }], a)
  assert.ok(!effectiveCaps(cuatro, b.pub).includes('sign'), 'sigue sin firmar')
  assert.equal(cuatro.renounced.filter((r) => r.member === b.pub).length, 1, 'la renuncia sigue escrita')
})

// --- Llave de CIFRADO del miembro (`encPub`) ---------------------------------

/** Una llave de cifrado (ECDH P-256) como la que registra un servicio. */
async function encKey () {
  const pair = await crypto.subtle.generateKey({ name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveBits'])
  const j = await crypto.subtle.exportKey('jwk', pair.publicKey)
  return JSON.stringify({ kty: j.kty, crv: j.crv, x: j.x, y: j.y })
}

test('encPub: se valida la FORMA, y se acepta que falte', async () => {
  const a = await key(); const s = await key()
  const g = await sealActa({ acta: genesisActa({ pub: a.pub, label: 'PC' }), privateJwk: a.privateJwk })

  // Sin llave: se admite igual. Es lo que permite que un acta anterior a esto siga
  // verificando en vez de dejar el vault sin arrancar.
  const sinLlave = await step(g, [{ op: 'admit', member: { pub: s.pub, cn: 'proxy', caps: ['secrets'] } }], a)
  assert.equal((await verifyActa({ acta: sinLlave })).ok, true)
  assert.equal(sinLlave.members.find((m) => m.pub === s.pub).encPub, null)

  // Con llave válida: entra tal cual.
  const enc = await encKey()
  const b = await key()
  const conLlave = await step(g, [{ op: 'admit', member: { pub: b.pub, cn: 'geo', caps: ['secrets'], encPub: enc } }], a)
  assert.equal(conLlave.members.find((m) => m.pub === b.pub).encPub, enc)

  // Basura: NO pasa. Una encPub mal formada es un miembro al que nadie puede
  // sellarle nada, y el fallo saldría mucho después, al intentarlo.
  for (const malo of ['no-es-json', JSON.stringify({ kty: 'RSA' }), JSON.stringify({ kty: 'EC', crv: 'P-384', x: 'a', y: 'b' })]) {
    const roto = { ...conLlave, members: conLlave.members.map((m) => (m.pub === b.pub ? { ...m, encPub: malo } : m)) }
    assert.equal(checkShape(roto), 'encpub-invalido', `deberia rechazar: ${malo}`)
  }
})

test('encpub: registra la llave de un miembro YA admitido, sin tocarle nada mas', async () => {
  const a = await key(); const s = await key()
  const g = await sealActa({ acta: genesisActa({ pub: a.pub, label: 'PC' }), privateJwk: a.privateJwk })
  const dos = await step(g, [{ op: 'admit', member: { pub: s.pub, cn: 'proxy', label: 'proxy1', caps: ['secrets'] } }], a)

  const enc = await encKey()
  const tres = await step(dos, [{ op: 'encpub', pub: s.pub, encPub: enc }], a)
  const antes = dos.members.find((m) => m.pub === s.pub)
  const ahora = tres.members.find((m) => m.pub === s.pub)

  assert.equal((await verifyActa({ acta: tres })).ok, true)
  assert.equal(ahora.encPub, enc)
  // Lo que NO debe moverse: es todo el sentido de que exista esta operación en vez
  // de re-enrolar (re-enrolar cambia la pub y con ella se pierde el cajón de variables).
  assert.equal(ahora.pub, antes.pub, 'la pubkey no se toca')
  assert.equal(ahora.cn, antes.cn)
  assert.equal(ahora.label, antes.label)
  assert.deepEqual(ahora.caps, antes.caps)
  assert.equal(ahora.addedAt, antes.addedAt)

  // Reemplazar la llave (rotarla) también vale.
  const otra = await encKey()
  const cuatro = await step(tres, [{ op: 'encpub', pub: s.pub, encPub: otra }], a)
  assert.equal(cuatro.members.find((m) => m.pub === s.pub).encPub, otra)

  // Y no se le puede poner llave a un desconocido, ni meter basura.
  const x = await key()
  await assert.rejects(() => step(cuatro, [{ op: 'encpub', pub: x.pub, encPub: otra }], a), /not in the record/)
  await assert.rejects(() => step(cuatro, [{ op: 'encpub', pub: s.pub, encPub: 'basura' }], a), /invalid encryption key/)
})

test('remote: los pedidos de aprobación viajan por vault.secrets (la tabla local de MSG los conoce)', async () => {
  const { VAULT_MSG } = await import('../vault/remote.js')
  assert.equal(VAULT_MSG.SECRETS, 'vault.secrets')
  assert.equal(VAULT_MSG.SECRETS_RESULT, 'vault.secrets.result')
})
