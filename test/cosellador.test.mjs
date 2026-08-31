/**
 * MULTIVAULT: dos bóvedas que pueden sellar la misma acta (dueño, 2026-08-30).
 *
 * Por qué se hace, con sus palabras: *«me resuelve el problema de un desastre que pierda
 * permanentemente un vault»*. Y por qué se puede hacer: *«usualmente no se abren los dos
 * al mismo tiempo»*.
 *
 * Lo que se paga a cambio, dicho sin adornos: con un solo sellador (D4), dos actas
 * legítimas al mismo `seq` eran **criptográficamente imposibles**. Con dos, dejan de
 * serlo: pasan a ser raras. Así que el empate deja de ser un caso que no puede ocurrir y
 * pasa a ser un caso que hay que resolver bien — y lo que lo resuelve ya estaba escrito
 * en `canAdopt`: gana el traspaso, y si no, la de hash menor. Determinista y sin relojes.
 *
 * Estas pruebas fijan las dos mitades: que un cosellador puede, y que quien NO está
 * nombrado sigue sin poder.
 */
import test from 'node:test'
import assert from 'node:assert/strict'
import {
  genesisActa, applyChanges, sealActa, verifyActa, canAdopt, canSeal, sealersOf,
  checkShape, actaHash, memberCanSign, memberCanScope, verifySealerChain,
  sealerLinkOf, verifySealerLinkChain
} from '../vault/acta.js'
import { makeDeviceKey, signWithDevice } from '../vault/capabilities.js'

/** `sealActa` firma con la llave de `acta.sealedBy`, que `applyChanges` deja puesta. */
const sellar = (acta, k) => sealActa({ acta, privateJwk: k.privateJwk })

/** Una cuenta con su bóveda principal (A) y otra bóveda (B) ya dentro como miembro. */
async function cuentaConDosBovedas () {
  const A = await makeDeviceKey()
  const B = await makeDeviceKey()
  let acta = genesisActa({ pub: A.publickey, label: 'bóveda A' })
  acta = await sellar(acta, A)

  // B entra como miembro Y queda nombrada cosellador, en el MISMO seq: un sellador que
  // no es miembro no existe (checkShape), así que las dos cosas van juntas.
  // El permiso `sealer` va en el admit, como cualquier otro: no hay op especial.
  acta = await applyChanges(acta, [
    { op: 'admit', member: { pub: B.publickey, label: 'bóveda B', caps: ['sign', 'read', 'store', 'sealer'] } }
  ], { by: A.publickey })
  acta = await sellar(acta, A)
  return { A, B, acta }
}

test('un cosellador queda nombrado, y el acta sigue siendo válida', async () => {
  const { A, B, acta } = await cuentaConDosBovedas()
  assert.equal(checkShape(acta), null)
  assert.ok((await verifyActa({ acta })).ok)
  assert.deepEqual(sealersOf(acta).sort(), [A.publickey, B.publickey].sort())
  assert.ok(canSeal(acta, B.publickey))
  // Ya no hay campo que mirar: los dos sellan porque los dos tienen el permiso, y no hay
  // ninguno «más master» que el otro (dueño, 2026-08-31: «SEAL es el nuevo master»).
  assert.equal(acta.sealer, undefined, 'el campo no existe: sellar es un permiso')
})

test('la bóveda B ya puede sellar: es lo que resuelve perder la A', async () => {
  const { A, B, acta } = await cuentaConDosBovedas()
  const nuevo = await makeDeviceKey()

  // A está perdida. B admite un aparato ella sola.
  let siguiente = await applyChanges(acta, { op: 'admit', member: { pub: nuevo.publickey, label: 'teléfono', caps: ['sign'] } }, { by: B.publickey })
  siguiente = await sellar(siguiente, B)

  assert.ok((await verifyActa({ acta: siguiente })).ok)
  assert.equal(siguiente.sealedBy, B.publickey)
  const r = await canAdopt({ candidate: siguiente, current: acta })
  assert.equal(r.adopt, true, 'los demás miembros lo adoptan: el acta lo autorizaba')
  assert.notEqual(A.publickey, siguiente.sealedBy)
})

test('quien NO está nombrado sigue sin poder sellar', async () => {
  const { A, acta } = await cuentaConDosBovedas()
  const intruso = await makeDeviceKey()

  await assert.rejects(
    () => applyChanges(acta, { op: 'admit', member: { pub: intruso.publickey, label: 'x', caps: ['sign'] } }, { by: intruso.publickey }),
    /not the master, nor a co-sealer/
  )
  assert.equal(canSeal(acta, intruso.publickey), false)
  assert.ok(canSeal(acta, A.publickey))
})

/**
 * EL CASO QUE ANTES ERA IMPOSIBLE. Las dos bóvedas sellan `seq` N con contenido distinto
 * —solo pasa si están las dos abiertas y sin verse—, y hay que resolverlo igual en todos
 * los aparatos, sin relojes y sin preguntarle a nadie.
 */
test('empate a igual seq: gana la de hash menor, y gana lo MISMO en los dos lados', async () => {
  const { A, B, acta } = await cuentaConDosBovedas()
  const unoA = await makeDeviceKey()
  const unoB = await makeDeviceKey()

  let ramaA = await applyChanges(acta, { op: 'admit', member: { pub: unoA.publickey, label: 'de A', caps: ['sign'] } }, { by: A.publickey })
  ramaA = await sellar(ramaA, A)
  let ramaB = await applyChanges(acta, { op: 'admit', member: { pub: unoB.publickey, label: 'de B', caps: ['sign'] } }, { by: B.publickey })
  ramaB = await sellar(ramaB, B)

  assert.equal(ramaA.seq, ramaB.seq, 'mismo seq: esto es el empate')

  const [hA, hB] = [await actaHash(ramaA), await actaHash(ramaB)]
  const ganadora = hA < hB ? ramaA : ramaB

  // Un aparato que tenía la de A y recibe la de B, y otro al revés: los dos acaban igual.
  const vieneB = await canAdopt({ candidate: ramaB, current: ramaA })
  const vieneA = await canAdopt({ candidate: ramaA, current: ramaB })
  assert.notEqual(vieneB.adopt, vieneA.adopt, 'exactamente una de las dos gana')
  assert.equal(vieneB.adopt, ganadora === ramaB)
  assert.equal(vieneA.adopt, ganadora === ramaA)

  // Y lo que hay que decir en voz alta (§2.4.1 punto 5): el cambio del que pierde SE
  // PIERDE. El aparato que admitió la rama muerta no está en la ganadora.
  const perdedor = ganadora === ramaA ? unoB : unoA
  assert.ok(!ganadora.members.some((m) => m.pub === perdedor.publickey),
    'el aparato admitido en la rama que pierde no queda en la cuenta: hay que avisarlo')
})

test('quitar a la bóveda B se lleva su permiso de sellar: no hay lista aparte', async () => {
  const { A, B, acta } = await cuentaConDosBovedas()
  let sinB = await applyChanges(acta, { op: 'remove', pub: B.publickey }, { by: A.publickey })
  sinB = await sellar(sinB, A)

  assert.equal(checkShape(sinB), null)
  assert.equal(canSeal(sinB, B.publickey), false)
  assert.deepEqual(sealersOf(sinB), [A.publickey])
})

/**
 * Al ser un permiso y no un campo aparte, «sellador que no es miembro» deja de poder
 * escribirse: los permisos viven DENTRO del miembro. Lo que sí hay que comprobar es que
 * se pueda QUITAR, que es la otra mitad de «se puede dar o quitar».
 */
test('el permiso de sellar se quita, y entonces B deja de poder', async () => {
  const { A, B, acta } = await cuentaConDosBovedas()
  let sinPermiso = await applyChanges(acta, { op: 'caps', pub: B.publickey, caps: ['sign', 'read', 'store'] }, { by: A.publickey })
  sinPermiso = await sellar(sinPermiso, A)

  assert.equal(canSeal(sinPermiso, B.publickey), false)
  assert.deepEqual(sealersOf(sinPermiso), [A.publickey])
  await assert.rejects(
    () => applyChanges(sinPermiso, { op: 'caps', pub: A.publickey, caps: ['sign'] }, { by: B.publickey }),
    /not the master, nor a co-sealer/
  )
})

/**
 * FIRMAR POR LA IDENTIDAD: manda el acta, y va enmascarado.
 *
 * El agujero que esto cierra: `setCaps` sella el acta pero NO reemite ni revoca el
 * certificado del aparato, así que quitarle `firma` no se lo quitaba mientras el papel
 * siguiera vivo — hasta 30 días. Quien autoriza es el acta.
 */
test('quitar «firma» del acta se nota aunque el papel siga vivo', async () => {
  const A = await makeDeviceKey()
  const tel = await makeDeviceKey()
  let acta = genesisActa({ pub: A.publickey, label: 'bóveda' })
  acta = await sellar(acta, A)
  acta = await applyChanges(acta, [
    { op: 'admit', member: { pub: tel.publickey, label: 'teléfono', caps: ['sign', 'read'] } }
  ], { by: A.publickey })
  acta = await sellar(acta, A)

  assert.equal(memberCanSign(acta, tel.publickey), true)

  acta = await applyChanges(acta, [{ op: 'caps', pub: tel.publickey, caps: ['read'] }], { by: A.publickey })
  acta = await sellar(acta, A)
  assert.equal(memberCanSign(acta, tel.publickey), false, 'el acta manda, no el certificado')
})

test('un servicio solo firma lo de su cajón; un aparato tuyo, todo', async () => {
  const A = await makeDeviceKey()
  const bot = await makeDeviceKey()
  const tel = await makeDeviceKey()
  let acta = genesisActa({ pub: A.publickey, label: 'bóveda' })
  acta = await sellar(acta, A)
  acta = await applyChanges(acta, [
    { op: 'admit', member: { pub: bot.publickey, label: 'bot', cn: 'eco', caps: ['sign', 'secrets'] } },
    { op: 'admit', member: { pub: tel.publickey, label: 'teléfono', caps: ['sign'] } }
  ], { by: A.publickey })
  acta = await sellar(acta, A)

  assert.equal(memberCanSign(acta, bot.publickey, 'eco'), true, 'dentro de su cajón, sí')
  assert.equal(memberCanSign(acta, bot.publickey, 'trueque'), false, 'fuera, no')
  // Y SIN decir cajón: eso es pedir «firma por la identidad, en general». El `cn` del
  // acta ya dice que este no puede, sin mirar qué se firma (dueño, 2026-08-31).
  assert.equal(memberCanSign(acta, bot.publickey), false, 'un servicio no firma por la identidad')
  assert.equal(memberCanSign(acta, tel.publickey), true, 'un aparato tuyo sí')
  assert.equal(memberCanSign(acta, tel.publickey, 'eco'), true, 'y ningún cajón lo limita')
})

/**
 * UN SOLO GUARDIA PARA TODOS LOS MOSTRADORES.
 *
 * El certificado dice a qué se comprometió la bóveda al conectar el aparato; el acta dice
 * lo que puede HOY. Cambiar permisos sella el acta pero no reemite el papel, que vive
 * hasta 30 días — así que un mostrador que se fíe del papel sigue diciendo que sí durante
 * esa ventana. Pasaba en `sign`, `read` y `store`, cada uno por su cuenta.
 */
test('el scope del papel se traduce al permiso del acta, y lo desconocido no pasa', async () => {
  const A = await makeDeviceKey()
  const tel = await makeDeviceKey()
  const bot = await makeDeviceKey()
  let acta = genesisActa({ pub: A.publickey, label: 'bóveda' })
  acta = await sellar(acta, A)
  acta = await applyChanges(acta, [
    { op: 'admit', member: { pub: tel.publickey, label: 'teléfono', caps: ['read'] } },
    { op: 'admit', member: { pub: bot.publickey, label: 'bot', cn: 'eco', caps: ['secrets'] } }
  ], { by: A.publickey })
  acta = await sellar(acta, A)

  assert.equal(memberCanScope(acta, tel.publickey, 'vault:read'), true)
  assert.equal(memberCanScope(acta, tel.publickey, 'vault:store'), false, 'lo que el acta no da, no pasa')
  assert.equal(memberCanScope(acta, tel.publickey, 'vault:sign'), false)

  assert.equal(memberCanScope(acta, bot.publickey, 'vault:secrets:eco'), true, 'su cajón')
  assert.equal(memberCanScope(acta, bot.publickey, 'vault:secrets:trueque'), false, 'el de al lado no')

  // Un scope que no está en la lista se RECHAZA en vez de colarse por no reconocerlo.
  assert.equal(memberCanScope(acta, tel.publickey, 'vault:inventado'), false)
  assert.equal(memberCanScope(acta, tel.publickey, ''), false)
  assert.equal(memberCanScope(null, tel.publickey, 'vault:read'), false, 'sin acta no se autoriza nada')
})

// ---------- la cadena de selladores: lo que verifica un EXTRAÑO ----------

/**
 * EL ATAQUE QUE ESTO CIERRA, y que se demostró funcionando antes de escribirlo: con tu
 * `profileId` —que es público, viaja en cada firma tuya— cualquiera fabrica un acta donde
 * él sella, la firma con su propia llave, y `verifyActa` la da por buena. Está firmada;
 * solo que por él. Con eso suplantaba tu identidad ante geo, ante reputación, ante todos.
 */
test('un acta suelta fabricada para tu profileId NO pasa la cadena', async () => {
  const victima = await makeDeviceKey()
  const suya = await sellar(genesisActa({ pub: victima.publickey, label: 'v' }), victima)

  const malo = await makeDeviceKey()
  // La forja va COMPLETA, con su eslabón coherente: si se dejara el de la víctima, el acta
  // ya no cuadraría consigo misma y la pillaría `verifyActa` sola. Se hace bien a propósito,
  // porque lo que esta prueba tiene que enseñar es que ni así cuela.
  const falsa = await sellar({
    ...suya,
    seq: 99,
    prev: 'a'.repeat(64),
    sealedBy: malo.publickey,
    sealerAnchor: { seq: 1, hash: await actaHash(suya) },
    sealerLink: { v: 1, profileId: suya.profileId, seq: 99, by: malo.publickey, sealers: [malo.publickey], prev: null, iat: Date.now() },
    members: [{ pub: malo.publickey, encPub: null, label: 'yo', cn: null, caps: ['sign', 'sealer'], addedAt: Date.now(), cert: null }]
  }, malo)

  // Sola pasa: está firmada por quien dice haberla firmado. Ese era el agujero.
  assert.equal((await verifyActa({ acta: falsa, expectedProfileId: suya.profileId })).ok, true)

  // Con la cadena no: el génesis de la víctima NO le da permiso de sellar.
  const r = await verifySealerChain([suya, falsa], { expectedProfileId: suya.profileId })
  assert.equal(r.ok, false)
  assert.match(r.reason, /sellador-no-autorizado/)

  // Y no puede empezar la cadena por la suya: no está autofirmada por ese profileId.
  const solo = await verifySealerChain([falsa], { expectedProfileId: suya.profileId })
  assert.equal(solo.ok, false)
})

test('la cadena legítima pasa, y solo lleva los cambios de sellador', async () => {
  const A = await makeDeviceKey()
  const B = await makeDeviceKey()
  const tel = await makeDeviceKey()

  const genesis = await sellar(genesisActa({ pub: A.publickey, label: 'A' }), A)

  // Emparejar aparatos NO entra en la cadena: no cambia quién sella.
  let acta = await applyChanges(genesis, [{ op: 'admit', member: { pub: tel.publickey, label: 'tel', caps: ['sign'] } }], { by: A.publickey })
  acta = await sellar(acta, A)
  assert.equal(acta.sealerChanged, false, 'admitir un aparato no cambia quién sella')

  // Sumar la segunda bóveda SÍ.
  let dos = await applyChanges(acta, [{ op: 'admit', member: { pub: B.publickey, label: 'B', caps: ['sign', 'sealer'] } }], { by: A.publickey })
  dos = await sellar(dos, A)
  assert.equal(dos.sealerChanged, true)

  // Y a partir de ahí, B sella sin que A intervenga — sin la llave del génesis.
  let tres = await applyChanges(dos, [{ op: 'label', pub: tel.publickey, label: 'Teléfono' }], { by: B.publickey })
  tres = await sellar(tres, B)

  const r = await verifySealerChain([genesis, dos, tres], { expectedProfileId: genesis.profileId })
  assert.equal(r.ok, true, r.reason)
  assert.deepEqual(r.sealers.sort(), [A.publickey, B.publickey].sort())
  assert.equal(r.seq, tres.seq)
})

/**
 * LOS ESLABONES NO CADUCAN. El resto de las actas sí —la ventana existe para que un
 * miembro que estuvo apagado compruebe el encadenamiento— pero si la poda se lleva un
 * cambio de sellador, nadie de fuera puede volver a anclar en el génesis. Y no hay forma
 * de reconstruirlo.
 */
test('la poda respeta los eslabones de la cadena, por muchas actas que pasen', async () => {
  const A = await makeDeviceKey()
  const B = await makeDeviceKey()
  let acta = await sellar(genesisActa({ pub: A.publickey, label: 'A' }), A)
  const historia = [acta]

  // Sumar la segunda bóveda: eslabón 2.
  acta = await applyChanges(acta, [{ op: 'admit', member: { pub: B.publickey, label: 'B', caps: ['sign', 'sealer'] } }], { by: A.publickey })
  acta = await sellar(acta, A)
  historia.push(acta)
  assert.equal(acta.sealerChanged, true)

  // Y 60 cambios que NO tocan quién sella: más que la ventana de retención (50).
  for (let i = 0; i < 60; i++) {
    acta = await applyChanges(acta, [{ op: 'label', pub: B.publickey, label: 'B' + i }], { by: A.publickey })
    acta = await sellar(acta, A)
    historia.push(acta)
    assert.equal(acta.sealerChanged, false, 'renombrar no cambia quién sella')
  }

  // La cadena sigue siendo de DOS eslabones más la actual, y verifica.
  const eslabones = historia.filter((a) => a.sealerChanged)
  assert.equal(eslabones.length, 2, 'solo el génesis y la entrada de B')
  const r = await verifySealerChain([...eslabones, acta], { expectedProfileId: historia[0].profileId })
  assert.equal(r.ok, true, r.reason)
})

/**
 * DÓNDE PREGUNTAR, y por qué va en el génesis.
 *
 * La cadena prueba quién puede sellar, no que no haya algo más nuevo. Para enterarse de
 * una revocación hay que poder mirar a algún lado — y si esa dirección viajara en la parte
 * cambiable, el sellador expulsado la cambiaría a la suya y te mandaría a su rama.
 */
test('la dirección de la cadena vive en el génesis y no se puede redirigir', async () => {
  const A = await makeDeviceKey()
  const B = await makeDeviceKey()
  const url = 'https://cadena.ejemplo.com/6f3a.json'

  const genesis = await sellar(genesisActa({ pub: A.publickey, label: 'A', chainUrl: url }), A)
  assert.equal(genesis.chainUrl, url)
  assert.equal(checkShape(genesis), null)

  // Un acta posterior no la lleva: la dirección es del génesis y solo de él.
  let dos = await applyChanges(genesis, [{ op: 'admit', member: { pub: B.publickey, label: 'B', caps: ['sign', 'sealer'] } }], { by: A.publickey })
  dos = await sellar(dos, A)
  const r = await verifySealerChain([genesis, dos], { expectedProfileId: genesis.profileId })
  assert.equal(r.ok, true, r.reason)
  assert.equal(genesis.chainUrl, url, 'quien verifica la lee del PRIMER eslabón, que nadie puede rehacer')
})

test('la dirección tiene que ser https, y sin adornos', async () => {
  const A = await makeDeviceKey()
  const mala = ['http://x.com/c.json', 'https://x.com/c.json#frag', 'https://u:p@x.com/c.json', 'no-es-una-url']
  for (const u of mala) {
    assert.throws(() => genesisActa({ pub: A.publickey, chainUrl: u }), /chainUrl/, u)
  }
  // Y sin dirección es lo NORMAL: una cuenta de una sola bóveda no tiene nada que refrescar.
  assert.equal(genesisActa({ pub: A.publickey }).chainUrl, null)
})

/**
 * LO QUE SE PUBLICA.
 *
 * El 2026-08-31 el registro llegó a publicar el acta ENTERA —los `label` y los `cn` de cada
 * aparato, y el llavero— porque «un eslabón» era un acta. La salida fue del dueño: se firma
 * el eslabón, se mete en el acta y se firma el acta encima. Uno solo, firmado dos veces.
 *
 * Estas pruebas fijan las dos mitades de eso: que lo que sale no lleva nada de dentro, y
 * que no puede contradecir al acta que lo lleva.
 */
test('el eslabón publicable no lleva aparatos, ni etiquetas, ni cajones, ni llavero', async () => {
  const A = await makeDeviceKey()
  const B = await makeDeviceKey()
  const g = await sellar(genesisActa({ pub: A.publickey, label: 'el-portátil-de-casa' }), A)
  let dos = await applyChanges(g, [
    { op: 'admit', member: { pub: B.publickey, label: 'servidor-secreto', cn: 'eco', caps: ['sign', 'sealer'] } }
  ], { by: A.publickey })
  dos = await sellar(dos, A)

  const publicado = JSON.stringify([sealerLinkOf(g), sealerLinkOf(dos)])
  for (const filtracion of ['el-portátil-de-casa', 'servidor-secreto', 'eco', 'members', 'keyring', 'card', 'cert']) {
    assert.ok(!publicado.includes(filtracion), `NO se publica: ${filtracion}`)
  }
  assert.deepEqual(Object.keys(sealerLinkOf(dos)).sort(),
    ['by', 'iat', 'prev', 'profileId', 'sealers', 'seq', 'sig', 'v'], 'y nada más que esto')
})

test('la cadena publicada se verifica sola, sin actas', async () => {
  const A = await makeDeviceKey()
  const B = await makeDeviceKey()
  const g = await sellar(genesisActa({ pub: A.publickey, label: 'A' }), A)
  let dos = await applyChanges(g, [
    { op: 'admit', member: { pub: B.publickey, label: 'B', caps: ['sign', 'sealer'] } }
  ], { by: A.publickey })
  dos = await sellar(dos, A)

  const cadena = [sealerLinkOf(g), sealerLinkOf(dos)]
  const r = await verifySealerLinkChain(cadena, { expectedProfileId: g.profileId })
  assert.equal(r.ok, true, r.reason)
  assert.equal(r.seq, 2)
  assert.deepEqual(r.sealers.slice().sort(), [A.publickey, B.publickey].sort())

  // Y no cuela una cadena fabricada con tu profileId, que es público.
  const malo = await makeDeviceKey()
  const inventado = { v: 1, profileId: g.profileId, seq: 1, by: malo.publickey, sealers: [malo.publickey], prev: null, iat: Date.now() }
  const falso = { ...inventado, sig: (await signWithDevice({ privateJwk: malo.privateJwk, data: inventado })).signature }
  const mala = await verifySealerLinkChain([falso], { expectedProfileId: g.profileId })
  assert.equal(mala.ok, false)
  assert.match(mala.reason, /genesis-no-autofirmado/)
})

test('el eslabón NO puede decir algo distinto que el acta que lo lleva', async () => {
  const A = await makeDeviceKey()
  const malo = await makeDeviceKey()
  const g = await sellar(genesisActa({ pub: A.publickey, label: 'A' }), A)

  // Alguien mete en el acta un eslabón que se nombra sellador. Está firmado por él, así que
  // el eslabón solo verifica — pero el acta y su eslabón dejan de contar lo mismo.
  const cuerpo = { v: 1, profileId: g.profileId, seq: 1, by: malo.publickey, sealers: [malo.publickey], prev: null, iat: Date.now() }
  const trucada = await sellar({
    ...g,
    sealerLink: { ...cuerpo, sig: (await signWithDevice({ privateJwk: malo.privateJwk, data: cuerpo })).signature }
  }, A)

  const v = await verifyActa({ acta: trucada })
  assert.equal(v.ok, false)
  assert.match(v.reason, /eslabon-(no-cuadra|otro-sellador)/)
})
