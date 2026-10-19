/**
 * LA BÓVEDA QUE SIRVE `id.dotrino.com`, CORRIENDO DE VERDAD.
 *
 * `test/vendor-up-to-date.test.mjs` comprueba que la copia es idéntica a la fuente, y la
 * fuente tiene sus propias pruebas. Pero el fallo del 2026-09-02 vivía en la copia —el
 * iframe corría un device-vault de hace dieciocho versiones— y ninguna prueba la tocaba.
 *
 * Así que esto arranca la bóveda con `vault/vendor/vault/browser.js` —el MISMO núcleo que
 * el binario, el archivo que se descarga un navegador al abrir `vault.dotrino.com/vault`—
 * y resuelve cada `@dotrino/...` con el import map de `index.html`
 * (`helpers/importmap-hooks.mjs`): si al import map le falta algo, revienta aquí.
 *
 * El emparejamiento corre contra un proxio de VERDAD (el enrolamiento levanta su propio
 * cliente). Sin `DOTRINO_PROXY` esa prueba se salta: una suite no abre conexiones a
 * producción por su cuenta. Las demás no tocan la red.
 *
 *   PORT=4099 node server.js                     # en dotrino-proxy
 *   DOTRINO_PROXY=ws://localhost:4099 node --test test/vendor-pairing.e2e.test.mjs
 */
import test from 'node:test'
import assert from 'node:assert/strict'
import { register } from 'node:module'

register('./helpers/importmap-hooks.mjs', import.meta.url)

import { createIdentityCore } from '../vault/core.js'
import { memoryDisk } from '../vault/vendor/vault/core/disk.js'
// EL ARCHIVO QUE SE SIRVE, no el paquete. Esa es toda la gracia. Se carga después de
// registrar el gancho, para que sus `@dotrino/...` salgan del import map.
const { startBrowserVault } = await import('../vault/vendor/vault/browser.js')

const PROXY = process.env.DOTRINO_PROXY || ''

// `localStorage` en memoria: el cliente del proxio guarda ahí su par de canales.
if (!globalThis.localStorage) {
  const mem = new Map()
  globalThis.localStorage = {
    getItem: (k) => (mem.has(k) ? mem.get(k) : null),
    setItem: (k, v) => mem.set(k, String(v)),
    removeItem: (k) => mem.delete(k),
    clear: () => mem.clear(),
  }
}

/** Un núcleo de identidad entero, en memoria: el mismo que corre en el navegador. */
async function nucleo () {
  const mem = new Map()
  let peers = {}
  return createIdentityCore({
    kv: {
      getItem: (k) => (mem.has(k) ? mem.get(k) : null),
      setItem: (k, v) => mem.set(k, String(v)),
      removeItem: (k) => mem.delete(k),
    },
    peers: {
      async initPeerStorage () {},
      loadPeers: () => peers,
      savePeers: (m) => { peers = m },
      setPeersDirect: (m) => { peers = m || {} },
      upsertPeer: (pub, patch) => {
        peers[pub] = { ...(peers[pub] || {}), ...patch, publickey: pub }
        return peers[pub]
      },
      onDirty () {},
    },
    makeSync: null,
  })
}

/** Un disco en memoria con la forma del de IndexedDB (Node no tiene IndexedDB). */
const discoDePrueba = async () => ({ ...memoryDisk(), flush: async () => {}, close () {} })

/** La bóveda de una pestaña, como la arranca `vault.js` (`startSelfDaemon`). */
const bovedaPestana = (core, extra = {}) => startBrowserVault({ core, openDisk: discoDePrueba, log: () => {}, ...extra })

test('la copia servida concede `passwords` al emparejar',
  { skip: PROXY ? false : 'sin DOTRINO_PROXY: no se toca producción' }, async (t) => {
    const bovedaCore = await nucleo()
    const handle = await bovedaPestana(bovedaCore, { proxyUrl: PROXY })
    t.after(() => handle.close())

    // La consola pide exactamente esto desde el 2026-09-02 (`selfVaultPairing({ scope })`).
    const { qr } = await handle.startPairing({ scope: ['vault:passwords'], label: 'gestor' })

    const aparato = await nucleo()
    let reto = null
    const off = aparato.onVaultEvent((e) => { if (e?.phase === 'challenge') reto = e })

    // El humano leyendo el código del aparato y tecleándolo en la bóveda: hacen falta LAS
    // DOS cosas —el pendiente aquí y el código allí— y llegan con un viaje de red en medio.
    const tecleando = setInterval(() => {
      const [p] = handle.listPending()
      if (p && reto?.code) {
        clearInterval(tecleando)
        handle.approve(p.deviceId, reto.code).catch(() => {})
      }
    }, 100)
    t.after(() => clearInterval(tecleando))

    const r = await aparato.handlers.vaultPair({ qr, label: 'gestor', join: 'new', approveTimeoutMs: 30000 })
    off()
    assert.ok(r?.ok, 'el emparejamiento no llegó a término')
    assert.equal(reto?.code?.length, 6, 'el código no es el de seis del ecosistema')

    // LO QUE FALLABA, comprobado volviendo a poner la copia de 0.34: `SCOPE_TO_CAP` no
    // tenía `vault:passwords`, así que `scopeToCaps` se lo comía por el `.filter(Boolean)`
    // y el aparato salía con CERO permisos — ni siquiera llegaba a entrar en el acta. Y la
    // bóveda-en-pestaña solo atiende a quien tiene `passwords`, o sea que no atendía a
    // nadie. La prueba se cae aquí mismo con esa copia; se comprobó que se cae.
    const yo = await aparato.handlers.publicMe()
    const { members } = await bovedaCore.handlers.profileMembers()
    const miembro = (members || []).find((m) => m.pub === yo.publickey)

    assert.ok(miembro, 'el aparato no quedó en el acta')
    assert.ok((miembro.caps || []).includes('passwords'),
      'el aparato entró SIN la capacidad `passwords` — la copia del iframe se quedó atrás. ' +
      'caps: ' + JSON.stringify(miembro.caps))
    assert.ok(miembro.encPub, 'entró sin llave de cifrado: la bóveda no podría sellarle nada')

    const v = await aparato.handlers.vaultStatus()
    assert.ok(v.scope.includes('vault:passwords'), 'el cert no lleva el permiso: ' + JSON.stringify(v.scope))
  })

/**
 * Y LA COPIA SERVIDA TAMBIÉN ABRE CON USUARIO Y CONTRASEÑA.
 *
 * Es la regla de las tres versiones: la pestaña tiene que hacer lo mismo que el binario,
 * menos lo que su contexto no permite. Aquí lo que su contexto no permite son los
 * archivos, y por eso el almacén se lo pone quien la monta — igual que hace `vault.js`.
 *
 * Esto NO necesita proxio: se le habla al mostrador por sus handles, que es justo lo que
 * hace la consola de la pestaña.
 */
test('la copia servida crea un inicio de sesión con contraseña y lo deja entrar', async (t) => {
  const { client: opaqueClient } = await import('../vault/vendor/opaque/src/index.js')
  const { makeDeviceKey } = await import('../vault/capabilities.js')

  const core = await nucleo()
  // Sin proxio: el mostrador de contraseñas no manda nada por la red — es la consola de
  // esta misma pestaña.
  const handle = await bovedaPestana(core, { makeClient: clienteMudo })
  t.after(() => handle.close())

  const password = 'una contraseña larga de verdad'
  const start = opaqueClient.registrationStart({ password })
  const { response } = await handle.loginRegisterBegin({ user: 'ana', request: start.request })
  const fin = opaqueClient.registrationFinish({ state: start.state, response, password })
  const device = await makeDeviceKey({ label: 'equipo prestado' })
  const r = await handle.loginRegisterFinish({
    user: 'ana', upload: fin.upload, pub: device.publickey, label: 'equipo prestado', blob: 'sellado:' + fin.exportKey.slice(0, 8)
  })
  assert.ok(r.cert?.sig, 'el aparato sale con su certificado')

  // Y está en el acta de la cuenta, que es lo que lo hace un aparato de verdad.
  const { members } = await core.handlers.profileMembers()
  assert.ok((members || []).some((m) => m.pub === device.publickey), 'el aparato no quedó en el acta')

  const s = opaqueClient.loginStart({ password })
  const b = await handle.loginBegin({ user: 'ana', request: s.request })
  const f = opaqueClient.loginFinish({ state: s.state, response: b.response, password })
  const entrada = await handle.loginEnd({ lid: b.lid, finalization: f.finalization })
  assert.equal(entrada.blob, 'sellado:' + fin.exportKey.slice(0, 8), 'devuelve el paquete tal cual se guardó')
  assert.equal(f.exportKey, fin.exportKey, 'la llave que lo abre sale de la contraseña')

  assert.equal(handle.listLogins().length, 1)
})

/**
 * LOS INICIOS DE SESIÓN DE ANTES SE TRAEN UNA VEZ. La pestaña los guardaba en su propio
 * almacén antes de correr la bóveda entera: se pasan al de la bóveda y se borran de allí.
 */
test('la bóveda de la pestaña se trae los inicios de sesión que había', async (t) => {
  const core = await nucleo()
  let borrado = false
  const viejo = { v: 1, logins: {} }
  const handle = await bovedaPestana(core, {
    makeClient: clienteMudo,
    legacyLogins: async () => ({ state: viejo, drop: () => { borrado = true } })
  })
  t.after(() => handle.close())
  assert.ok(handle.disk.exists('logins.json'), 'no se guardaron en el almacén de la bóveda')
  assert.ok(borrado, 'la copia vieja se quedó: dos copias acaban diciendo cosas distintas')
})

/**
 * LA CONSOLA DE ESTA PESTAÑA ADMINISTRA SU BÓVEDA con el mismo protocolo que usa contra el
 * binario (`vault.admin`, `vault.secrets`), por el camino local y sin proxio. Es lo que
 * hace que la pestaña tenga las mismas pantallas que el demonio: cajones, bloqueados y
 * pedidos.
 */
test('la consola de la pestaña administra su propia bóveda por el camino local', async (t) => {
  const core = await nucleo()
  const handle = await bovedaPestana(core, { makeClient: clienteMudo })
  t.after(() => handle.close())

  assert.equal(await core.handlers.canAdminVault(), true, 'la maestra de la cuenta tiene que poder administrar su bóveda')
  const bloqueados = await core.handlers.vaultAdmin({ op: 'blocked' })
  assert.deepEqual(bloqueados?.items, [], 'la lista de bloqueados no llegó por el camino local')
  const cajones = await core.handlers.vaultAdmin({ op: 'vars' })
  assert.ok(cajones?.enc, 'los cajones llegan sellados a este aparato, como desde el binario')

  // Bloquear y desbloquear: lo que hasta ahora solo hacía el binario.
  const otro = await nucleo()
  const pub = (await otro.handlers.publicMe()).publickey
  await core.handlers.vaultAdmin({ op: 'block', sub: pub })
  assert.equal((await core.handlers.vaultAdmin({ op: 'blocked' })).items.length, 1)
  await core.handlers.vaultAdmin({ op: 'unblock', sub: pub })
  assert.equal((await core.handlers.vaultAdmin({ op: 'blocked' })).items.length, 0)

  // La lista de aparatos sale de la bóveda, con lo que da el binario.
  const lista = await core.handlers.listVaultDevices()
  assert.ok(Array.isArray(lista?.devices), 'la lista de aparatos no salió de la bóveda local')

  // Al parar, la consola deja de tener a quién administrar.
  await handle.close()
  await assert.rejects(core.handlers.vaultAdmin({ op: 'blocked' }), /not paired/)
})

/** Un transporte que no habla con nadie: aquí se prueba el mostrador, no la red. */
function clienteMudo () {
  return {
    token: 'MUDO', isConnected: true, url: 'ws://mudo',
    on () {}, off () {},
    async connect () {}, async identify () {}, async identifyAs () {},
    async publish () {}, async list () { return [] },
    send () {}, sendByPubkey () {}, sendSealed () {}, close () {}
  }
}

/**
 * EL WASM QUE SE DESCARGA EL NAVEGADOR, ejecutado.
 *
 * La prueba de arriba importa `@dotrino/opaque` por su nombre, o sea el paquete de
 * `node_modules`: en el navegador eso lo resuelve el import map a `vendor/opaque/`, que es
 * OTRA copia. Esta importa los archivos servidos y los hace trabajar, para que una copia
 * truncada o de otra versión no pase inadvertida — el WASM viaja dentro del JS, así que un
 * archivo a medias sigue pareciendo un archivo.
 */
test('el OPAQUE servido instancia su WASM y hace un intercambio entero', async () => {
  const { client, server, suiteId } = await import('../vault/vendor/opaque/src/index.js')
  assert.ok(suiteId(), 'la suite se nombra')
  const setup = server.createSetup()
  const password = 'una contraseña larga de verdad'
  const credentialId = 'ana'

  const reg = client.registrationStart({ password })
  const response = server.registrationResponse({ setup, request: reg.request, credentialId })
  const fin = client.registrationFinish({ state: reg.state, response, password })
  const record = server.registrationFinish({ upload: fin.upload })

  const s = client.loginStart({ password })
  const b = server.loginStart({ setup, record, request: s.request, credentialId })
  const f = client.loginFinish({ state: s.state, response: b.response, password })
  server.loginFinish({ state: b.state, finalization: f.finalization })
  assert.equal(f.exportKey, fin.exportKey, 'la misma contraseña da la misma llave')
})

/**
 * UNA BÓVEDA QUE NO SELLA SU ACTA NO ARRANCA (2026-10-19). Una pestaña con una cuenta entrada
 * con usuario y contraseña —miembro, no selladora— arrancaba la bóveda igual, y el fallo salía
 * al aprobar a alguien, con el código ya en pantalla.
 */
test('la bóveda de la pestaña no arranca si su llave no sella el acta', async () => {
  const core = await nucleo()
  const real = core.handlers.profileActa
  core.handlers.profileActa = async (a) => ({ ...(await real(a)), isMaster: false })
  await assert.rejects(bovedaPestana(core, { makeClient: clienteMudo }), (e) => e.code === 'not-sealer')
})

/**
 * LA BÓVEDA ES DE UNA CUENTA. Si en la pestaña se abre otra con la bóveda en marcha, no firma
 * nada como la nueva con el disco de la vieja: se para y lo dice.
 */
test('la bóveda de la pestaña se niega a aprobar si cambió la cuenta abierta', async (t) => {
  const core = await nucleo()
  const handle = await bovedaPestana(core, { makeClient: clienteMudo })
  t.after(() => handle.close())
  await core.handlers.createProfile({ name: 'otra' })
  await assert.rejects(handle.approve('AB12-CD34', '123456'), (e) => e.code === 'profile-changed')
})
