/**
 * LA COPIA QUE SIRVE `id.dotrino.com`, CORRIENDO DE VERDAD.
 *
 * `test/vendor-up-to-date.test.mjs` comprueba que la copia es idéntica a la fuente, y la
 * fuente tiene sus propias pruebas. Eso es una cadena razonable, pero nunca se había
 * EJECUTADO la copia: el fallo que se arregló el 2026-09-02 vivía exactamente ahí —el
 * iframe corría un device-vault de hace dieciocho versiones, sin `vault:passwords` en su
 * mapa de permisos— y ninguna prueba del ecosistema lo tocaba, porque todas importan el
 * pilar desde `node_modules`.
 *
 * Así que esto arranca la bóveda con `vault/vendor/vault/index.js`, el archivo que se
 * descarga un navegador al abrir `vault.dotrino.com/vault`, y recorre el emparejamiento
 * entero pidiendo el permiso de contraseñas. Si la copia se queda atrás otra vez y el
 * `vendor-up-to-date` se saltara (no está el repo hermano), esto lo caza igual.
 *
 * Corre contra un proxio de VERDAD, porque el enrolamiento levanta su propio cliente y no
 * admite un transporte de mentira. Sin `DOTRINO_PROXY` se salta: una suite no abre
 * conexiones a producción por su cuenta.
 *
 *   PORT=4099 node server.js                     # en dotrino-proxy
 *   DOTRINO_PROXY=ws://localhost:4099 node --test test/vendor-empareja.e2e.test.mjs
 */
import test from 'node:test'
import assert from 'node:assert/strict'

import { createIdentityCore } from '../vault/core.js'
// EL ARCHIVO QUE SE SIRVE, no el paquete. Esa es toda la gracia.
import { startDeviceVault } from '../vault/vendor/vault/index.js'

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

/** El mismo adaptador que `vault.js` le pasa a `startDeviceVault` desde el iframe. */
const comoElIframe = (core) => ({
  get me () { return core.me },
  signData: (data) => core.handlers.signData({ data }),
  signDelegation: (sub, scope, opts = {}) => core.handlers.signDelegation({ sub, scope, ...opts }),
  listDelegations: () => core.handlers.listDelegations({}),
  revokeDelegation: (nonce) => core.handlers.revokeDelegation({ nonce }),
  revokeDevice: (sub) => core.handlers.revokeDevice({ sub }),
  admitMember: (m) => core.handlers.admitMember(m),
  profileActa: () => core.handlers.profileActa({}),
  joinProfile: (acta) => core.handlers.joinProfile({ acta }),
})

test('la copia servida concede `passwords` al emparejar',
  { skip: PROXY ? false : 'sin DOTRINO_PROXY: no se toca producción' }, async (t) => {
    const bovedaCore = await nucleo()
    const handle = await startDeviceVault(comoElIframe(bovedaCore), { proxyUrl: PROXY })
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
  const { client: opaqueClient } = await import('@dotrino/opaque')
  const { createLoginDesk } = await import('../vault/vendor/vault/passwordLogins.js')
  const { makeDeviceKey } = await import('../vault/capabilities.js')

  const core = await nucleo()
  let guardado = null
  const logins = createLoginDesk({
    load: () => (guardado ? JSON.parse(guardado) : null),
    save: (s) => { guardado = JSON.stringify(s) }
  })
  // Sin proxio: `startDeviceVault` acepta un cliente puesto desde fuera, y el mostrador de
  // contraseñas no manda nada por la red — es la consola de esta misma pestaña.
  const handle = await startDeviceVault(comoElIframe(core), { client: clienteMudo(), logins })
  t.after(() => handle.close())

  const password = 'una contraseña larga de verdad'
  const start = opaqueClient.registrationStart({ password })
  const { response } = handle.loginRegisterBegin({ user: 'ana', request: start.request })
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
  const b = handle.loginBegin({ user: 'ana', request: s.request })
  const f = opaqueClient.loginFinish({ state: s.state, response: b.response, password })
  const entrada = handle.loginEnd({ lid: b.lid, finalization: f.finalization })
  assert.equal(entrada.blob, 'sellado:' + fin.exportKey.slice(0, 8), 'devuelve el paquete tal cual se guardó')
  assert.equal(f.exportKey, fin.exportKey, 'la llave que lo abre sale de la contraseña')

  assert.equal(handle.listLogins().length, 1)
})

/**
 * SIN ALMACÉN LO DICE, y no dice que la contraseña está mal. Son cosas distintas: una la
 * arregla quien monta la bóveda, la otra quien escribe la contraseña.
 */
test('la copia servida sin almacén contesta `logins-unavailable`', async (t) => {
  const core = await nucleo()
  const handle = await startDeviceVault(comoElIframe(core), { client: clienteMudo() })
  t.after(() => handle.close())
  assert.throws(() => handle.listLogins(), (e) => e.code === 'logins-unavailable')
})

/** Un transporte que no habla con nadie: aquí se prueba el mostrador, no la red. */
function clienteMudo () {
  return {
    token: 'MUDO',
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
