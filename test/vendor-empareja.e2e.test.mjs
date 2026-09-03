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
