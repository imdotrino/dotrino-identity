/**
 * ENTRAR CON USUARIO Y CONTRASEÑA, EN EL NAVEGADOR (`temporary-access.md` §3.4).
 *
 * Aquí se prueba la mitad que es de esta casa: qué le pasa a ESTE navegador cuando alguien
 * entra con la dirección de su cuenta. Lo que se comprueba, y por qué importa cada cosa:
 *
 *   · el navegador pasa a SER ese aparato (su llave, su acta, su papel), no una cuenta nueva;
 *   · sin «Recordar» es una CUENTA DE PASO: sobrevive a navegar dentro de la pestaña —si no,
 *     el primer enlace te echa—, pero no entra en la lista de perfiles del equipo, no cambia
 *     su cuenta por defecto, y el primer arranque que la vea sin latido la borra entera;
 *   · con «Recordar», se guarda como cualquier otra cuenta de ese navegador;
 *   · en las dos, la llave privada va como `CryptoKey` NO EXTRAÍBLE;
 *   · salir no deja rastro.
 *
 * Se usan los archivos VENDORIZADOS (`vault/vendor/vault/`), que son los que se descarga un
 * navegador: el núcleo los carga por el import map, así que probar el paquete de
 * `node_modules` probaría otra copia.
 */
import test from 'node:test'
import assert from 'node:assert/strict'
import { createIdentityCore } from '../vault/core.js'
import { startDeviceVault } from '../vault/vendor/vault/index.js'
import { createLoginDesk, sealDeviceKeys, accountCode } from '../vault/vendor/vault/passwordLogins.js'
import { loginWithPassword } from '../vault/vendor/vault/loginClient.js'
import { makeDeviceKey, makeDeviceEncKey, pubkeyId } from '../vault/capabilities.js'
import { client as opaqueClient } from '@dotrino/opaque'

if (!globalThis.localStorage) {
  const mem = new Map()
  globalThis.localStorage = {
    getItem: (k) => (mem.has(k) ? mem.get(k) : null),
    setItem: (k, v) => mem.set(k, String(v)),
    removeItem: (k) => mem.delete(k),
    clear: () => mem.clear()
  }
}

/**
 * Un núcleo de identidad entero, con el almacén a la vista para poder mirarlo.
 *
 * `mem`/`llaves` son EL EQUIPO (su `localStorage` y su IndexedDB) y `ses` es LA PESTAÑA.
 * Pasándolos se reabre el mismo navegador: con el mismo `ses` es recargar la pestaña, con
 * uno nuevo es abrir otra.
 */
async function nucleo ({ mem = new Map(), llaves = new Map(), ses = new Map() } = {}) {
  let peers = {}
  const kv = {
    getItem: (k) => (mem.has(k) ? mem.get(k) : null),
    setItem: (k, v) => mem.set(k, String(v)),
    removeItem: (k) => mem.delete(k)
  }
  const sessionKv = {
    getItem: (k) => (ses.has(k) ? ses.get(k) : null),
    setItem: (k, v) => ses.set(k, String(v)),
    removeItem: (k) => ses.delete(k)
  }
  // El mismo almacén de llaves del navegador: `CryptoKey` no extraíbles, por nombre.
  const keyStore = {
    get: async (name) => llaves.get(name) || null,
    set: async (name, pair) => { llaves.set(name, pair) },
    remove: async (name) => { llaves.delete(name) }
  }
  const core = await createIdentityCore({
    kv,
    keyStore,
    sessionKv,
    peers: {
      async initPeerStorage () {},
      loadPeers: () => peers,
      savePeers: (m) => { peers = m },
      setPeersDirect: (m) => { peers = m || {} },
      upsertPeer: (pub, patch) => { peers[pub] = { ...(peers[pub] || {}), ...patch, publickey: pub }; return peers[pub] },
      onDirty () {},
      setProfile () {}
    },
    makeSync: null
  })
  return { core, mem, llaves, ses }
}

/** El adaptador que `vault.js` le pasa a `startDeviceVault` desde el iframe. */
const comoElIframe = (core) => ({
  get me () { return core.me },
  signData: (data) => core.handlers.signData({ data }),
  signDelegation: (sub, scope, opts = {}) => core.handlers.signDelegation({ sub, scope, ...opts }),
  listDelegations: () => core.handlers.listDelegations({}),
  revokeDelegation: (nonce) => core.handlers.revokeDelegation({ nonce }),
  revokeDevice: (sub) => core.handlers.revokeDevice({ sub }),
  admitMember: (m) => core.handlers.admitMember(m),
  profileActa: () => core.handlers.profileActa({}),
  joinProfile: (acta) => core.handlers.joinProfile({ acta })
})

/** Un proxio de mentira: tokens, entrega dirigida y canales. */
function fakeProxy () {
  const conexiones = new Map()
  const canales = new Map()
  let n = 0
  return {
    connect (nombre) {
      const token = `${nombre}-${++n}`
      const oyentes = []
      conexiones.set(token, oyentes)
      return {
        token,
        url: 'wss://test.invalid',
        on (ev, fn) {
          if (ev !== 'message') return () => {}
          oyentes.push(fn)
          return () => { const i = oyentes.indexOf(fn); if (i >= 0) oyentes.splice(i, 1) }
        },
        send (to, obj) {
          for (const dest of (Array.isArray(to) ? to : [to])) {
            for (const fn of conexiones.get(dest) || []) queueMicrotask(() => fn(token, obj, {}))
          }
        },
        sendByPubkey () {},
        async identify () { return { ok: true } },
        async identifyAs () { return { ok: true } },
        async publish (c) { if (!canales.has(c)) canales.set(c, new Set()); canales.get(c).add(token); return { ok: true } },
        async list (c) { return [...(canales.get(c) || [])] },
        async requestPairingCode () { return { code: 'ABC123' } },
        close () { conexiones.delete(token) }
      }
    }
  }
}

/** Una bóveda-pestaña con un inicio de sesión ya dado de alta, y su dirección. */
async function bovedaConLogin (t, { user = 'ana', password = 'una contraseña larga de verdad' } = {}) {
  const proxy = fakeProxy()
  const { core } = await nucleo()
  const handle = await startDeviceVault(comoElIframe(core), {
    client: proxy.connect('vault'),
    logins: (() => { let g = null; return createLoginDesk({ load: () => (g ? JSON.parse(g) : null), save: (s) => { g = JSON.stringify(s) } }) })()
  })
  t.after(() => handle.close())

  const device = await makeDeviceKey({ label: 'equipo prestado' })
  const enc = await makeDeviceEncKey()
  const reg = opaqueClient.registrationStart({ password })
  const { response } = await handle.loginRegisterBegin({ user, request: reg.request })
  const fin = opaqueClient.registrationFinish({ state: reg.state, response, password })
  const blob = await sealDeviceKeys(fin.exportKey, { sign: device.privateJwk, enc: enc.encPrivateJwk })
  await handle.loginRegisterFinish({ user, upload: fin.upload, pub: device.publickey, encPub: enc.encPublickey, label: 'equipo prestado', blob })

  const { acta } = await core.handlers.profileActa({})
  const address = `${user}@${accountCode((await pubkeyId(acta.profileId)).slice(0, 16))}`
  return { proxy, boveda: core, handle, device, address, password, user, acta }
}

/**
 * Entrar de verdad, con el cliente vendorizado, y adoptar lo que salga.
 *
 * `proxy` apunta a un sitio donde no hay nadie a propósito: al SALIR, el núcleo abre su
 * propia conexión para avisar a la bóveda, y una prueba no llama a producción. Que no lo
 * consiga es justo el caso interesante —avisar es mejor esfuerzo, borrar de aquí no—, y la
 * otra mitad (que la bóveda suelta la plaza) está probada en `dotrino-vault`.
 */
async function entrar (proxy, navegador, { address, password, remember }) {
  const transporte = proxy.connect('prestado')
  const entrada = await loginWithPassword({ transport: transporte, address, password, label: 'el cyber' })
  const r = await navegador.adoptLogin(entrada, { remember, proxy: 'ws://127.0.0.1:1' })
  transporte.close()
  return { entrada, r }
}

test('el navegador pasa a SER el aparato: su llave, su acta y su papel', async (t) => {
  const { proxy, device, address, password, acta } = await bovedaConLogin(t)
  const { core } = await nucleo()

  const { r } = await entrar(proxy, core, { address, password, remember: true })

  const yo = await core.handlers.publicMe()
  assert.equal(yo.publickey, device.publickey, 'no entró con la llave del aparato')
  const mia = await core.handlers.profileActa({})
  assert.equal(mia.acta.profileId, acta.profileId, 'no adoptó la cuenta de la bóveda')
  const v = await core.handlers.vaultStatus()
  assert.ok(v.scope?.length, 'entró sin papel: no podría pedirle nada a la bóveda')
  assert.equal(r.volatile, false)

  const perfiles = await core.handlers.listProfiles()
  const suyo = perfiles.find((p) => p.current)
  assert.equal(suyo.login.address, address, 'la lista no dice que se entró con contraseña')
  assert.equal(suyo.login.volatile, false)
})

test('una cuenta de paso no se mete en el equipo: ni en su lista, ni como cuenta por defecto', async (t) => {
  const { proxy, address, password } = await bovedaConLogin(t)
  const { core, mem } = await nucleo()
  const suyaAntes = mem.get('dotrino.identity.profiles')
  const porDefectoAntes = mem.get('dotrino.identity.current')

  const { r } = await entrar(proxy, core, { address, password, remember: false })
  assert.equal(r.volatile, true)

  assert.ok((await core.handlers.listProfiles()).find((p) => p.current)?.login, 'la cuenta activa no es la del inicio de sesión')
  assert.equal(mem.get('dotrino.identity.profiles'), suyaAntes, 'se metió en la lista de perfiles del equipo')
  assert.equal(mem.get('dotrino.identity.current'), porDefectoAntes, 'le cambió la cuenta por defecto al equipo')
  assert.ok(JSON.parse(mem.get('dotrino.identity.volatile'))[r.id], 'sin latido, el primer arranque la borraría al instante')
})

test('sobrevive a navegar en ESA pestaña, y ninguna otra la ve', async (t) => {
  const { proxy, address, password } = await bovedaConLogin(t)
  const { core, mem, llaves, ses } = await nucleo()
  const { r } = await entrar(proxy, core, { address, password, remember: false })

  // Navegar = el iframe se muere y vuelve a nacer con el mismo `sessionStorage`.
  const recargada = await nucleo({ mem, llaves, ses })
  const activa = (await recargada.core.handlers.listProfiles()).find((p) => p.current)
  assert.equal(activa?.id, r.id, 'al navegar se perdió el inicio de sesión')
  assert.equal(activa.login.address, address)

  // Otra pestaña del mismo equipo: ni la ve, ni la puede usar.
  const otra = await nucleo({ mem, llaves })
  assert.notEqual((await otra.core.handlers.currentProfile()).id, r.id, 'otra pestaña acabó dentro de la cuenta prestada')
  assert.equal((await otra.core.handlers.listProfiles()).filter((p) => p.id === r.id).length, 0, 'otra pestaña la lista')
})

test('la cuenta de paso que nadie mantiene viva se borra al arrancar', async (t) => {
  const { proxy, address, password } = await bovedaConLogin(t)
  const { core, mem, llaves } = await nucleo()
  const { r } = await entrar(proxy, core, { address, password, remember: false })
  assert.ok([...llaves.keys()].some((k) => k.includes(`.p.${r.id}.`)), 'no guardó la llave del aparato')

  // La pestaña se cerró hace rato: su latido se quedó viejo.
  const vivas = JSON.parse(mem.get('dotrino.identity.volatile'))
  vivas[r.id] = Date.now() - 10 * 60 * 1000
  mem.set('dotrino.identity.volatile', JSON.stringify(vivas))

  await nucleo({ mem, llaves })   // el arranque siguiente, en cualquier pestaña

  assert.equal([...llaves.keys()].filter((k) => k.includes(`.p.${r.id}.`)).length, 0, 'la llave del aparato sigue en ese equipo')
  assert.equal([...mem.keys()].filter((k) => k.includes(`.p.${r.id}.`)).length, 0, 'quedaron datos de la cuenta prestada')
  assert.equal(JSON.parse(mem.get('dotrino.identity.volatile'))[r.id], undefined)
})

test('con «Recordar» sí se guarda, y la llave no es extraíble', async (t) => {
  const { proxy, address, password } = await bovedaConLogin(t)
  const { core, mem, llaves } = await nucleo()

  const { r } = await entrar(proxy, core, { address, password, remember: true })

  const guardadas = [...llaves.keys()].filter((k) => k.includes(`.p.${r.id}.`))
  assert.equal(guardadas.length, 2, 'no guardó las dos llaves del aparato')
  for (const k of guardadas) assert.equal(llaves.get(k).privateKey.extractable, false, 'la privada se guardó extraíble')
  assert.ok(JSON.stringify([...mem.entries()]).includes('"login"') || [...mem.keys()].some((k) => k.endsWith('.login')),
    'no anotó que esta cuenta se abrió con contraseña')
})

test('salir no deja rastro y devuelve la cuenta que había', async (t) => {
  const { proxy, handle, address, password, user } = await bovedaConLogin(t)
  const { core, mem, llaves, ses } = await nucleo()
  const antes = (await core.handlers.currentProfile()).id

  const { r: entrada } = await entrar(proxy, core, { address, password, remember: false })
  assert.equal(handle.listLogins().find((l) => l.user === user).sessions.length, 1, 'la bóveda no anotó la entrada')

  const r = await core.handlers.logoutLogin({})

  assert.equal(r.ok, true)
  assert.equal(r.told, false, 'con la bóveda inalcanzable no se puede haber avisado')
  assert.equal((await core.handlers.currentProfile()).id, antes, 'no volvió a la cuenta que había')
  assert.equal([...mem.keys()].filter((k) => k.includes(`.p.${entrada.id}.`)).length, 0, 'salir dejó datos suyos en el equipo')
  assert.equal([...llaves.keys()].filter((k) => k.includes(`.p.${entrada.id}.`)).length, 0, 'salir dejó su llave en el equipo')
  assert.equal(JSON.parse(mem.get('dotrino.identity.volatile'))[entrada.id], undefined, 'sigue anotada como cuenta de paso')
  assert.equal(ses.size, 0, 'la pestaña la sigue reclamando')
  assert.equal((await core.handlers.listProfiles()).filter((p) => p.login).length, 0, 'la cuenta sigue en la lista')
})

test('una llave que el acta no nombra no se adopta', async (t) => {
  const { proxy, address, password } = await bovedaConLogin(t)
  const { core } = await nucleo()
  const transporte = proxy.connect('prestado')
  const entrada = await loginWithPassword({ transport: transporte, address, password })
  transporte.close()

  const otra = await makeDeviceKey({ label: 'de nadie' })
  const e = await core.adoptLogin({ ...entrada, publickey: otra.publickey }, { remember: false }).catch((x) => x)
  assert.equal(e.code, 'not-a-member')
  assert.equal((await core.handlers.listProfiles()).filter((p) => p.login).length, 0, 'dejó media cuenta instalada')
})
