/**
 * Dotrino Identity Vault (cáscara de navegador).
 *
 * Cargado dentro de un iframe oculto por las apps. La criptografía y todos los
 * handlers viven en `./core.js` (runtime-agnóstico); este archivo sólo provee
 * los backends del navegador —`localStorage` (kv), el peer book en IndexedDB
 * (`./peerStore.js`) y el sync a Google Drive (`./sync.js`)— y el transporte
 * `postMessage` con los embebedores. La clave privada nunca sale de esta página.
 */

import { createSync } from './sync.js'
import {
  initPeerStorage, loadPeers, savePeers, setPeersDirect, upsertPeer, onDirty
} from './peerStore.js'
import { createIdentityCore } from './core.js'
import { pubkeyId } from './capabilities.js'

;(async () => {
  // kv estilo localStorage (síncrono) para me, nonces, delegaciones, certs.
  const kv = {
    getItem: (k) => localStorage.getItem(k),
    setItem: (k, v) => localStorage.setItem(k, v),
    removeItem: (k) => localStorage.removeItem(k)
  }

  // keyStore: las llaves PRIVADAS viven como CryptoKey NO EXTRACTABLES en
  // IndexedDB (clonado estructurado). Nadie —ni este código, ni un XSS en este
  // origen— puede leer sus bytes; solo firmar/derivar con ellas. Las llaves
  // planas (JWK) viejas de localStorage se migran y se borran (core.js).
  const keyStore = await (() => new Promise((resolve) => {
    const req = indexedDB.open('dotrino-identity-keys', 1)
    req.onupgradeneeded = () => req.result.createObjectStore('keys')
    req.onsuccess = () => {
      const db = req.result
      const op = (mode, fn) => new Promise((res, rej) => {
        const tx = db.transaction('keys', mode)
        const r = fn(tx.objectStore('keys'))
        r.onsuccess = () => res(r.result ?? null)
        r.onerror = () => rej(r.error)
      })
      resolve({
        get: (name) => op('readonly', (st) => st.get(name)),
        set: (name, pair) => op('readwrite', (st) => st.put(pair, name)),
        remove: (name) => op('readwrite', (st) => st.delete(name))
      })
    }
    req.onerror = () => resolve(null) // sin IDB (raro): cae al modo kv legado
  }))()

  // sessionKv: la prueba de desbloqueo del candado por contraseña vive en
  // sessionStorage — POR PESTAÑA: sobrevive al refresco, muere al cerrarla.
  const sessionKv = {
    getItem: (k) => sessionStorage.getItem(k),
    setItem: (k, v) => sessionStorage.setItem(k, v),
    removeItem: (k) => sessionStorage.removeItem(k)
  }

  const core = await createIdentityCore({
    kv,
    peers: { initPeerStorage, loadPeers, savePeers, setPeersDirect, upsertPeer, onDirty },
    makeSync: createSync,
    keyStore,
    sessionKv
  })

  const { handlers } = core

  // ---- Control de ORIGEN (crítico): la identidad solo habla con el ecosistema. ----
  // Sin esto, CUALQUIER web podía embeber este iframe y llamar `exportIdentity`
  // (llave privada cruda), `signData` (suplantación) o leer tu perfil/contactos.
  // Permitidos: *.dotrino.com (y apex), el mirror de la org en GitHub Pages, y
  // orígenes de desarrollo (localhost / 127.0.0.1 / IPs de LAN privada).
  const ALLOWED_ORIGIN = new RegExp(
    '^(' +
    'https://([a-z0-9-]+\\.)*dotrino\\.com' + '|' +
    'https://imdotrino\\.github\\.io' + '|' +
    'https?://localhost(:\\d+)?' + '|' +
    'https?://127\\.0\\.0\\.1(:\\d+)?' + '|' +
    'https?://192\\.168\\.\\d{1,3}\\.\\d{1,3}(:\\d+)?' + '|' +
    'https?://10\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}(:\\d+)?' + '|' +
    'https?://172\\.(1[6-9]|2\\d|3[01])\\.\\d{1,3}\\.\\d{1,3}(:\\d+)?' +
    ')$'
  )
  const isAllowed = (origin) => typeof origin === 'string' && ALLOWED_ORIGIN.test(origin)

  // Broadcast de eventos del vault (sync + emparejamiento) SOLO a embebedores que
  // ya hicieron una petición válida (ventana+origen verificados), nunca con '*'.
  const embedders = [] // [{ win, origin }]
  const rememberEmbedder = (win, origin) => {
    if (!win || win === window) return
    if (!embedders.some((e) => e.win === win)) embedders.push({ win, origin })
  }
  const broadcast = (eventName, payload) => {
    for (const { win, origin } of embedders) {
      try { win.postMessage({ _cci: true, type: 'event', event: eventName, payload }, origin) } catch {}
    }
  }
  core.onSyncStatus((p) => broadcast('sync', p))
  core.onVaultEvent((p) => broadcast('vault', p))

  // ---- Modo SELF: este navegador actúa como bóveda (daemon device-vault) ----
  // startDeviceVault convierte la identidad P en CA: atiende enrolamientos y consultas
  // de revocación por el proxy. Solo UN iframe por origin es el daemon activo
  // (navigator.locks): la pestaña VISIBLE sostiene el lock; al pasar a background lo
  // libera y otra pestaña visible lo toma. Así varias apps abiertas no compiten.
  const SELF_FLAG = 'dotrino.self-vault.enabled' // persistido en localStorage (kv)
  const SELF_LOCK = 'dotrino-self-vault'
  let daemon = null           // handle de startDeviceVault cuando ESTE iframe es el activo
  let _lockResolver = null    // resolver del callback del lock (libera al resolverlo)

  // Adaptador: startDeviceVault exige identity.{me.publickey, signData, signDelegation,
  // listDelegations, revokeDelegation}; el core los expone vía handlers + getter me.
  const selfIdentity = {
    get me () { return core.me },
    signData: (data) => handlers.signData({ data }),
    signDelegation: (sub, scope, opts) => handlers.signDelegation({ sub, scope, ...(opts || {}) }),
    listDelegations: () => handlers.listDelegations({}),
    revokeDelegation: (nonce) => handlers.revokeDelegation({ nonce })
  }

  async function startSelfDaemon () {
    if (daemon) return
    try {
      // Import dinámico: aísla fallos del vendor del arranque del vault (cargado por
      // todas las apps). El import map de index.html resuelve @dotrino/vault.
      const { startDeviceVault } = await import('@dotrino/vault')
      daemon = await startDeviceVault(selfIdentity)
      daemon.onPendingChange(() => broadcast('selfVault', { pending: daemon.listPending() }))
      broadcast('selfVault', { running: true })
    } catch (e) { daemon = null; broadcast('selfVault', { error: e?.message || String(e) }) }
  }
  function stopSelfDaemon () {
    if (!daemon) return
    try { daemon.close() } catch {}
    daemon = null
    broadcast('selfVault', { running: false })
  }

  // Adquiere el lock solo si el modo self está activado Y la pestaña es visible.
  function holdSelfLock () {
    if (!navigator.locks) return
    if (kv.getItem(SELF_FLAG) !== '1' || document.visibilityState !== 'visible') return
    navigator.locks.request(SELF_LOCK, { mode: 'exclusive', ifAvailable: true }, async (lock) => {
      if (!lock) return // otra pestaña visible lo tiene
      await startSelfDaemon()
      await new Promise((resolve) => { _lockResolver = resolve }) // mantener el lock
      stopSelfDaemon()
    }).catch(() => {})
  }
  function releaseSelfLock () { if (_lockResolver) { _lockResolver(); _lockResolver = null } }

  document.addEventListener('visibilitychange', () => {
    if (document.visibilityState === 'visible') holdSelfLock()
    else releaseSelfLock()
  })

  // Sonda de presencia (ping/pong por el proxy del daemon). Mandamos AMBOS tipos
  // (ra.ping para agentes @dotrino/remote-agent —ia—; terminal.ping para terminal
  // pre-migración) y consideramos online si responde cualquiera. Reusa el cliente
  // del proxy del daemon activo en ESTE iframe; si no hay daemon, devuelve vacío.
  function probeOnline (pubkeys, { timeoutMs = 4000 } = {}) {
    return new Promise((resolve) => {
      const online = new Set()
      const client = daemon?.client
      if (!client?.sendByPubkey || !pubkeys.length) return resolve(online)
      let rest = pubkeys.length
      const byNonce = new Map()
      const off = client.on('message', (_f, p) => {
        if (!p || typeof p !== 'object') return
        if (p.type === 'ra.pong' || p.type === 'terminal.pong') {
          const pk = byNonce.get(p.n)
          if (pk) { online.add(pk); byNonce.delete(p.n); settle() }
        }
      })
      function settle () { if (--rest <= 0) { off(); resolve(online) } }
      for (const pk of pubkeys) {
        const n = pk.slice(0, 6) + Math.random().toString(36).slice(2, 8)
        byNonce.set(n, pk)
        try { client.sendByPubkey(pk, { type: 'ra.ping', n }); client.sendByPubkey(pk, { type: 'terminal.ping', n }) } catch {}
        setTimeout(settle, timeoutMs)
      }
    })
  }

  // Handlers de UI (emparejamiento/gestión) expuestos por postMessage. Las ACCIONES
  // (pairing/approve) requieren que ESTE iframe sea el daemon activo (la pestaña visible);
  // la lectura (máquinas/pending) siempre funciona (lee delegaciones persistidas).
  const selfHandlers = {
    // En modo self, listar máquinas enroladas lee LOCAL (listDelegations) en vez de
    // hacer RPC al daemon del PC: somos nuestra propia maestra. Así ia/terminal listan
    // agentes siempre, sin depender de qué pestaña sostenga el lock del daemon.
    listVaultDevices: async () => {
      if (kv.getItem(SELF_FLAG) !== '1') return handlers.listVaultDevices({})
      const { issued, revoked } = await handlers.listDelegations({})
      const now = Date.now()
      const bySub = new Map()
      for (const x of (issued || [])) {
        if (!x.sub || x.revokedAt || (x.exp && x.exp <= now)) continue
        if (!Array.isArray(x.scope) || !x.scope.includes('vault:sign')) continue
        if (!bySub.has(x.sub) || (x.exp || 0) > (bySub.get(x.sub).exp || 0)) bySub.set(x.sub, x)
      }
      const devices = await Promise.all([...bySub.values()].map(async (x) => ({
        deviceId: (await pubkeyId(x.sub)).slice(0, 8).toUpperCase().replace(/(.{4})(.{4})/, '$1-$2'),
        sub: x.sub, label: x.label || '', scope: x.scope, exp: x.exp, nonce: x.nonce
      })))
      return { devices, revoked: (revoked || []).map((r) => r.nonce || r) }
    },
    selfVaultStatus: async () => ({ enabled: kv.getItem(SELF_FLAG) === '1', running: !!daemon }),
    setSelfVault: async ({ enabled }) => {
      kv.setItem(SELF_FLAG, enabled ? '1' : '0')
      if (enabled) holdSelfLock(); else releaseSelfLock()
      return { ok: true, enabled: !!enabled }
    },
    selfVaultPairing: async (opts) => {
      if (!daemon) throw new Error('esta pestaña no es la bóveda activa; ábrela como pestaña visible')
      return daemon.startPairing(opts)
    },
    selfVaultPending: async () => (daemon ? daemon.listPending() : []),
    selfVaultMachines: async () => {
      if (daemon) return daemon.listMachines()
      const { issued } = await handlers.listDelegations({})
      return issued || []
    },
    selfVaultApprove: async ({ deviceId, code }) => {
      if (!daemon) throw new Error('esta pestaña no es la bóveda activa')
      return daemon.approve(deviceId, code)
    },
    selfVaultReject: async ({ deviceId }) => {
      if (!daemon) throw new Error('esta pestaña no es la bóveda activa')
      daemon.reject(deviceId)
      return { ok: true }
    },
    selfVaultRevoke: async ({ nonce }) => {
      if (daemon) return daemon.revoke(nonce)
      return handlers.revokeDelegation({ nonce })
    },
    // Presencia online (ping/pong) de las máquinas enroladas. Requiere que ESTE
    // iframe sea el daemon activo (tiene el cliente del proxy); si no, devuelve [].
    selfVaultProbe: async ({ pubkeys }) => ({ online: [...(await probeOnline(pubkeys || []))] })
  }

  window.addEventListener('message', async (event) => {
    const msg = event.data
    if (!msg || msg._cci !== true || msg.type !== 'request') return
    if (!isAllowed(event.origin)) return // origen ajeno: silencio total
    rememberEmbedder(event.source, event.origin)
    const { id, method, params } = msg
    const reply = (payload) => event.source?.postMessage(
      { _cci: true, type: 'response', id, ...payload },
      event.origin
    )
    const handler = selfHandlers[method] || handlers[method]
    if (!handler) return reply({ error: `Unknown method: ${method}` })
    try {
      const result = await handler(params || {})
      reply({ result })
    } catch (e) {
      reply({ error: e?.message || String(e) })
    }
  })

  // Avisar al padre que el vault está listo — solo si su origen (referrer) es del
  // ecosistema; a una página ajena no se le revela NADA (ni pubkey ni apodo).
  if (window.parent && window.parent !== window) {
    let parentOrigin = null
    try { parentOrigin = new URL(document.referrer).origin } catch {}
    if (parentOrigin && isAllowed(parentOrigin)) {
      rememberEmbedder(window.parent, parentOrigin)
      // Perfil BLOQUEADO por contraseña → ready sin datos (ni apodo ni pubkey):
      // la app debe desbloquear (unlockProfile) y refrescar con getMe.
      const lock = await handlers.profileLockStatus().catch(() => ({ locked: false }))
      window.parent.postMessage({ _cci: true, type: 'ready', ...(lock.locked ? { locked: true } : { me: core.me }) }, parentOrigin)
    } else {
      // Sin referrer (política estricta del padre) no podemos verificar el origen:
      // señalamos ready SIN datos (no revela nada; y las peticiones de orígenes
      // ajenos se ignoran igual). Las apps del ecosistema refrescan `me` por RPC.
      window.parent.postMessage({ _cci: true, type: 'ready' }, '*')
    }
  }
  // Si el modo self-vault ya estaba activado, intentar tomar el lock (pestaña visible).
  holdSelfLock()
})()
