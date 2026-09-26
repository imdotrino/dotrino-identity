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
import { withExternalKeys, appBridge } from './externalKeys.js'
import { nativeBackends } from './nativeStore.js'
import { useBackend as usePeerBackend } from './peerStore.js'

;(async () => {
  // DENTRO DE LA APP, el puente con el teléfono. En un navegador no está y nada cambia.
  const idKeys = typeof window !== 'undefined' ? window.DotrinoIdentityKeys : null
  const bridge = idKeys ? appBridge(idKeys) : null
  // Y si la app GUARDA la identidad (`storage`, la de iOS): todo vive allí, uno para todas
  // las páginas, porque WebKit parte el almacén de este iframe por página (`./nativeStore.js`).
  const native = bridge && idKeys.storage === true ? await nativeBackends(bridge) : null
  if (native) usePeerBackend(native.peers)

  // kv estilo localStorage (síncrono) para me, nonces, delegaciones, certs.
  const kv = native ? native.kv : {
    getItem: (k) => localStorage.getItem(k),
    setItem: (k, v) => localStorage.setItem(k, v),
    removeItem: (k) => localStorage.removeItem(k)
  }

  // keyStore: las llaves PRIVADAS viven como CryptoKey NO EXTRACTABLES en
  // IndexedDB (clonado estructurado). Nadie —ni este código, ni un XSS en este
  // origen— puede leer sus bytes; solo firmar/derivar con ellas. Las llaves
  // planas (JWK) viejas de localStorage se migran y se borran (core.js).
  const baseKeyStore = native ? native.keyStore : await (() => new Promise((resolve) => {
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
  // DENTRO DE LA APP (Android e iOS), las llaves nuevas nacen en el chip del teléfono: una sola
  // llave por cuenta, la misma que aprueba en la pantalla nativa (`./externalKeys.js`). El
  // puente solo existe en este origen; en un navegador no está y nada cambia.
  const keyStore = bridge && baseKeyStore ? withExternalKeys(baseKeyStore, bridge) : baseKeyStore

  // sessionKv: la prueba de desbloqueo del candado por contraseña vive en
  // sessionStorage — POR PESTAÑA: sobrevive al refresco, muere al cerrarla.
  const sessionKv = {
    getItem: (k) => sessionStorage.getItem(k),
    setItem: (k, v) => sessionStorage.setItem(k, v),
    removeItem: (k) => sessionStorage.removeItem(k)
  }

  /**
   * EL PANEL DE PERMISO LO PINTA ESTE IFRAME, no la aplicación que pide.
   *
   * Es la diferencia entre un permiso y un trámite: la aplicación vive en otro origen, así
   * que no puede pulsar aquí dentro ni leer lo que hay. Lo único que puede hacer es NO
   * mostrarnos —y entonces no consigue el permiso, que es el lado correcto en el que
   * fallar—. Por eso se le pide que nos muestre (`consent:open`) y, si no lo hace, la
   * pregunta se queda sin responder y se deniega sola.
   */
  const T_CONSENT = (() => {
    const en = (navigator.language || 'es').startsWith('en')
    return en
      ? { title: 'wants to see', allow: 'Allow', deny: 'No', who: 'Your Dotrino identity', once: 'Only what you allow leaves here.', via: 'through' }
      : { title: 'quiere ver', allow: 'Permitir', deny: 'No', who: 'Tu identidad de Dotrino', once: 'De aquí solo sale lo que permitas.', via: 'a través de' }
  })()
  const SCOPE_TXT = (() => {
    const en = (navigator.language || 'es').startsWith('en')
    return en
      ? { 'profile:name': 'your name', 'profile:avatar': 'your picture', 'profile:email': 'your email', 'profile:social': 'your links', 'id:whoami': 'who you are' }
      : { 'profile:name': 'tu nombre', 'profile:avatar': 'tu foto', 'profile:email': 'tu correo', 'profile:social': 'tus enlaces', 'id:whoami': 'quién eres' }
  })()

  /**
   * CÓMO SE LLAMA QUIEN PIDE. Una dirección cruda no dice nada —y quien la lee deprisa no
   * distingue `chat.dotrino.com` de `chat.dotrlno.com`—, así que se enseña el nombre y
   * DEBAJO la dirección entera, que es lo que de verdad identifica.
   *
   * No se importa el catálogo de aplicaciones: eso ataría este iframe al repositorio del
   * home y habría que subirlo cada vez que nace una app. El subdominio ya es el nombre.
   */
  /** Lo que dice el origen se pinta como texto, nunca como marcado: quien lo escribe es él. */
  const escaparTexto = (t) => String(t).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]))

  function nombreDeOrigen (origin) {
    try {
      const h = new URL(origin).hostname
      if (h === 'dotrino.com' || h === 'www.dotrino.com') return 'Dotrino'
      const m = /^([a-z0-9-]+)\.dotrino\.com$/.exec(h)
      if (m) return m[1].charAt(0).toUpperCase() + m[1].slice(1)
      return h
    } catch (_) { return String(origin) }
  }

  let consentAbierto = null
  function askConsent ({ origin, scopes, onBehalfOf }) {
    if (consentAbierto) return Promise.resolve(false)   // una pregunta a la vez
    return new Promise((resolve) => {
      const host = document.createElement('div')
      host.style.cssText = 'position:fixed;inset:0;z-index:2147483647;display:flex;align-items:center;justify-content:center;background:rgba(10,8,20,.86);font-family:system-ui,-apple-system,Segoe UI,sans-serif'
      const lista = scopes.map((x) => `<li>${SCOPE_TXT[x] || x}</li>`).join('')
      host.innerHTML = `<div style="background:#171331;border:1px solid #2a2350;border-radius:16px;padding:22px;min-width:min(320px,90vw);max-width:90vw;color:#e7e3ff">
        <div style="opacity:.7;font-size:13px">${T_CONSENT.who}</div>
        <div style="font-weight:700;margin:8px 0 4px">${onBehalfOf ? escaparTexto(onBehalfOf) : nombreDeOrigen(origin)} ${T_CONSENT.title}:</div>
        <div style="opacity:.55;font-size:12px;margin-bottom:6px">${onBehalfOf ? T_CONSENT.via + ' ' : ''}${String(origin).replace(/^https?:\/\//, '')}</div>
        <ul style="margin:6px 0 12px 18px;padding:0">${lista}</ul>
        <div style="opacity:.7;font-size:12px;margin-bottom:12px">${T_CONSENT.once}</div>
        <div style="display:flex;gap:8px">
          <button data-yes style="flex:1;padding:10px;border-radius:10px;border:0;background:#7c3aed;color:#fff;font:inherit;font-weight:600;cursor:pointer">${T_CONSENT.allow}</button>
          <button data-no style="flex:1;padding:10px;border-radius:10px;border:1px solid #2a2350;background:transparent;color:inherit;font:inherit;cursor:pointer">${T_CONSENT.deny}</button>
        </div></div>`
      const cerrar = (v) => { try { host.remove() } catch (_) {} consentAbierto = null; broadcast('consent:close', {}); resolve(v) }
      host.querySelector('[data-yes]').addEventListener('click', () => cerrar(true))
      host.querySelector('[data-no]').addEventListener('click', () => cerrar(false))
      consentAbierto = host
      document.body.appendChild(host)
      broadcast('consent:open', { origin })
      // Si nadie contesta —porque nadie nos mostró—, se deniega. Nunca al revés.
      setTimeout(() => { if (consentAbierto === host) cerrar(false) }, 60000)
    })
  }

  const core = await createIdentityCore({
    kv,
    peers: { initPeerStorage, loadPeers, savePeers, setPeersDirect, upsertPeer, onDirty },
    makeSync: createSync,
    keyStore,
    sessionKv,
    askConsent
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
  /**
   * Proxio del mostrador, SOLO en localhost (`?proxy=ws://…` en la URL de este iframe).
   *
   * En producción es el del ecosistema y no hay nada que elegir. Existe porque las
   * pruebas de punta a punta levantan su propio proxio y prometen no tocar producción:
   * sin esto, el mostrador de una bóveda-en-pestaña marcaba a `proxy.dotrino.com` desde
   * el banco de pruebas. Es el mismo permiso que ya tiene `?vault=` en la consola.
   */
  const selfProxyUrl = (() => {
    try {
      const u = new URL(location.href)
      if (!/^(localhost|127\.0\.0\.1|\[::1\])$/.test(u.hostname)) return null
      const p = u.searchParams.get('proxy')
      return /^wss?:\/\//.test(p || '') ? p : null
    } catch (_) { return null }
  })()
  let daemon = null           // handle de startDeviceVault cuando ESTE iframe es el activo
  let _lockResolver = null    // resolver del callback del lock (libera al resolverlo)

  // Adaptador: startDeviceVault exige identity.{me.publickey, signData, signDelegation,
  // listDelegations, revokeDelegation}; el core los expone vía handlers + getter me.
  // `admitMember`/`profileActa` son opcionales para el mostrador de enrolamiento, pero sin
  // ellos aprobar emitiría el cert SIN meter al dispositivo en el acta: se pasan también.
  const selfIdentity = {
    get me () { return core.me },
    signData: (data) => handlers.signData({ data }),
    signDelegation: (sub, scope, opts) => handlers.signDelegation({ sub, scope, ...(opts || {}) }),
    listDelegations: () => handlers.listDelegations({}),
    revokeDelegation: (nonce) => handlers.revokeDelegation({ nonce }),
    revokeDevice: (sub) => handlers.revokeDevice({ sub }),
    admitMember: (m) => handlers.admitMember(m),
    profileActa: () => handlers.profileActa({}),
    // Camino A (`mode: 'adopt'`): la bóveda se queda con la cuenta que trae el aparato,
    // y para eso tiene que poder ENTRAR en su acta. Sin esto, adoptar fallaba con un
    // «no es una función» en vez de con un error del protocolo.
    joinProfile: (acta) => handlers.joinProfile({ acta })
  }

  /**
   * EL ESCRITORIO DE LOS INICIOS DE SESIÓN CON CONTRASEÑA, con el almacén de este navegador.
   *
   * La bóveda no decide dónde se guarda nada: en el navegador no hay archivos, así que el
   * estado lo pone quien la monta —esto—. Sin escritorio la pestaña contesta
   * `logins-unavailable`, que es distinto de «contraseña incorrecta» y por eso se ve.
   *
   * Cuelga del PERFIL ACTIVO: los inicios de sesión son de una cuenta, no de este
   * navegador, y dos cuentas en el mismo equipo no comparten usuarios.
   *
   * Se carga solo aquí, y no arriba, porque arrastra el OPAQUE en WASM (~270 KB): el
   * iframe lo cargan las ~30 apps del ecosistema y solo esta pestaña es bóveda.
   *
   * Lo que guarda aguanta lo mismo que el disco del daemon: con una copia de este
   * `localStorage` se pueden probar contraseñas sin límite contra el registro de OPAQUE.
   * Lo único que aguanta ahí es que la contraseña sea larga (`temporary-access.md` §4).
   */
  async function makeLoginDesk () {
    const { createLoginDesk } = await import('@dotrino/vault/password-logins')
    const { id: pid } = await handlers.currentProfile()
    if (!pid) throw new Error('no profile: password logins belong to an account')
    const key = `dotrino.identity.p.${pid}.self-vault.logins`
    return createLoginDesk({
      load: () => {
        const raw = kv.getItem(key)
        // Si está y no parsea, REVIENTA aquí a propósito: devolver `null` haría nacer el
        // escritorio vacío, y el primer guardado se llevaría por delante todos los inicios
        // de sesión de esta cuenta sin que nadie se enterara.
        return raw ? JSON.parse(raw) : null
      },
      save: (s) => kv.setItem(key, JSON.stringify(s))
    })
  }

  async function startSelfDaemon () {
    if (daemon) return
    try {
      // Import dinámico: aísla fallos del vendor del arranque del vault (cargado por
      // todas las apps). El import map de index.html resuelve @dotrino/vault.
      const { startDeviceVault } = await import('@dotrino/vault')
      daemon = await startDeviceVault(selfIdentity, {
        ...(selfProxyUrl ? { proxyUrl: selfProxyUrl } : {}),
        logins: await makeLoginDesk()
      })
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
      if (!daemon) throw new Error('this tab is not the active vault; open it as a visible tab')
      return daemon.startPairing(opts)
    },
    selfVaultPending: async () => (daemon ? daemon.listPending() : []),
    selfVaultMachines: async () => {
      if (daemon) return daemon.listMachines()
      const { issued } = await handlers.listDelegations({})
      return issued || []
    },
    selfVaultApprove: async ({ deviceId, code }) => {
      if (!daemon) throw new Error('this tab is not the active vault')
      return daemon.approve(deviceId, code)
    },
    selfVaultReject: async ({ deviceId }) => {
      if (!daemon) throw new Error('this tab is not the active vault')
      daemon.reject(deviceId)
      return { ok: true }
    },
    /**
     * QUITAR UN APARATO cuando la bóveda es ESTE navegador. Por `sub` (su llave): sale del
     * acta y se le retiran todos los certificados, que son las dos caras del mismo acto.
     *
     * Con `nonce` a secas solo cae UN papel y el aparato sigue siendo miembro — un
     * fantasma en la lista al que además ya nunca le llega el aviso de expulsión, porque
     * mientras siga en el acta un papel retirado significa «renueva», no «estás fuera».
     * Se conserva para quien de verdad quiera retirar un certificado suelto.
     */
    selfVaultRevoke: async ({ sub, nonce }) => {
      if (sub) {
        if (daemon?.revokeDevice) return daemon.revokeDevice(sub)
        return handlers.revokeDevice({ sub })
      }
      if (daemon) return daemon.revoke(nonce)
      return handlers.revokeDelegation({ nonce })
    },
    // Presencia online (ping/pong) de las máquinas enroladas. Requiere que ESTE
    // iframe sea el daemon activo (tiene el cliente del proxy); si no, devuelve [].
    selfVaultProbe: async ({ pubkeys }) => ({ online: [...(await probeOnline(pubkeys || []))] }),

    // ----- ENTRAR CON USUARIO Y CONTRASEÑA, desde la PESTAÑA -----
    //
    // La bóveda-pestaña ya sabía ATENDER un inicio de sesión desde el primer día; lo que no
    // había era forma de CREAR uno: el mostrador estaba montado y sus operaciones no
    // asomaban por aquí, así que solo el binario podía dar de alta el aparato. Eso rompe la
    // regla de las tres versiones (`sealed-passwords.md` §2.7), y esto la cumple.
    //
    // El OPAQUE de las dos puntas corre AQUÍ DENTRO: el alta necesita la mitad del cliente
    // —la que tiene la contraseña— y la mitad del servidor, y las dos están en esta pestaña
    // cuando es bóveda. La contraseña cruza el `postMessage` como ya lo hace la del perfil
    // (`unlockProfile`), y no sale de este origen.
    selfVaultLogins: async () => (daemon ? daemon.listLogins() : []),

    /**
     * DAR DE ALTA un aparato que se abre con usuario y contraseña.
     *
     * Las llaves del aparato NACEN aquí y salen ya cerradas con lo que deriva la contraseña:
     * la bóveda guarda un paquete que no puede abrir. Es el mismo camino que `logins add`
     * del binario, con la misma pieza compartida.
     */
    selfVaultLoginAdd: async ({ user, password, label = '', caps } = {}) => {
      const d = pidaDaemon()
      const { client: opaque } = await import('@dotrino/opaque')
      const { makeDeviceKey, makeDeviceEncKey } = await import('@dotrino/identity/capabilities')
      const { sealDeviceKeys, loginAddress, accountFingerprint } = await import('@dotrino/vault/password-logins')
      if (typeof password !== 'string' || password.length < 12) {
        throw Object.assign(new Error('the password must be at least 12 characters'), { code: 'weak-password' })
      }
      const nombre = String(label || 'equipo prestado')
      const reg = opaque.registrationStart({ password })
      const { response } = await d.loginRegisterBegin({ user, request: reg.request })
      const fin = opaque.registrationFinish({ state: reg.state, response, password })
      const device = await makeDeviceKey({ label: nombre })
      const enc = await makeDeviceEncKey()
      const blob = await sealDeviceKeys(fin.exportKey, { sign: device.privateJwk, enc: enc.encPrivateJwk })
      const r = await d.loginRegisterFinish({
        user, upload: fin.upload, pub: device.publickey, encPub: enc.encPublickey,
        // Los PERMISOS del acta, cualquiera de ellos: los traduce a scopes el pilar del vault.
        label: nombre, blob, ...(caps ? { caps } : {})
      })
      return { ...r, address: loginAddress(user, await accountFingerprint(selfIdentity)) }
    },

    /**
     * CAMBIAR LA CONTRASEÑA es abrir y volver a cerrar: el aparato, su llave y su papel
     * siguen siendo los mismos. Por eso hace falta la vieja — sin ella no hay nada que
     * volver a cerrar — y por eso lo que estuviera abierto se cierra.
     */
    selfVaultLoginPasswd: async ({ user, oldPassword, newPassword } = {}) => {
      const d = pidaDaemon()
      const { client: opaque } = await import('@dotrino/opaque')
      const { sealDeviceKeys, openDeviceKeys } = await import('@dotrino/vault/password-logins')
      if (typeof newPassword !== 'string' || newPassword.length < 12) {
        throw Object.assign(new Error('the password must be at least 12 characters'), { code: 'weak-password' })
      }
      const start = opaque.loginStart({ password: oldPassword })
      const begun = await d.loginBegin({ user, request: start.request })
      let fin
      try { fin = opaque.loginFinish({ state: start.state, response: begun.response, password: oldPassword }) }
      catch (_) { throw Object.assign(new Error('wrong password'), { code: 'login-failed' }) }
      const entered = await d.loginEnd({ lid: begun.lid, finalization: fin.finalization, label: 'consola' })
      const keys = await openDeviceKeys(fin.exportKey, entered.blob)

      const reg = opaque.registrationStart({ password: newPassword })
      const { response } = await d.loginRegisterBegin({ user, request: reg.request, replace: true })
      const nueva = opaque.registrationFinish({ state: reg.state, response, password: newPassword })
      await d.loginRegisterFinish({
        user, upload: nueva.upload, blob: await sealDeviceKeys(nueva.exportKey, keys), replace: true
      })
      return { ok: true, user }
    },

    /** Cerrar un inicio de sesión abierto (sin `sid`, todos los de ese usuario). */
    selfVaultLoginClose: async ({ user, sid = null } = {}) => {
      const d = pidaDaemon()
      if (sid) return d.closeLogin({ user, sid })
      const fila = d.listLogins().find((x) => x.user === user)
      for (const s of fila?.sessions || []) d.closeLogin({ user, sid: s.sid })
      return { ok: true, closed: (fila?.sessions || []).length }
    },

    /** Quitar la espera de los intentos fallidos, desde la máquina de la bóveda. */
    selfVaultLoginUnblock: async ({ user } = {}) => pidaDaemon().clearLoginBlock({ user }),

    /**
     * QUITARLO. Se va de aquí **y su llave sale del acta**: borrar solo el inicio de sesión
     * dejaba un miembro que ya no puede entrar y sigue siendo de la cuenta.
     */
    selfVaultLoginRemove: async ({ user } = {}) => {
      const d = pidaDaemon()
      const fila = d.listLogins().find((x) => x.user === user)
      const r = d.removeLogin({ user })
      if (r?.ok && fila?.pub) {
        try { await handlers.revokeDevice({ sub: fila.pub }) } catch (e) {
          throw Object.assign(new Error(`the login is gone but its key is still in the record: ${e.message}`), { code: 'revoke-failed' })
        }
      }
      return { ...r, deviceId: fila?.deviceId || null }
    }
  }

  /**
   * El mostrador solo existe mientras ESTA pestaña sea la bóveda activa. Se dice con esas
   * palabras porque es lo que hay que hacer: abrirla y dejarla visible.
   */
  function pidaDaemon () {
    if (!daemon) {
      throw Object.assign(
        new Error('this tab is not the active vault: open it as a visible tab and turn on «this device is a vault»'),
        { code: 'not-the-vault' })
    }
    return daemon
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
      // EL ORIGEN LO PONE EL IFRAME, no quien llama: va pisado a propósito. Es el único
      // dato que la aplicación no puede falsificar —el navegador lo garantiza— y de él
      // depende a quién se le concedió qué.
      const result = await handler({ ...(params || {}), __origin: event.origin })
      reply({ result })
    } catch (e) {
      // `code` (y su `detail`) CRUZAN. Sin ellos, al otro lado solo llegaba la frase, y una
      // app que quiere reaccionar a un rechazo concreto —«esa bóveda ya está en otra cuenta
      // de este aparato»— no tenía más remedio que emparejarla por su texto: se traduce o se
      // reescribe y deja de funcionar sin que nadie se entere.
      reply({
        error: e?.message || String(e),
        ...(e?.code ? { code: e.code } : {}),
        ...(e?.detail ? { detail: e.detail } : {})
      })
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
