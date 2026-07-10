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

;(async () => {
  // kv estilo localStorage (síncrono) para keypairs, me y nonces.
  const kv = {
    getItem: (k) => localStorage.getItem(k),
    setItem: (k, v) => localStorage.setItem(k, v),
    removeItem: (k) => localStorage.removeItem(k)
  }

  const core = await createIdentityCore({
    kv,
    peers: { initPeerStorage, loadPeers, savePeers, setPeersDirect, upsertPeer, onDirty },
    makeSync: createSync
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
    const handler = handlers[method]
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
      window.parent.postMessage({ _cci: true, type: 'ready', me: core.me }, parentOrigin)
    } else {
      // Sin referrer (política estricta del padre) no podemos verificar el origen:
      // señalamos ready SIN datos (no revela nada; y las peticiones de orígenes
      // ajenos se ignoran igual). Las apps del ecosistema refrescan `me` por RPC.
      window.parent.postMessage({ _cci: true, type: 'ready' }, '*')
    }
  }
})()
