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

  // Broadcast de eventos del vault (sync + emparejamiento) a todos los embebedores.
  const broadcast = (eventName, payload) => {
    for (const w of [window.parent, ...Array.from(document.querySelectorAll('iframe')).map(f => f.contentWindow)]) {
      if (!w || w === window) continue
      try { w.postMessage({ _cci: true, type: 'event', event: eventName, payload }, '*') } catch {}
    }
  }
  core.onSyncStatus((p) => broadcast('sync', p))
  core.onVaultEvent((p) => broadcast('vault', p))

  window.addEventListener('message', async (event) => {
    const msg = event.data
    if (!msg || msg._cci !== true || msg.type !== 'request') return
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

  // Avisar a todo padre que el vault está listo.
  if (window.parent && window.parent !== window) {
    window.parent.postMessage({ _cci: true, type: 'ready', me: core.me }, '*')
  }
})()
