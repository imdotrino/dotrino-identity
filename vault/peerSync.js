/**
 * EL LIBRO DE CONTACTOS EN LA BÓVEDA: los mismos contactos en todos los aparatos del perfil.
 *
 * Hasta aquí el libro vivía en cada aparato (el navegador, la app de identidad del teléfono) y
 * solo viajaba por Google Drive, que es opcional y no existe en las apps nativas: el mismo perfil
 * veía sus conversaciones en otro aparato (el historial sí se respalda) pero no a sus contactos.
 *
 * Ahora el libro es UN HILO más del almacén de la bóveda (`identity.peers`), con una entrada por
 * persona `{ id, ts, peer }`: `id` sale de su llave y `ts` es la última vez que su ficha cambió
 * (`stampOf`). Viaja cifrado con la clave de contenido del perfil, por el mismo camino que el
 * historial (`identity.vaultStore`). Se reconcilia por índice: se sube lo que aquí es más nuevo y
 * se trae lo que allí lo es, y lo que llega se FUNDE con lo de aquí (`mergePeer`), no lo pisa.
 *
 * Quitar un contacto es un cambio más (`changedAt`): gana el más reciente, así un contacto que
 * quitaste no vuelve desde otro aparato. Lo mismo hacen `PeerBookBackup` en Android e iOS.
 */

export const PEERS_THREAD = 'identity.peers'

/** Tope de una tanda de subida (cifrada, con su sobre, queda bajo el 1 MB del proxio). */
const PUSH_BYTES = 350_000

/** La última vez que la ficha cambió: la vio (`lastSeen`) o la tocaste (`changedAt`). */
export function stampOf (rec) {
  return Math.max(Number(rec?.lastSeen) || 0, Number(rec?.changedAt) || 0)
}

/** El id de la entrada: de su llave, estable y sin comillas (sha-256, 32 hex). */
export async function peerIdOf (publickey) {
  const d = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(String(publickey)))
  return [...new Uint8Array(d)].slice(0, 16).map((b) => b.toString(16).padStart(2, '0')).join('')
}

/**
 * Reconciliar el libro con la bóveda. `peers` es el libro de aquí (`{ publickey: ficha }`),
 * `call(method, args)` habla con el almacén de la bóveda. Devuelve las fichas que llegaron (para
 * fundirlas aquí) y cuántas subieron.
 */
export async function syncPeers ({ peers, call }) {
  const remote = new Map()
  let cursor = null
  do {
    const page = await call('getThreadIndexes', { keys: [PEERS_THREAD], cursor })
    const idx = page?.indexes?.[PEERS_THREAD]
    for (const [id, ts] of idx?.items || []) remote.set(String(id), Number(ts) || 0)
    cursor = page?.next ?? null
  } while (cursor != null)

  const local = new Map()
  for (const [pk, rec] of Object.entries(peers || {})) {
    if (!rec || typeof rec !== 'object') continue
    local.set(await peerIdOf(pk), { pk, rec, ts: stampOf(rec) })
  }

  // SUBIR primero lo que aquí es más nuevo, en tandas.
  const up = [...local.entries()].filter(([id, l]) => !remote.has(id) || l.ts > remote.get(id))
  let batch = []; let bytes = 0; let pushed = 0
  const flush = async () => {
    if (!batch.length) return
    await call('importThreads', { threads: { [PEERS_THREAD]: batch }, tombs: {}, mode: 'merge' })
    pushed += batch.length; batch = []; bytes = 0
  }
  for (const [id, l] of up) {
    const entry = { id, ts: l.ts, peer: { ...l.rec, publickey: l.rec.publickey || l.pk } }
    const size = JSON.stringify(entry).length
    if (bytes + size > PUSH_BYTES) await flush()
    batch.push(entry); bytes += size
  }
  await flush()

  // TRAER lo que allí es más nuevo.
  const down = [...remote.entries()].filter(([id, ts]) => !local.has(id) || ts > local.get(id).ts).map(([id]) => id)
  const incoming = []
  let refs = down.length ? { [PEERS_THREAD]: down } : null
  while (refs) {
    const page = await call('getEntries', { refs })
    for (const e of page?.threads?.[PEERS_THREAD] || []) if (e?.peer?.publickey) incoming.push(e.peer)
    refs = page?.rest && Object.keys(page.rest).length ? page.rest : null
  }
  return { incoming, pushed }
}
