/**
 * exNotices.js — LOS AVISOS DE EXPULSIÓN YA FIRMADOS, uno por cada aparato que estuvo en las
 * actas de la ventana del historial y ya no está (dueño, 2026-10-22).
 *
 * La bóveda solo atiende al acta (`gate.js`). A quien salió se le contesta UNA cosa —«¿sigo
 * dentro?»— y la respuesta es su aviso, para que se borre aunque el que se le mandó al
 * echarlo no le llegara (la cola del proxio dura 24 h). El aviso se firma una vez, con la
 * bóveda abierta, y se guarda: contestar no firma nada, así que preguntar no sirve para que
 * la maestra firme a pedido de nadie. Sin caducidad: tiene que valer el día que vuelva.
 *
 * Cifrado en reposo, como todo lo de la bóveda. Si no se puede leer, se para y se dice.
 */
export const EX_NOTICES_FILE = 'exnotices.json'

const fail = (code, message) => Object.assign(new Error(message), { code })

export function openExNotices ({ disk }) {
  const file = EX_NOTICES_FILE
  const atRest = disk.atRest
  /** pub → { body, signature } */
  let items = load()

  function load () {
    let raw
    try { raw = disk.read(file) } catch (e) {
      throw fail('exnotices-unreadable', `cannot read ${EX_NOTICES_FILE}: ${e.message}`)
    }
    if (raw == null) return new Map()
    let d
    try { d = JSON.parse(atRest.decrypt(raw)) } catch (e) { throw fail('exnotices-unreadable', `${EX_NOTICES_FILE} cannot be opened: ${e.message}`) }
    if (d?.v !== 1 || !d.items || typeof d.items !== 'object') throw fail('exnotices-unreadable', `${EX_NOTICES_FILE} has an unknown shape`)
    return new Map(Object.entries(d.items))
  }

  function save () {
    disk.write(file, atRest.encrypt(JSON.stringify({ v: 1, items: Object.fromEntries(items) })))
  }

  return {
    has: (pub) => items.has(pub),
    get: (pub) => items.get(pub) || null,
    pubs: () => [...items.keys()],
    /**
     * Deja exactamente los avisos de `past` (los ex-miembros de la ventana): firma con `sign`
     * los que falten y quita los de quien ya salió de la ventana. Devuelve cuántos firmó.
     */
    async sync (past, sign) {
      const keep = new Set(past)
      let changed = false
      for (const pub of [...items.keys()]) if (!keep.has(pub)) { items.delete(pub); changed = true }
      let signed = 0
      for (const pub of keep) {
        if (items.has(pub)) continue
        // Sin `nonce` ni `exp`: habla del APARATO, no de un papel, y vale siempre.
        const body = { op: 'revoke', sub: pub, iat: Date.now() }
        items.set(pub, { body, signature: await sign(body) })
        signed++
        changed = true
      }
      if (changed) save()
      return signed
    }
  }
}

export default { openExNotices, EX_NOTICES_FILE }
