/**
 * EL RESPALDO DE LA BÓVEDA: un archivo cifrado con una contraseña, con lo que hay en los
 * cajones y en la bóveda de contraseñas. Diseño: `docs/respaldo.md`.
 *
 * QUÉ LLEVA Y QUÉ NO (dueño, 2026-10-16: «como las llaves son de dispositivo, solo se
 * respalda el contenido de sobres y cajones»):
 *
 *   · SÍ: los VALORES de cada cajón (`ns:<scope>`, `dev:<aparato>`, el perfil `@me`) y las
 *     entradas de la bóveda de contraseñas, abiertos y vueltos a cerrar con la contraseña
 *     del respaldo.
 *   · NO: ninguna llave. Ni la maestra, ni la de comunicación, ni las de los aparatos, ni
 *     el acta. Una llave es de su aparato; quien restaura en otra bóveda la reparte con sus
 *     propias llaves, a los aparatos de SU acta.
 *   · NO: el histórico. Un respaldo es lo vigente.
 *
 * Por qué los valores en claro (dentro del archivo cifrado) y no los sobres tal cual: los
 * sobres van envueltos a los aparatos de ESTA cuenta y a su copia de recuperación. En otra
 * bóveda no los abre nadie, y mover un cajón de una bóveda a otra es la mitad de lo que esto
 * tiene que hacer.
 *
 * LAS DOS PUNTAS EXIGEN LA BÓVEDA ABIERTA. Exportar es leer —lo que guarda la frase—, e
 * importar compara con lo que ya hay, que también es leer.
 *
 * CONFLICTOS. Importar NUNCA pisa en silencio: primero se hace un PLAN (`planImport`) que
 * dice, valor por valor, qué es nuevo, qué es igual y qué choca. Si algo choca y quien
 * importa no dijo qué hacer, no se escribe NADA y se devuelve la lista (`BACKUP_CONFLICTS`).
 * Las dos respuestas posibles son `keep` (se queda lo de la bóveda) y `replace` (gana el
 * respaldo), para todo de una vez o para cada choque.
 *
 * El cifrado del archivo es el de `@dotrino/passmanager` (PBKDF2-SHA256 600 000 + AES-GCM):
 * corre igual en el navegador y en Node, así que lo que exporta una versión de la bóveda lo
 * abre cualquiera de las otras (regla de las tres versiones).
 */
import { deriveKeyFromPassword, makeSalt, makeVerifier, checkVerifier, sealValue, openValue, toBase64, fromBase64 } from '@dotrino/passmanager'

export const BACKUP_FORMAT = 'dotrino-vault-backup'
export const BACKUP_VERSION = 1
/** El nombre del cajón de las contraseñas en un respaldo. No choca con un `ns:`/`dev:`. */
export const PASSWORDS_DRAWER = 'passwords'
/** Mínimo de la contraseña del respaldo: el archivo se ataca fuera de línea, sin freno. */
export const BACKUP_PWD_MIN = 12
const KDF_ITERATIONS = 600_000
const AAD = 'dotrino-vault-backup/v1'

const coded = (message, code, extra = {}) => Object.assign(new Error(message), { code, ...extra })

// --- el archivo ----------------------------------------------------------------

/**
 * CIERRA un respaldo con su contraseña. Devuelve el objeto que se escribe al archivo.
 * Lo único en claro es el formato y la fecha: ni los nombres de los cajones salen.
 */
export async function sealBackup (payload, password) {
  if (typeof password !== 'string' || password.length < BACKUP_PWD_MIN) {
    throw coded(`the backup password must be at least ${BACKUP_PWD_MIN} characters`, 'WEAK_PASSWORD')
  }
  const salt = makeSalt()
  const key = await deriveKeyFromPassword(password, salt, KDF_ITERATIONS)
  return {
    format: BACKUP_FORMAT,
    v: BACKUP_VERSION,
    createdAt: payload.createdAt,
    kdf: { name: 'PBKDF2-SHA256', iterations: KDF_ITERATIONS, salt: toBase64(salt) },
    verifier: await makeVerifier(key),
    box: await sealValue(key, JSON.stringify(payload), AAD)
  }
}

/**
 * ABRE un respaldo. Distingue «no es un respaldo», «esa contraseña no es» y «está roto»,
 * porque se arreglan de formas distintas.
 */
export async function openBackup (file, password) {
  if (!file || file.format !== BACKUP_FORMAT) throw coded('this is not a vault backup file', 'NOT_A_BACKUP')
  if (file.v !== BACKUP_VERSION) throw coded(`unknown backup version v${file.v}: update the vault`, 'BACKUP_VERSION')
  if (file.kdf?.name !== 'PBKDF2-SHA256' || !file.kdf.salt || !file.kdf.iterations) {
    throw coded('the backup file has no usable key derivation', 'BACKUP_CORRUPT')
  }
  const key = await deriveKeyFromPassword(String(password || ''), fromBase64(file.kdf.salt), file.kdf.iterations)
  if (!(await checkVerifier(key, file.verifier))) throw coded('that password does not open this backup', 'WRONG_PASSWORD')
  let payload
  try { payload = JSON.parse(await openValue(key, file.box, AAD)) } catch (_) {
    throw coded('the backup opens but its content cannot be read', 'BACKUP_CORRUPT')
  }
  if (!Array.isArray(payload?.drawers)) throw coded('the backup has no drawers', 'BACKUP_CORRUPT')
  return payload
}

// --- qué cajones -----------------------------------------------------------------

/**
 * ¿Entra este cajón? `selected` es la lista que pidió quien exporta o importa (`null` =
 * todos). Vale el dueño entero (`ns:proxy`, `dev:<pub>`, `passwords`) y `@me` como atajo.
 */
export function wants (selected, owner) {
  if (!selected || !selected.length) return true
  return selected.some((s) => s === owner || (s === '@me' && owner === 'ns:@me'))
}

/** Valida que todo lo pedido exista: pedir un cajón que no está no es «nada que hacer». */
export function assertSelected (selected, available) {
  if (!selected || !selected.length) return
  const missing = selected.filter((s) => !available.some((o) => wants([s], o)))
  if (missing.length) throw coded(`no such drawer: ${missing.join(', ')}`, 'NO_SUCH_DRAWER', { missing })
}

// --- importar: el plan -----------------------------------------------------------

/** Lo que identifica un valor dentro de un plan: `<cajón destino> <clave>`. */
export const itemRef = (owner, key) => `${owner} ${key}`

/**
 * EL PLAN DE IMPORTACIÓN. Puro: no lee ni escribe nada, recibe lo que hay.
 *
 * @param {object} payload el respaldo ya abierto
 * @param {object} o
 *   `selected`  qué cajones del respaldo (`null` = todos)
 *   `map`       `{ <cajón del respaldo>: <cajón destino> }` para moverlo de nombre o de
 *               aparato. Sin entrada, va al mismo nombre.
 *   `current`   `{ <cajón destino>: { KEY: {value, public} } | null }` lo que ya hay
 *   `devices`   pubs de los aparatos del acta de destino: un `dev:` solo entra si su
 *               aparato existe aquí
 *   `passwords` `{ entries: [...] }` lo que ya hay en la bóveda de contraseñas, abierto
 */
export function planImport (payload, { selected = null, map = {}, current = {}, devices = [], passwords = null } = {}) {
  const available = payload.drawers.map((d) => d.owner)
  assertSelected(selected, available)
  const withDevice = new Set(devices)
  const plan = { drawers: [], counts: { new: 0, same: 0, conflict: 0, skipped: 0 } }
  for (const d of payload.drawers) {
    if (!wants(selected, d.owner)) continue
    const to = map[d.owner] || d.owner
    if (d.owner === PASSWORDS_DRAWER) {
      plan.drawers.push(planPasswords(d, passwords, plan.counts))
      continue
    }
    const out = { from: d.owner, to, label: d.label || null, status: 'ok', items: [] }
    if (to.startsWith('dev:') && !withDevice.has(to.slice(4))) {
      // EL APARATO NO ESTÁ EN ESTA CUENTA. No se guarda «por si acaso»: un cajón de aparato
      // sin aparato no lo lee nadie, y reaparecería solo si un día entra esa llave. Se dice,
      // y se puede mover a otro aparato con `map`.
      out.status = 'no-device'
      plan.counts.skipped += Object.keys(d.vars || {}).length
      plan.drawers.push(out)
      continue
    }
    const have = current[to] || {}
    for (const [key, v] of Object.entries(d.vars || {})) {
      const existing = have[key]
      const status = !existing ? 'new' : (existing.value === v.value ? 'same' : 'conflict')
      plan.counts[status]++
      out.items.push({ key, status, public: !!v.public, ...(existing ? { currentPublic: !!existing.public } : {}) })
    }
    plan.drawers.push(out)
  }
  return plan
}

/**
 * Lo que dice que una entrada de contraseñas es «la misma» que otra: el mismo id, o los
 * mismos sitios y el mismo usuario (una credencial por sitio y usuario).
 */
const sitesKey = (e) => [...(e.sites || [])].map((s) => String(s).toLowerCase()).sort().join(' ')
const whoKey = (e) => `${sitesKey(e)}\u0000${String(e.username || '').toLowerCase()}\u0000${e.sites?.length ? '' : String(e.title || '')}`
/** Lo que se compara para decir «igual»: el contenido, sin fechas. */
export const entryContent = (e) => JSON.stringify({
  type: e.type || 'login', title: e.title || '', sites: [...(e.sites || [])].sort(),
  name: e.name || '', username: e.username || '', secret: e.secret || '', totp: e.totp || '',
  notes: e.notes || '', fields: e.fields || '[]', webauthn: e.webauthn || null
})

function planPasswords (d, passwords, counts) {
  const out = { from: PASSWORDS_DRAWER, to: PASSWORDS_DRAWER, status: 'ok', items: [] }
  if (!passwords) {
    // Sin bóveda de contraseñas en el destino no hay con quién comparar ni dónde guardar:
    // se dice. No se inventa una llave de perfil a medias.
    out.status = 'no-passwords'
    counts.skipped += (d.entries || []).length
    return out
  }
  const byId = new Map(passwords.entries.map((e) => [e.id, e]))
  const byWho = new Map(passwords.entries.map((e) => [whoKey(e), e]))
  for (const e of d.entries || []) {
    const existing = byId.get(e.id) || byWho.get(whoKey(e)) || null
    const status = !existing ? 'new' : (entryContent(existing) === entryContent(e) ? 'same' : 'conflict')
    counts[status]++
    out.items.push({ key: e.id, title: e.title || (e.sites || [])[0] || '', username: e.username || '', status, ...(existing ? { currentId: existing.id } : {}) })
  }
  return out
}

/**
 * LA DECISIÓN DE CADA CHOQUE. `onConflict` vale para todos; `decisions` (por `itemRef`) manda
 * sobre él. Si queda alguno sin decidir, se para con la lista entera: importar a medias y
 * descubrir el resto después es peor que no importar.
 */
export function resolvePlan (plan, { onConflict = null, decisions = {} } = {}) {
  if (onConflict && onConflict !== 'keep' && onConflict !== 'replace') {
    throw coded(`unknown conflict policy "${onConflict}" (use keep or replace)`, 'BAD_POLICY')
  }
  const pending = []
  for (const d of plan.drawers) {
    for (const it of d.items) {
      if (it.status !== 'conflict') continue
      const r = decisions[itemRef(d.to, it.key)] || onConflict
      if (r !== 'keep' && r !== 'replace') { pending.push({ drawer: d.to, key: it.key, ...(it.title ? { title: it.title } : {}) }); continue }
      it.resolution = r
    }
  }
  if (pending.length) {
    throw coded(`${pending.length} conflict(s) without a decision: nothing was imported`, 'BACKUP_CONFLICTS', { conflicts: pending, plan })
  }
  return plan
}

/**
 * LO QUE HAY QUE ESCRIBIR, ya resuelto: `[{ to, key, value, public }]` para los cajones y
 * `[{ entry, replaces }]` para las contraseñas. Lo `same` y lo `keep` no se tocan.
 *
 * La VISIBILIDAD: si lo que había era privado, se queda privado aunque el respaldo diga
 * público. Hacer público un secreto no puede colarse en una importación (es la misma regla
 * de `PrivateStaysPrivate`), y se anota para decirlo.
 */
export function writesOf (plan, payload) {
  const vars = []
  const entries = []
  const byOwner = new Map(payload.drawers.map((d) => [d.owner, d]))
  for (const d of plan.drawers) {
    if (d.status !== 'ok') continue
    const src = byOwner.get(d.from)
    for (const it of d.items) {
      if (it.status === 'same' || (it.status === 'conflict' && it.resolution !== 'replace')) continue
      if (d.from === PASSWORDS_DRAWER) {
        const entry = src.entries.find((e) => e.id === it.key)
        entries.push({ entry, replaces: it.status === 'conflict' ? it.currentId : null })
        continue
      }
      const v = src.vars[it.key]
      const keptPrivate = it.currentPublic === false && !!v.public
      vars.push({ to: d.to, key: it.key, value: v.value, public: keptPrivate ? false : !!v.public, ...(keptPrivate ? { keptPrivate: true } : {}) })
    }
  }
  return { vars, entries }
}
