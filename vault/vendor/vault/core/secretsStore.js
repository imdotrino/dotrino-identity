/**
 * Store de SECRETOS de servicios (`secrets.json`, 0600, mismo dir 0700 que la
 * maestra), **cifrado en reposo** con la clave ligada a la máquina (`atrest.js`) y,
 * desde v4, con los valores privados **SELLADOS A SU DESTINATARIO**.
 *
 * QUÉ CAMBIA EN v5 Y POR QUÉ: **ESCRIBIR NO PIDE LA FRASE**. Cifrar es una capacidad
 * pública —envolver una llave solo necesita la `encPub` del que va a leer— así que
 * sellar una variable nunca necesitó la contraseña. Lo que la pedía era la COPIA
 * MAESTRA de v4, que guardaba las CEK cifradas con ella; para escribir había que
 * abrirla, y eso obligaba a teclear la frase del perfil en el navegador. Aquí se va la
 * copia maestra y en su lugar entra un **par de recuperación**: su pública se guarda en
 * claro (cualquiera puede envolverle) y su privada, sellada bajo la frase (solo el
 * dueño abre). Diseño completo: `docs/secretos-sellados.md` §8.
 *
 * De ahí salen las tres reglas de este archivo:
 *
 *   · **Escribir** = CEK nueva → envolverla a los destinatarios → cifrar → firmar.
 *     Ningún secreto de la bóveda interviene.
 *   · **UNA GENERACIÓN POR ESCRITURA**, y no es un capricho: la bóveda no puede
 *     reutilizar la CEK del cajón porque no puede abrir ninguna envoltura para
 *     recuperarla. Las generaciones que ya no referencia ningún valor ni el histórico
 *     se recogen solas.
 *   · **Leer** (ver un valor, cambiar su visibilidad, rotar re-cifrando) sigue pidiendo
 *     la frase, porque leer es exactamente lo que la frase guarda.
 *
 * DOS CAJONES, y esa es la razón de ser de este archivo:
 *
 *   · **Por scope** (`ns`) — un NAMESPACE de servicio (`proxy`, `geo`, `bots`…).
 *     Lo comparten TODOS los aparatos del perfil que sirven ese namespace: la
 *     llave de la API es la misma la corra quien la corra.
 *   · **Por aparato** (`dev`) — la llave es la del miembro (su `pub`), y solo la
 *     lee ESE aparato. Es donde va lo que cambia de máquina a máquina (el puerto,
 *     la URL pública, el nombre del nodo) sin partir el ns en uno por servidor.
 *
 * Al pedir el bundle se entregan MEZCLADOS y **manda el aparato**: lo suyo pisa
 * lo del scope. Es el orden que espera cualquiera que haya usado un `.env`
 * general y otro de la máquina — lo específico gana. **La mezcla sigue aquí** y sigue
 * siendo una línea: los NOMBRES no se sellan, solo los valores, así que juntarlos no
 * exige poder leerlos. Quien descifra es el agente, después.
 *
 * CADA VARIABLE ES PÚBLICA O PRIVADA, y eso decide UNA cosa: si su VALOR puede
 * salir de esta máquina hacia la consola remota (`docs/consola-remota.md`). Al
 * servicio que la lee le da igual —recibe las dos—; lo que cambia es que el valor
 * de una privada no se le enseña a nadie más. Se nace PRIVADA: enseñar un secreto
 * tiene que ser una decisión, no un descuido.
 *
 * EL HISTÓRICO. Cada escritura guarda el sobre ANTERIOR, con quién y cuándo. La bóveda
 * lo escribe sin poder leerlo; auditar y revertir los hace quien puede abrir. Tiene
 * tope: un histórico de secretos también es un pasivo — mantiene vivas credenciales
 * viejas — así que se poda.
 *
 * ESTE MÓDULO NO HACE CRIPTOGRAFÍA. Recibe un `sealer` (ver `src/sealer.js`) y le
 * pide sobres. Así se prueba con un sellador falso y determinista, y la forma del
 * archivo se razona sin mirar una sola llave.
 */
import { readJson, writeJson } from './disk.js'
import { isValidSecretsNs } from '../protocol.js'

const SCHEMA_VERSION = 5
/** v4: sellado, pero con la copia maestra bajo la frase. Se lee y se sirve; no se escribe. */
const SEALED_MASTER_VERSION = 4
const LEGACY_VERSION = 3
const MAX_VALUE_LEN = 8 * 1024
const KEY_RE = /^[A-Z0-9_]{1,64}$/

/**
 * La envoltura de la copia de RECUPERACIÓN va en el llavero como una más, con este
 * nombre en lugar de la pubkey de un miembro. No es un miembro y no debe parecerlo: el
 * acta no lo conoce y nadie le sirve un bundle.
 */
export const RECOVERY = '#recovery'

/**
 * EL CAJÓN DEL PERFIL. Los datos de tu identidad se guardan como cualquier variable —
 * mismo sobre, mismo llavero, mismo histórico— porque son lo mismo: un valor que solo
 * pueden leer tus aparatos. Diseño: `docs/datos-del-perfil.md`.
 *
 * SE LLAMA `@me` A PROPÓSITO, y es la garantía entera: un nombre de cajón válido es
 * `[a-z0-9-]{1,32}`, así que **ningún servicio puede llamarse `@me`**. Por lo tanto
 * `memberCanReadSecrets(acta, quien, '@me')` no puede ser cierto nunca y no hay forma de
 * pedir el perfil por el camino de los secretos. No es una comprobación que alguien pueda
 * olvidarse de hacer: es un nombre que el validador no deja existir.
 */
export const PROFILE_NS = '@me'
export const PROFILE_OWNER = 'ns:' + PROFILE_NS

/**
 * El nombre de un dato del perfil. NO vale `assertVar`: aquélla exige MAYÚSCULAS porque
 * describe una variable de entorno, y aquí los campos son `nickname`, `telefono`,
 * `apellidos`. Mismo espíritu —un nombre corto y previsible, sin sorpresas al serializar—
 * y distinto alfabeto.
 */
export function assertProfileKey (key) {
  if (typeof key !== 'string' || !/^[a-z][a-z0-9_]{0,31}$/.test(key)) {
    throw new Error('invalid profile field (use lowercase_with_underscores, e.g. "nickname")')
  }
}

/** Lo más largo que puede ser un dato del perfil (una foto pequeña cabe). */
const MAX_PROFILE_LEN = 200000

/** Valida un dato del perfil: su nombre (`assertProfileKey`) y su valor. */
export function assertProfileValue (key, value) {
  assertProfileKey(key)
  if (typeof value !== 'string' || !value) throw new Error('value must be a non-empty string')
  if (value.length > MAX_PROFILE_LEN) throw new Error(`profile value too long (max ${MAX_PROFILE_LEN})`)
}

/** Cuántas versiones anteriores se conservan, en total. Ver «EL HISTÓRICO» arriba. */
const MAX_HISTORY = 500

/**
 * Valida un par nombre/valor. Se exporta porque quien carga varias variables de golpe
 * las comprueba TODAS antes de escribir ninguna: media configuración aplicada y un
 * error a la mitad es justo lo que la carga en grupo viene a evitar.
 */
export function assertVar (key, value) {
  if (!KEY_RE.test(String(key || ''))) throw new Error('invalid key (use UPPERCASE_WITH_UNDERSCORES, e.g. TURN_KEY_ID)')
  if (typeof value !== 'string' || !value) throw new Error('value must be a non-empty string')
  if (value.length > MAX_VALUE_LEN) throw new Error(`value too long (max ${MAX_VALUE_LEN})`)
}

/** Se pidió una operación que necesita LEER un valor, y no vino la llave que lo abre. */
export class NeedsPassword extends Error {
  constructor (what) {
    super(`this needs the profile password: ${what}`)
    this.code = 'NEEDS_PASSWORD'
  }
}

/**
 * El archivo sigue en v4 (con copia maestra) y hay que convertirlo antes de escribir.
 * Convertir exige la frase UNA vez —hay que abrir la maestra para poder re-sellar—, y a
 * partir de ahí no se pide nunca más para escribir.
 */
export class NeedsMigration extends Error {
  constructor () {
    super('the secrets file is still v4: unlock the profile once to convert it (it needs the password only this time)')
    this.code = 'NEEDS_MIGRATION'
  }
}

/**
 * Privada es para siempre. Una variable puede dejar de mostrarse (pública → privada), pero
 * nunca al revés: lo que se marcó como secreto no se destapa ni por `visibility` ni de
 * refilón con un `set --public`. Si hace falta un valor público, es OTRA variable (o se
 * borra esta y se crea de nuevo, y eso queda a la vista).
 */
export class PrivateStaysPrivate extends Error {
  constructor (key) {
    super(`${key} is private and a private variable cannot be made public: delete it and create it again as public`)
    this.code = 'PRIVATE_STAYS_PRIVATE'
  }
}

/** Migra un cajón `{KEY: 'valor'}` (v1/v2) a `{KEY: {v, pub}}`: todo entra como PRIVADO. */
function migrateBag (bag) {
  const out = {}
  for (const [k, v] of Object.entries(bag || {})) out[k] = (v && typeof v === 'object') ? v : { v: v, pub: false }
  return out
}

/**
 * Abre el store.
 *
 * @param {string} dir
 * @param {{ sealer?: object, recipients?: (owner: string) => any, signer?: (body: any) => any,
 *          defaultKey?: () => Uint8Array }} [opts]
 *   `sealer`: el puerto de sobres (`src/sealer.js`). Sin él, el store solo sabe leer y
 *   servir lo que ya hay — que es exactamente lo que hace falta para arrancar sin nada.
 *   `recipients(owner)`: a quién hay que envolverle la llave de ese cajón — los servicios
 *   de ese namespace y los aparatos que administran. Sale del acta, y por eso lo pone
 *   quien llama: este módulo no conoce el acta.
 *   `signer(body)`: firma del sobre, `{ seq, sig }` o `null`. Es lo que dice que el sobre
 *   salió de esta bóveda (§8.8).
 *   `defaultKey`: con qué sellar la privada de recuperación cuando el perfil NO tiene
 *   contraseña. Vive aquí, en un solo sitio, para que dé igual por qué puerta se entre.
 */
export function openSecretsStore (disk, { sealer = null, recipients = null, signer = null, defaultKey = null, onChange = null } = {}) {
  const file = 'secrets.json'
  let data = readJson(disk, file, null)

  // v1 → v2: el cajón por scope se conserva y estrena el `dev`.
  // v2 → v3: los valores dejan de ser strings sueltos y pasan a llevar su visibilidad.
  //          Lo que ya existía entra como PRIVADO: nadie marcó nunca que se pudiera ver.
  if (data && data.schemaVersion > 0 && data.schemaVersion < LEGACY_VERSION) {
    const ns = {}; const dev = {}
    for (const [k, bag] of Object.entries(data.ns || {})) ns[k] = migrateBag(bag)
    for (const [k, bag] of Object.entries(data.dev || {})) dev[k] = migrateBag(bag)
    data = { schemaVersion: LEGACY_VERSION, ns, dev }
  }
  if (!data) data = { schemaVersion: SCHEMA_VERSION, ns: {}, dev: {}, recovery: null, history: [] }
  if (!data.dev) data.dev = {}
  if (!data.history) data.history = []
  // LÁPIDAS (`docs/replicas.md` §11.4): lo borrado se recuerda, con su generación, para que
  // una hermana que todavía lo tiene no lo resucite al mezclar. `deleted[owner][key] = { gen, at }`.
  if (!data.deleted) data.deleted = {}
  // 0.47.0/0.48.0 guardaron una «política» DENTRO del cajón (salía como variable): fuera.
  for (const bag of Object.values(data.ns || {})) if (bag?.policy && typeof bag.policy === 'object' && !('v' in bag.policy)) delete bag.policy
  delete data.policies

  // v3 → v5 y v4 → v5 NO se hacen al abrir, y es deliberado: el daemon tiene que poder
  // arrancar y SERVIR sin nada (un perfil bloqueado sigue atendiendo a sus agentes). Un
  // archivo viejo se queda como está, sirviendo igual que siempre, hasta que alguien lo
  // convierta. Hasta entonces el despliegue se deshace con un reinicio.
  const isLegacy = () => data.schemaVersion === LEGACY_VERSION
  const needsMigration = () => data.schemaVersion === SEALED_MASTER_VERSION

  writeJson(disk, file, data) // reescribe al abrir: cifra lo que venía en claro

  // Un grupo de escrituras se guarda UNA vez (ver `batch`). Fuera de un grupo, `held`
  // vale 0 y cada cambio va al disco en el acto, como siempre.
  let held = 0
  let pending = false
  // `onChange`: que lo guardado cambió POR UNA ESCRITURA de aquí, para empujárselo a las
  // hermanas. Lo que llega de una hermana (`mergeState`) se guarda sin avisar: si avisara,
  // las dos se lo devolverían para siempre.
  let quiet = false
  const flush = () => { writeJson(disk, file, data); if (!quiet) { try { onChange?.() } catch (_) {} } }
  const save = () => { if (held) { pending = true; return } ; flush() }

  const assertNs = (ns) => {
    if (!isValidSecretsNs(ns)) throw new Error('invalid namespace (use [a-z0-9-]{1,32}, e.g. "proxy")')
  }
  const assertPub = (pub) => {
    if (typeof pub !== 'string' || !pub) throw new Error('device required (the member public key)')
  }
  const assertKeyValue = assertVar
  const needSealer = (what) => { if (!sealer) throw new NeedsPassword(what) }
  /** La llave con la que se abre la privada de recuperación: la dada, o la de la máquina. */
  const keyOr = (adminKey) => adminKey || defaultKey?.() || null

  /** Borra la rama si se quedó vacía: un scope (o un aparato) sin variables no existe. */
  const prune = (bag, k) => { if (bag[k] && Object.keys(bag[k]).length === 0) delete bag[k] }
  /** Etiqueta corta de NUESTRO par de recuperación, para distinguirlo del de una hermana. */
  const recoveryTag = () => {
    const pub = String(data.recovery?.pub || '')
    if (!pub) return 'none'
    // FNV-1a de 32 bits sobre toda la pública: corto, estable y distinto para cada par.
    let h = 0x811c9dc5
    for (let i = 0; i < pub.length; i++) { h ^= pub.charCodeAt(i); h = Math.imul(h, 0x01000193) >>> 0 }
    return h.toString(16).padStart(8, '0')
  }
  /** Cambia el nombre de una envoltura (`from` → `to`; `to = null` devuelve la nuestra a su sitio). */
  const retag = (wraps, from, tag) => {
    const out = { ...(wraps || {}) }
    if (tag && from in out) { out[`${RECOVERY}@${tag}`] = out[from]; delete out[from] }
    if (!tag && from in out) { out[RECOVERY] = out[from]; delete out[from] }
    return out
  }

  // --- forma de un cajón -------------------------------------------------------
  // v3: `bag[k]` ES el mapa de variables. v4/v5: `bag[k] = { vars, keyring }`.
  // `varsOf` es el único sitio que conoce las dos, para que el resto del archivo
  // hable de variables y no de versiones.
  const varsOf = (bag, k) => (isLegacy() ? (bag[k] || {}) : (bag[k]?.vars || {}))
  const ensureBag = (bag, k) => {
    if (isLegacy()) { if (!bag[k]) bag[k] = {}; return bag[k] }
    if (!bag[k]) bag[k] = { vars: {}, keyring: [] }
    if (!bag[k].vars) bag[k].vars = {}
    if (!bag[k].keyring) bag[k].keyring = []
    return bag[k].vars
  }

  /** Los NOMBRES con su visibilidad: es lo que ve cualquier lista. Nunca valores. */
  const names = (bag, k) => Object.entries(varsOf(bag, k)).map(([key, e]) => ({ key, public: !!e.pub }))
  /** Solo las PÚBLICAS, con valor: lo único que puede salir de esta máquina en claro. */
  /**
   * LOS NOMBRES de las públicas. Ya no hay valores que devolver: desde 2026-09-02 una
   * pública se guarda en sobre igual que una privada, y `pub` solo dice si se despacha sin
   * aprobación. Para VER un valor hay que poder abrirlo, como con cualquier otro.
   */
  const publics = (bag, k) => Object.keys(varsOf(bag, k)).filter((key) => varsOf(bag, k)[key].pub)
  /**
   * Las entradas TAL CUAL van al bundle: la pública con su valor, la privada con su
   * sobre y su firma. No se descifra nada aquí — de eso vive todo esto.
   */
  const entriesOf = (bag, k) => ({ ...varsOf(bag, k) })

  /** La generación vigente de un cajón (la de `gen` mayor). */
  const topGen = (bag, k) => {
    const kr = bag[k]?.keyring || []
    return kr.reduce((best, g) => (!best || (g.gen || 0) > (best.gen || 0) ? g : best), null)
  }

  /**
   * LA GENERACIÓN QUE TOCA ESTRENAR. Se mira el llavero Y las entradas, no solo el llavero:
   * un dato PÚBLICO del perfil lleva generación pero no sobre, así que no deja nada en el
   * llavero. Contando solo el llavero, dos escrituras públicas seguidas salían con la MISMA
   * generación — y la generación es lo que ordena un dato entre réplicas (`mergeBundle`):
   * con empate gana el de hash menor, que puede ser el valor viejo.
   */
  const nextGen = (bag, k, owner) => {
    let top = topGen(bag, k)?.gen || 0
    for (const e of Object.values(bag[k]?.vars || {})) if ((e.gen || 0) > top) top = e.gen
    for (const h of data.history) if (h.owner === owner && (h.gen || 0) > top) top = h.gen
    for (const t of Object.values(data.deleted?.[owner] || {})) if ((t.gen || 0) > top) top = t.gen
    // LA HORA, SI VA POR DELANTE (`docs/replicas.md` §11.4). Dos bóvedas de la cuenta pueden
    // escribir el mismo cajón sin verse, y con un contador cada una estrenaría la MISMA
    // generación para cosas distintas. Con la hora no chocan, y ordenarlas es «gana el último
    // cambio», que es lo decidido. Nunca baja: si el reloj va por detrás, manda el contador.
    return Math.max(top + 1, Date.now())
  }

  /**
   * UN CAMBIO A LA VEZ.
   *
   * Todo lo que toca el llavero es leer-modificar-escribir con un `await` en medio, así
   * que dos operaciones en vuelo se pisan la una a la otra. No es teórico: en v4 un
   * `rewrap` lanzado al aprobar un aparato volvía a sellar la copia maestra **con la
   * llave vieja** justo después de cambiar la contraseña del perfil, y el vault quedaba
   * abierto para cualquiera con una copia del disco, sin un solo mensaje de error.
   *
   * La cola es de este proceso, que es el único que escribe este archivo.
   */
  let queue = Promise.resolve()
  const queued = (fn) => {
    const r = queue.then(fn, fn)
    queue = r.then(() => {}, () => {})
    return r
  }

  // --- histórico y recogida de generaciones ------------------------------------

  /** Guarda la versión que se va a pisar. Sin valores en claro: el sobre tal cual. */
  const pushHistory = (owner, key, before, by) => {
    if (!before || before.pub) return // una pública no es un secreto que revertir a ciegas
    data.history.push({ ts: Date.now(), owner, key, gen: before.gen, e: before.e, seal: before.seal || null, by: by || null })
    if (data.history.length > MAX_HISTORY) data.history = data.history.slice(-MAX_HISTORY)
  }

  /**
   * Tira las generaciones que ya no abre nada. Con una generación por escritura, el
   * llavero crecería sin fin; lo que hay que conservar es lo que todavía referencia una
   * variable viva o una entrada del histórico — ni una más, porque cada generación
   * conservada es una llave que sigue por ahí.
   */
  const gcKeyring = (bag, k, owner) => {
    if (!bag[k]) return
    const aliveOnes = new Set()
    // TAMBIÉN LAS PÚBLICAS. Se saltaban porque antes no tenían generación —se guardaban en
    // claro—, así que su llave se recogía por «no la usa nadie» y la variable quedaba
    // ilegible. Desde 2026-09-02 van en sobre como todas y cuentan como todas.
    for (const e of Object.values(bag[k].vars || {})) if (e.gen != null) aliveOnes.add(e.gen)
    for (const h of data.history) if (h.owner === owner && h.gen != null) aliveOnes.add(h.gen)
    bag[k].keyring = (bag[k].keyring || []).filter((g) => aliveOnes.has(g.gen))
  }

  /**
   * Abre la privada de RECUPERACIÓN. Es la única puerta de este módulo a un valor en
   * claro, y por eso es la única que pide la frase.
   */
  const openRecovery = async (adminKey) => {
    needSealer('read a private variable')
    if (!data.recovery?.priv) throw new NeedsPassword('this store has no recovery key yet')
    return sealer.openMaster(data.recovery.priv, keyOr(adminKey))
  }

  /**
   * El par de recuperación, creándolo si es la primera vez. Se sella con lo que haya:
   * con la frase si quien llama la trajo, y si no con la llave de la máquina — que es
   * la protección de siempre y no una nueva promesa. Cuando el perfil estrene
   * contraseña, `rekeyRecovery` lo vuelve a cerrar con ella.
   */
  const ensureRecovery = async (adminKey) => {
    if (data.recovery?.pub) return data.recovery
    needSealer('create the recovery key')
    const pair = await sealer.makeRecoveryPair()
    data.recovery = { pub: pair.pub, priv: await sealer.sealMaster(pair.priv, keyOr(adminKey)) }
    return data.recovery
  }

  /** Los destinatarios de un cajón: los que dice el acta, más la copia de recuperación. */
  /**
   * @param {boolean} isPublic Una PÚBLICA se envuelve además para quien administra, aunque
   *   el cajón tenga dueño (dueño, 2026-09-02). Puede variar por variable porque cada
   *   escritura estrena su propia CEK: el llavero guarda una generación por valor.
   */
  const wrapAll = async (cek, owner, isPublic = false) => {
    const members = (await recipients?.(owner, { public: isPublic })) || []
    const { wraps, sinLlave: noKey } = await sealer.wrapFor(cek, members)
    wraps[RECOVERY] = await sealer.wrapForKey(cek, data.recovery.pub)
    return { wraps, sinLlave: noKey }
  }

  return {
    /** `true` mientras el archivo siga en v3 (sin sellar). */
    isLegacy,
    /** `true` si sigue en v4 (sellado, pero con copia maestra): hay que convertirlo. */
    needsMigration,
    schemaVersion: () => data.schemaVersion,
    /** ¿La privada de recuperación está sellada solo con la llave de esta máquina? */
    recoveryPub: () => data.recovery?.pub || null,
    /**
     * CREA LA LLAVE DE RECUPERACIÓN SI NO EXISTE. Se llama al ABRIR la bóveda, que es el
     * único momento en que se puede: sellar su privada necesita la maestra.
     *
     * Nacía perezosamente, al escribir el primer secreto. En un perfil recién hecho eso
     * significaba que la bóveda no tenía a quién envolver, y como crearla exige estar
     * abierta, escribir el PERFIL con la bóveda cerrada era imposible — que es justo lo
     * que el perfil en sobres viene a permitir. Lo encontró el escenario del navegador:
     * «the vault did not say who to seal the profile for».
     *
     * Idempotente: si ya está, no toca nada.
     */
    async ensureRecovery (adminKey = null) { return queued(async () => (await ensureRecovery(adminKey)).pub) },

    /**
     * MUCHAS ESCRITURAS, UN GUARDADO. Cargar la configuración de un servicio son veinte
     * variables pero un solo cambio: con un `save()` por variable, el archivo entero se
     * reescribía y se volvía a cifrar veinte veces.
     */
    async batch (fn) {
      held++
      try { return await fn() } finally {
        held--
        if (!held && pending) { pending = false; flush() }
      }
    },

    /**
     * El bundle que se le entrega a un servicio: lo del scope con lo del aparato
     * ENCIMA. Públicas y privadas por igual — la visibilidad no es un permiso de
     * lectura del servicio, es si el valor puede salir de esta máquina.
     *
     * Devuelve las entradas SIN abrir, más las envolturas **de este miembro y solo las
     * suyas**: el resto del llavero son las llaves de sus compañeros y no le hacen falta.
     * Van TODAS sus generaciones, no solo la última, porque desde v5 cada variable puede
     * venir de una escritura distinta. En v3 devuelve los valores en claro, como siempre.
     */
    /**
     * @param {string} ns
     * @param {string|null} devicePub
     * @param {{publicOnly?: boolean}} [opts] `publicOnly`: SOLO las públicas — pero CON sus
     *   envolturas, porque desde 2026-09-02 van en sobre igual que las privadas. Lo que las
     *   distingue es solo que se despachan sin aprobación (ver `handleSecrets`); aquí se
     *   devolvía el paquete sin llavero, y entonces no había con qué abrirlas.
     */
    bundleFor (ns, devicePub = null, { publicOnly = false } = {}) {
      assertNs(ns)
      const everything = { ...entriesOf(data.ns, ns), ...(devicePub ? entriesOf(data.dev, devicePub) : {}) }
      // EL FILTRO LO HACE LA BÓVEDA, no quien pide. Si mandara todo y el cliente eligiera,
      // pedir «solo públicas» sería la forma de saltarse la aprobación y llevarse las
      // privadas igual — o sea justo lo contrario de lo que se quiere.
      const entries = publicOnly
        ? Object.fromEntries(Object.entries(everything).filter(([, e]) => e.pub))
        : everything
      if (isLegacy()) return { legacy: true, entries }

      const misWraps = (bag, k) => (bag[k]?.keyring || [])
        .filter((g) => g.wraps?.[devicePub])
        .map((g) => ({ gen: g.gen, wrap: g.wraps[devicePub] }))
      const ns1 = misWraps(data.ns, ns)
      const dev1 = devicePub ? misWraps(data.dev, devicePub) : []
      return {
        entries,
        // Compat con el bundle de v4, que llevaba UNA envoltura por cajón: se manda la
        // vigente ahí y la lista entera aparte. Quien sepa leer `wraps` usa la lista.
        ns: ns1[ns1.length - 1] || null,
        dev: dev1[dev1.length - 1] || null,
        wraps: { ns: ns1, dev: dev1 }
      }
    },

    /**
     * VER UN VALOR. Es lo único que pide la frase, y es lo que la frase significa desde
     * v5 (§8.3). Devuelve `null` si esa variable no existe.
     */
    async reveal (owner, key, adminKey = null) {
      const [kind, k] = splitOwner(owner)
      const bag = kind === 'ns' ? data.ns : data.dev
      const e = varsOf(bag, k)[key]
      if (!e) return null
      // UNA PÚBLICA SE ABRE IGUAL QUE UNA PRIVADA (dueño, 2026-09-02). Aquí había un atajo
      // —`if (e.pub) return e.v`— porque una pública se guardaba en claro. Ya no: la marca
      // solo dice si se despacha sin aprobación, y para VER un valor hay que poder abrirlo.
      if (isLegacy()) return e.v
      const priv = await openRecovery(adminKey)
      const cek = await this._cekOf(bag, k, e.gen, priv)
      return sealer.openValue(cek, e.e)
    },


    /**
     * Las variables privadas de un cajón que ESE miembro **no puede abrir**: las que no
     * tienen envoltura para su llave en la generación vigente.
     *
     * Es la deuda del §8.7 vista desde el aparato en vez de desde el cajón. Un aparato
     * que entra después de escrita una variable no tiene envoltura de ella —y no la
     * puede tener, porque envolver exige abrir la CEK y eso pide la frase—, así que se
     * queda sin poder leerla. Eso es correcto y no se relaja; lo que no puede pasar es
     * que no se vea, que era el modo de fallo de verdad: un servicio en el acta,
     * aparentemente bien, que arranca sin configuración.
     *
     * @param {string} owner `ns:<scope>` o `dev:<pub>`
     * @param {string} memberPub la llave de FIRMA del miembro (así se indexan las envolturas)
     * @param {{ only?: (isPublic: boolean) => boolean }} [opts] qué variables le TOCAN, según
     *   su visibilidad: a quien administra se le envuelven las públicas de un cajón con dueño
     *   y no las privadas, así que la falta de una privada no es deuda suya.
     * @returns {string[]} nombres de variables, vacío si puede con todas
     */
    missingFor (owner, memberPub, { only = null } = {}) {
      if (isLegacy()) return []
      const [kind, k] = splitOwner(owner)
      const bag = kind === 'ns' ? data.ns : data.dev
      const out = []
      for (const [key, e] of Object.entries(varsOf(bag, k))) {
        // Lo PÚBLICO DEL PERFIL no lleva sobre: va en claro y firmado, porque quien lo lee
        // desde fuera no tiene ninguna llave tuya. No hay envoltura que pueda faltarle a
        // nadie, y contarla como deuda era un aviso que ningún reparto podía apagar.
        if (e.cls === 'public') continue
        if (only && !only(!!e.pub)) continue
        // También las públicas: desde 2026-09-02 van en sobre, así que a quien no tenga su
        // envoltura le falta igual que con una privada.
        const g = (bag[k]?.keyring || []).find((x) => x.gen === e.gen)
        if (!g?.wraps?.[memberPub]) out.push(key)
      }
      return out
    },

    /**
     * Las generaciones de un cajón que a `memberPub` le faltan, con LA ENVOLTURA DE
     * QUIEN PREGUNTA para cada una. Es lo que necesita un aparato que administra para
     * completar a otro sin la frase: abre cada una con su llave y la vuelve a envolver
     * (`rewrapFor` de `@dotrino/identity`).
     *
     * Devuelve solo las generaciones que están EN USO (alguna variable las apunta): las
     * viejas no hacen falta y re-envolverlas sería repartir llaves que ya no abren nada.
     *
     * @returns {Array<{ gen: number, mine: any }>} vacío si quien pregunta tampoco puede
     */
    wrapsToShare (owner, memberPub, myPub) {
      if (isLegacy()) return []
      const [kind, k] = splitOwner(owner)
      const bag = kind === 'ns' ? data.ns : data.dev
      const inUse = new Set(Object.values(varsOf(bag, k)).map((e) => e.gen))
      const out = []
      for (const g of bag[k]?.keyring || []) {
        if (!inUse.has(g.gen) || g.wraps?.[memberPub]) continue
        if (g.wraps?.[myPub]) out.push({ gen: g.gen, mine: g.wraps[myPub] })
      }
      return out
    },

    /**
     * Guarda una envoltura que hizo otro. La bóveda NO la puede comprobar —abrirla
     * exigiría la frase, que es justo lo que este camino evita—, así que lo que sí
     * comprueba es lo que puede: que la generación exista y que ese miembro no tuviera
     * ya una. Una envoltura mala deja al servicio sin leer, que se ve; no da acceso a
     * nadie.
     */
    putWrap (owner, gen, memberPub, wrap) {
      const [kind, k] = splitOwner(owner)
      const bag = kind === 'ns' ? data.ns : data.dev
      const g = (bag[k]?.keyring || []).find((x) => x.gen === gen)
      if (!g) throw new Error(`putWrap: generation ${gen} of ${owner} does not exist`)
      if (!wrap?.epk || !wrap?.iv || !wrap?.ct) throw new Error('putWrap: envoltura mal formada')
      // SOLO AÑADE, NUNCA PISA. Quien re-envuelve es un servicio, y un servicio no
      // administra: si pudiera reemplazar una envoltura existente podría dejar sin leer
      // a otro miembro —o a quien administra— con una envoltura basura, y eso es
      // denegación de servicio disfrazada de reparto. Reemplazar es cosa de la bóveda,
      // por el camino de escribir (que estrena generación entera).
      if (g.wraps?.[memberPub]) throw new Error(`putWrap: ${memberPub.slice(0, 12)}… already has a wrap for generation ${gen}`)
      g.wraps = { ...(g.wraps || {}), [memberPub]: wrap }
      save()
      return true
    },


    /** @private La CEK de una generación, abierta con la privada de recuperación. */
    async _cekOf (bag, k, gen, priv) {
      const g = (bag[k]?.keyring || []).find((x) => x.gen === gen) || topGen(bag, k)
      const w = g?.wraps?.[RECOVERY]
      if (!w) throw new NeedsPassword(`there is no recovery copy of the key for generation ${gen}`)
      return sealer.openWrapWith(priv, w)
    },

    /**
     * Igual que `bundleFor` pero YA ABIERTO. Solo existe para las pruebas y para
     * diagnosticar: pide la frase. Nadie del camino de servir lo llama.
     */
    async openBundle (ns, devicePub = null, adminKey = null) {
      const b = this.bundleFor(ns, devicePub)
      if (b.legacy) return Object.fromEntries(Object.entries(b.entries).map(([k, e]) => [k, e.v]))
      const priv = await openRecovery(adminKey)
      const out = {}
      for (const [key, e] of Object.entries(b.entries)) {
        if (e.pub) { out[key] = e.v; continue }
        const [kind, k] = splitOwner(e.owner)
        const bag = kind === 'ns' ? data.ns : data.dev
        out[key] = await sealer.openValue(await this._cekOf(bag, k, e.gen, priv), e.e)
      }
      return out
    },

    /**
     * UN CAJÓN ENTERO, ABIERTO. Es para el RESPALDO (`backup.js`), y por eso pide lo mismo
     * que ver un valor: la copia de recuperación, o sea la bóveda abierta. Se abre UNA vez
     * y se usa para todas las variables.
     *
     * Lo público del perfil (`cls: 'public'`) no tiene sobre: se guarda en claro y firmado,
     * y sale tal cual. El histórico no sale: un respaldo es lo vigente.
     *
     * @returns {Promise<Object<string,{value:string, public:boolean}>|null>} `null` si el
     *   cajón no existe.
     */
    async exportDrawer (owner, adminKey = null) {
      const [kind, k] = splitOwner(owner)
      const bag = kind === 'ns' ? data.ns : data.dev
      if (!bag[k]) return null
      if (needsMigration()) throw new NeedsMigration()
      const vars = varsOf(bag, k)
      /** @type {Object<string,{value:string, public:boolean}>} */
      const out = {}
      let priv = null
      for (const [key, e] of Object.entries(vars)) {
        if (e?.cls === 'public' && typeof e.pubv === 'string') { out[key] = { value: e.pubv, public: true }; continue }
        if (isLegacy()) { out[key] = { value: e.v, public: !!e.pub }; continue }
        if (!priv) priv = await openRecovery(adminKey)
        out[key] = { value: await sealer.openValue(await this._cekOf(bag, k, e.gen, priv), e.e), public: !!e.pub }
      }
      return out
    },

    /**
     * ESCRIBE UN VALOR IMPORTADO en cualquier cajón, también en el del perfil.
     *
     * Es escribir y nada más (no pide la frase): lo de `@me` público va por
     * `profilePutPublic`, como lo escribiría un aparato; lo demás, por el mismo camino que
     * `set`. Lo que decide si se escribe —el conflicto con lo que ya había— lo decide
     * `backup.js` antes de llegar aquí.
     */
    async importValue (owner, key, value, isPublic, { by = null } = {}) {
      if (owner === PROFILE_OWNER && isPublic) return this.profilePutPublic(key, value, { by })
      const [kind, k] = splitOwner(owner)
      if (kind === 'ns' && owner !== PROFILE_OWNER) assertNs(k)
      else if (kind === 'dev') assertPub(k)
      else if (kind !== 'ns') throw new Error('invalid drawer: expected "ns:<name>" or "dev:<pubkey>"')
      return this._put(kind === 'ns' ? data.ns : data.dev, k, owner, key, value, isPublic, by)
    },

    // --- escritura: NO pide la frase (§8.1) --------------------------------------
    /**
     * Escribe en un cajón. `isPublic` es OPCIONAL a propósito: sin decir nada se
     * conserva lo que la variable ya era (rotar un valor no debe cambiar quién puede
     * verlo por olvido) y una variable nueva nace PRIVADA.
     *
     * `by` es quién la escribió (la pubkey del aparato), y va al histórico.
     */
    async set (ns, key, value, isPublic, { by = null } = {}) {
      assertNs(ns)
      return this._put(data.ns, ns, `ns:${ns}`, key, value, isPublic, by)
    },
    async setDevice (pub, key, value, isPublic, { by = null } = {}) {
      assertPub(pub)
      return this._put(data.dev, pub, `dev:${pub}`, key, value, isPublic, by)
    },
    /** @private */
    async _put (...a) { return queued(() => this._putRaw(...a)) },
    /** @private El cuerpo, ya en fila (ver `enFila`). */
    async _putRaw (bag, k, owner, key, value, isPublic, by) {
      // El cajón del perfil tiene su propio alfabeto (`nickname`, no `NICKNAME`). Por aquí
      // solo llega con `importValue`: `set` ya rechaza `@me` como nombre de cajón.
      if (owner === PROFILE_OWNER) assertProfileValue(key, value)
      else assertKeyValue(key, value)
      const vars = ensureBag(bag, k)
      const before = vars[key]
      const pub = isPublic === undefined ? !!before?.pub : !!isPublic
      if (before && !before.pub && pub) throw new PrivateStaysPrivate(key)

      // v3: se guarda como siempre. Convertir a sobres es un gesto aparte y explícito
      // (`migrate`), no algo que ocurra de refilón al escribir.
      if (isLegacy()) { vars[key] = { v: value, pub }; save(); return }
      if (needsMigration()) throw new NeedsMigration()

      // PÚBLICA Y PRIVADA SE GUARDAN IGUAL (dueño, 2026-09-02: «las variables públicas
      // igual, codificadas en sobres… la única diferencia es si se despachan o no, son
      // políticas, dales el mismo tratamiento de seguridad»).
      //
      // Antes una pública se guardaba EN CLARO, y eso mezclaba dos cosas que no tienen que
      // ver: quién puede recibirla (política) y cómo se guarda (seguridad). El precio era
      // un valor legible en el disco y un camino aparte en cada sitio que las tocaba.
      // Ahora `pub` es solo la marca de despacho: se lleva sin aprobación (`--public`).
      needSealer('write a variable')
      await ensureRecovery(null)

      // CEK NUEVA, siempre: no se puede reutilizar la de antes sin poder abrirla.
      const cek = await sealer.newKey()
      const gen = nextGen(bag, k, owner)
      const { wraps, sinLlave: noKey } = await wrapAll(cek, owner, pub)
      const e = await sealer.encrypt(cek, value, gen)
      // La FIRMA dice que este sobre salió de esta bóveda, y con qué acta (§8.8). Si no
      // hay con qué firmar, el sobre sale sin firma: guardar es más importante.
      const seal = signer ? await signer({ owner, key, gen, iv: e.iv, ct: e.ct }) : null

      pushHistory(owner, key, before, by)
      vars[key] = { pub, owner, gen, e, seal, at: Date.now(), by: by || null }
      bag[k].keyring = [...(bag[k].keyring || []), { gen, createdAt: Date.now(), wraps }]
      gcKeyring(bag, k, owner)
      save()
      return { gen, sinLlave: noKey }
    },

    /**
     * GUARDAR UN SOBRE YA HECHO, SIN ABRIRLO (dueño, 2026-09-01).
     *
     * «La bóveda cerrada no puede ver el valor; debe confiar en la firma del admin y en el
     * contenido de esos sobres, y es la razón por la que al abrir la bóveda rehace los
     * sobres: por si alguno tiene alguna incoherencia.»
     *
     * Antes, escribir hacía un rodeo absurdo: la consola sellaba el valor AL PERFIL, la
     * bóveda lo ABRÍA para sacarlo en claro y `_putRaw` lo volvía a cerrar. Ese descifrado
     * era el único motivo por el que la llave de cifrado del perfil tenía que estar
     * accesible con la bóveda cerrada — o sea, la razón por la que una copia del disco
     * abría todos los sobres dirigidos al perfil.
     *
     * Aquí no se abre nada: llega el valor ya cifrado con una CEK nueva y esa CEK ya
     * envuelta para cada destinatario. Lo único que se comprueba es lo que se puede
     * comprobar sin la llave — la FORMA, y sobre todo que venga la envoltura de
     * recuperación: sin ella el cajón nace ilegible para siempre, y eso no se arregla
     * después ni abriendo la bóveda.
     *
     * @param {string} owner `ns:<scope>` o `dev:<pub>`
     * @param {{e:{iv:string,ct:string,gen?:number}, wraps:Object}} envelope
     */
    async putSealed (owner, key, envelope, { by = null, public: isPublic = false } = {}) {
      return queued(() => this._putSealedRaw(owner, key, envelope, by, !!isPublic))
    },
    /** @private */
    async _putSealedRaw (owner, key, envelope, by, isPublic) {
      if (isLegacy()) throw new Error('putSealed: this store is still v3 (run `migrate` first)')
      if (needsMigration()) throw new NeedsMigration()
      const [kind, k] = splitOwner(owner)
      const bag = kind === 'ns' ? data.ns : data.dev
      const e = envelope?.e; const wraps = envelope?.wraps
      if (!e || typeof e.iv !== 'string' || typeof e.ct !== 'string') {
        throw new Error('putSealed: the envelope must carry `iv` and `ct`')
      }
      if (!wraps || typeof wraps !== 'object' || !wraps[RECOVERY]) {
        // SIN LA ENVOLTURA DE RECUPERACIÓN EL CAJÓN NACE MUERTO. Es la que abre la frase, y
        // la única que puede rehacer las demás: si falta, ni el dueño con su contraseña
        // podría reenvolverlo para nadie. Se rechaza antes de tocar el disco.
        throw new Error('putSealed: the wraps must include the recovery one (#recovery), or the drawer could never be re-wrapped')
      }
      const vars = ensureBag(bag, k)
      const before = vars[key]
      // Una PRIVADA no se vuelve pública: cambiar eso es cambiar quién la recibe sin
      // aprobación, y no puede colarse en una escritura normal.
      if (before && !before.pub && isPublic) throw new PrivateStaysPrivate(key)

      // LA GENERACIÓN LA PONE EL ALMACÉN, no quien escribe: es la que ordena el llavero, y
      // dejar que la eligiera el que llega permitiría pisar una anterior.
      const gen = nextGen(bag, k, owner)
      // La FIRMA sigue siendo de la bóveda —dice que este sobre salió de aquí y con qué
      // acta (§8.8)— y se hace con la llave de SELLADO, que funciona con el perfil cerrado.
      const seal = signer ? await signer({ owner, key, gen, iv: e.iv, ct: e.ct }) : null

      pushHistory(owner, key, before, by)
      vars[key] = { pub: isPublic, owner, gen, e: { ...e, gen }, seal, at: Date.now(), by: by || null }
      bag[k].keyring = [...(bag[k].keyring || []), { gen, createdAt: Date.now(), wraps }]
      gcKeyring(bag, k, owner)
      save()
      return { gen }
    },

    /**
     * LO QUE SE CLONA A LAS HERMANAS (`docs/replicas.md` §11.3): los cajones tal cual —sobres
     * ya sellados, generaciones con sus envolturas— y las lápidas. Nada se abre: guardarlo no
     * exige poder leerlo, y por eso una bóveda cerrada también lo recibe. El histórico no
     * viaja: es la memoria de lo que pasó AQUÍ.
     *
     * La envoltura de recuperación es de ESTA bóveda (su par de recuperación): viaja con su
     * etiqueta (`#recovery@<x>`) para que la hermana la conserve sin confundirla con la suya.
     */
    exportState () {
      if (isLegacy() || needsMigration()) return null
      const mine = recoveryTag()
      const bagOut = (bag) => Object.fromEntries(Object.entries(bag || {}).map(([k, b]) => [k, {
        vars: { ...(b?.vars || {}) },
        keyring: (b?.keyring || []).map((g) => ({ ...g, wraps: retag(g.wraps, RECOVERY, mine) }))
      }]))
      return { v: 1, ns: bagOut(data.ns), dev: bagOut(data.dev), deleted: JSON.parse(JSON.stringify(data.deleted || {})) }
    },

    /**
     * ¿TENEMOS ALGO QUE ESA HERMANA NO? Compara su estado con el nuestro: un dato que ella no
     * tiene, o que tiene en una generación anterior, o una lápida que no ha visto. Es lo que
     * decide si, después de mezclar lo suyo, hay que devolverle lo nuestro (sin bucle: la
     * vuelta ya lo trae todo y la siguiente comparación sale que no).
     */
    aheadOf (state) {
      if (!state || isLegacy() || needsMigration()) return false
      const theirs = (kind, k, key) => state[kind]?.[k]?.vars?.[key]
      for (const kind of ['ns', 'dev']) {
        const bag = kind === 'ns' ? data.ns : data.dev
        for (const [k, b] of Object.entries(bag || {})) {
          for (const [key, e] of Object.entries(b?.vars || {})) {
            const t = theirs(kind, k, key)
            const owner = kind === 'ns' ? `ns:${k}` : `dev:${k}`
            const tomb = state.deleted?.[owner]?.[key]
            if (tomb && (tomb.gen || 0) >= (e.gen || 0)) continue
            if (!t || (t.gen || 0) < (e.gen || 0)) return true
          }
        }
      }
      for (const [owner, keys] of Object.entries(data.deleted || {})) {
        for (const [key, t] of Object.entries(keys || {})) {
          const theirsTomb = state.deleted?.[owner]?.[key]
          if (!theirsTomb || (theirsTomb.gen || 0) < (t.gen || 0)) return true
        }
      }
      return false
    },

    /**
     * MEZCLAR LO DE UNA HERMANA, dato a dato. Gana la generación más alta (que es la hora de
     * la escritura: «gana el último cambio»); un empate lo rompe el `ct` menor, igual en las
     * dos, para que acaben idénticas. Una lápida gana a un valor de su generación o anterior.
     * Las envolturas de una misma generación se SUMAN. Devuelve cuántos datos cambiaron.
     */
    async mergeState (state) {
      return queued(() => {
        if (isLegacy() || needsMigration()) throw new Error('mergeState: this store is not v5 yet')
        if (!state || state.v !== 1) throw new Error('mergeState: unknown state')
        const mine = recoveryTag()
        let changed = 0
        const tombOf = (owner, key) => data.deleted?.[owner]?.[key] || null
        // Las lápidas primero: borran lo que tapan y quedan anotadas.
        for (const [owner, keys] of Object.entries(state.deleted || {})) {
          for (const [key, t] of Object.entries(keys || {})) {
            const here = tombOf(owner, key)
            if (!here || (t.gen || 0) > (here.gen || 0)) {
              if (!data.deleted[owner]) data.deleted[owner] = {}
              data.deleted[owner][key] = { gen: t.gen || 0, at: t.at || null }
            }
            const [kind, k] = splitOwner(owner)
            const bag = kind === 'ns' ? data.ns : data.dev
            const e = bag[k]?.vars?.[key]
            if (e && (e.gen || 0) <= (t.gen || 0)) { delete bag[k].vars[key]; changed++ }
          }
        }
        for (const kind of ['ns', 'dev']) {
          const bag = kind === 'ns' ? data.ns : data.dev
          for (const [k, b] of Object.entries(state[kind] || {})) {
            const owner = kind === 'ns' ? `ns:${k}` : `dev:${k}`
            ensureBag(bag, k)
            // El llavero: generaciones nuevas enteras; las que ya hay, sumando envolturas.
            for (const g of b?.keyring || []) {
              const wraps = retag(g.wraps, `${RECOVERY}@${mine}`, null)
              const here = bag[k].keyring.find((x) => x.gen === g.gen)
              if (!here) bag[k].keyring.push({ ...g, wraps })
              else for (const [who, w] of Object.entries(wraps)) if (!(who in here.wraps)) here.wraps[who] = w
            }
            for (const [key, e] of Object.entries(b?.vars || {})) {
              const t = tombOf(owner, key)
              if (t && (t.gen || 0) >= (e.gen || 0)) continue
              const a = bag[k].vars[key]
              const ga = a?.gen || 0; const gb = e.gen || 0
              if (!a || gb > ga || (gb === ga && String(e.e?.ct ?? '') < String(a.e?.ct ?? ''))) {
                if (!a || a.gen !== e.gen || a.e?.ct !== e.e?.ct) { bag[k].vars[key] = e; changed++ }
              }
            }
            gcKeyring(bag, k, owner)
            if (Object.keys(bag[k].vars).length === 0) prune(bag, k)
          }
        }
        if (changed) { quiet = true; try { flush() } finally { quiet = false } }
        return { changed }
      })
    },

    /**
     * LA ENTRADA TAL CUAL (sobre, generación, visibilidad) — sin abrir nada.
     *
     * Es lo que hace falta para MANDARLE a alguien una variable que sí puede leer: el sobre
     * viaja cerrado y lo abre en su casa, con su envoltura. Aquí no se descifra.
     */
    entryOf (owner, key) {
      const [kind, k] = splitOwner(owner)
      const bag = kind === 'ns' ? data.ns : data.dev
      return varsOf(bag, k)[key] || null
    },
    /** La envoltura de ESA generación para ESE miembro, o `null` si no la tiene. */
    wrapOf (owner, gen, memberPub) {
      const [kind, k] = splitOwner(owner)
      const bag = kind === 'ns' ? data.ns : data.dev
      return (bag[k]?.keyring || []).find((g) => g.gen === gen)?.wraps?.[memberPub] || null
    },

    /**
     * ¿EXISTE YA ESTA VARIABLE? Sin abrirla ni decir qué vale.
     *
     * Hace falta para la regla de «un servicio solo rellena lo que falta, no pisa lo que
     * hay» (dueño, 2026-09-01): quien decide eso necesita saber si había algo, y nada más.
     */
    has (owner, key) {
      const [kind, k] = splitOwner(owner)
      const bag = kind === 'ns' ? data.ns : data.dev
      return key in varsOf(bag, k)
    },

    /**
     * PARA QUIÉN hay que envolver, con su llave pública de cifrado, más la de recuperación.
     * Es lo que necesita quien va a fabricar el sobre — y se lo dice la BÓVEDA, para que no
     * haya dos sitios respondiendo a «quién puede abrir este cajón» (la lista la sabe el
     * acta, y de ahí sale `recipients`).
     */
    async recipientsFor (owner, { public: isPublic = false } = {}) {
      await ensureRecovery(null)
      const members = (await recipients?.(owner, { public: isPublic })) || []
      return {
        recoveryPub: data.recovery.pub,
        members: members.filter((m) => m.encPub).map((m) => ({ pub: m.pub, encPub: m.encPub }))
      }
    },

    async delete (ns, key) {
      assertNs(ns)
      return this._drop(data.ns, ns, `ns:${ns}`, key)
    },
    async deleteDevice (pub, key) {
      assertPub(pub)
      return this._drop(data.dev, pub, `dev:${pub}`, key)
    },
    /**
     * @private Borrar NO exige la frase: quitar algo no pide poder leerlo.
     *
     * Y borrar SE LLEVA SU HISTÓRICO. Si no, borrar una variable dejaría sus versiones
     * anteriores guardadas —cifradas, pero recuperables— y «borré esa credencial» sería
     * mentira. El histórico existe para revertir mientras la variable vive; cuando se va,
     * se va entera.
     */
    _drop (bag, k, owner, key) {
      const vars = varsOf(bag, k)
      const existed = key in vars
      if (!existed) return false
      if (!isLegacy()) {
        if (!data.deleted[owner]) data.deleted[owner] = {}
        data.deleted[owner][key] = { gen: nextGen(bag, k, owner), at: Date.now() }
      }
      delete vars[key]
      data.history = data.history.filter((h) => !(h.owner === owner && h.key === key))
      if (!isLegacy()) gcKeyring(bag, k, owner)
      if (Object.keys(vars).length === 0) prune(bag, k)
      save()
      return true
    },

    /**
     * Cambiar la visibilidad solo va en UNA dirección: de pública a privada (sellar el
     * valor, que es escribir y no pide nada). De privada a pública NO existe
     * (`PrivateStaysPrivate`): destapar un secreto no es una casilla, es borrarlo y
     * crear otro.
     */
    async setVisibility (ns, key, isPublic, adminKey = null) {
      assertNs(ns)
      return this._setVis(data.ns, ns, `ns:${ns}`, key, isPublic, adminKey)
    },
    async setDeviceVisibility (pub, key, isPublic, adminKey = null) {
      assertPub(pub)
      return this._setVis(data.dev, pub, `dev:${pub}`, key, isPublic, adminKey)
    },
    /** @private */
    async _setVis (...a) { return queued(() => this._setVisRaw(...a)) },
    /** @private El cuerpo, ya en fila. */
    async _setVisRaw (bag, k, owner, key, isPublic, adminKey) {
      const vars = varsOf(bag, k)
      const e = vars[key]
      if (!e) return false
      const want = !!isPublic
      if (!!e.pub === want) return true
      // DE PRIVADA A PÚBLICA NO EXISTE, y no es una limitación técnica: hacer despachable
      // sin aprobación algo que se guardó como secreto no puede ser una casilla. Se crea
      // otra variable a propósito.
      if (!e.pub) throw new PrivateStaysPrivate(key)
      if (isLegacy()) { e.pub = false; save(); return true }
      if (needsMigration()) throw new NeedsMigration()

      // DE PÚBLICA A PRIVADA ES CAMBIAR LA MARCA, Y NADA MÁS (dueño, 2026-09-02).
      //
      // Antes había que reescribir la variable entera —generación nueva, sobre nuevo—
      // porque una pública se guardaba EN CLARO y taparla significaba cifrarla por primera
      // vez. Ya no: las dos se guardan igual desde el principio, así que aquí solo cambia
      // a quién se le despacha sin aprobación. Reescribir ahora sería trabajo (y una
      // generación) para no cambiar nada de lo guardado.
      e.pub = false
      save()
      return true
    },

    // --- lecturas que NO abren nada ---------------------------------------------
    /** Nombres y visibilidad (ns → [{key, public}]), sin valores: para `secret list`. */
    list () {
      const out = {}
      for (const ns of Object.keys(data.ns)) out[ns] = names(data.ns, ns)
      return out
    },
    /** Nombres y visibilidad (pub → [{key, public}]), sin valores. */
    listDevices () {
      const out = {}
      for (const pub of Object.keys(data.dev)) out[pub] = names(data.dev, pub)
      return out
    },
    /**
     * QUIÉN puede abrir la generación vigente de un cajón (sus llaves de firma, más
     * `#recovery`). Es diagnóstico, no un secreto: saber a cuántos se les envolvió no
     * ayuda a abrir nada, y en cambio es lo único que responde de verdad a «¿quién
     * puede leer esto?» — que es la pregunta que uno se hace mirando un cajón.
     */
    recipientsIn (owner) {
      const [kind, k] = splitOwner(owner)
      const bag = kind === 'ns' ? data.ns : data.dev
      // La recuperación de una HERMANA no es un destinatario de aquí (`exportState`).
      return Object.keys(topGen(bag, k)?.wraps || {}).filter((w) => !w.startsWith(`${RECOVERY}@`))
    },

    /** Los NOMBRES de las públicas de un scope. Ya no hay valor que devolver: van en sobre. */
    publicOf (ns) {
      assertNs(ns)
      return publics(data.ns, ns)
    },
    /** Los NOMBRES de las públicas de un aparato. */
    publicOfDevice (pub) {
      assertPub(pub)
      return publics(data.dev, pub)
    },

    // --- histórico: qué había antes, y cómo se vuelve ---------------------------
    /**
     * Las versiones anteriores, de la más nueva a la más vieja. SIN valores: son sobres.
     * Quien pueda abrirlos los abre con `revealHistory`; quien no, ve que existieron.
     */
    history (owner = null, key = null) {
      return data.history
        .filter((h) => (!owner || h.owner === owner) && (!key || h.key === key))
        .map((h) => ({ ts: h.ts, owner: h.owner, key: h.key, gen: h.gen, by: h.by || null, signed: !!h.seal }))
        .reverse()
    },

    /** El valor de una versión anterior. Pide la frase, como cualquier lectura. */
    async revealHistory (owner, key, ts, adminKey = null) {
      const h = data.history.find((x) => x.owner === owner && x.key === key && x.ts === ts)
      if (!h) return null
      const [kind, k] = splitOwner(owner)
      const bag = kind === 'ns' ? data.ns : data.dev
      const priv = await openRecovery(adminKey)
      return sealer.openValue(await this._cekOf(bag, k, h.gen, priv), h.e)
    },

    /**
     * REVERTIR: coge una versión anterior y la vuelve a guardar. No es un modo especial
     * del store —es abrir y escribir—, así que hereda las dos reglas: abrir pide la
     * frase (o la hace quien puede leer, desde su aparato) y escribir no pide nada.
     */
    async revert (owner, key, ts, { adminKey = null, by = null } = {}) {
      const value = await this.revealHistory(owner, key, ts, adminKey)
      if (value == null) return false
      const [kind, k] = splitOwner(owner)
      const bag = kind === 'ns' ? data.ns : data.dev
      await this._put(bag, k, owner, key, value, false, by)
      return true
    },

    // --- llavero: quién puede abrir cada cajón ----------------------------------
    /**
     * Re-envuelve la llave de lo YA GUARDADO a los miembros dados. Hace falta cuando
     * entra un aparato a un cajón que ya tiene variables: lo que se escriba desde ahora
     * ya se le envuelve solo, pero lo de antes está cerrado con llaves que él no tiene.
     *
     * Y por eso ESTO sí pide la frase: heredar lo viejo obliga a abrirlo.
     */
    async rewrap (...a) { return queued(() => this._rewrap(...a)) },
    /** Los cajones que existen, para poder recorrerlos todos (`ns:…` y `dev:…`). */
    owners () {
      return [...Object.keys(data.ns).map((k) => `ns:${k}`), ...Object.keys(data.dev).map((k) => `dev:${k}`)]
    },
    // ---------------- EL PERFIL (`docs/datos-del-perfil.md`) ----------------
    //
    // Escribir un dato PRIVADO no necesita nada de aquí: es `putSealed(PROFILE_OWNER, …)`,
    // que ya guarda un sobre hecho sin abrirlo y funciona con la bóveda cerrada. Lo que
    // falta es leerlo, y el camino de lo PÚBLICO, que no se parece a ninguna variable.

    /**
     * Los sobres del perfil TALLADOS a un aparato: sus entradas y las envolturas suyas.
     * Igual que `bundleFor`, sin `assertNs` — `@me` no es un nombre de cajón válido, y esa
     * es justamente su garantía.
     *
     * El PAQUETE LO ARMA EL APARATO (dueño, 2026-09-03): aquí solo se entrega lo que hay.
     */
    profileBundleFor (devicePub) {
      const bag = data.ns
      const k = PROFILE_NS
      if (isLegacy() || !bag[k]) return { entries: {}, wraps: [] }
      const wraps = (bag[k].keyring || [])
        .filter((g) => g.wraps?.[devicePub])
        .map((g) => ({ gen: g.gen, wrap: g.wraps[devicePub] }))
      return { entries: { ...varsOf(bag, k) }, wraps }
    },

    /**
     * LO PÚBLICO DE VERDAD: en claro, y firmado. Es lo que recibe quien pregunta desde
     * fuera y no tiene ninguna llave tuya — no hay a quién sellárselo (dueño, 2026-09-03).
     *
     * Va firmado igual que lo demás: un dato público sin firma es un dato que cualquiera
     * puede inventar en tu nombre, que es peor que no tenerlo.
     */
    profileView () {
      // EL PERFIL TAL COMO LO TIENE LA BÓVEDA, para enseñárselo al dueño (`dotrino-vault me`,
      // la TUI). Sale del cajón `@me`, que es donde escribe el aparato dato a dato. Lo
      // público va en claro; de lo privado solo el NOMBRE del dato: viaja sellado y la
      // bóveda no lo abre para enseñarlo (§8.1), igual que una variable privada.
      const vars = data.ns[PROFILE_NS]?.vars || {}
      const pub = {}
      const priv = []
      let at = 0
      for (const [key, e] of Object.entries(vars)) {
        if (!e) continue
        at = Math.max(at, e.at || 0)
        if (e.cls === 'public' && typeof e.pubv === 'string') pub[key] = e.pubv
        else priv.push(key)
      }
      return { public: pub, private: priv.sort(), updatedAt: at || null }
    },

    profilePublic () {
      const bag = data.ns[PROFILE_NS]
      if (!bag?.vars) return {}
      const out = {}
      for (const [key, e] of Object.entries(bag.vars)) {
        if (e?.cls !== 'public' || typeof e.pubv !== 'string') continue
        out[key] = { v: e.pubv, gen: e.gen, seal: e.seal || null, at: e.at || null, by: e.by || null }
      }
      return out
    },

    /**
     * Guarda un dato PÚBLICO del perfil: en claro y con su firma. No lleva sobre ni
     * envoltura porque no se le sella a nadie.
     *
     * `pubv` y no `v`: un `v` suelto dentro de un paquete de variables es un error duro
     * desde el 2026-09-02 (`plaintext-var`), y con razón. Aquí es lo correcto, así que se
     * escribe con otro nombre — el paquete del perfil lo arma otro código y esa invariante
     * de los secretos se queda intacta.
     */
    async profilePutPublic (key, value, { by = null } = {}) {
      return queued(async () => {
        if (isLegacy()) throw new Error('profile: this store is still v3 (run `migrate` first)')
        if (needsMigration()) throw new NeedsMigration()
        assertProfileKey(key)
        if (typeof value !== 'string' || value.length > MAX_PROFILE_LEN) {
          throw new Error('a public profile field must be a string of at most 200 kB')
        }
        const vars = ensureBag(data.ns, PROFILE_NS)
        const before = vars[key]
        const gen = nextGen(data.ns, PROFILE_NS, PROFILE_OWNER)
        const seal = signer ? await signer({ owner: PROFILE_OWNER, key, gen, iv: '', ct: value }) : null
        pushHistory(PROFILE_OWNER, key, before, by)
        vars[key] = { cls: 'public', pub: true, owner: PROFILE_OWNER, gen, pubv: value, seal, at: Date.now(), by: by || null }
        save()
        return { gen }
      })
    },

    /** @private */
    /**
     * @param {Array|((isPublic:boolean)=>Promise<Array>)} members A quién envolver. Puede ser
     *   una FUNCIÓN de la visibilidad: desde 2026-09-02 una pública se envuelve además para
     *   quien administra, y eso se decide por variable — cada escritura estrena su CEK, así
     *   que el llavero tiene una generación por valor. Con una lista fija se aplicaría la
     *   misma a todas y se le daría a la consola la envoltura de una privada con dueño.
     */
    async _rewrap (owner, members, adminKey = null, { exact = false } = {}) {
      needSealer('re-wrap the key of a drawer')
      if (needsMigration()) throw new NeedsMigration()
      const [kind, k] = splitOwner(owner)
      const bag = kind === 'ns' ? data.ns : data.dev
      if (!bag[k]) return { wrapped: 0, sinLlave: [] }
      const priv = await openRecovery(adminKey)
      let wrapped = 0
      let sealed = 0
      const noKey = new Set()
      const vars = varsOf(bag, k)
      const forVisibility = async (isPublic) => (typeof members === 'function' ? members(isPublic) : members)

      // UN VALOR QUE SE QUEDÓ EN CLARO SE SELLA AQUÍ, que es el único sitio donde se puede.
      //
      // Una pública escrita antes del 2026-09-02 se guardó legible y SIN sobre, así que no
      // tiene generación ni entrada en el llavero. Y el llavero es lo único que este
      // método reenvuelve: por muchas veces que se abra la bóveda, a esa variable no se le
      // crea una envoltura nunca. Sus aparatos la reclaman para siempre («no key yet») y la
      // consola invita a abrir la bóveda, que es justo lo que no lo arregla. Peor: desde
      // 2026-09-02 el agente rechaza el cajón ENTERO por ella, así que una variable de
      // prueba deja sin leer el token que está al lado.
      //
      // Con la bóveda abierta el valor está delante, así que se cifra como si se acabara
      // de escribir. No es un repliegue ni una migración a medias: es la conversión que
      // faltaba, y ocurre en el único momento en que hay con qué hacerla.
      for (const [key, e] of Object.entries(vars)) {
        if (typeof e.v !== 'string' || e.e) continue
        const cek = await sealer.newKey()
        const gen = nextGen(bag, k, owner)
        const r = await sealer.wrapFor(cek, await forVisibility(!!e.pub))
        r.wraps[RECOVERY] = await sealer.wrapForKey(cek, data.recovery.pub)
        const envelope = await sealer.encrypt(cek, e.v, gen)
        const seal = signer ? await signer({ owner, key, gen, iv: envelope.iv, ct: envelope.ct }) : null
        // `pub` y `at` se conservan: no es un valor nuevo, es el mismo mejor guardado.
        vars[key] = { pub: !!e.pub, owner, gen, e: envelope, seal, at: e.at || Date.now(), by: e.by || null }
        bag[k].keyring = [...(bag[k].keyring || []), { gen, createdAt: Date.now(), wraps: r.wraps }]
        for (const x of r.sinLlave) noKey.add(x)
        sealed++
      }

      // De qué variable es cada generación: es lo que dice si esa CEK es de una pública.
      // Se calcula DESPUÉS de sellar, para que las generaciones recién creadas entren.
      const visibility = new Map()
      for (const e of Object.values(vars)) if (e.gen != null) visibility.set(e.gen, !!e.pub)
      const forGen = async (gen) => forVisibility(visibility.get(gen) === true)
      for (const g of bag[k].keyring || []) {
        const w = g.wraps?.[RECOVERY]
        if (!w) continue
        const cek = await sealer.openWrapWith(priv, w)
        const r = await sealer.wrapFor(cek, await forGen(g.gen))
        // `exact`: el llavero queda con lo que dice el acta y NADA más. Es lo que hace
        // falta para rehacerlo al abrir la bóveda:
        //   · una envoltura basura que metió alguien se reemplaza por la buena;
        //   · una que sobra —de quien administraba antes de que este cajón tuviera
        //     dueño, o de un miembro inventado— se cae.
        // Sin `exact` se fusiona, que es lo correcto cuando solo se está repartiendo a
        // unos pocos y no se quiere tocar al resto.
        //
        // OJO con lo que esto NO es: quitarle la envoltura a alguien no le quita lo que
        // ya leyó ni la llave que se haya guardado. Cortar de verdad es `rotate`.
        g.wraps = exact ? { ...r.wraps, [RECOVERY]: w } : { ...g.wraps, ...r.wraps }
        for (const s of r.sinLlave) noKey.add(s)
        wrapped += Object.keys(r.wraps).length
      }
      save()
      return { wrapped, sealed, sinLlave: [...noKey] }
    },

    /**
     * RENOMBRAR UNA VARIABLE. Cambia el nombre y NADA MÁS: el mismo sobre, la misma
     * generación, las mismas envolturas. El valor no se toca ni se mira.
     *
     * Lo único que hay que rehacer es la FIRMA, porque el nombre va dentro de lo firmado
     * (§8.8: `{owner, key, gen, iv, ct}`). Sin eso el sobre quedaría diciendo que se llama
     * de otra manera y el agente lo rechazaría al abrirlo — un fallo que aparecería lejos
     * de aquí y sin pista.
     *
     * Y firmar de nuevo NO pide la frase: la llave de sellado existe justo para esto, no
     * abre nada. Así que renombrar funciona con la bóveda cerrada, como escribir.
     *
     * El HISTÓRICO se muda con ella: es la misma variable, y dejarlo bajo el nombre viejo
     * lo volvería inalcanzable — se vería como un hueco, no como una decisión.
     */
    async rename (owner, from, to) { return queued(() => this._renameRaw(owner, from, to)) },
    /** @private */
    async _renameRaw (owner, from, to) {
      if (needsMigration()) throw new NeedsMigration()
      assertKeyValue(to, 'x')
      const [kind, k] = splitOwner(owner)
      const bag = kind === 'ns' ? data.ns : data.dev
      const vars = varsOf(bag, k)
      const e = vars[from]
      if (!e) throw new Error(`there is no variable called "${from}" in ${owner}`)
      if (from === to) return { renamed: false }
      if (vars[to]) throw new Error(`"${to}" already exists in ${owner}: pick another name or remove it first`)

      // La firma lleva el nombre dentro, así que se rehace. Si esta bóveda no puede firmar,
      // se para: dejar el sobre con la firma vieja es dejarlo roto para quien lo abra.
      if (e.e) {
        if (!signer) throw new Error('this vault cannot sign right now: renaming would leave the envelope signed with the old name')
        e.seal = await signer({ owner, key: to, gen: e.gen, iv: e.e.iv, ct: e.e.ct })
      }
      delete vars[from]
      vars[to] = e
      for (const h of data.history) if (h.owner === owner && h.key === from) h.key = to
      save()
      return { renamed: true }
    },

    /**
     * ROTA de verdad: vuelve a cifrar las variables privadas del cajón con llaves nuevas
     * y solo para los miembros dados. Es lo que corta el acceso de quien salió —
     * quitarle la envoltura no basta, porque si guardó la llave sigue abriendo lo que ya
     * estaba cifrado con ella.
     *
     * No devuelve lo que el expulsado ya leyó. Eso no se puede deshacer y no se promete.
     */
    async rotate (...a) { return queued(() => this._rotate(...a)) },
    /** @private */
    async _rotate (owner, members, adminKey = null) {
      needSealer('rotate the key of a drawer')
      if (needsMigration()) throw new NeedsMigration()
      const [kind, k] = splitOwner(owner)
      const bag = kind === 'ns' ? data.ns : data.dev
      if (!bag[k]) return { rotated: 0, sinLlave: [] }
      const priv = await openRecovery(adminKey)

      const vars = bag[k].vars || {}
      const plainOnes = {}
      for (const [key, e] of Object.entries(vars)) {
        if (!e.pub) plainOnes[key] = await sealer.openValue(await this._cekOf(bag, k, e.gen, priv), e.e)
      }
      // Se tira el llavero entero: las generaciones viejas son justamente lo que el que
      // se fue podría abrir. Con ellas se va el histórico de este cajón, que estaba
      // cifrado con ellas — rotar es renunciar a poder revertir lo de antes.
      bag[k].keyring = []
      data.history = data.history.filter((h) => h.owner !== owner)
      const noKey = new Set()
      let gen = 0
      for (const [key, value] of Object.entries(plainOnes)) {
        const cek = await sealer.newKey()
        gen += 1
        const { wraps, sinLlave: missingOnes } = await sealer.wrapFor(cek, members)
        wraps[RECOVERY] = await sealer.wrapForKey(cek, data.recovery.pub)
        for (const s of missingOnes) noKey.add(s)
        const e = await sealer.encrypt(cek, value, gen)
        const seal = signer ? await signer({ owner, key, gen, iv: e.iv, ct: e.ct }) : null
        vars[key] = { pub: false, owner, gen, e, seal, at: Date.now(), by: null }
        bag[k].keyring.push({ gen, createdAt: Date.now(), wraps })
      }
      save()
      return { rotated: Object.keys(plainOnes).length, sinLlave: [...noKey], gen, cambio: true }
    },

    /**
     * Se va un aparato, se van sus variables. Lo llama el vault al quitar un
     * miembro: dejarlas sería guardar la configuración de una llave que ya no
     * entra, y reaparecería sola si mañana se enrola otro aparato con esa llave.
     *
     * NO exige la frase: es la mitad del interruptor de emergencia. Su cajón `dev`
     * estaba sellado solo a él, así que borrarlo es inmediato y completo. Lo que sí queda
     * pendiente es rotar los `ns` que compartía (ver `rotate`).
     */
    forgetDevice (pub) {
      assertPub(pub)
      const keys = Object.keys(varsOf(data.dev, pub))
      if (keys.length || data.dev[pub]) { delete data.dev[pub]; save() }
      data.history = data.history.filter((h) => h.owner !== `dev:${pub}`)
      return keys.length
    },

    /**
     * Quita a un miembro del llavero de un cajón, sin abrir nada. Es lo que se puede
     * hacer SIN la frase cuando alguien sale: deja de poder abrir lo que se guarde en
     * adelante y lo que aún no había abierto. Lo que ya guardó no se arregla así — para
     * eso está `rotate`, que sí pide la frase.
     */
    unwrap (owner, pub) {
      if (isLegacy() || needsMigration()) return 0
      const [kind, k] = splitOwner(owner)
      const bag = kind === 'ns' ? data.ns : data.dev
      if (!bag[k]) return 0
      let n = 0
      for (const g of bag[k].keyring || []) {
        if (g.wraps?.[pub]) { delete g.wraps[pub]; n++ }
      }
      if (n) save()
      return n
    },

    /**
     * Vuelve a cerrar la privada de RECUPERACIÓN con otra llave. Es lo que hay que hacer
     * al poner, cambiar o quitar la contraseña del perfil: los sobres de las variables no
     * se tocan —siguen sellados a cada destinatario—, lo único que cambia es con qué se
     * abre la copia del dueño.
     *
     * Sin esto, cambiar la contraseña dejaría los secretos ILEGIBLES para él: la copia
     * seguiría sellada con la llave vieja y ya nadie tendría cómo abrirla. Es barato (un
     * solo sobre) y es obligatorio.
     *
     * `null` en cualquiera de las dos significa «la del perfil sin contraseña».
     */
    async rekeyRecovery (...a) { return queued(() => this._rekeyRecovery(...a)) },
    /**
     * ¿ESTA llave abre la copia de recuperación? Lanza si no.
     *
     * Sirve para saber con cuál está cerrada sin tocar nada — que es lo que hace falta para
     * decidir si hay que migrarla. Preguntarlo intentando reenvolver un cajón mezcla dos
     * cosas y deja el fallo diciendo «wrong password» sobre el cajón, que no es donde está.
     */
    /**
     * ABRE UNA ENVOLTURA DE RECUPERACIÓN y devuelve lo que lleva dentro.
     *
     * Es para OTROS almacenes de este mismo perfil —hoy la bóveda de contraseñas—, que
     * comparten ESTA copia de recuperación en vez de estrenar una segunda. Una segunda
     * sería otra llave que custodiar, otra que rotar y otra que se queda atrás.
     *
     * Sigue siendo la única puerta a un valor en claro, y sigue pidiendo la frase.
     */
    async openRecoveryWrap (wrap, adminKey = null) {
      const priv = await openRecovery(adminKey)
      return sealer.openWrapWith(priv, wrap)
    },

    async recoveryOpensWith (key) {
      needSealer('check the recovery key')
      if (!data.recovery?.priv) throw new NeedsPassword('this store has no recovery key yet')
      await sealer.openMaster(data.recovery.priv, keyOr(key))
      return true
    },
    /** @private */
    async _rekeyRecovery (oldKey, newKey) {
      if (isLegacy()) return { rekeyed: false, reason: 'v3' }
      if (!data.recovery?.priv) return { rekeyed: false, reason: 'no-recovery' }
      needSealer('change the profile password')
      const priv = await sealer.openMaster(data.recovery.priv, keyOr(oldKey))
      data.recovery.priv = await sealer.sealMaster(priv, keyOr(newKey))
      save()
      return { rekeyed: true }
    },

    // --- conversión a v5 ---------------------------------------------------------
    /**
     * Lleva el archivo a v5, venga de donde venga:
     *
     *   · **desde v3** (valores en claro): no hace falta la frase para nada. Se sella
     *     cada valor a sus destinatarios y se estrena el par de recuperación.
     *   · **desde v4** (sellado con copia maestra): la frase hace falta UNA vez, para
     *     abrir esa copia. A partir de ahí, escribir no la pide nunca más.
     *
     * Verificar antes de reemplazar, igual que `migrateFile()` de `atrest.js`: se
     * construye la forma nueva, se vuelve a abrir **valor por valor** y se compara con
     * el original, y solo entonces se escribe. Si algo no cuadra no se toca nada y se
     * lanza: media migración es peor que ninguna.
     */
    async migrate (...a) { return queued(() => this._migrate(...a)) },
    /** @private */
    async _migrate (membersOf, adminKey = null) {
      if (data.schemaVersion === SCHEMA_VERSION) return { migrated: false, reason: 'already-v5' }
      needSealer('seal the store')
      const since = data.schemaVersion

      // De v4: las CEK viejas viven en la copia maestra, y para abrirla hace falta la
      // frase. Es la única vez que se pide.
      const master = since === SEALED_MASTER_VERSION ? await sealer.openMaster(data.master, keyOr(adminKey)) : null
      const plain = async (owner, e) => {
        if (e.pub) return e.v
        if (since === LEGACY_VERSION) return e.v
        return sealer.decrypt(master, e.e, e.owner || owner)
      }

      const pair = await sealer.makeRecoveryPair()
      const next = {
        schemaVersion: SCHEMA_VERSION,
        ns: {},
        dev: {},
        recovery: { pub: pair.pub, priv: await sealer.sealMaster(pair.priv, keyOr(adminKey)) },
        // El histórico empieza aquí: de lo de antes no se guardó ninguna versión previa.
        history: []
      }
      const antes = {}
      const noKey = {}

      for (const [kind, src, dst] of [['ns', data.ns, next.ns], ['dev', data.dev, next.dev]]) {
        for (const [k, bag] of Object.entries(src)) {
          const owner = `${kind}:${k}`
          const entries = since === LEGACY_VERSION ? (bag || {}) : (bag?.vars || {})
          const vars = {}
          const keyring = []
          // UNA SOLA generación para todo el cajón, y no es una excepción a «una por
          // escritura»: convertir es UN acto, y aquí la bóveda tiene delante todos los
          // valores en claro, así que puede sellarlos con la misma llave sin tener que
          // recuperar nada. Además deja el cajón como lo espera un agente que todavía no
          // se ha actualizado —una envoltura por cajón—, y eso es lo que permite convertir
          // sin apagar a nadie. Lo que se escriba DESPUÉS ya estrena generación.
          const gen = 1
          let cek = null
          for (const [key, e] of Object.entries(entries)) {
            const value = await plain(owner, e)
            antes[`${owner}\u0000${key}`] = value
            // LA PÚBLICA TAMBIÉN SE SELLA (dueño, 2026-09-02). Aquí se dejaba en claro,
            // así que un archivo migrado se quedaba con valores legibles en el disco —
            // exactamente lo que la conversión venía a quitar. La marca se conserva: dice
            // a quién se le despacha sin aprobación, no cómo se guarda.
            if (!cek) {
              cek = await sealer.newKey()
              const { wraps, sinLlave: missingOnes } = await sealer.wrapFor(cek, (await membersOf(owner)) || [])
              wraps[RECOVERY] = await sealer.wrapForKey(cek, next.recovery.pub)
              if (missingOnes.length) noKey[owner] = missingOnes
              keyring.push({ gen, createdAt: Date.now(), wraps })
            }
            const envelope = await sealer.encrypt(cek, value, gen)
            const seal = signer ? await signer({ owner, key, gen, iv: envelope.iv, ct: envelope.ct }) : null
            vars[key] = { pub: !!e.pub, owner, gen, e: envelope, seal, at: Date.now(), by: null }
          }
          dst[k] = { vars, keyring }
        }
      }

      // Releer lo escrito y comparar contra el original, antes de reemplazar nada.
      const priv = await sealer.openMaster(next.recovery.priv, keyOr(adminKey))
      for (const [kind, dst] of [['ns', next.ns], ['dev', next.dev]]) {
        for (const [k, bag] of Object.entries(dst)) {
          const owner = `${kind}:${k}`
          for (const [key, e] of Object.entries(bag.vars)) {
            // Se abre TODO, también las públicas: ahora van selladas igual, así que la
            // comprobación de que la migración no cambió ningún valor vale para las dos.
            const g = bag.keyring.find((x) => x.gen === e.gen)
            const isOpen = await sealer.openValue(await sealer.openWrapWith(priv, g.wraps[RECOVERY]), e.e)
            if (isOpen !== antes[`${owner}\u0000${key}`]) {
              throw new Error(`secrets: the migration check failed on ${owner}/${key}; nothing was touched`)
            }
          }
        }
      }

      // Copia de lo anterior antes de pisarlo. Con nodos en producción, deshacer tiene
      // que ser un `mv`, no una restauración. La borra el operador a mano.
      writeJson(disk, `${file}.v${since}.bak`, data)
      data = next
      flush()
      return { migrated: true, from: since, sinLlave: noKey }
    }
  }
}

/** `ns:proxy` → `['ns','proxy']`. El `dev:` lleva dentro un JWK con dos puntos. */
function splitOwner (owner) {
  const i = String(owner).indexOf(':')
  if (i < 0) throw new Error('invalid drawer: expected "ns:<name>" or "dev:<pubkey>"')
  return [owner.slice(0, i), owner.slice(i + 1)]
}
