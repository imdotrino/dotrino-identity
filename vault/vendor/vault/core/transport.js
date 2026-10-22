/**
 * Transporte headless del vault: el cliente OFICIAL `@dotrino/proxy-client`
 * corriendo en Node (mismo patrón que `dotrino-bots/src/core/transport.js`).
 * Hace el `identify` — liga el token efímero de la conexión a una pubkey estable,
 * habilitando el direccionamiento por pubkey (`sendByPubkey`) y la cola offline
 * de 24 h del proxy.
 *
 * QUIÉN FIRMA ESE `identify`, que es lo que cambió: **la llave de comunicación**
 * (`commKey.js`), no la maestra. La maestra sella el acta y reenvuelve sobres, y
 * nada más; si además tuviera que firmar aquí no podría vivir bajo llave, porque
 * esto se firma en cada conexión Y en cada reconexión — una bóveda cerrada no
 * existiría en la red.
 *
 * Lo que ata el token al PERFIL entonces ya no es un certificado sino el ACTA: el
 * proxio comprueba que quien habla sea miembro (`verifyActaMembership`) y ata el
 * token también al `profileId`. Por eso se manda el acta siempre.
 *
 * IMPORTANTE: `me.publickey` puede ser null en el primer arranque (solo se puebla
 * al fijar un nickname), así que la pubkey maestra se obtiene de forma robusta
 * con un `signData` de cortesía si hace falta. El daemon (vault.js) además puebla
 * `me` antes de conectar.
 */

const DEFAULT_PROXY = 'wss://proxy.dotrino.com'

export async function masterPubkeyOf (identity) {
  return identity.me?.publickey || (await identity.signData({ op: 'whoami', ts: Date.now() })).publickey
}

/**
 * Conecta el transporte y lo identifica con la maestra del vault.
 * @param {Object} opts
 * @param {import('@dotrino/identity/facade').IdentityFacade} opts.identity
 * @param {Function} [opts.makeClient]  quién crea el cliente del proxio. Sin él, el del
 *   ecosistema; el navegador lo pasa siempre (un service worker no puede hacer `import()`).
 * @param {string} [opts.url] URL del proxy (default wss://proxy.dotrino.com).
 * @returns {Promise<{ client, token:string, identify():Promise<void> }>}
 */
export async function createTransport ({ identity, url = DEFAULT_PROXY, commKey = null, log = () => {}, makeClient = null, announce = null, wakeUrl = null, recheckMs = 60_000, patienceMs = 5 * 60_000, reannounceMs = 10 * 60_000 }) {
  // Import dinámico DESPUÉS de instalar los globals que el paquete usa.
  // `WebSocketProxyClient` (la clase) y NO el helper `getWebSocketProxyClient`:
  // ese es un SINGLETON de proceso, y con multi-perfil el vault necesita una
  // conexión POR PERFIL (cada maestra se identifica con su propia pubkey ante el
  // proxy). Con el singleton, el segundo perfil reusaba el cliente del primero y
  // su `identify` pisaba al anterior. Sigue siendo el cliente oficial del paquete.
  // `makeClient` es la costura de las PRUEBAS, y existe por una razón concreta: comprobar
  // que un `identify` rechazado no tumba el perfil y se reintenta solo. Sin ella habría que
  // levantar un proxio de verdad para probar el caso que ya costó una tarde. En producción
  // no se pasa nunca y esto es el cliente oficial de siempre.
  const { WebSocketProxyClient } = makeClient ? {} : await import('@dotrino/proxy-client')

  /**
   * EL CANAL DIRECTO, ENCENDIDO Y CON LA PUERTA CERRADA.
   *
   * Encendido porque es el escalón 2 de la regla del transporte (`CLAUDE.md`) y en Node ya
   * hay con qué (`werift`, que el pilar carga solo). Si no lo hubiera, negociar falla y se
   * sigue por el proxio — el escalón 4 siempre está.
   *
   * Y con la puerta cerrada desde el primer día, que es lo que hace defendible encenderlo:
   * **solo se le negocia a quien está en el acta.** Aceptar una señal arranca DTLS, ICE y
   * SCTP, o sea código que parsea red no confiable, dentro del proceso que guarda la
   * maestra. Quien decide si eso corre no puede ser el que llama a la puerta.
   *
   * Reconexión prácticamente ilimitada: un daemon de larga duración no debe rendirse tras
   * unos intentos.
   */
  // La puerta tiene que decidir AL INSTANTE (la señal llega y o se atiende o no), y pedir
  // el acta es asíncrono. Así que se guarda una copia y se refresca donde ya se refresca
  // todo: en `identify`, que es lo que corre cada vez que el acta cambia o se reconecta.
  let seenActa = null
  // ¿Está esta bóveda ATADA al proxio ahora mismo? Conectado no es identificado: el socket
  // puede estar perfectamente abierto y el sobre rechazado, y entonces nadie la alcanza por
  // su pubkey. Se expone para que `status` lo enseñe en vez de dejarlo a un log del arranque.
  let identified = false
  const inActa = (token) => {
    // SIN ACTA NO SE NEGOCIA. No se sabe quién es nadie, y en la duda no se arranca a
    // parsear red no confiable. Se sigue por el proxio, que es el escalón que siempre está.
    if (!seenActa) return false
    return (seenActa.members || []).some((m) => m?.pub === token)
  }
  const client = makeClient ? makeClient({ url, acceptDirectFrom: inActa }) : new WebSocketProxyClient({
    url, enableWebRTC: true, acceptDirectFrom: inActa, autoReconnect: true,
    maxReconnectAttempts: 100000, reconnectDelay: 4000
  })

  await client.connect()

  // LO ENCOLADO LLEGA AL IDENTIFICARSE, y quien monta la bóveda todavía no escucha: pone su
  // oyente cuando ya tiene todo listo, bastante después. Sin esto, lo que el proxio guardaba
  // para una bóveda dormida —el acta nueva que sacó la otra bóveda, un pedido— se entregaba
  // a nadie y se perdía. Se guarda aquí hasta que llegue el oyente (`listen`).
  let early = []
  const offEarly = client.on('message', (from, payload) => { early?.push([from, payload]) })
  const listen = (fn) => {
    const off = client.on('message', fn)
    const pending = early || []
    early = null
    try { offEarly?.() } catch (_) {}
    for (const [from, payload] of pending) { try { fn(from, payload) } catch (_) {} }
    return off
  }

  const identify = async () => {
    identified = false
    if (!client.token) return
    const record = (await identity.profileActa?.().catch(() => null))?.acta || null
    seenActa = record   // la copia que mira la puerta del canal directo
    const comm = commKey?.pub?.() || null
    // ¿Nos nombra el acta? Con `cn` o sin él, lo que el proxio mira es la pertenencia.
    const isMember = comm && (record?.members || []).some((m) => m?.pub === comm)

    if (comm && isMember) {
      // El sobre lo arma el pilar (`identifyAs`), que le pone el destinatario.
      try {
        await client.identifyAs({ publickey: comm, sign: (d) => commKey.sign(d), acta: record })
        identified = true
        // SE DICE QUE SE IDENTIFICÓ, y con qué llave. Este camino era MUDO: al pasar de la
        // maestra a la llave de comunicación, el único rastro de «estoy alcanzable» que
        // quedaba en el log era el del repliegue. Así que cuando la consola decía «no
        // contesta», no había forma de saber desde aquí si la bóveda estaba atada al proxio
        // o no. Una línea por reconexión es barata; no tenerla cuesta una hora de sondeos.
        log(`[vault] identified on the proxy with the communication key · record #${record?.seq ?? '?'}`)
        return
      } catch (e) {
        // SOLO «esta llave no firma» cae al camino de abajo, y se distingue por el `code`.
        // Un fallo de red no es eso: tragárselo aquí mandaría a la maestra a firmar por un
        // problema pasajero, que es justo lo que la llave de comunicación vino a evitar.
        if (e?.code !== 'no-signature') throw e
      }
    }

    // REPLIEGUE, y solo para migrar: una bóveda que todavía no ha metido su llave de
    // comunicación en el acta se identifica con la maestra, como siempre. Exige el perfil
    // ABIERTO —la maestra bajo llave no firma— y por eso se dice en voz alta: mientras se
    // esté aquí, cerrar el perfil deja la bóveda sin voz.
    //
    // QUEDARSE SIN VOZ NO ES NO ARRANCAR, y aquí eran lo mismo. Un perfil con la maestra
    // sellada y sin llave de comunicación todavía llegaba hasta este `signData`, que tira
    // `vault locked`; el error subía por `createTransport` hasta `startVault` y **el perfil
    // entero se quedaba sin abrir**. Al dueño le pasó el 2026-09-02: su perfil principal no
    // arrancaba, `unlock` lo marcaba abierto igual y cada petición contestaba «profile is
    // not open», con la TUI vacía y sin un error a la vista.
    //
    // Se dice y se sigue. Sin red se puede vivir hasta que alguien teclee la frase; sin
    // bóveda, no.
    try {
      const publickey = await masterPubkeyOf(identity)
      if (!publickey) return
      log('[vault] identifying with the master key: this vault is not in its own record yet (open the profile once to fix it)')
      await client.identifyAs({ publickey, sign: (d) => identity.signData(d), acta: record })
      identified = true
    } catch (e) {
      log(`[vault] cannot identify on the proxy yet: ${e.message} — the profile still opens; unlock it once and it gets its own communication key`)
    }
  }
  /**
   * IDENTIFICARSE PUEDE FALLAR, Y ESO NO PUEDE TUMBAR EL PERFIL — NI QUEDARSE ASÍ.
   *
   * Esto era `await identify()` a secas, así que cualquier «no» del proxio subía por
   * `createTransport` hasta `startVault` y el perfil **no se abría en absoluto**: no es que
   * se quedara sin voz, es que cada petición contestaba `profile is not open` y en el
   * `status` el perfil salía sin huella. Y no se reintentaba nunca: `identify` solo vuelve a
   * correr con el evento `token`, o sea al RECONECTAR, y aquí el socket estaba perfectamente
   * conectado — lo que el proxio rechazó fue el sobre.
   *
   * El caso real (2026-09-10): esta máquina arranca con el reloj 35 minutos atrasado (el
   * `systemd-timesyncd` no contactó el servidor de hora hasta media hora después del
   * arranque), el proxio rechaza el `identify` con «ts fuera de la ventana ±5min» y la
   * bóveda se quedaba fuera de la red DESDE EL ARRANQUE HASTA QUE ALGUIEN LA REINICIABA.
   * Con ella fuera no hay a quién timbrar: el teléfono nunca recibía un pedido de
   * aprobación, y desde fuera eso se ve igual que «no hay pedidos».
   *
   * Reintentar con espera creciente lo arregla solo en cuanto el reloj se corrige, y cada
   * intento se dice en voz alta: una bóveda inalcanzable en silencio es el fallo que ya
   * costó un día entero (`CLAUDE.md`, el apagón del 1-2 de septiembre).
   */
  /**
   * EL ANUNCIO DE LA CUENTA (`temporary-access.md` §3.2).
   *
   * Quien entra con usuario y contraseña no tiene ninguna llave todavía: no sabe la pubkey
   * de esta bóveda y no puede escribirle. Lo único que trae es el código de la dirección
   * (`nombre@AB12-CD34-EF56`), y con él lista este canal para encontrar a quien atiende esa
   * cuenta — esta bóveda, o cualquiera de sus réplicas.
   *
   * Va PEGADO a `identify` y no en el arranque, porque la pertenencia a un canal es del
   * token, y el token cambia en cada reconexión: anunciarse una sola vez deja a la bóveda
   * fuera del canal en cuanto se cae el socket, y eso se ve desde fuera como «esa cuenta no
   * existe». Si el anuncio falla, la bóveda sigue sirviendo a todo lo demás y se dice en voz
   * alta: lo que se pierde es que la encuentren por su dirección, no que deje de funcionar.
   */
  let announcedAt = 0
  const announceAccount = async () => {
    if (!announce || !identified) return
    announcedAt = Date.now()
    try { await client.publish(announce) } catch (e) {
      log(`[vault] could not announce this account on the proxy (${e.message}) — a borrowed machine will not find this vault by its address`)
    }
  }

  /**
   * DESPIÉRTAME AQUÍ (una bóveda que no vive conectada, `lambda/`). Si la plataforma da una
   * URL, se registra en el proxio con la llave de comunicación y el acta, para que llame a esa
   * URL cuando llegue algo para la cuenta y no haya nadie suyo conectado. Va pegado a
   * `identify` por lo mismo que el anuncio: el acta puede haber cambiado. Si falla, se dice:
   * lo que se pierde es que la despierten, y eso no se puede callar.
   */
  const registerWake = async () => {
    if (!wakeUrl || !identified) return
    const comm = commKey?.pub?.() || null
    if (!comm || !seenActa) { log('[vault] cannot register the wake URL: no communication key in the record yet'); return }
    try {
      await client.registerWake({ publicKey: comm, sign: (d) => commKey.sign(d), url: wakeUrl, acta: seenActa, channel: announce || undefined })
      // Y POR SU PROPIA LLAVE. Lo dirigido a la cuenta solo la despierta si no hay nadie más
      // de la cuenta conectado; con otra bóveda encendida, nunca. La consola que elige ESTA
      // bóveda le escribe a su llave de comunicación (`vault` en el acta), y es por ella
      // por donde tiene que despertarse.
      await client.registerWake({ publicKey: comm, sign: (d) => commKey.sign(d), url: wakeUrl, acta: seenActa, self: true })
      log('[vault] wake URL registered on the proxy')
    } catch (e) {
      log(`[vault] could not register the wake URL (${e.code || ''} ${e.message}) — the proxy will not wake this vault`)
    }
  }

  let retry = null
  let failures = 0
  const identifyWithRetry = async () => {
    if (retry) { clearTimeout(retry); retry = null }
    try {
      await identify()
      await announceAccount()
      await registerWake()
      if (failures) log(`[vault] identified on the proxy after ${failures + 1} attempt(s)`)
      failures = 0
    } catch (e) {
      failures++
      const wait = Math.min(60000, 5000 * failures)
      log(`[vault] could not identify on the proxy (${e.message}) — retrying in ${Math.round(wait / 1000)}s; until then this vault is unreachable and cannot ring anyone`)
      retry = setTimeout(() => { retry = null; identifyWithRetry() }, wait)
      retry.unref?.()
    }
  }
  await identifyWithRetry()
  // Re-identificar al reconectar (el token cambia).
  client.on('token', () => { failures = 0; identifyWithRetry() })

  /**
   * QUE NO SE PUEDA VOLVER A QUEDAR MUDA.
   *
   * El 16 de septiembre esta bóveda se cayó del proxio y no volvió en 36 HORAS, con el
   * proceso vivo y sin una sola línea en el log: el cliente del transporte se rendía tras
   * un reintento fallido (arreglado en `@dotrino/proxy-client` 0.23.0). Desde fuera eso se
   * ve igual que «no pasa nada»: el teléfono no timbra y nadie sabe por qué.
   *
   * El arreglo del pilar quita ESA causa. Esto quita el SILENCIO, que es lo que costó las
   * 36 horas — con cualquier causa, futura incluida:
   *
   *   · se dice cuándo se cae y cuándo vuelve, una vez cada cosa (no una línea cada 4 s);
   *   · y si lleva 5 minutos fuera, se vuelve a marcar en vez de esperar sentada.
   *
   * `connect()` es seguro de repetir: si ya está conectado devuelve el token y no abre
   * nada.
   */
  const RECHECK_MS = recheckMs
  const PATIENCE_MS = patienceMs
  const REANNOUNCE_MS = reannounceMs   // la mitad de lo que el proxio guarda una entrada
  let downSince = 0
  let saidDown = false
  client.on('disconnect', ({ code, reason } = {}) => {
    // Sin socket no hay nadie atado al proxio: lo que se identificó era la conexión anterior.
    identified = false
    if (!downSince) downSince = Date.now()
    if (saidDown) return
    saidDown = true
    log(`[vault] off the proxy (${code || '?'}${reason ? ': ' + reason : ''}) — nobody can reach this vault while this lasts`)
  })
  // LOS INTENTOS SE VEN. El 2026-10-15 la bóveda pasó hora y media fuera y no quedó ni una
  // línea de si el transporte estaba reintentando o no; en el proxio no llegó ninguno. El
  // primero se dice, y luego uno de cada 15 (un minuto con el retardo de 4 s).
  client.on('reconnecting', (attempt) => {
    if (attempt === 1 || attempt % 15 === 0) log(`[vault] reconnecting to the proxy (attempt ${attempt})`)
  })
  client.on('reconnect_failed', (attempts) => {
    log(`[vault] the transport gave up reconnecting after ${attempts} attempt(s) — this vault is unreachable until it is restarted`)
  })
  const watchdog = setInterval(async () => {
    // CONECTADO DE VERDAD, no «tengo un token». El token es el de la última conexión y no se
    // borra al caerse, así que mirarlo daba la bóveda por vuelta con el socket cerrado: el
    // 2026-10-15 dijo «back on the proxy after 50s», no volvió a marcar nunca y pasó hora y
    // media fuera, avisando cada 10 minutos de que no podía anunciarse.
    if (identified && client.isConnected && client.token) {
      if (downSince) log(`[vault] back on the proxy after ${Math.round((Date.now() - downSince) / 1000)}s`)
      downSince = 0; saidDown = false
      // EL ANUNCIO CADUCA: el proxio borra una entrada de canal a los 20 minutos de publicada.
      // Sin renovarlo, entrar con usuario y contraseña solo funcionaba los primeros 20 minutos
      // tras identificarse, y desde fuera se veía como «no hay ninguna bóveda en esa dirección»
      // con la bóveda encendida (2026-10-12, la demo de los revisores).
      if (announce && Date.now() - announcedAt >= REANNOUNCE_MS) await announceAccount()
      return
    }
    if (!downSince) downSince = Date.now()
    const downMs = Date.now() - downSince
    if (downMs < PATIENCE_MS) return
    log(`[vault] ${Math.round(downMs / 60000)} min off the proxy — dialling again`)
    try { await client.connect() } catch (e) { log(`[vault] could not reconnect: ${e.message}`) }
    await identifyWithRetry()
  }, RECHECK_MS)
  watchdog.unref?.()

  return { client, token: client.token, identify: identifyWithRetry, isIdentified: () => identified, listen }
}
