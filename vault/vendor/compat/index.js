/**
 * @dotrino/compat — QUÉ VERSIÓN ERES, Y SI PODEMOS TRABAJAR.
 *
 * EL PROBLEMA QUE VIENE A RESOLVER, dicho con los tres casos que costaron días:
 *
 *   · El apagón del 1-2 de septiembre: endurecer la bóveda dejó mudos a `content`, a los
 *     selladores y al bot social durante un día entero. Ningún fallo era un error: eran
 *     reintentos cada 60 segundos contra alguien que ya no les entendía.
 *   · `@dotrino/env` pedía `^0.33.2` con la librería en 0.60: enrolar contestaba
 *     `invalid cert: no-acta`, que es verdad y no es la causa. La causa era la versión.
 *   · La bóveda se quedó MUDA tres días porque su respuesta pasaba el tope del proxio: el
 *     socket moría con un 1009 y no lo decía nadie.
 *
 * Los tres son el mismo fallo: **una incompatibilidad se manifiesta como SILENCIO**. El
 * que llama no sabe si el otro está apagado, ocupado o hablando otro idioma, así que
 * reintenta para siempre — y el que atiende no sabe que le están hablando.
 *
 * Aquí no hay red, ni disco, ni cripto: son funciones puras. Decidir es de este módulo;
 * anunciar y refunfuñar es de quien lo usa. Y por eso no tiene dependencias — lo importan
 * los ~30 PWA, los daemons y el proxio, y un pilar dentro de otro se cuela anidado a cada
 * consumidor (ver `PENDIENTES.md`, «pilar anidado»).
 */

/** Lo que responde `check`. El `code` es lo que se compara; el texto puede cambiar. */
import { satisfies } from './ranges.js'

export const OK = 'ok'
export const INCOMPATIBLE_PROTOCOL = 'incompatible-protocol'
export const BROKEN_PEER = 'broken-peer'
export const UNDECLARED = 'undeclared'

/**
 * ESTO INFORMA, NO BLOQUEA (dueño, 2026-09-04, corrigiendo el punto 3 del mismo día:
 * *«quizás el aviso de incompatibilidad no debería ser bloqueante, pero sí visible»*).
 *
 * Y es mejor diseño, por cuatro razones que conviene tener escritas para no volver atrás:
 *
 *   · **No hay interruptor remoto.** Un aviso que solo informa se puede firmar y repartir
 *     sin que nadie pueda dejar a otro sin bóveda desde fuera.
 *   · **No hay trampa de orden.** Si bloqueara, el día que una pieza empieza a comprobar
 *     dejaría de hablar con todas las que aún no anuncian: habría que desplegar en un orden
 *     exacto. Informando se enciende donde sea y cuando sea.
 *   · **Falla del lado seguro.** Bloquear es código nuevo decidiendo si algo funciona: un
 *     rango mal escrito o una errata en un manifiesto pasaría de aviso falso a caída real.
 *   · **Es lo que dicen los tres incidentes.** En el apagón del 1-2 de septiembre, en el
 *     `^0.33.2` y en la bóveda muda, lo que faltó fue ENTERARSE, no parar. Parar no habría
 *     arreglado ninguno.
 *
 * Lo que se pierde y se dice: un par realmente incompatible sigue medio funcionando. Pero
 * medio funcionando **con un cartel que explica por qué** es otra cosa — y lo que no cuadra
 * falla solo, con el aviso pegado al error (`annotate`).
 *
 * Quien consuma esto **no debe** convertir un `compatible: false` en un «no atiendo». Si
 * algún día se decide bloquear, se decide arriba y se escribe allí, no aquí.
 */

/** ¿Tiene forma de anuncio? No dice si es compatible, solo si se puede juzgar. */
export function isDeclaration (d) {
  return !!d && typeof d.product === 'string' && d.product.length > 0 &&
    typeof d.version === 'string' && d.version.length > 0 &&
    Number.isInteger(d.protocol) &&
    Array.isArray(d.speaks) && d.speaks.length > 0 && d.speaks.every(Number.isInteger)
}

/** Lo que se pone en el sobre firmado de `identify`. Corto, porque viaja en cada conexión. */
export function declare ({ product, version, protocol, speaks }) {
  if (!Number.isInteger(protocol)) throw new Error('compat: protocol must be an integer')
  const habla = speaks && speaks.length ? [...new Set(speaks)].sort((a, b) => a - b) : [protocol]
  if (!habla.includes(protocol)) throw new Error('compat: speaks must include protocol')
  const d = { product: String(product), version: String(version), protocol, speaks: habla }
  if (!isDeclaration(d)) throw new Error('compat: incomplete declaration')
  return d
}

/**
 * ¿ESTE PAR ESTÁ EN LA LISTA DE ROTAS?
 *
 * `versions` acepta lo mismo que un rango del manifiesto (`ranges.js`): una versión
 * exacta, un `>=`, un intervalo `a - b`, o una lista que es un O. El dueño pidió rangos
 * para los manifiestos (2026-09-04) y aquí se usa el MISMO comparador, no otro: dos formas
 * de decir «esta versión entra» acaban discrepando, y esa discrepancia no hace ruido.
 *
 * Lo que no se entiende no coincide — no marca roto y tampoco absuelve: solo no dice nada.
 */
export function isBroken (lista, { product, version }) {
  for (const b of lista || []) {
    if (b?.product !== product) continue
    if (satisfies(version, b.versions)) return b
  }
  return null
}

/**
 * ¿ESTA PAREJA CUADRA?
 *
 * Devuelve un DICTAMEN, no un permiso: `compatible` dice si cuadran, y nadie debe usarlo
 * para dejar de atender (ver arriba). Se enseña, se registra y se le pega a los errores.
 *
 * **JUZGA EL QUE ENTRA** (dueño, 2026-09-04): *«el que define si es compatible o no es la
 * versión que entra, ya que la versión antigua de un producto no tiene idea con qué es o no
 * compatible»*. Exacto: una build de hace tres meses no sabe nada de lo que vino después.
 * Así que esto NO es simétrico — miro si YO te entiendo y si TÚ estás en mi lista de rotas;
 * lo que tú creas de mí no entra en la cuenta.
 *
 * Y de ahí sale por qué avisar es la otra mitad: si el viejo no puede juzgar, tampoco puede
 * enterarse solo. El que ve la incompatibilidad es el único que puede decírselo.
 *
 * @param {object} o.mine     mi declaración
 * @param {object} o.theirs   la del otro (o null si no dijo nada)
 * @param {Array}  [o.broken] mi lista de rotas (la del código más la del aviso de la red)
 * @returns {{compatible:boolean, code:string, reason:string, peer:object|null}}
 */
export function check ({ mine, theirs, broken = [] } = {}) {
  if (!isDeclaration(mine)) throw new Error('compat: my own declaration is not valid')

  if (!isDeclaration(theirs)) {
    return {
      compatible: false,
      code: UNDECLARED,
      peer: null,
      reason: 'the other side does not say what it is or which version it runs'
    }
  }

  const roto = isBroken(broken, theirs)
  if (roto) {
    return {
      compatible: false,
      code: BROKEN_PEER,
      peer: theirs,
      reason: `${theirs.product} ${theirs.version} is known to be broken: ${roto.why || 'no reason recorded'}` +
        (roto.fix ? ` — ${roto.fix}` : '')
    }
  }

  if (!mine.speaks.includes(theirs.protocol)) {
    return {
      compatible: false,
      code: INCOMPATIBLE_PROTOCOL,
      peer: theirs,
      reason: `${mine.product} ${mine.version} speaks protocol ${mine.speaks.join(', ')} and ` +
        `${theirs.product} ${theirs.version} speaks ${theirs.protocol}: update ${theirs.product}`
    }
  }

  return { compatible: true, code: OK, peer: theirs, reason: '' }
}

/**
 * PEGA EL AVISO AL ERROR QUE YA OCURRE, y esto es lo que de verdad ahorra el día perdido.
 *
 * El caso real: `@dotrino/env` pedía `^0.33.2` con la librería en 0.60, y enrolar contestaba
 * `invalid cert: no-acta`. Es verdad y no es la causa — la causa era la versión, y encontrarlo
 * costó horas. Con esto el mismo error sale:
 *
 *   invalid cert: no-acta — heads up: vault 0.33.2 against vaultd 0.106.2 …
 *
 * El mensaje original no se toca: se le añade detrás. Nadie que empareje por texto se rompe
 * si compara por prefijo, y quien compare por `code` no se entera (ver «los errores son un
 * contrato»).
 */
export function annotate (message, verdict) {
  if (!verdict || verdict.compatible !== false) return message
  return `${message} — heads up: ${verdict.reason}`
}

/**
 * EL AVISO QUE SE MANDA CUANDO NO SE PUEDE TRABAJAR (punto 3 del dueño: «se comunican,
 * pero solo para alertar la incompatibilidad»).
 *
 * Lleva las dos declaraciones porque el que lo recibe suele ser el que NO sabe que está
 * roto —es el viejo—, así que hay que decirle qué es él, qué somos nosotros y qué hacer.
 * Sin esto el rechazo sería otro silencio, que es de lo que venimos huyendo.
 */
export function incompatibleNotice ({ mine, theirs, verdict }) {
  return {
    op: 'incompatible',
    code: verdict.code,
    reason: verdict.reason,
    mine: { product: mine.product, version: mine.version, protocol: mine.protocol, speaks: mine.speaks },
    yours: theirs && isDeclaration(theirs)
      ? { product: theirs.product, version: theirs.version, protocol: theirs.protocol }
      : null,
    fix: 'update the older side; nothing here will work until the two versions match'
  }
}

export default { declare, check, isBroken, isDeclaration, incompatibleNotice, annotate, OK, INCOMPATIBLE_PROTOCOL, BROKEN_PEER, UNDECLARED }
