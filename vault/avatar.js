/**
 * @dotrino/identity/avatar — el AVATAR identicon, solo.
 *
 * Vive aparte de `capabilities.js` a propósito: es una función pura de ~30
 * líneas, sin dependencias, sin crypto y sin vault, pero `capabilities.js`
 * importa `core.js` (55 KB) y `core.js` importa de vuelta `capabilities.js`
 * (dependencia circular). O sea que quien solo quería el identicon —el topbar,
 * la tarjeta de perfil— se arrastraba el vault entero, o dependía de que el
 * bundler podara `core.js` de milagro (ningún paquete declara `sideEffects`).
 *
 * Este subpath da la garantía: importar el avatar cuesta el avatar.
 *
 * NO copies estas funciones dentro de tu app. El identicon es DETERMINISTA a
 * partir del pubkey: si cada app llevara su copia, el mismo usuario podría
 * derivar un avatar distinto según dónde lo miren.
 *
 * `capabilities.js` re-exporta de aquí, así que los importadores viejos siguen
 * funcionando igual.
 */

/** Hash FNV-1a + xorshift. Sin necesidades de seguridad: es decorativo. */
/** @param {string} s @returns {{ h: number, bytes: number[] }} */
function _hashSeed (s) {
  let h = 2166136261 >>> 0
  for (let i = 0; i < s.length; i++) { h ^= s.charCodeAt(i); h = Math.imul(h, 16777619) }
  /** @type {number[]} */
  const bytes = []
  let x = (h ^ 0x9e3779b9) >>> 0
  for (let i = 0; i < 16; i++) { x ^= x << 13; x ^= x >>> 17; x ^= x << 5; x >>>= 0; bytes.push(x & 0xff) }
  return { h: h >>> 0, bytes }
}

/**
 * La GEOMETRÍA del identicon: colores y celdas de la rejilla 5×5. Es la única fuente: el SVG
 * y el canvas (`avatarPaint`) se dibujan de aquí, así que no pueden salir distintos.
 *
 * @param {unknown} seed
 * @returns {{ h: number, fg: string, bg1: string, bg2: string, cells: Array<[number, number]> }}
 *   `cells`: pares `[columna, fila]` encendidos, en una rejilla de 5×5.
 */
function _avatarModel (seed) {
  const { h, bytes } = _hashSeed(String(seed || 'dotrino'))
  const hue = h % 360
  const hue2 = (hue + 40) % 360
  /** @type {Array<[number, number]>} */
  const cells = []
  for (let col = 0; col < 3; col++) {
    for (let row = 0; row < 5; row++) {
      if (!(bytes[col * 5 + row] & 1)) continue
      for (const c of (col === 2 ? [2] : [col, 4 - col])) cells.push([c, row])
    }
  }
  return { h, fg: `hsl(${hue} 62% 46%)`, bg1: `hsl(${hue} 48% 95%)`, bg2: `hsl(${hue2} 48% 90%)`, cells }
}

/**
 * Identicon determinista de una semilla (normalmente el pubkey): así cada perfil
 * nace con imagen sin que el usuario tenga que subir nada. Síncrono → usable
 * directo en plantillas. Rejilla 5×5 simétrica sobre una "moneda" redondeada,
 * con color derivado del hash.
 *
 * @param {unknown} seed
 * @param {{ size?: number }} [opts]
 * @returns {string}
 */
export function avatarSvg (seed, { size = 80 } = {}) {
  const { h, fg, bg1, bg2, cells } = _avatarModel(seed)
  const unit = size / 5
  let rects = ''
  for (const [c, row] of cells) {
    rects += `<rect x="${(c * unit).toFixed(2)}" y="${(row * unit).toFixed(2)}" width="${unit.toFixed(2)}" height="${unit.toFixed(2)}"/>`
  }
  const id = 'g' + (h % 100000)
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${size} ${size}" width="${size}" height="${size}">` +
    `<defs><linearGradient id="${id}" x1="0" y1="0" x2="1" y2="1"><stop offset="0" stop-color="${bg1}"/><stop offset="1" stop-color="${bg2}"/></linearGradient></defs>` +
    `<rect width="${size}" height="${size}" rx="${(size * 0.5).toFixed(2)}" fill="url(#${id})"/>` +
    `<g fill="${fg}" transform="translate(${(size * 0.12).toFixed(2)} ${(size * 0.12).toFixed(2)}) scale(0.76)">${rects}</g></svg>`
}

/**
 * El mismo identicon, pintado en un canvas 2D (`CanvasRenderingContext2D` u
 * `OffscreenCanvasRenderingContext2D`). Existe para donde no se puede rasterizar un SVG:
 * un service worker no decodifica `image/svg+xml`, y el icono de una extensión
 * (`chrome.action.setIcon`) pide píxeles. Pinta en `[0, size]` desde el origen.
 *
 * @param {{ fillStyle: unknown, beginPath (): void, arc (x: number, y: number, r: number, a0: number, a1: number): void, fill (): void, fillRect (x: number, y: number, w: number, h: number): void, createLinearGradient (x0: number, y0: number, x1: number, y1: number): { addColorStop (o: number, c: string): void } }} ctx
 * @param {unknown} seed
 * @param {{ size?: number }} [opts]
 */
export function avatarPaint (ctx, seed, { size = 80 } = {}) {
  const { fg, bg1, bg2, cells } = _avatarModel(seed)
  const grad = ctx.createLinearGradient(0, 0, size, size)
  grad.addColorStop(0, bg1)
  grad.addColorStop(1, bg2)
  ctx.fillStyle = grad
  ctx.beginPath()
  ctx.arc(size / 2, size / 2, size / 2, 0, Math.PI * 2)
  ctx.fill()
  ctx.fillStyle = fg
  const unit = (size / 5) * 0.76
  const off = size * 0.12
  for (const [c, row] of cells) ctx.fillRect(off + c * unit, off + row * unit, unit, unit)
}

/**
 * El avatar como data-URI listo para `<img src>` o `background-image`.
 * @param {unknown} seed
 * @param {{ size?: number }} [opts]
 * @returns {string}
 */
export function avatarDataUri (seed, opts) {
  return 'data:image/svg+xml,' + encodeURIComponent(avatarSvg(seed, opts))
}
