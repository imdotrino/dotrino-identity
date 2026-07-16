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
function _hashSeed (s) {
  let h = 2166136261 >>> 0
  for (let i = 0; i < s.length; i++) { h ^= s.charCodeAt(i); h = Math.imul(h, 16777619) }
  const bytes = []
  let x = (h ^ 0x9e3779b9) >>> 0
  for (let i = 0; i < 16; i++) { x ^= x << 13; x ^= x >>> 17; x ^= x << 5; x >>>= 0; bytes.push(x & 0xff) }
  return { h: h >>> 0, bytes }
}

/**
 * Identicon determinista de una semilla (normalmente el pubkey): así cada perfil
 * nace con imagen sin que el usuario tenga que subir nada. Síncrono → usable
 * directo en plantillas. Rejilla 5×5 simétrica sobre una "moneda" redondeada,
 * con color derivado del hash.
 */
export function avatarSvg (seed, { size = 80 } = {}) {
  const { h, bytes } = _hashSeed(String(seed || 'dotrino'))
  const hue = h % 360
  const hue2 = (hue + 40) % 360
  const fg = `hsl(${hue} 62% 46%)`
  const bg1 = `hsl(${hue} 48% 95%)`
  const bg2 = `hsl(${hue2} 48% 90%)`
  const cells = 5
  const unit = size / cells
  let rects = ''
  for (let col = 0; col < 3; col++) {
    for (let row = 0; row < cells; row++) {
      if (!(bytes[col * cells + row] & 1)) continue
      for (const c of (col === 2 ? [2] : [col, cells - 1 - col])) {
        rects += `<rect x="${(c * unit).toFixed(2)}" y="${(row * unit).toFixed(2)}" width="${unit.toFixed(2)}" height="${unit.toFixed(2)}"/>`
      }
    }
  }
  const id = 'g' + (h % 100000)
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${size} ${size}" width="${size}" height="${size}">` +
    `<defs><linearGradient id="${id}" x1="0" y1="0" x2="1" y2="1"><stop offset="0" stop-color="${bg1}"/><stop offset="1" stop-color="${bg2}"/></linearGradient></defs>` +
    `<rect width="${size}" height="${size}" rx="${(size * 0.5).toFixed(2)}" fill="url(#${id})"/>` +
    `<g fill="${fg}" transform="translate(${(size * 0.12).toFixed(2)} ${(size * 0.12).toFixed(2)}) scale(0.76)">${rects}</g></svg>`
}

/** El avatar como data-URI listo para `<img src>` o `background-image`. */
export function avatarDataUri (seed, opts) {
  return 'data:image/svg+xml,' + encodeURIComponent(avatarSvg(seed, opts))
}
