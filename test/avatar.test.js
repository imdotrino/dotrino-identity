/**
 * El identicon: el SVG y el canvas salen de la MISMA geometría (`_avatarModel`), así que
 * pintan las mismas celdas con los mismos colores.
 */
import test from 'node:test'
import assert from 'node:assert/strict'
import { avatarSvg, avatarPaint } from '../vault/avatar.js'

function fakeCtx () {
  const ops = []
  return {
    ops,
    set fillStyle (v) { ops.push(['fill', typeof v === 'string' ? v : 'gradient']) },
    beginPath () {}, fill () {}, arc () { ops.push(['arc']) },
    fillRect (x, y, w, h) { ops.push(['rect', x, y, w, h]) },
    createLinearGradient () { return { addColorStop (o, c) { ops.push(['stop', o, c]) } } },
  }
}

test('avatarPaint pinta las mismas celdas y colores que avatarSvg', () => {
  for (const seed of ['abc', 'MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE', '']) {
    const svg = avatarSvg(seed, { size: 100 })
    const ctx = fakeCtx()
    avatarPaint(ctx, seed, { size: 100 })
    const rects = ctx.ops.filter(o => o[0] === 'rect')
    assert.equal(rects.length, (svg.match(/<rect x=/g) || []).length)
    const fg = svg.match(/<g fill="([^"]+)"/)[1]
    assert.ok(ctx.ops.some(o => o[0] === 'fill' && o[1] === fg))
    const stops = [...svg.matchAll(/stop-color="([^"]+)"/g)].map(m => m[1])
    assert.deepEqual(ctx.ops.filter(o => o[0] === 'stop').map(o => o[2]), stops)
    // cada celda del canvas cae donde la del SVG, ya escalada (0.76) y desplazada (12 %)
    const svgCells = [...svg.matchAll(/<rect x="([\d.]+)" y="([\d.]+)"/g)].map(m => [+m[1] * 0.76 + 12, +m[2] * 0.76 + 12])
    rects.forEach((r, i) => { assert.ok(Math.abs(r[1] - svgCells[i][0]) < 0.05 && Math.abs(r[2] - svgCells[i][1]) < 0.05) })
  }
})
