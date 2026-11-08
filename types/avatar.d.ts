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
export function avatarSvg(seed: unknown, { size }?: {
    size?: number;
}): string;
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
export function avatarPaint(ctx: {
    fillStyle: unknown;
    beginPath(): void;
    arc(x: number, y: number, r: number, a0: number, a1: number): void;
    fill(): void;
    fillRect(x: number, y: number, w: number, h: number): void;
    createLinearGradient(x0: number, y0: number, x1: number, y1: number): {
        addColorStop(o: number, c: string): void;
    };
}, seed: unknown, { size }?: {
    size?: number;
}): void;
/**
 * El avatar como data-URI listo para `<img src>` o `background-image`.
 * @param {unknown} seed
 * @param {{ size?: number }} [opts]
 * @returns {string}
 */
export function avatarDataUri(seed: unknown, opts?: {
    size?: number;
}): string;
