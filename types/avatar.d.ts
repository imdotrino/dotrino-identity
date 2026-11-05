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
 * El avatar como data-URI listo para `<img src>` o `background-image`.
 * @param {unknown} seed
 * @param {{ size?: number }} [opts]
 * @returns {string}
 */
export function avatarDataUri(seed: unknown, opts?: {
    size?: number;
}): string;
