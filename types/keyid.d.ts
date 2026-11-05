/**
 * id corto y estable de un pubkey (sha-256 hex de los campos canónicos del JWK).
 * @param {string | JsonWebKey} publicJwkStr
 * @returns {Promise<string>}
 */
export function pubkeyId(publicJwkStr: string | JsonWebKey): Promise<string>;
/**
 * La huella que SÍ se le enseña a una persona: `AB12-CD34`. Corta, comparable de un vistazo
 * y la misma en todo el ecosistema (emparejamiento, acta, lista de dispositivos).
 *
 * @param {string | JsonWebKey | null | undefined} publicJwkStr
 * @returns {Promise<string>}
 */
export function keyLabel(publicJwkStr: string | JsonWebKey | null | undefined): Promise<string>;
declare namespace _default {
    export { pubkeyId };
    export { keyLabel };
}
export default _default;
