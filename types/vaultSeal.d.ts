/** ¿Todavía se tolera el claro de la migración? */
/** @param {number} [now] @returns {boolean} */
export function plainAllowed(now?: number): boolean;
/**
 * Las llaves de comunicación de las bóvedas de la cuenta, según el acta.
 * @param {import('./acta.js').MaybeActa} acta
 * @returns {string[]}
 */
export function vaultKeysOf(acta: import("./acta.js").MaybeActa): string[];
/**
 * EL ACTA MÁS NUEVA QUE ENCADENA CON LA MÍA, de la copia que guarda el proxio
 * (`getActas`, websocket-proxy ≥ 1.10.0). Sin esto, un aparato con el acta atrasada le
 * sellaría a una llave de comunicación que la bóveda ya cambió, y la petición se perdería
 * en silencio: la bóveda no puede abrirla y no sabe de quién era.
 *
 * No se fía del proxio: cada acta tiene que verificarse y encadenar con la anterior aceptada
 * (`canAdopt`, la regla de siempre). Un proxio que no guarda actas (`no-acta-cache`) no es un
 * fallo: se sigue con la que ya se tenía, que es la verificada. Cualquier otro error se dice.
 * @param {any} client  un cliente de `@dotrino/proxy-client`
 * @param {import('./acta.js').MaybeActa} acta
 * @returns {Promise<import('./acta.js').MaybeActa>}
 */
export function latestActa(client: any, acta: import("./acta.js").MaybeActa): Promise<import("./acta.js").MaybeActa>;
/**
 * Manda `payload` a la bóveda SELLADO.
 *
 * @param {any} client  un cliente de `@dotrino/proxy-client` (o el local, `client.local`)
 * @param {object} o
 * @param {string} o.dest  a qué llave se enruta (la cuenta, o `to`)
 * @param {string|null} [o.to]  una bóveda concreta (su llave de comunicación): solo a ella
 * @param {import('./acta.js').MaybeActa} [o.acta]  el acta de la cuenta que este aparato ya aceptó: de ella (o de una
 *   más nueva que encadene con ella, `latestActa`) salen las bóvedas
 * @param {object} o.payload  `{ type, data, signature, cert }`
 * @param {boolean} [o.quiet]  no timbra a una bóveda dormida
 * @param {((line:string)=>void) | null} [o.warn]  dónde se dice que salió en claro (migración)
 * @param {number} [o.now]
 * @returns {Promise<{ sealed:number, why?:string }>}
 */
export function sendToVault(client: any, { dest, to, acta, payload, quiet, warn, now }: {
    dest: string;
    to?: string | null;
    acta?: import("./acta.js").MaybeActa;
    payload: object;
    quiet?: boolean;
    warn?: ((line: string) => void) | null;
    now?: number;
}): Promise<{
    sealed: number;
    why?: string;
}>;
/**
 * ¿Se acepta esta respuesta? Sellada, siempre. Por el socket local, siempre. En claro, solo
 * durante la migración, y se dice. Devuelve `false` para ignorarla.
 * @param {{ meta?: { sealed?: boolean } | null, local?: boolean, type?: string, warn?: ((line: string) => void) | null, now?: number }} args
 * @returns {boolean}
 */
export function acceptReply({ meta, local, type, warn, now }: {
    meta?: {
        sealed?: boolean;
    } | null;
    local?: boolean;
    type?: string;
    warn?: ((line: string) => void) | null;
    now?: number;
}): boolean;
export { VAULT_CN };
/** MIGRACIÓN: hasta cuándo se tolera hablar en claro con una bóveda vieja (2026-12-15 UTC). */
export const PLAIN_UNTIL: number;
export const PLAIN_UNTIL_TEXT: "2026-12-15";
import { VAULT_CN } from './acta.js';
