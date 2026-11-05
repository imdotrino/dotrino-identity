/** ¿Todavía se tolera el claro de la migración? */
export function plainAllowed(now?: number): boolean;
/** Las llaves de comunicación de las bóvedas de la cuenta, según el acta. */
export function vaultKeysOf(acta: any): any[];
/**
 * EL ACTA MÁS NUEVA QUE ENCADENA CON LA MÍA, de la copia que guarda el proxio
 * (`getActas`, websocket-proxy ≥ 1.10.0). Sin esto, un aparato con el acta atrasada le
 * sellaría a una llave de comunicación que la bóveda ya cambió, y la petición se perdería
 * en silencio: la bóveda no puede abrirla y no sabe de quién era.
 *
 * No se fía del proxio: cada acta tiene que verificarse y encadenar con la anterior aceptada
 * (`canAdopt`, la regla de siempre). Un proxio que no guarda actas (`no-acta-cache`) no es un
 * fallo: se sigue con la que ya se tenía, que es la verificada. Cualquier otro error se dice.
 */
export function latestActa(client: any, acta: any): Promise<any>;
/**
 * Manda `payload` a la bóveda SELLADO.
 *
 * @param {any} client  un cliente de `@dotrino/proxy-client` (o el local, `client.local`)
 * @param {object} o
 * @param {string} o.dest  a qué llave se enruta (la cuenta, o `to`)
 * @param {string|null} [o.to]  una bóveda concreta (su llave de comunicación): solo a ella
 * @param {object|null} [o.acta]  el acta de la cuenta que este aparato ya aceptó: de ella (o de una
 *   más nueva que encadene con ella, `latestActa`) salen las bóvedas
 * @param {object} o.payload  `{ type, data, signature, cert }`
 * @param {boolean} [o.quiet]  no timbra a una bóveda dormida
 * @param {(line:string)=>void} [o.warn]  dónde se dice que salió en claro (migración)
 * @param {number} [o.now]
 * @returns {Promise<{ sealed:number, why?:string }>}
 */
export function sendToVault(client: any, { dest, to, acta, payload, quiet, warn, now }: {
    dest: string;
    to?: string | null;
    acta?: object | null;
    payload: object;
    quiet?: boolean;
    warn?: (line: string) => void;
    now?: number;
}): Promise<{
    sealed: number;
    why?: string;
}>;
/**
 * ¿Se acepta esta respuesta? Sellada, siempre. Por el socket local, siempre. En claro, solo
 * durante la migración, y se dice. Devuelve `false` para ignorarla.
 */
export function acceptReply({ meta, local, type, warn, now }: {
    meta: any;
    local?: boolean;
    type?: string;
    warn?: any;
    now?: number;
}): boolean;
export { VAULT_CN };
/** MIGRACIÓN: hasta cuándo se tolera hablar en claro con una bóveda vieja (2026-12-15 UTC). */
export const PLAIN_UNTIL: number;
export const PLAIN_UNTIL_TEXT: "2026-12-15";
import { VAULT_CN } from './acta.js';
