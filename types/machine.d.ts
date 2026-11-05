/**
 * Lo deja en la forma de siempre, o `null` si no dice nada que valga. Nunca lanza: un aparato
 * viejo o raro no puede tumbar un emparejamiento por cómo describe su máquina.
 * @param {any} raw
 * @returns {{ kind: string, os: string, name: string } | null}
 */
export function cleanMachine(raw: any): {
    kind: string;
    os: string;
    name: string;
} | null;
/**
 * Una línea para enseñarlo: `node · Linux 7.0.0 · mi-pc`. Vacía si no hay nada.
 * @param {any} m
 * @returns {string}
 */
export function machineLine(m: any): string;
/**
 * La máquina de ESTE navegador. `env` se inyecta en las pruebas; en la página es `globalThis`.
 * Lo nativo se reconoce por el puente de `dotrino-native` (`DotrinoNative.platform()`), la
 * extensión por tener `chrome.runtime.id`, y el resto es un navegador.
 * @param {any} [env]
 */
export function browserMachine(env?: any): {
    kind: string;
    os: string;
    name: string;
};
/**
 * QUÉ MÁQUINA ES CADA APARATO: dónde corre, y nada más.
 *
 * En la lista de aparatos de la bóveda solo había un ID (`AB12-CD34`), una etiqueta que pone
 * el propio aparato —muchas veces el apodo del usuario, igual en todos— y la fecha de alta.
 * Con tres navegadores y dos agentes no había forma de saber cuál era cuál (dueño,
 * 2026-10-15). Esto es lo que lo distingue a simple vista:
 *
 *   · `kind` — qué es: `node` (un agente o un comando), `browser`, `extension`, `ios`, `android`.
 *   · `os`   — el sistema donde corre (`Linux 7.0.0`, `Windows`, `macOS`, `Android 14`).
 *   · `name` — en Node, el hostname; en un navegador, el navegador (`Chrome`). Un navegador no
 *     sabe el nombre de la máquina, y lo que no se sabe no se inventa.
 *
 * Lo DICE el aparato y va dentro de lo que firma, así que nadie más puede escribirlo por él.
 * Tampoco es una prueba de nada: un aparato puede llamarse como quiera. Sirve para reconocerlo,
 * no para decidir — ninguna puerta mira esto.
 *
 * Una sola pieza para las dos puntas: lo limpia igual quien lo manda y quien lo guarda (el acta,
 * la bóveda), para que un campo de más o una cadena de un megabyte no entren por ningún lado.
 */
export const MACHINE_KINDS: string[];
export function sameMachine(a: any, b: any): boolean;
declare namespace _default {
    export { MACHINE_KINDS };
    export { cleanMachine };
    export { machineLine };
    export { sameMachine };
    export { browserMachine };
}
export default _default;
