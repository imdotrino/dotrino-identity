/**
 * Normaliza los alcances pedidos: solo los del catálogo, sin repetidos y en orden estable
 * (el cuerpo se firma canónicamente, así que el orden importa para no firmar dos cosas
 * distintas que dicen lo mismo).
 *
 * Pedir alcances desconocidos NO es un aviso que se pueda ignorar: se descartan, y si no
 * queda ninguno se emite el mínimo (`id:whoami`), que es lo que significa «solo quiero
 * saber quién eres».
 * @param {unknown} scopes
 * @returns {string[]}
 */
export function cleanScopes(scopes: unknown): string[];
/**
 * Las claves de datos que esos alcances permiten llevar.
 * @param {unknown} scopes
 * @returns {Set<string>}
 */
export function claimsAllowed(scopes: unknown): Set<string>;
/**
 * El cuerpo que se firma. Se construye AQUÍ y en un solo sitio, porque quien firma y quien
 * verifica tienen que estar mirando exactamente los mismos campos: si el emisor añadiera
 * uno que el verificador no reconstruye, la firma no cuadraría y el fallo aparecería como
 * «firma inválida», que manda a buscar al sitio equivocado.
 *
 * Lanza si le falta algo: es un error de programación de quien emite, no un dato del otro
 * lado que pueda venir mal.
 * @param {{ sub: string, aud: string, nonce: string, scopes?: unknown, claims?: Record<string, unknown> | null, iat: number, exp: number }} args
 */
export function assertionBody({ sub, aud, nonce, scopes, claims, iat, exp }: {
    sub: string;
    aud: string;
    nonce: string;
    scopes?: unknown;
    claims?: Record<string, unknown> | null;
    iat: number;
    exp: number;
}): {
    v: number;
    op: string;
    sub: string;
    aud: string;
    nonce: string;
    iat: number;
    exp: number;
    scopes: string[];
    claims: Record<string, unknown>;
};
/**
 * ¿Vale esta prueba, PARA MÍ y AHORA?
 *
 * `audience` y `nonce` los pone quien verifica, y son obligatorios: son las dos cosas que
 * él sabe y la prueba no puede inventar. Faltando cualquiera de las dos no se puede
 * juzgar, y decir «ok» sin haber comprobado es cómo un sobre de otro seguía entrando.
 *
 * Devuelve `{ ok:true, profileId, signer, seq, scopes, claims, aud, exp }` o
 * `{ ok:false, reason }`.
 */
/**
 * @param {any} assertion
 * @param {{ audience?: string, nonce?: string, expectedProfileId?: string|null, now?: number, maxSkewMs?: number }} [opts]
 */
export function verifyAssertion(assertion: any, opts?: {
    audience?: string;
    nonce?: string;
    expectedProfileId?: string | null;
    now?: number;
    maxSkewMs?: number;
}): Promise<{
    ok: boolean;
    reason: string;
    profileId?: undefined;
    signer?: undefined;
    seq?: undefined;
    scopes?: undefined;
    claims?: undefined;
    aud?: undefined;
    exp?: undefined;
} | {
    ok: boolean;
    profileId: string;
    signer: string;
    seq: number;
    scopes: any[];
    claims: any;
    aud: any;
    exp: any;
    reason?: undefined;
}>;
/**
 * ¿ESTE CONTENIDO FIRMADO VA DIRIGIDO A MÍ? La otra mitad del destinatario, y **no es lo
 * mismo que una prueba**: conviene tener claras las dos, porque confundirlas lleva a pedir
 * un reto donde no hay quien lo emita.
 *
 *   · **Prueba** (`verifyAssertion`) — autenticación INTERACTIVA: alguien me habla, yo le
 *     mando un reto y quiero saber quién es AHORA. Lleva `nonce` porque hay dos partes.
 *   · **Contenido dirigido** (esto) — un pin de geo, una atestación de reputación: se
 *     firma y se publica, sin nadie al otro lado que pueda dar un reto de antemano. Lo que
 *     falta ahí es `aud`, y solo `aud`: sin él, un pin firmado para geo lo acepta igual
 *     reputación.
 *
 * `aud` es obligatorio, como en la prueba. `exp` es OPCIONAL, y esa es la diferencia real:
 * lo publicado tiene su propia caducidad (el TTL del pin, la vigencia de la atestación) y
 * quien la lleva es el servicio; si el cuerpo trae `exp`, se respeta.
 */
/**
 * `ns`: el cajón del servicio que firma (su `cn` en el acta). Solo hace falta cuando lo
 * firmado viene de un SERVICIO de la cuenta y no de un aparato de la persona.
 *
 * @param {{ data?: any, signature?: string, publickey?: string, chain?: any[], audience?: string, expectedProfileId?: string|null, ns?: string|null, now?: number, maxSkewMs?: number }} [args]
 */
export function verifySignedFor(args?: {
    data?: any;
    signature?: string;
    publickey?: string;
    chain?: any[];
    audience?: string;
    expectedProfileId?: string | null;
    ns?: string | null;
    now?: number;
    maxSkewMs?: number;
}): Promise<{
    ok: boolean;
    reason: string;
    profileId?: undefined;
    signer?: undefined;
    seq?: undefined;
    aud?: undefined;
} | {
    ok: boolean;
    profileId: string;
    signer: string;
    seq: number;
    aud: any;
    reason?: undefined;
}>;
/**
 * LA OTRA MITAD DE `verifySignedFor`: firma una petición dirigida a un servicio (`aud`) con el
 * perfil activo, lista para mandarla. Es lo que usan las páginas que hablan con un servicio de
 * la cuenta sin sesiones ni cookies (el directorio de nombres, las cuentas de la bóveda
 * alojada): cada petición lleva su firma, la llave del aparato y la cadena de selladores que
 * prueba que ese aparato habla por la cuenta. Una vez aquí, y no copiado en cada página.
 *
 *   const req = await signedFor(identity, { aud: 'https://accounts.dotrino.com', fields: { v: 1, op: 'mine' } })
 *   → { body: { aud, iat, exp, nonce, v, op }, signature, publickey, chain }
 *
 * Sin cadena no hay petición: el servicio no podría saber de qué cuenta es, y mandarla igual
 * sería mandar algo que va a rechazar. Se para con `no-chain`.
 *
 * @param {{ signData: (d: object) => Promise<{ signature: string, publickey: string, chain?: any[] }> }} identity
 * @param {{ aud: string, fields?: object, ttlMs?: number, now?: number }} opts
 */
export function signedFor(identity: {
    signData: (d: object) => Promise<{
        signature: string;
        publickey: string;
        chain?: any[];
    }>;
}, { aud, fields, ttlMs, now }?: {
    aud: string;
    fields?: object;
    ttlMs?: number;
    now?: number;
}): Promise<{
    body: any;
    signature: string;
    publickey: string;
    chain: any[];
}>;
export const ASSERTION_V: 1;
/**
 * VIGENCIA. Corta a propósito: es lo que hace barata la revocación —no hay nada que
 * invalidar, solo se deja de renovar— y lo que limita el daño de una prueba interceptada.
 *
 * El tope lo comprueba también QUIEN RECIBE, no solo quien emite: fiarse de que el otro
 * puso un `exp` sensato es fiarse de la buena fe del que firma, y una prueba con un año de
 * vigencia es una credencial al portador.
 */
export const ASSERTION_MAX_TTL_MS: number;
export const ASSERTION_DEFAULT_TTL_MS: number;
/**
 * Tolerancia de reloj para `iat`. No es un repliegue: dos máquinas honestas difieren en
 * segundos, y sin margen una prueba recién firmada se rechazaría por venir «del futuro».
 * Solo afecta al arranque de la ventana; el vencimiento no se estira (ver §verify).
 */
export const ASSERTION_MAX_SKEW_MS: number;
/** Lo que se puede pedir. Lista CERRADA: lo que no está aquí no existe. */
export const SCOPES: readonly string[];
/**
 * Qué dato deja ver cada alcance. `id:whoami` no deja ver NINGUNO —es el mínimo: dice
 * quién eres y nada más— y por eso es la lista vacía y no una omisión.
 */
export const SCOPE_CLAIMS: Readonly<{
    'id:whoami': readonly any[];
    'profile:name': readonly string[];
    'profile:avatar': readonly string[];
    'profile:email': readonly string[];
    'profile:social': readonly string[];
}>;
export function newAssertionNonce(): `${string}-${string}-${string}-${string}-${string}`;
declare namespace _default {
    export { ASSERTION_V };
    export { ASSERTION_MAX_TTL_MS };
    export { ASSERTION_DEFAULT_TTL_MS };
    export { ASSERTION_MAX_SKEW_MS };
    export { SCOPES };
    export { SCOPE_CLAIMS };
    export { newAssertionNonce };
    export { cleanScopes };
    export { claimsAllowed };
    export { assertionBody };
    export { verifyAssertion };
    export { verifySignedFor };
    export { signedFor };
}
export default _default;
