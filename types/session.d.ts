/**
 * Normaliza los alcances pedidos: solo los del catálogo, sin repetidos y en orden estable.
 * @param {unknown} scopes
 * @returns {string[]}
 */
export function cleanSessionScopes(scopes: unknown): string[];
/**
 * El cuerpo que firma el aparato que respalda. Un solo sitio: quien firma y quien verifica miran lo mismo.
 * @param {{ sid: string, s: string, by: string, origin: string, scopes?: unknown, iat: number, exp: number }} args
 */
export function sessionBody({ sid, s, by, origin, scopes, iat, exp }: {
    sid: string;
    s: string;
    by: string;
    origin: string;
    scopes?: unknown;
    iat: number;
    exp: number;
}): {
    v: number;
    op: string;
    sid: string;
    s: string;
    by: string;
    origin: string;
    scopes: string[];
    iat: number;
    exp: number;
};
/**
 * Firma un papel de sesión. Lo llama el APARATO que respalda, con su propia llave.
 *
 * `sign` recibe el cuerpo y devuelve la firma (o el paquete del vault). No se le pasa la
 * privada: este módulo no toca llaves.
 * @param {{ sid: string, s: string, by: string, origin: string, scopes?: unknown, ttlMs?: number, now?: number }} args
 * @param {(body: object) => Promise<string | { signature?: string }>} sign
 */
export function signSession({ sid, s, by, origin, scopes, ttlMs, now }: {
    sid: string;
    s: string;
    by: string;
    origin: string;
    scopes?: unknown;
    ttlMs?: number;
    now?: number;
}, sign: (body: object) => Promise<string | {
    signature?: string;
}>): Promise<{
    sig: string;
    v: number;
    op: string;
    sid: string;
    s: string;
    by: string;
    origin: string;
    scopes: string[];
    iat: number;
    exp: number;
}>;
/**
 * ¿Vale este papel de sesión, AHORA?
 *
 * `chain` es la cadena de actas del perfil, y es obligatoria: sin ella no se puede saber si
 * el aparato que respalda sigue siendo de la casa —que es lo que hace que quitar un aparato
 * se lleve por delante sus sesiones—. Devuelve `{ ok, profileId, scopes, sid, exp }` o
 * `{ ok:false, reason }`.
 * @param {any} paper
 * @param {{ chain?: any, expectedProfileId?: string | null, origin?: string | null, now?: number, maxSkewMs?: number }} [opts]
 * @returns {Promise<{ ok: false, reason: string } | { ok: true, profileId: string, seq: number, sid: string, s: string, by: string, origin: string, scopes: string[], exp: number }>}
 */
export function verifySession(paper: any, { chain, expectedProfileId, origin, now, maxSkewMs }?: {
    chain?: any;
    expectedProfileId?: string | null;
    origin?: string | null;
    now?: number;
    maxSkewMs?: number;
}): Promise<{
    ok: false;
    reason: string;
} | {
    ok: true;
    profileId: string;
    seq: number;
    sid: string;
    s: string;
    by: string;
    origin: string;
    scopes: string[];
    exp: number;
}>;
/**
 * ¿Firmó ESTA SESIÓN esto, y podía?
 *
 * Es lo que llama quien recibe algo de una sesión: comprueba la firma de la llave de
 * sesión, el papel que la respalda y —si se pide— que el alcance cubra lo que se pretende.
 * @param {{ data?: unknown, signature?: unknown, session?: any, chain?: any, scope?: string | null, origin?: string | null, expectedProfileId?: string | null, now?: number }} [args]
 * @returns {Promise<{ ok: false, reason: string } | { ok: true, profileId: string, sid: string, scopes: string[], exp: number }>}
 */
export function verifySessionSigned({ data, signature, session, chain, scope, origin, expectedProfileId, now }?: {
    data?: unknown;
    signature?: unknown;
    session?: any;
    chain?: any;
    scope?: string | null;
    origin?: string | null;
    expectedProfileId?: string | null;
    now?: number;
}): Promise<{
    ok: false;
    reason: string;
} | {
    ok: true;
    profileId: string;
    sid: string;
    scopes: string[];
    exp: number;
}>;
export const SESSION_V: 1;
/** Cuánto dura una sesión. Horas, no meses: es un rato en un aparato que no es tuyo. */
export const SESSION_DEFAULT_TTL_MS: number;
export const SESSION_MAX_TTL_MS: number;
/** Tolerancia de reloj para el arranque (no para el vencimiento). */
export const SESSION_MAX_SKEW_MS: number;
/**
 * Lo que una sesión puede llegar a hacer. Lista CERRADA y corta a propósito: es lo de bajo
 * riesgo, lo que haría inviable la sesión si hubiera que preguntarle al teléfono cada vez.
 *
 *   · `id:whoami`      — decir quién eres (identificarse ante el transporte).
 *   · `vault:store`    — leer y escribir en el almacén del perfil, si el papel lo dice.
 *
 * Firmar POR LA PERSONA no está aquí, y es deliberado: eso se le pide al aparato que
 * respalda, que es quien tiene una llave que el acta reconoce.
 */
export const SESSION_SCOPES: readonly string[];
/**
 * Lo que una sesión NUNCA lleva, dijera lo que dijera el papel. Está aparte de la lista
 * blanca a propósito: si mañana alguien añade un alcance a `SESSION_SCOPES` sin pensarlo,
 * esto sigue cortando lo que no puede pasar.
 */
export const SESSION_FORBIDDEN: readonly string[];
export function newSessionId(): `${string}-${string}-${string}-${string}-${string}`;
declare namespace _default {
    export { SESSION_V };
    export { SESSION_DEFAULT_TTL_MS };
    export { SESSION_MAX_TTL_MS };
    export { SESSION_MAX_SKEW_MS };
    export { SESSION_SCOPES };
    export { SESSION_FORBIDDEN };
    export { newSessionId };
    export { cleanSessionScopes };
    export { sessionBody };
    export { signSession };
    export { verifySession };
    export { verifySessionSigned };
}
export default _default;
