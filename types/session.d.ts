/** Normaliza los alcances pedidos: solo los del catálogo, sin repetidos y en orden estable. */
export function cleanSessionScopes(scopes: any): any[];
/** El cuerpo que firma el aparato que respalda. Un solo sitio: quien firma y quien verifica miran lo mismo. */
export function sessionBody({ sid, s, by, origin, scopes, iat, exp }: {
    sid: any;
    s: any;
    by: any;
    origin: any;
    scopes: any;
    iat: any;
    exp: any;
}): {
    v: number;
    op: string;
    sid: any;
    s: any;
    by: any;
    origin: any;
    scopes: any[];
    iat: any;
    exp: any;
};
/**
 * Firma un papel de sesión. Lo llama el APARATO que respalda, con su propia llave.
 *
 * `sign` recibe el cuerpo y devuelve la firma (o el paquete del vault). No se le pasa la
 * privada: este módulo no toca llaves.
 */
export function signSession({ sid, s, by, origin, scopes, ttlMs, now }: {
    sid: any;
    s: any;
    by: any;
    origin: any;
    scopes: any;
    ttlMs: any;
    now?: number;
}, sign: any): Promise<{
    sig: any;
    v: number;
    op: string;
    sid: any;
    s: any;
    by: any;
    origin: any;
    scopes: any[];
    iat: any;
    exp: any;
}>;
/**
 * ¿Vale este papel de sesión, AHORA?
 *
 * `chain` es la cadena de actas del perfil, y es obligatoria: sin ella no se puede saber si
 * el aparato que respalda sigue siendo de la casa —que es lo que hace que quitar un aparato
 * se lleve por delante sus sesiones—. Devuelve `{ ok, profileId, scopes, sid, exp }` o
 * `{ ok:false, reason }`.
 */
export function verifySession(paper: any, { chain, expectedProfileId, origin, now, maxSkewMs }?: {
    expectedProfileId?: any;
    origin?: any;
    now?: number;
    maxSkewMs?: number;
}): Promise<{
    ok: boolean;
    reason: string;
    profileId?: undefined;
    seq?: undefined;
    sid?: undefined;
    s?: undefined;
    by?: undefined;
    origin?: undefined;
    scopes?: undefined;
    exp?: undefined;
} | {
    ok: boolean;
    profileId: any;
    seq: any;
    sid: any;
    s: any;
    by: any;
    origin: any;
    scopes: any[];
    exp: any;
    reason?: undefined;
}>;
/**
 * ¿Firmó ESTA SESIÓN esto, y podía?
 *
 * Es lo que llama quien recibe algo de una sesión: comprueba la firma de la llave de
 * sesión, el papel que la respalda y —si se pide— que el alcance cubra lo que se pretende.
 */
export function verifySessionSigned({ data, signature, session, chain, scope, origin, expectedProfileId, now }?: {
    scope?: any;
    origin?: any;
    expectedProfileId?: any;
    now?: number;
}): Promise<{
    ok: boolean;
    reason: string;
    profileId?: undefined;
    seq?: undefined;
    sid?: undefined;
    s?: undefined;
    by?: undefined;
    origin?: undefined;
    scopes?: undefined;
    exp?: undefined;
} | {
    ok: boolean;
    profileId: any;
    seq: any;
    sid: any;
    s: any;
    by: any;
    origin: any;
    scopes: any[];
    exp: any;
    reason?: undefined;
} | {
    ok: boolean;
    profileId: any;
    sid: any;
    scopes: any[];
    exp: any;
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
