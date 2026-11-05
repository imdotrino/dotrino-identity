/** El código corto que el humano compara. Seis dígitos, como el del emparejamiento. */
export function sessionCode(sid: any): string;
/**
 * Lo que viaja en el QR. Corto a propósito: un QR más denso se lee peor con poca luz, que
 * es justo cuando alguien intenta entrar desde un aparato prestado.
 */
export function buildInvite({ sid, s, encPub, origin, scopes, proxy }: {
    sid: any;
    s: any;
    encPub: any;
    origin: any;
    scopes: any;
    proxy: any;
}): {
    v: number;
    t: string;
    sid: any;
    s: any;
    encPub: any;
    origin: any;
    scopes: any[];
    proxy: any;
};
/** Lee una invitación, venga del QR o pegada a mano. `null` si no es una. */
export function parseInvite(raw: any): any;
/**
 * LADO DEL QUE ENTRA. Genera la sesión, publica la invitación y espera el papel.
 *
 * `transport` es un cliente ya conectado e identificado bajo la llave de sesión (`s`): así
 * el aparato que responde puede escribirle por pubkey. `onInvite` recibe lo que hay que
 * enseñar —la invitación y el código— para que la app pinte el QR con `@dotrino/qr`.
 *
 * Devuelve `{ paper, chain, profileId }` cuando alguien concede, o lanza si se deniega o
 * se agota la espera. No guarda nada: dónde vive la sesión lo decide quien llama.
 */
export function openSession({ transport, sessionPubkey, encPub, origin, scopes, onInvite, timeoutMs, sid }?: {
    timeoutMs?: number;
    sid?: `${string}-${string}-${string}-${string}-${string}`;
}): Promise<any>;
/**
 * LADO DEL QUE RESPALDA. Firma el papel y se lo manda al que espera.
 *
 * `sign` firma con la llave de ESTE aparato (la que el acta nombra) y `chain` es la cadena
 * del perfil: las dos cosas viajan juntas porque por separado no sirven.
 *
 * `scopes` acota lo que se concede: por omisión, lo que pidió la invitación. Quien llama
 * puede recortarlo —nunca ampliarlo, que de eso ya se encarga `verifySession`.
 */
export function grantSession({ transport, invite, by, sign, chain, scopes, ttlMs, now }?: {
    ttlMs?: number;
    now?: number;
}): Promise<{
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
/** Decir que no, en vez de dejar al otro mirando una pantalla que no avanza. */
export function denySession({ transport, invite }?: {}): Promise<void>;
/**
 * CERRARLA. Se avisa a la sesión para que se borre en el acto; lo que la corta de verdad es
 * que el papel vence y nadie lo renueva —y que quitar el aparato se lleva todos los suyos.
 */
export function closeSession({ transport, sessionPubkey, encPub, sid }?: {}): Promise<void>;
export const SESSION_OP: Readonly<{
    GRANT: "session.grant";
    DENY: "session.deny";
    CLOSE: "session.close";
}>;
declare namespace _default {
    export { SESSION_OP };
    export { sessionCode };
    export { buildInvite };
    export { parseInvite };
    export { openSession };
    export { grantSession };
    export { denySession };
    export { closeSession };
}
export default _default;
