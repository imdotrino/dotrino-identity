/**
 * El código corto que el humano compara. Seis dígitos, como el del emparejamiento.
 * @param {unknown} sid
 * @returns {string}
 */
export function sessionCode(sid: unknown): string;
/**
 * Lo que viaja en el QR. Corto a propósito: un QR más denso se lee peor con poca luz, que
 * es justo cuando alguien intenta entrar desde un aparato prestado.
 * @param {{ sid: string, s: string, encPub?: string, origin: string, scopes?: unknown, proxy?: string }} args
 * @returns {SessionInvite}
 */
export function buildInvite({ sid, s, encPub, origin, scopes, proxy }: {
    sid: string;
    s: string;
    encPub?: string;
    origin: string;
    scopes?: unknown;
    proxy?: string;
}): SessionInvite;
/**
 * Lee una invitación, venga del QR o pegada a mano. `null` si no es una.
 * @param {unknown} raw
 * @returns {SessionInvite | null}
 */
export function parseInvite(raw: unknown): SessionInvite | null;
/**
 * LADO DEL QUE ENTRA. Genera la sesión, publica la invitación y espera el papel.
 *
 * `transport` es un cliente ya conectado e identificado bajo la llave de sesión (`s`): así
 * el aparato que responde puede escribirle por pubkey. `onInvite` recibe lo que hay que
 * enseñar —la invitación y el código— para que la app pinte el QR con `@dotrino/qr`.
 *
 * Devuelve `{ paper, chain, profileId }` cuando alguien concede, o lanza si se deniega o
 * se agota la espera. No guarda nada: dónde vive la sesión lo decide quien llama.
 * @param {{ transport: SessionTransport, sessionPubkey: string, encPub?: string, origin: string, scopes?: unknown, onInvite?: (i: { invite: SessionInvite, code: string, qr: string }) => void, timeoutMs?: number, sid?: string }} args
 * @returns {Promise<{ paper: any, chain: any, profileId: string, sid: string, scopes: string[], exp: number }>}
 */
export function openSession({ transport, sessionPubkey, encPub, origin, scopes, onInvite, timeoutMs, sid }?: {
    transport: SessionTransport;
    sessionPubkey: string;
    encPub?: string;
    origin: string;
    scopes?: unknown;
    onInvite?: (i: {
        invite: SessionInvite;
        code: string;
        qr: string;
    }) => void;
    timeoutMs?: number;
    sid?: string;
}): Promise<{
    paper: any;
    chain: any;
    profileId: string;
    sid: string;
    scopes: string[];
    exp: number;
}>;
/**
 * LADO DEL QUE RESPALDA. Firma el papel y se lo manda al que espera.
 *
 * `sign` firma con la llave de ESTE aparato (la que el acta nombra) y `chain` es la cadena
 * del perfil: las dos cosas viajan juntas porque por separado no sirven.
 *
 * `scopes` acota lo que se concede: por omisión, lo que pidió la invitación. Quien llama
 * puede recortarlo —nunca ampliarlo, que de eso ya se encarga `verifySession`.
 * @param {{ transport: SessionTransport, invite: unknown, by: string, sign: (body: object) => Promise<string | { signature?: string }>, chain: any[], scopes?: unknown, ttlMs?: number, now?: number }} args
 */
export function grantSession({ transport, invite, by, sign, chain, scopes, ttlMs, now }?: {
    transport: SessionTransport;
    invite: unknown;
    by: string;
    sign: (body: object) => Promise<string | {
        signature?: string;
    }>;
    chain: any[];
    scopes?: unknown;
    ttlMs?: number;
    now?: number;
}): Promise<{
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
 * Decir que no, en vez de dejar al otro mirando una pantalla que no avanza.
 * @param {{ transport: SessionTransport, invite: unknown }} args
 */
export function denySession({ transport, invite }?: {
    transport: SessionTransport;
    invite: unknown;
}): Promise<void>;
/**
 * CERRARLA. Se avisa a la sesión para que se borre en el acto; lo que la corta de verdad es
 * que el papel vence y nadie lo renueva —y que quitar el aparato se lleva todos los suyos.
 * @param {{ transport: SessionTransport, sessionPubkey: string, encPub?: string, sid: string }} args
 */
export function closeSession({ transport, sessionPubkey, encPub, sid }?: {
    transport: SessionTransport;
    sessionPubkey: string;
    encPub?: string;
    sid: string;
}): Promise<void>;
/**
 * Lo que se usa del transporte (`@dotrino/proxy-client`).
 * @typedef {{ url?: string, on (event: string, handler: (...args: any[]) => void): () => void,
 *   sendByPubkey (to: string | string[], payload: any): void,
 *   sendSealed? (to: string[], payload: any, opts: { peerEncPub: string }): Promise<void> }} SessionTransport
 */
/**
 * Una invitación a abrir sesión (lo que va en el QR).
 * @typedef {{ v: number, t: string, sid: string, s: string, encPub?: string, origin: string, scopes: string[], proxy?: string }} SessionInvite
 */
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
/**
 * Lo que se usa del transporte (`@dotrino/proxy-client`).
 */
export type SessionTransport = {
    url?: string;
    on(event: string, handler: (...args: any[]) => void): () => void;
    sendByPubkey(to: string | string[], payload: any): void;
    sendSealed?(to: string[], payload: any, opts: {
        peerEncPub: string;
    }): Promise<void>;
};
/**
 * Una invitación a abrir sesión (lo que va en el QR).
 */
export type SessionInvite = {
    v: number;
    t: string;
    sid: string;
    s: string;
    encPub?: string;
    origin: string;
    scopes: string[];
    proxy?: string;
};
