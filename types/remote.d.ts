/**
 * Un aparato enrolado: su llave (en JWK, CryptoKey o un firmador externo) y su máquina.
 * @typedef {{ publickey: string, privateJwk?: JsonWebKey, privateKey?: import('./capabilities.js').SigningKey | null,
 *   sign?: (text: string) => Promise<string>, machine?: any, label?: string, deviceId?: string }} DeviceKey
 */
/**
 * Lo que se usa del cliente del proxio (`@dotrino/proxy-client`), o del local que imita su forma.
 * @typedef {{ local?: boolean, token?: string | null,
 *   on (event: string, fn: (from: string, payload: any, meta?: any) => void): () => unknown,
 *   send? (to: string, payload: any): void,
 *   sendByPubkey (to: string | string[], payload: any, opts?: any): void,
 *   identify? (envelope: { data: any, signature: string, cert?: any, acta?: any }): Promise<any>,
 *   connect? (): Promise<unknown>, identifyAs? (args: any): Promise<unknown>,
 *   redeemPairingCode? (code: string): Promise<any>,
 *   close (): void }} VaultClient
 */
/**
 * Con qué se habla con la bóveda emparejada.
 * @typedef {{ master: string, proxy: string, device: DeviceKey, cert: any, acta?: any,
 *   onRevoked?: (() => void) | null, timeoutMs?: number, to?: string | null }} PairingContext
 */
/**
 * ¿Es AUTÉNTICO este `vault.revoked`? Solo lo es si va firmado por la maestra PINEADA al
 * emparejar, es para ESTE dispositivo y no ha caducado. Es la única puerta al autoborrado:
 * un `vault.error` con la palabra «revocado» no borra nada (cierra el wipe-DoS, ver
 * `dotrino-vault/docs/pairing-protocol.md §2.3`).
 * @param {{ body: any, signature: unknown, master: string, devicePubkey: string, currentNonce?: string | null }} args
 * @returns {Promise<boolean>}
 */
export function isAuthenticRevoke({ body, signature, master, devicePubkey, currentNonce }: {
    body: any;
    signature: unknown;
    master: string;
    devicePubkey: string;
    currentNonce?: string | null;
}): Promise<boolean>;
/**
 * @param {Object} opts
 * @param {{v?:number, iss?:string, proxy?:string, token?:string, sn:string, conn?:string, acct?:string, m?:any}} opts.qr  QR v2 del vault.
 * @param {(c:{deviceId:string, code:string})=>void} [opts.onChallenge]  Para mostrar el código a tipear en el PC.
 * @param {string[] | null} [opts.requireCaps]  permisos del acta sin los que este aparato no entra (`sealer`
 *   para una bóveda): si la invitación no los da, se para antes del código (`missing-caps`).
 * @param {string} [opts.label]
 * @param {number} [opts.approveTimeoutMs]  Espera de la aprobación humana (def 3 min).
 * @param {string | null} [opts.account]  si viene (`pubkeyId` del perfil, 64 hex), SOLO entra en esa cuenta:
 *   se comprueba al llegar el reto, antes de enseñar el código (`wrong-account`).
 * @param {any} [opts.device]
 * @param {any} [opts.continuity]
 * @param {string | null} [opts.encPub]
 * @param {string} [opts.intent]
 * @param {string | null} [opts.profileId]
 * @param {((m: { pub: string, encPub: string | null, label: string }) => any) | null} [opts.onAdopt]
 * @param {any} [opts.machine]
 * @returns {Promise<{device: any, cert: any, master:string, proxy:string, deviceId:string, account:string, acta?: any, adopted?: boolean}>}
 */
export function enrollDevice({ qr, device, onChallenge, label, continuity, encPub, approveTimeoutMs, intent, profileId, onAdopt, machine, account, requireCaps }?: {
    qr: {
        v?: number;
        iss?: string;
        proxy?: string;
        token?: string;
        sn: string;
        conn?: string;
        acct?: string;
        m?: any;
    };
    onChallenge?: (c: {
        deviceId: string;
        code: string;
    }) => void;
    requireCaps?: string[] | null;
    label?: string;
    approveTimeoutMs?: number;
    account?: string | null;
    device?: any;
    continuity?: any;
    encPub?: string | null;
    intent?: string;
    profileId?: string | null;
    onAdopt?: ((m: {
        pub: string;
        encPub: string | null;
        label: string;
    }) => any) | null;
    machine?: any;
}): Promise<{
    device: any;
    cert: any;
    master: string;
    proxy: string;
    deviceId: string;
    account: string;
    acta?: any;
    adopted?: boolean;
}>;
/**
 * Pide a la MAESTRA (en el vault del PC) que firme `payload`, adjuntando el cert de
 * delegación de este dispositivo. La maestra nunca sale del vault: vuelve solo la
 * firma. Requiere que el vault esté online.
 * @param {PairingContext & { payload: any }} args
 * @returns {Promise<{ signature:string, publickey:string }>}  publickey = la maestra.
 */
export function requestSign({ master, proxy, device, cert, acta, payload, onRevoked, timeoutMs }?: PairingContext & {
    payload: any;
}): Promise<{
    signature: string;
    publickey: string;
}>;
/**
 * @param {string} master
 * @param {(onReply: (reply: any) => void) => { send (payload: any): void, close (): void }} open
 * @returns {() => void}
 */
export function registerLocalVault(master: string, open: (onReply: (reply: any) => void) => {
    send(payload: any): void;
    close(): void;
}): () => void;
/**
 * PREGUNTA SIN CERTIFICADO: «¿sigo estando en el acta?».
 *
 * Es el único camino que le queda al aparato que perdió su papel — sin cert no puede
 * firmar, ni leer, ni renovar, así que tampoco podía enterarse de que lo habían echado y se
 * quedaba enseñando una cuenta que ya no era suya. Va firmada con SU llave, que es lo que
 * el acta nombra.
 *
 * La bóveda contesta sí o no, y nada más. Si el no viene acompañado del aviso FIRMADO de
 * expulsión, ESE es el que borra la cuenta aquí (`onRevoked`); el «no» pelado no borra
 * nada, como cualquier otro mensaje sin firma.
 * @param {{ master: string, proxy: string, device: DeviceKey, acta?: any, onRevoked?: (() => void) | null, timeoutMs?: number }} args
 * @returns {Promise<{ in?: boolean, wiped?: boolean, error?: string, code?: string }>}
 */
export function checkMembership({ master, proxy, device, acta, onRevoked, timeoutMs }?: {
    master: string;
    proxy: string;
    device: DeviceKey;
    acta?: any;
    onRevoked?: (() => void) | null;
    timeoutMs?: number;
}): Promise<{
    in?: boolean;
    wiped?: boolean;
    error?: string;
    code?: string;
}>;
/**
 * Lee/escribe el store de hilos+aperturas EN el vault (con el cert del dispositivo).
 * @param {PairingContext & { method: string, args?: any, enc?: any, wake?: boolean }} args
 * @returns {Promise<any>}
 */
export function requestStore({ master, proxy, device, cert, acta, method, args, enc, onRevoked, wake }?: PairingContext & {
    method: string;
    args?: any;
    enc?: any;
    wake?: boolean;
}): Promise<any>;
/**
 * Lista (solo lectura) los dispositivos enrolados en tu vault.
 * @param {PairingContext & { sinceSeq?: number }} args
 */
export function requestDevices({ master, to, timeoutMs, proxy, device, cert, acta, sinceSeq, onRevoked }?: PairingContext & {
    sinceSeq?: number;
}): Promise<{
    devices: any;
    siblingCerts: any;
    revoked: any;
    acta: any;
    chain: any;
    sealerChain: any;
}>;
/**
 * RENUEVA el cert de este dispositivo (requiere el cert aún VIGENTE y no revocado):
 * el vault firma uno fresco para la misma sub-clave y scope, sin QR ni aprobación.
 * @param {PairingContext} args
 * @returns {Promise<{ cert: any, acta: any }>}
 */
export function requestRenew({ master, proxy, device, cert, acta, onRevoked }?: PairingContext): Promise<{
    cert: any;
    acta: any;
}>;
/**
 * Manda a la bóveda la RENUNCIA de este dispositivo para que la selle en el acta.
 *
 * Sin esto, renunciar solo valía en el propio aparato: la bóveda seguía teniendo escrito
 * que podía firmar, le seguía aceptando peticiones, y cualquiera que mirara el acta lo
 * seguía viendo como firmante. Una renuncia que no llega al acta no es oponible a nadie —
 * y en el caso que la justifica (te robaron el aparato) su registro local no vale nada,
 * porque lo borra quien lo tenga en la mano.
 *
 * El `record` va FIRMADO por el propio miembro y solo puede QUITAR, así que la bóveda no
 * necesita comprobar ningún certificado para honrarlo: le basta la firma.
 * @param {PairingContext & { record: any }} args
 * @returns {Promise<{ ok: boolean, seq: number | null }>}
 */
export function requestRenounce({ master, proxy, device, cert, acta, record, onRevoked }?: PairingContext & {
    record: any;
}): Promise<{
    ok: boolean;
    seq: number | null;
}>;
/**
 * CONSOLA REMOTA (`dotrino-vault/docs/consola-remota.md`): administrar el perfil desde
 * este dispositivo, sin ir al PC. Requiere un cert con scope `vault:admin`, que **no se
 * recibe al emparejar** — se concede a mano en la bóveda.
 *
 * `op`: `pending` · `pair` · `approve` · `reject` · `revoke` · `audit`. Lo que NO existe
 * aquí es tan importante como lo que sí: cambiar permisos, traspasar el mando y los
 * secretos de servicios no se administran a distancia.
 *
 * El `nonce` de un solo uso va en cada petición porque `approve` y `revoke` cambian
 * estado, y para eso la ventana de frescura de ±5 min no alcanza.
 * @param {PairingContext & { op: string, nonce?: string } & Record<string, any>} args
 * @returns {Promise<any>}
 */
export function requestAdmin({ master, to, timeoutMs, proxy, device, cert, acta, op, onRevoked, nonce: dado, ...rest }?: PairingContext & {
    op: string;
    nonce?: string;
} & Record<string, any>): Promise<any>;
/**
 * PEDIDOS DE APROBACIÓN (cajones con `approval`): `approvals` (listar) · `approve` ·
 * `deny`. Van por `vault.secrets`, firmados por un aparato cuyo cert lleve
 * `vault:approve` — que, como `admin`, no se recibe al emparejar: se concede a mano.
 * La bóveda contesta un cuerpo firmado por la maestra (`{ op, items | ok }`).
 * @param {PairingContext & { op: string, id?: string, notify?: boolean }} args
 * @returns {Promise<any>}
 */
export function requestApproval({ master, proxy, device, cert, acta, op, id, notify, onRevoked }?: PairingContext & {
    op: string;
    id?: string;
    notify?: boolean;
}): Promise<any>;
/**
 * ¿Es AUTÉNTICO este `vault.admin.event` (entró o salió alguien del perfil)? Solo si va
 * firmado por la maestra PINEADA. Un aviso sin firma no se muestra: si no, cualquiera
 * podría llenar de alarmas falsas los dispositivos del usuario.
 * @param {{ body: any, signature: unknown, master: string }} args
 * @returns {Promise<boolean>}
 */
export function isAuthenticAdminEvent({ body, signature, master }: {
    body: any;
    signature: unknown;
    master: string;
}): Promise<boolean>;
export { MSG as VAULT_MSG };
/**
 * Un aparato enrolado: su llave (en JWK, CryptoKey o un firmador externo) y su máquina.
 */
export type DeviceKey = {
    publickey: string;
    privateJwk?: JsonWebKey;
    privateKey?: import("./capabilities.js").SigningKey | null;
    sign?: (text: string) => Promise<string>;
    machine?: any;
    label?: string;
    deviceId?: string;
};
/**
 * Lo que se usa del cliente del proxio (`@dotrino/proxy-client`), o del local que imita su forma.
 */
export type VaultClient = {
    local?: boolean;
    token?: string | null;
    on(event: string, fn: (from: string, payload: any, meta?: any) => void): () => unknown;
    send?(to: string, payload: any): void;
    sendByPubkey(to: string | string[], payload: any, opts?: any): void;
    identify?(envelope: {
        data: any;
        signature: string;
        cert?: any;
        acta?: any;
    }): Promise<any>;
    connect?(): Promise<unknown>;
    identifyAs?(args: any): Promise<unknown>;
    redeemPairingCode?(code: string): Promise<any>;
    close(): void;
};
/**
 * Con qué se habla con la bóveda emparejada.
 */
export type PairingContext = {
    master: string;
    proxy: string;
    device: DeviceKey;
    cert: any;
    acta?: any;
    onRevoked?: (() => void) | null;
    timeoutMs?: number;
    to?: string | null;
};
declare namespace MSG {
    let HELLO: string;
    let HELLO_OK: string;
    let ENROLL: string;
    let ENROLL_CHALLENGE: string;
    let ENROLLED: string;
    let ENROLL_ADOPT: string;
    let ACTA_SEALED: string;
    let ACTA_ADOPTED: string;
    let REVOKED: string;
    let CHECK: string;
    let CHECKED: string;
    let ADMIN: string;
    let ADMIN_RESULT: string;
    let ADMIN_EVENT: string;
    let RENOUNCE: string;
    let RENOUNCE_RESULT: string;
    let SECRETS: string;
    let SECRETS_RESULT: string;
    let ERROR: string;
}
