/**
 * ¿Es AUTÉNTICO este `vault.revoked`? Solo lo es si va firmado por la maestra PINEADA al
 * emparejar, es para ESTE dispositivo y no ha caducado. Es la única puerta al autoborrado:
 * un `vault.error` con la palabra «revocado» no borra nada (cierra el wipe-DoS, ver
 * `dotrino-vault/docs/pairing-protocol.md §2.3`).
 */
export function isAuthenticRevoke({ body, signature, master, devicePubkey, currentNonce }: {
    body: any;
    signature: any;
    master: any;
    devicePubkey: any;
    currentNonce?: any;
}): Promise<boolean>;
/**
 * @param {Object} opts
 * @param {{v:number, iss:string, proxy:string, token:string, sn:string}} opts.qr  QR v2 del vault.
 * @param {(c:{deviceId:string, code:string})=>void} [opts.onChallenge]  Para mostrar el código a tipear en el PC.
 * @param {string[]} [opts.requireCaps]  permisos del acta sin los que este aparato no entra (`sealer`
 *   para una bóveda): si la invitación no los da, se para antes del código (`missing-caps`).
 * @param {string} [opts.label]
 * @param {number} [opts.approveTimeoutMs]  Espera de la aprobación humana (def 3 min).
 * @param {string} [opts.account]  si viene (`pubkeyId` del perfil, 64 hex), SOLO entra en esa cuenta:
 *   se comprueba al llegar el reto, antes de enseñar el código (`wrong-account`).
 * @returns {Promise<{device, cert, master:string, proxy:string, deviceId:string, account:string}>}
 */
export function enrollDevice({ qr, device, onChallenge, label, continuity, encPub, approveTimeoutMs, intent, profileId, onAdopt, machine, account, requireCaps }?: {
    qr: {
        v: number;
        iss: string;
        proxy: string;
        token: string;
        sn: string;
    };
    onChallenge?: (c: {
        deviceId: string;
        code: string;
    }) => void;
    requireCaps?: string[];
    label?: string;
    approveTimeoutMs?: number;
    account?: string;
}): Promise<{
    device: any;
    cert: any;
    master: string;
    proxy: string;
    deviceId: string;
    account: string;
}>;
/**
 * Pide a la MAESTRA (en el vault del PC) que firme `payload`, adjuntando el cert de
 * delegación de este dispositivo. La maestra nunca sale del vault: vuelve solo la
 * firma. Requiere que el vault esté online.
 * @returns {Promise<{ signature:string, publickey:string }>}  publickey = la maestra.
 */
export function requestSign({ master, proxy, device, cert, acta, payload, onRevoked, timeoutMs }?: {
    acta?: any;
    timeoutMs?: number;
}): Promise<{
    signature: string;
    publickey: string;
}>;
export function registerLocalVault(master: any, open: any): () => void;
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
 */
export function checkMembership({ master, proxy, device, acta, onRevoked, timeoutMs }?: {
    acta?: any;
    timeoutMs?: number;
}): Promise<any>;
/** Lee/escribe el store de hilos+aperturas EN el vault (con el cert del dispositivo). */
export function requestStore({ master, proxy, device, cert, acta, method, args, enc, onRevoked, wake }?: {
    acta?: any;
    wake?: boolean;
}): Promise<any>;
/** Lista (solo lectura) los dispositivos enrolados en tu vault. */
export function requestDevices({ master, to, timeoutMs, proxy, device, cert, acta, sinceSeq, onRevoked }?: {
    to?: any;
    acta?: any;
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
 * @returns {Promise<{ cert: object }>}
 */
export function requestRenew({ master, proxy, device, cert, acta, onRevoked }?: {
    acta?: any;
}): Promise<{
    cert: object;
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
 */
export function requestRenounce({ master, proxy, device, cert, acta, record, onRevoked }?: {
    acta?: any;
}): Promise<{
    ok: boolean;
    seq: any;
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
 */
export function requestAdmin({ master, to, timeoutMs, proxy, device, cert, acta, op, onRevoked, nonce: dado, ...rest }?: {
    to?: any;
    acta?: any;
}): Promise<any>;
/**
 * PEDIDOS DE APROBACIÓN (cajones con `approval`): `approvals` (listar) · `approve` ·
 * `deny`. Van por `vault.secrets`, firmados por un aparato cuyo cert lleve
 * `vault:approve` — que, como `admin`, no se recibe al emparejar: se concede a mano.
 * La bóveda contesta un cuerpo firmado por la maestra (`{ op, items | ok }`).
 */
export function requestApproval({ master, proxy, device, cert, acta, op, id, notify, onRevoked }?: {
    acta?: any;
}): Promise<any>;
/**
 * ¿Es AUTÉNTICO este `vault.admin.event` (entró o salió alguien del perfil)? Solo si va
 * firmado por la maestra PINEADA. Un aviso sin firma no se muestra: si no, cualquiera
 * podría llenar de alarmas falsas los dispositivos del usuario.
 */
export function isAuthenticAdminEvent({ body, signature, master }: {
    body: any;
    signature: any;
    master: any;
}): Promise<boolean>;
export { MSG as VAULT_MSG };
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
