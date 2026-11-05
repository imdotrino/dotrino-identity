/**
 * Verifica que `signature` (base64) sobre `data` fue hecha por la privada de
 * `publickey` (JWK string). Prueba de POSESION de una sub-clave de dispositivo (no
 * es cadena de delegacion): la usa el vault para confirmar que quien pide enrolar
 * `dpub` realmente tiene su privada (un token robado ya no alcanza para enrolar).
 * @param {{ publickey: unknown, data: unknown, signature: unknown }} args
 * @returns {Promise<boolean>}
 */
export function verifyDeviceSig({ publickey, data, signature }: {
    publickey: unknown;
    data: unknown;
    signature: unknown;
}): Promise<boolean>;
/**
 * Short Authentication String: 6 digitos deterministas derivados de (maestra,
 * dispositivo, nonce de sesion). NO es un secreto: su valor esta en COMPARARLO
 * visualmente entre las dos pantallas (PC del vault y dispositivo) al emparejar —
 * eso mata el relay/phishing (un atacante remoto no puede mostrar el SAS correcto
 * en el dispositivo fisico de la victima).
 * @param {string} master
 * @param {string} dpub
 * @param {unknown} sn
 * @returns {Promise<string>}
 */
export function deriveSAS(master: string, dpub: string, sn: unknown): Promise<string>;
/**
 * Código de emparejamiento ALEATORIO de 6 dígitos. Lo genera el DISPOSITIVO y lo MUESTRA;
 * el usuario lo tipea en el vault. El vault NO lo conoce: el dispositivo solo manda un
 * COMPROMISO (`commitCode`), no el código → el vault lo aprende únicamente cuando vos se lo
 * das, tipeándolo. Así, aprobar exige TENER el dispositivo (de ahí sale el código).
 * @returns {string}
 */
export function makePairingCode(): string;
/**
 * Compromiso del código: `SHA-256(code ‖ dpub ‖ sn)` en hex. Va en el ENROLL (no el código).
 * Liga el código a ESTE dispositivo y sesión (no reusable para otro). El vault lo guarda y,
 * cuando tipeás el código, recomputa y compara → verifica posesión sin conocer el código antes.
 * @param {{ code: unknown, dpub: string, sn: unknown }} args
 * @returns {Promise<string>}
 */
export function commitCode({ code, dpub, sn }: {
    code: unknown;
    dpub: string;
    sn: unknown;
}): Promise<string>;
/** Cuerpo canónico del certificado (lo que se firma): el cert SIN la firma. */
/**
 * Lo que se firma de un certificado. `seq` en vez de `exp` (dueño, 2026-08-31).
 *
 * EL PAPEL YA NO CADUCA POR RELOJ: caduca cuando cambia el acta. Antes vencía a los 30
 * días, y eso obligaba a que alguien con la maestra estuviera disponible cada mes o los
 * aparatos se quedaban fuera — con una bóveda que pasa casi todo el tiempo cerrada, eso
 * no iba a pasar nunca.
 *
 * Atarlo al `seq` hace las dos cosas de golpe: quitarle un permiso a un aparato surte
 * efecto AL INSTANTE (el acta sube de `seq` y su papel deja de valer, sin esperar a
 * ninguna renovación), y nadie tiene que abrir nada por calendario.
 * @param {Delegation} cert
 */
export function delegationBody(cert: Delegation): {
    v: number;
    iss: string;
    sub: string;
    scope: string | string[];
    iat: number;
    exp: number;
    nonce: string;
    seq?: undefined;
} | {
    v: number;
    iss: string;
    sub: string;
    scope: string | string[];
    iat: number;
    seq: number;
    nonce: string;
    exp?: undefined;
};
/**
 * Genera una sub-clave de DISPOSITIVO `D`. Corre EN el dispositivo / bridge; la
 * clave maestra nunca ve la privada. Solo `publickey` (JWK string) sale del device.
 * @param {{ label?: string }} [opts]
 */
export function makeDeviceKey({ label }?: {
    label?: string;
}): Promise<{
    publickey: string;
    privateJwk: JsonWebKey;
    publicJwk: JsonWebKey;
    label: string;
    createdAt: number;
    deviceId: string;
}>;
/**
 * Genera la llave de CIFRADO del dispositivo (ECDH P-256): la hermana de
 * `makeDeviceKey`, que es de FIRMA. Hacen falta las dos y no son intercambiables —
 * con ECDSA no se puede cifrar.
 *
 * Es lo que permite escribirle a un aparato **por adelantado**, sin que esté
 * conectado: su pública va al acta como `encPub` y cualquiera puede envolverle un
 * secreto con `wrapForMember` (ver `./content.js`). La privada no sale de aquí.
 *
 * Sale EXTRAÍBLE porque un servicio headless la persiste en su archivo de identidad
 * (cifrado en reposo). En el navegador la pareja del perfil vive como CryptoKey no
 * extraíble en IndexedDB — eso lo hace `core.js`, no esto.
 */
export function makeDeviceEncKey(): Promise<{
    encPublickey: string;
    encPrivateJwk: JsonWebKey;
    encPublicJwk: JsonWebKey;
    createdAt: number;
}>;
/**
 * Reconstruye la llave privada de cifrado desde su JWK. Es lo que hay que pasarle a
 * `openWrap({ myEncPrivateKey })` para abrir un sobre dirigido a este aparato.
 *
 * Existe para que nadie la importe a mano: `deriveBits` es el ÚNICO uso correcto, y
 * pedir otro (`deriveKey`) hace fallar la importación en Node con un error que no
 * dice nada útil.
 * @param {JsonWebKey} encPrivateJwk
 * @returns {Promise<CryptoKey>}
 */
export function importDeviceEncKey(encPrivateJwk: JsonWebKey): Promise<CryptoKey>;
/**
 * Firma un certificado de delegación con una `privateKey` (CryptoKey) cuyo pubkey
 * es `iss`. Lo usa el handler del vault (con la clave maestra). Devuelve el cert
 * completo `{ v, iss, sub, scope, iat, seq, nonce, sig }`.
 * @param {SigningKey} privateKey
 * @param {string} iss
 * @param {{ sub: string, scope: string | string[], iat: number, seq: number, nonce?: string }} body
 * @returns {Promise<Delegation>}
 */
export function signDelegationWith(privateKey: SigningKey, iss: string, { sub, scope, iat, seq, nonce }: {
    sub: string;
    scope: string | string[];
    iat: number;
    seq: number;
    nonce?: string;
}): Promise<Delegation>;
/**
 * Firma datos con la clave de DISPOSITIVO (formato byte-idéntico a `signData` del
 * vault → lo que el dispositivo/bridge usa para firmar cada pin/acción).
 * @param {{ privateJwk?: JsonWebKey, privateKey?: SigningKey | null, publickey?: string, data: unknown, sign?: ((text: string) => Promise<string>) | null }} args
 * @returns {Promise<{ signature: string, publickey: string }>}
 */
export function signWithDevice({ privateJwk, privateKey, publickey, data, sign }: {
    privateJwk?: JsonWebKey;
    privateKey?: SigningKey | null;
    publickey?: string;
    data: unknown;
    sign?: ((text: string) => Promise<string>) | null;
}): Promise<{
    signature: string;
    publickey: string;
}>;
/**
 * Verifica un CERTIFICADO de delegación (offline; no requiere la clave maestra):
 *   1) firma de la maestra (`iss`) sobre el cuerpo canónico,
 *   2) el acta: quien lo emitió puede sellar, y el papel no es de un acta más nueva que la mía,
 *   3) `scope` incluye `expectedScope` (si se pide),
 *   4) `sub` === `expectedSub` (si se pide),
 *   5) `nonce` no revocado (`revoked`: fn(nonce)→bool, Set o mapa).
 * @param {{ cert?: any, expectedScope?: string | null, expectedSub?: string | null, actaSeq?: number | null, sealers?: string[] | null, revoked?: RevokedSet | null }} [args]
 * @returns {Promise<{ok:boolean, reason?:string, iss?: string, sub?: string, scope?: string | string[], iat?: number, seq?: number, nonce?: string}>}
 */
export function verifyDelegation({ cert, expectedScope, expectedSub, actaSeq, sealers, revoked }?: {
    cert?: any;
    expectedScope?: string | null;
    expectedSub?: string | null;
    actaSeq?: number | null;
    sealers?: string[] | null;
    revoked?: RevokedSet | null;
}): Promise<{
    ok: boolean;
    reason?: string;
    iss?: string;
    sub?: string;
    scope?: string | string[];
    iat?: number;
    seq?: number;
    nonce?: string;
}>;
/**
 * Verificación de CADENA de una acción/pin delegado (lo único que llama el bridge):
 *   1) el dispositivo `D` (= `data.publickey`) firmó `data`,
 *   2) el cert delega a ESTE dispositivo (`cert.sub === data.publickey`),
 *   3) el cert es válido (firma de una selladora, scope, revocación),
 *   4) opcional: `cert.iss === trustedIssuer` (fija la identidad maestra esperada).
 * @param {{ data?: any, signature?: unknown, cert?: any, expectedScope?: string | null, actaSeq?: number | null, sealers?: string[] | null, revoked?: RevokedSet | null }} [args]
 * @returns {Promise<{ok:boolean, reason?:string, issuer?:string, device?:string, scope?: string | string[]}>}
 */
export function verifyChain({ data, signature, cert, expectedScope, actaSeq, sealers, revoked }?: {
    data?: any;
    signature?: unknown;
    cert?: any;
    expectedScope?: string | null;
    actaSeq?: number | null;
    sealers?: string[] | null;
    revoked?: RevokedSet | null;
}): Promise<{
    ok: boolean;
    reason?: string;
    issuer?: string;
    device?: string;
    scope?: string | string[];
}>;
/**
 * Una llave que firma: una CryptoKey, o una llave que vive fuera (el chip del teléfono) y
 * firma por su cuenta.
 */
export type SigningKey = CryptoKey | {
    external: true;
    sign: (bytes: Uint8Array) => Promise<string>;
};
/**
 * Un certificado de delegación: `iss` autoriza a `sub` para `scope`, válido mientras el acta
 * no lo deje atrás (`seq`). Los viejos llevaban `exp` en vez de `seq`.
 */
export type Delegation = {
    v: number;
    iss: string;
    sub: string;
    scope: string | string[];
    iat: number;
    seq?: number;
    exp?: number;
    nonce?: string;
    sig: string;
};
/**
 * Qué nonces están revocados: una función, un Set o un objeto `{ nonce: true }`.
 */
export type RevokedSet = ((nonce: string) => boolean) | Set<string> | Record<string, unknown>;
import { pubkeyId } from './keyid.js';
import { keyLabel } from './keyid.js';
export { pubkeyId, keyLabel };
export { avatarSvg, avatarDataUri } from "./avatar.js";
