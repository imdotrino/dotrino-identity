/**
 * Genera una clave de contenido nueva (AES-256-GCM). Devuelve los bytes en base64.
 * @returns {Promise<string>}
 */
export function makeContentKey(): Promise<string>;
/**
 * Envuelve la CEK hacia la llave de cifrado de un miembro. La envoltura es pública: solo
 * la abre quien tenga la privada de `memberEncPub`, así que puede viajar en el acta.
 * @param {{ cek: string, memberEncPub: string }} args
 * @returns {Promise<{epk:string, iv:string, ct:string}>}
 */
export function wrapForMember({ cek, memberEncPub }: {
    cek: string;
    memberEncPub: string;
}): Promise<{
    epk: string;
    iv: string;
    ct: string;
}>;
/**
 * Abre la envoltura con la llave de cifrado privada de ESTE miembro.
 * @param {{ wrap: any, myEncPrivateKey: any }} args
 * @returns {Promise<string>}
 */
export function openWrap({ wrap, myEncPrivateKey }: {
    wrap: any;
    myEncPrivateKey: any;
}): Promise<string>;
/**
 * Genera la CEK de una generación y la envuelve a TODOS los miembros que tengan llave de
 * cifrado. Un miembro sin `encPub` simplemente no recibe envoltura (y por tanto no lee el
 * contenido): se devuelve la lista para que la consola lo diga en vez de fallar en silencio.
 * @param {{ members?: Array<{ pub: string, encPub?: string | null }> | null, gen?: number, cek?: string | null, now?: number }} args
 * @returns {Promise<{ generation: KeyringGeneration, cek: string, sinLlave: Array<string | undefined> }>}
 */
export function makeGeneration({ members, gen, cek, now }: {
    members?: Array<{
        pub: string;
        encPub?: string | null;
    }> | null;
    gen?: number;
    cek?: string | null;
    now?: number;
}): Promise<{
    generation: KeyringGeneration;
    cek: string;
    sinLlave: Array<string | undefined>;
}>;
/**
 * La CEK vigente para mí, sacada del llavero del acta. `null` si no tengo envoltura.
 * @param {{ keyring?: KeyringGeneration[] | null, myPub: string, myEncPrivateKey: any }} args
 * @returns {Promise<{ gen: number, cek: string } | null>}
 */
export function myContentKey({ keyring, myPub, myEncPrivateKey }: {
    keyring?: KeyringGeneration[] | null;
    myPub: string;
    myEncPrivateKey: any;
}): Promise<{
    gen: number;
    cek: string;
} | null>;
/**
 * Cifra con una clave simétrica. Devuelve `{ gen, iv, ct }` (el `gen` dice con cuál).
 *
 * Es GENÉRICA: la usan la llave de la cuenta y también llaves que no son de la cuenta (los
 * cajones de secretos, cada entrada del gestor de contraseñas, el transporte). Por eso NO
 * lleva la marca: la marca dice «esto es de la cuenta» y solo la pone `sealAccount`. En
 * 0.107.0 la ponía aquí, y marcaba como de la cuenta sobres que la cuenta no abre.
 * @param {{ cek: string, gen: number, plaintext: string }} args
 * @returns {Promise<{ gen: number, iv: string, ct: string }>}
 */
export function encryptWithCek({ cek, gen, plaintext }: {
    cek: string;
    gen: number;
    plaintext: string;
}): Promise<{
    gen: number;
    iv: string;
    ct: string;
}>;
/**
 * Cifra BYTES con una clave simétrica, y devuelve bytes: `{ iv, ct }` como `Uint8Array`.
 *
 * Es la hermana binaria de `encryptWithCek`, para lo que no tiene por qué pasar por texto:
 * un archivo de 5 MB cifrado y en base64 ocupa 6,7 MB, y si además iba dentro de un JSON en
 * base64, 8,9 MB. Así viaja con lo que ocupa. Lo usa el transporte para los mensajes con
 * archivos: el archivo se cifra con una CEK nueva y solo la CEK pasa por el sellado de
 * siempre (`wrapForMember`, o la bóveda).
 *
 * @param {{ cek: string, bytes: Uint8Array<ArrayBuffer> }} o
 * @returns {Promise<{ iv: Uint8Array, ct: Uint8Array }>}
 */
export function encryptBytesWithCek({ cek, bytes }: {
    cek: string;
    bytes: Uint8Array<ArrayBuffer>;
}): Promise<{
    iv: Uint8Array;
    ct: Uint8Array;
}>;
/**
 * El inverso de `encryptBytesWithCek`. Lanza si los bytes no son de esa clave o se tocaron.
 * @param {{ cek: string, iv: Uint8Array<ArrayBuffer>, ct: Uint8Array<ArrayBuffer> }} args
 * @returns {Promise<Uint8Array>}
 */
export function decryptBytesWithCek({ cek, iv, ct }: {
    cek: string;
    iv: Uint8Array<ArrayBuffer>;
    ct: Uint8Array<ArrayBuffer>;
}): Promise<Uint8Array>;
/**
 * Cierra con la LLAVE DE LA CUENTA (generación `gen`): el sobre lleva la marca.
 * @param {{ cek: string, gen: number, plaintext: string }} args
 * @returns {Promise<CekEnvelope>}
 */
export function sealAccount({ cek, gen, plaintext }: {
    cek: string;
    gen: number;
    plaintext: string;
}): Promise<CekEnvelope>;
/**
 * Descifra un sobre teniendo YA la CEK. Es el inverso exacto de `encryptWithCek`.
 *
 * Existe para quien administra: tiene la clave a mano (la sacó de donde la guarde) y no
 * necesita el llavero ni ser miembro. El camino normal —el del aparato que solo tiene su
 * propia llave— es `decryptWithKeyring`.
 * @param {{ cek: string, envelope: { iv: string, ct: string } }} args
 * @returns {Promise<string>}
 */
export function decryptWithCek({ cek, envelope }: {
    cek: string;
    envelope: {
        iv: string;
        ct: string;
    };
}): Promise<string>;
/**
 * Descifra un sobre. Hay que darle el llavero porque el contenido viejo está cifrado con
 * generaciones anteriores: por eso las CEK antiguas se conservan (32 bytes cada una) en vez
 * de re-cifrarlo todo de golpe al rotar.
 * @param {{ envelope: any, keyring?: KeyringGeneration[] | null, myPub: string, myEncPrivateKey: any }} args
 * @returns {Promise<string>}
 */
export function decryptWithKeyring({ envelope, keyring, myPub, myEncPrivateKey }: {
    envelope: any;
    keyring?: KeyringGeneration[] | null;
    myPub: string;
    myEncPrivateKey: any;
}): Promise<string>;
/**
 * VUELVE A CERRAR con la generación vigente todo sobre de la cuenta de una generación
 * anterior que haya dentro de `value`, a cualquier profundidad. Devuelve una copia (no toca
 * el original) y cuántos sobres cambió.
 *
 * Es lo que hace la bóveda al abrirse y después de una rotación (dueño, 2026-09-30): lo que
 * sirve va SIEMPRE con la llave vigente, así que un aparato que entra después —que solo
 * recibe esa generación— abre todo, y la llave vieja deja de abrir nada porque ya no se le
 * sirve nada cerrado con ella.
 *
 * `reseal(envelope)` abre y vuelve a cerrar un sobre con la llave de la cuenta; lo pone quien
 * la tiene, y debe devolver un sobre MARCADO de la generación `gen`.
 *
 *  · Un sobre MARCADO que no abre PARA todo: es de la cuenta y algo va mal; no se deja a
 *    medias ni se salta en silencio.
 *  · Un sobre SIN MARCA (migración, hasta `LEGACY_UNMARKED_UNTIL`) se prueba aunque ya
 *    tenga la generación vigente —hay que ponerle la marca—; si no abre, se deja y se
 *    cuenta en `skipped`.
 *
 * @param {any} value
 * @param {{ gen: number, reseal: (env: object) => Promise<object>, now?: number }} o
 * @returns {Promise<{ value: any, changed: number, skipped: number }>}
 */
export function resealStale(value: any, { gen, reseal, now }: {
    gen: number;
    reseal: (env: object) => Promise<object>;
    now?: number;
}): Promise<{
    value: any;
    changed: number;
    skipped: number;
}>;
/**
 * La marca de un sobre de la llave de la cuenta. La lleva todo sobre de `encryptWithCek`
 * para que quien guarda datos ajenos —la bóveda con el almacén de las apps— lo RECONOZCA
 * dentro de un JSON cualquiera sin adivinar por la forma, y pueda volver a cerrarlo con la
 * generación vigente cuando la llave rota (`resealStale`).
 */
export const CEK_ENVELOPE: "dotrino-cek";
export function isCekEnvelope(v: any): v is CekEnvelope;
/**
 * MIGRACIÓN, con fecha de caducidad: hasta 0.107.0 los sobres de la cuenta salían SIN marca,
 * como `{ gen, iv, ct }` a secas. Hasta esta fecha, `resealStale` también prueba esos: si
 * abren con la llave de la cuenta, los vuelve a cerrar ya marcados; si no abren, no eran de
 * la cuenta y se dejan como están. Pasada la fecha, un sobre sin marca ya no se toca. Se
 * quita el código cuando pase (y su prueba con él).
 */
export const LEGACY_UNMARKED_UNTIL: number;
export function isLegacyCekEnvelope(v: any): v is CekEnvelope;
declare namespace _default {
    export { makeContentKey };
    export { wrapForMember };
    export { openWrap };
    export { makeGeneration };
    export { myContentKey };
    export { encryptWithCek };
    export { encryptBytesWithCek };
    export { decryptBytesWithCek };
    export { sealAccount };
    export { decryptWithCek };
    export { decryptWithKeyring };
    export { CEK_ENVELOPE };
    export { isCekEnvelope };
    export { isLegacyCekEnvelope };
    export { LEGACY_UNMARKED_UNTIL };
    export { resealStale };
}
export default _default;
/**
 * La envoltura de la clave de contenido para un miembro: ECDH efímero + AES-GCM.
 */
export type Wrap = {
    epk: string;
    iv: string;
    ct: string;
};
/**
 * Un sobre cerrado con la clave de la cuenta (`gen` dice con cuál).
 */
export type CekEnvelope = {
    t?: string;
    gen: number;
    iv: string;
    ct: string;
};
export type KeyringGeneration = import("./acta.js").KeyringGeneration;
