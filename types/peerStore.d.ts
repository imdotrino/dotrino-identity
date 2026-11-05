/** @param {PeerBackend | null | undefined} b */
export function useBackend(b: PeerBackend | null | undefined): void;
/**
 * Registra el callback que marca el estado como "sucio" para el sync.
 * @param {(() => void) | null} fn
 */
export function onDirty(fn: (() => void) | null): void;
/**
 * Multi-perfil: namespacea el peer book por perfil. El core lo llama antes de initPeerStorage.
 * @param {string | null | undefined} pid
 * @param {{ volatile?: boolean }} [opts]
 */
export function setProfile(pid: string | null | undefined, { volatile: esVolatil }?: {
    volatile?: boolean;
}): void;
/**
 * Migración: copia el peer book VIEJO (pre-multi-perfil, sin namespace) al perfil `pid`.
 * @param {string} pid
 */
export function adoptLegacy(pid: string): Promise<void>;
/** @returns {Promise<PeerBook>} */
export function initPeerStorage(): Promise<PeerBook>;
/**
 * Promesa que resuelve cuando se completaron los write-through pendientes (tests).
 * @returns {Promise<void>}
 */
export function flushPeers(): Promise<void>;
/** @returns {PeerBook} */
export function loadPeers(): PeerBook;
/** @param {PeerBook} peers */
export function savePeers(peers: PeerBook): void;
/**
 * Escritura directa (merge del sync): persiste sin marcar dirty.
 * @param {PeerBook} peers
 */
export function setPeersDirect(peers: PeerBook): void;
/**
 * @param {string} publickey
 * @param {Record<string, any>} patch
 * @returns {PeerRecord}
 */
export function upsertPeer(publickey: string, patch: Record<string, any>): PeerRecord;
export function _resetForTest(): void;
/**
 * Almacén del peer book del vault (nicknames + ratings + endorsements firmados).
 *
 * Migrado de localStorage (~5 MB de techo, compartido) a IndexedDB (cuota grande,
 * non-evictable con `persist()`), porque el peer book crece con los contactos y,
 * sobre todo, con los endorsements del registro de reputación. Patrón idéntico
 * al del store del ecosistema:
 *   - `_peers` en memoria es la fuente de verdad en runtime.
 *   - `loadPeers()` es SÍNCRONA (lee la cache) → los handlers del vault no cambian.
 *   - `initPeerStorage()` (async, en el bootstrap) la rellena desde IndexedDB,
 *     MIGRANDO una sola vez del localStorage viejo. Si IndexedDB no está (modo
 *     privado) cae a localStorage para no perder función.
 *   - `savePeers()` actualiza la cache y hace write-through async a IndexedDB.
 *
 * El módulo es independiente del resto del vault (testeable en aislamiento).
 */
export const PEERS_STORAGE: "dotrino.identity.peers";
/**
 * La ficha de un contacto: `publickey` y lo que sus pantallas apunten (apodo, avatar, fechas).
 */
export type PeerRecord = {
    publickey: string;
    firstSeen?: number;
    lastSeen?: number;
    changedAt?: number;
} & Record<string, any>;
/**
 * El libro de contactos: pubkey → ficha.
 */
export type PeerBook = Record<string, PeerRecord>;
/**
 * Dónde guarda la app el libro (el almacén de la app nativa).
 */
export type PeerBackend = {
    get(key: string): Promise<any>;
    put(key: string, val: any): Promise<void>;
};
