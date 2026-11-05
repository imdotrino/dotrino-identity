/** La última vez que la ficha cambió: la vio (`lastSeen`) o la tocaste (`changedAt`). */
export function stampOf(rec: any): number;
/** El id de la entrada: de su llave, estable y sin comillas (sha-256, 32 hex). */
export function peerIdOf(publickey: any): Promise<string>;
/**
 * Reconciliar el libro con la bóveda. `peers` es el libro de aquí (`{ publickey: ficha }`),
 * `call(method, args)` habla con el almacén de la bóveda. Devuelve las fichas que llegaron (para
 * fundirlas aquí) y cuántas subieron.
 */
export function syncPeers({ peers, call }: {
    peers: any;
    call: any;
}): Promise<{
    incoming: any[];
    pushed: number;
}>;
/**
 * EL LIBRO DE CONTACTOS EN LA BÓVEDA: los mismos contactos en todos los aparatos del perfil.
 *
 * Hasta aquí el libro vivía en cada aparato (el navegador, la app de identidad del teléfono) y
 * solo viajaba por Google Drive, que es opcional y no existe en las apps nativas: el mismo perfil
 * veía sus conversaciones en otro aparato (el historial sí se respalda) pero no a sus contactos.
 *
 * Ahora el libro es UN HILO más del almacén de la bóveda (`identity.peers`), con una entrada por
 * persona `{ id, ts, peer }`: `id` sale de su llave y `ts` es la última vez que su ficha cambió
 * (`stampOf`). Viaja cifrado con la clave de contenido del perfil, por el mismo camino que el
 * historial (`identity.vaultStore`). Se reconcilia por índice: se sube lo que aquí es más nuevo y
 * se trae lo que allí lo es, y lo que llega se FUNDE con lo de aquí (`mergePeer`), no lo pisa.
 *
 * Quitar un contacto es un cambio más (`changedAt`): gana el más reciente, así un contacto que
 * quitaste no vuelve desde otro aparato. Lo mismo hacen `PeerBookBackup` en Android e iOS.
 */
export const PEERS_THREAD: "identity.peers";
