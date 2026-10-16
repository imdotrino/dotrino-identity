// Los errores cruzan procesos (extensión ↔ vault ↔ teléfono), así que se comprueban
// por `e.code`, NUNCA por el texto: traducir un mensaje que alguien empareja por
// regex lo rompe en silencio. El mensaje es para el humano; el código, para el código.

export class VaultError extends Error {
  constructor (code, message) {
    super(message || code)
    this.name = 'VaultError'
    this.code = code
  }
}

export const CODES = {
  LOCKED: 'locked',                 // la bóveda está cerrada
  NO_KEY: 'no-key',                 // este aparato no tiene la CEK (extensión, por diseño)
  READ_ONLY: 'read-only',           // caché local: puede leer, no escribir
  NOT_FOUND: 'not-found',
  DENIED: 'denied',                 // la política dijo que no
  NOT_APPROVED: 'not-approved',     // el humano dijo que no. NO es lo mismo que `denied`:
                                    // uno se arregla dando permiso al aparato, el otro
                                    // volviendo a pedirlo y pulsando que sí
  APPROVAL_TIMEOUT: 'approval-timeout', // nadie aprobó desde el teléfono
  UNREACHABLE: 'unreachable',       // no hay bóveda al otro lado
  NO_LINK: 'no-link',               // este perfil no está emparejado con ninguna bóveda
  BAD_INVITE: 'bad-invite',         // eso que pegaste no es una invitación de bóveda
  UNSEALED: 'unsealed',             // llegó (o iba a salir) sin cifrar: NO se acepta
  UNDECIPHERABLE: 'undecipherable', // sellado, pero no para mí
  // Estos tres se usaban desde el principio y NO estaban aquí: `CODES.NOT_ALLOWED` valía
  // `undefined`, el error cruzaba sin código y quien pedía lo convertía en `unreachable`.
  // O sea, «la bóveda te contestó que no» se leía en pantalla como «no hay bóveda».
  NOT_ALLOWED: 'not-allowed',       // esta punta no tiene llave para eso (no se la envolvieron)
  NOT_SEALED: 'not-sealed',         // la bóveda sigue en el formato viejo: hay que convertirla
  UNKNOWN: 'unknown',               // falló algo que no trae código propio
}
