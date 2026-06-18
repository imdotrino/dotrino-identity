export interface IdentityOptions {
  vaultUrl?: string
  timeoutMs?: number
}

export interface Me {
  publickey: string
  encryptionPubkey?: string
  nickname?: string
}

export interface EnvelopeV1 {
  v: 1
  iv: string
  ct: string
  wrap: Record<string, { iv: string; ct: string }>
}

export interface EncryptRecipient {
  token: string
  encryptionPubkey: string
}

export interface SignedRating {
  subject: string
  rating: number
  notes: string
  ratedBy: string
  issuedAt: number
  signature: string
}

export interface QueryStats {
  queriesMade: number
  queriesKnown: number
}

export interface PeerInfo {
  publickey: string
  encryptionPubkey?: string
  nickname?: string
  rating?: number
  notes?: string
  myRating?: SignedRating | null
  endorsements?: SignedRating[]
  queryStats?: QueryStats
  firstSeen?: number
  lastSeen?: number
}

export interface Challenge {
  nonce: string
}

export interface ChallengeResponse {
  nonce: string
  publickey: string
  encryptionPubkey?: string
  signature: string
}

export interface VerifyResult {
  ok: boolean
  publickey?: string
  encryptionPubkey?: string | null
  peer?: PeerInfo
}

export interface IdentityExport {
  version: number
  privateJwk: Record<string, any>
  publicJwk: Record<string, any>
  me: Me | null
  peers: Record<string, PeerInfo>
  exportedAt: string
}

export class Identity {
  static connect (options?: IdentityOptions): Promise<Identity>
  static current (): Identity | null
  constructor (options?: IdentityOptions)
  ready (): Promise<Identity>
  destroy (): void
  readonly me: Me | null
  makeChallenge (): Promise<Challenge>
  signChallenge (nonce: string): Promise<ChallengeResponse>
  verifyResponse (response: ChallengeResponse): Promise<VerifyResult>
  getPeer (publickey: string): Promise<PeerInfo | null>
  setNickname (publickey: string, nickname: string): Promise<PeerInfo>
  setRating (publickey: string, rating: number, notes?: string): Promise<PeerInfo>
  listPeers (): Promise<PeerInfo[]>
  forgetPeer (publickey: string): Promise<void>
  addContact (input: {
    publickey: string
    nickname?: string
    encryptionPubkey?: string
    lastToken?: string
    notes?: string
  }): Promise<PeerInfo>
  updateContact (
    publickey: string,
    patch: Partial<{ nickname: string; encryptionPubkey: string; lastToken: string; contactNotes: string }>
  ): Promise<PeerInfo | null>
  removeContact (publickey: string): Promise<PeerInfo | null>
  listContacts (): Promise<PeerInfo[]>
  signData (data: any): Promise<{ signature: string; publickey: string }>
  setMyNickname (nickname: string): Promise<{ me: Me }>
  getEncryptionPubkey (): Promise<string>
  encrypt (recipients: EncryptRecipient[], plaintext: string): Promise<EnvelopeV1>
  decrypt (
    senderEncryptionPubkey: string,
    myToken: string,
    envelope: EnvelopeV1
  ): Promise<{ plaintext: string }>
  mergeEndorsements (
    subject: string,
    endorsements: SignedRating[],
    askerPubkey?: string
  ): Promise<{ merged: number; total: number }>
  getRatingsForSubject (
    subject: string
  ): Promise<{ mine: SignedRating | null; endorsements: SignedRating[] }>
  recordQuery (askerPubkey: string, subject?: string): Promise<PeerInfo | null>
  /** Firma un certificado de delegación de capacidad para una sub-clave de dispositivo. */
  signDelegation (sub: string, scope: string | string[], opts?: DelegationOpts): Promise<{ cert: CapabilityCert }>
  /** Revoca una delegación por su nonce. */
  revokeDelegation (nonce: string): Promise<{ ok: true; revokedAt: number }>
  /** Lista las delegaciones emitidas + la lista de revocación. */
  listDelegations (): Promise<{ issued: IssuedDelegation[]; revoked: { nonce: string; revokedAt: number }[] }>
  exportIdentity (): Promise<IdentityExport>
  importIdentity (blob: IdentityExport | Record<string, any>): Promise<{ me: Me }>
  syncConnect (clientId: string): Promise<{ accessToken: string; expiresAt: number }>
  syncDisconnect (): Promise<void>
  syncUnlock (passphrase: string): Promise<{ ok: boolean }>
  syncLock (): Promise<void>
  syncStatus (): Promise<SyncStatus>
  syncNow (): Promise<SyncStatus>
  onSync (handler: (event: SyncEvent) => void): () => void
  on (event: 'peer_updated' | 'me_updated' | 'sync', handler: (payload: any) => void): () => void
}

export interface SyncStatus {
  kind?: 'identity' | 'store'
  connected: boolean
  unlocked: boolean
  dirty: boolean
  lastError?: string | null
}

export interface SyncEvent {
  kind: 'identity' | 'store'
  status: 'connected' | 'disconnected' | 'unlocked' | 'locked' | 'syncing' | 'synced' | 'conflict' | 'offline' | 'error'
  error?: string
  ts: number
}

// ----- delegación de capacidad (sub-clave de dispositivo con scope/exp/revocación) -----

/** Certificado de delegación firmado por la maestra (`iss`) para una sub-clave (`sub`). */
export interface CapabilityCert {
  v: 1
  iss: string            // pubkey JWK string de la identidad maestra (emisor)
  sub: string            // pubkey JWK string de la clave de dispositivo (sujeto)
  scope: string | string[]
  iat: number            // ms epoch
  exp: number            // ms epoch (tope MAX_DELEGATION_MS)
  nonce: string          // mango de revocación
  sig: string            // base64 de la firma cruda ECDSA de la maestra sobre el cuerpo canónico
}
export interface DelegationOpts { ttlMs?: number; exp?: number; nonce?: string; label?: string }
export interface IssuedDelegation { nonce: string; sub: string; scope: string | string[]; iat: number; exp: number; label?: string; revokedAt?: number }
/** Sub-clave de dispositivo generada localmente (la privada nunca va a la maestra). */
export interface DeviceKey { publickey: string; privateJwk: JsonWebKey; publicJwk: JsonWebKey; label: string; createdAt: number; deviceId: string }

export const MAX_DELEGATION_MS: number
export const DEFAULT_DELEGATION_MS: number
/** Genera una sub-clave de dispositivo `D` (corre EN el dispositivo). */
export function makeDeviceKey (opts?: { label?: string }): Promise<DeviceKey>
/** id corto y estable de un pubkey (sha-256 hex de los campos canónicos del JWK). */
export function pubkeyId (publicJwkStr: string): Promise<string>
/** Firma datos con una clave de dispositivo (formato byte-idéntico a signData). */
export function signWithDevice (args: { privateJwk: JsonWebKey; data: any }): Promise<{ signature: string; publickey: string }>
/** Verifica un certificado de delegación (firma de la maestra + exp + scope + sub + revocación). */
export function verifyDelegation (args: { cert: CapabilityCert; expectedScope?: string; expectedSub?: string; now?: number; revoked?: ((nonce: string) => boolean) | Set<string> | Record<string, any> }): Promise<{ ok: boolean; reason?: string; iss?: string; sub?: string; scope?: string | string[]; iat?: number; exp?: number; nonce?: string }>
/** Verifica la cadena de una acción/pin delegado: D firmó + cert prueba D←P + scope/exp/revocación. */
export function verifyChain (args: { data: any; signature: string; cert: CapabilityCert; expectedScope?: string; trustedIssuer?: string; now?: number; revoked?: ((nonce: string) => boolean) | Set<string> | Record<string, any> }): Promise<{ ok: boolean; reason?: string; issuer?: string; device?: string }>

