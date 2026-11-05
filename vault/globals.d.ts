// Globales del navegador que usa la identidad y que TypeScript no trae: solo para el chequeo
// de tipos (`npm run type-check`), no se publican como tipos del paquete.

/** Google Identity Services (lo justo de `oauth2` que usa `sync.js`). */
interface GoogleTokenResponse {
  access_token?: string
  expires_in?: number | string
  error?: string
}
interface GoogleTokenClient {
  callback: (resp: GoogleTokenResponse) => void
  requestAccessToken (opts?: { prompt?: string }): void
  /** Lo apunta `sync.js` para saber para qué cliente se creó. */
  _clientId?: string
}

interface Window {
  google?: {
    accounts?: {
      oauth2?: {
        initTokenClient (cfg: { client_id: string, scope: string, prompt: string, callback: (resp: GoogleTokenResponse) => void }): GoogleTokenClient
      }
    }
  }
}

interface Window {
  /**
   * El puente con el chip del teléfono, dentro de la app nativa (`addWebMessageListener`).
   * `storage: true`: la app guarda también la identidad (la de iOS).
   */
  DotrinoIdentityKeys?: { onmessage: ((ev: { data: string }) => void) | null, postMessage (data: string): void, storage?: boolean }
}

// Módulos que el iframe resuelve con su import map (`@dotrino/vault`, vendorizado en
// `vault/vendor/`) y que este paquete no instala: lo justo de lo que se usa.
declare module '@dotrino/vault/browser' {
  /** La bóveda entera sobre IndexedDB; devuelve su mostrador (`listPending`, `approve`…). */
  export function startBrowserVault (opts: Record<string, any>): Promise<any>
}
declare module '@dotrino/vault/password-logins' {
  export function sealDeviceKeys (exportKey: any, keys: { sign: JsonWebKey, enc: JsonWebKey }): Promise<any>
  export function openDeviceKeys (exportKey: any, blob: any): Promise<{ sign: JsonWebKey, enc: JsonWebKey }>
  export function loginAddress (user: string, fingerprint: string): string
  export function accountFingerprint (identity: { profileActa (): Promise<any> }): Promise<string>
  export function vaultChannel (code: string): string
}
declare module '@dotrino/vault/backup' {
  export function sealBackup (payload: any, password: string): Promise<any>
  export function openBackup (file: any, password: string): Promise<any>
}
// `@dotrino/opaque` se instala, pero no publica tipos.
declare module '@dotrino/opaque' {
  export const client: {
    registrationStart (args: { password: string }): { request: any, state: any }
    registrationFinish (args: { state: any, response: any, password: string }): { upload: any, exportKey: any }
    loginStart (args: { password: string }): { request: any, state: any }
    loginFinish (args: { state: any, response: any, password: string }): { finalization: any, exportKey: any }
  }
}
