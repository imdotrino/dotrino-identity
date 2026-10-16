export * from './crypto.js'
export * from './model.js'
export * from './match.js'
export * from './fields.js'
export * from './generate.js'
// Los importadores son parte de la API: sin esto una app tenía que ir al subpath, y
// eso se descubre cuando ya está escrito el import.
export * from './import.js'
export * from './pubkey.js'
export * from './totp.js'
export { LocalVault } from './vault/local.js'
// Las contraseñas SELLADAS por aparato viven en `./sealed/` y se importan por su subpath
// (`@dotrino/passmanager/sealed`), que es lo que arrastra la cripto de los sobres. Aquí solo
// las dos puntas del protocolo, que es lo que cablea cada bóveda y cada aparato.
export { SealedVault } from './vault/sealed.js'
export { SealedResponder } from './vault/sealed-responder.js'
export { SealedLocalVault } from './vault/sealed-local.js'
export { SealedStore, SealedError } from './sealed/store.js'
export { RemoteVault } from './vault/remote.js'
export { VaultResponder } from './vault/responder.js'
export { GuardedVault } from './vault/guard.js'
export { ApprovalGate } from './vault/approval.js'
export { SessionCache } from './session-cache.js'
export { ProxyTransport } from './transport/proxy.js'
export * from './transport/protocol.js'
export * from './transport/sealed.js'
export { VaultError, CODES } from './vault/errors.js'
