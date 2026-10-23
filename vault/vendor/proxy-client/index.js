export { WebSocketProxyClient } from './client.js'
export { canonicalStringify } from './canonical.js'
export { getPublicKeyJwk, signData, verifyData, samePubkey, buildSignedChannel, setKeypairStore } from './signature.js'
export {
  seal, open, isSealed, makeEncKeypair, importEncPrivate, exportEncPrivate,
  setSealingPrimitives, identitySealing,
} from './sealing.js'
export {
  ENCPUB_V, ENCPUB_AUD, encPubBody, isEncPub,
  buildEncPubStatement, readEncPubStatement,
} from './encpub.js'

export { listTransports, routeOf } from './stats.js'
export { PART_TAG, DIRECT_PART_CHARS, PROXY_PART_CHARS, QUEUE_MAX_CHARS, RELAY_MAX_CHARS, DIRECT_PART_BYTES, PROXY_PART_BYTES, QUEUE_MAX_BYTES, RELAY_MAX_BYTES } from './parts.js'
export { pack, unpack, hasBinary, encodeFrame, decodeFrame } from './binpack.js'
export { logStats, formatStats, netReport, splitPeers } from './stats-log.js'
export { encodeContact, decodeContact, KIND_PAIR, KIND_CONTACT } from './ble/wire.js'

import { WebSocketProxyClient } from './client.js'

let _singleton = null
/**
 * Singleton helper. Returns the same instance across calls.
 * Useful in apps that want a single global client.
 */
export function getWebSocketProxyClient (options) {
  if (!_singleton) _singleton = new WebSocketProxyClient(options)
  else if (options) _singleton.updateConfig(options)
  return _singleton
}
