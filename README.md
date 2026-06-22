# @dotrino/identity

> **Parte del ecosistema [Dotrino](https://dotrino.com).** Misión: aplicaciones que resuelven problemas comunes, respetando tu privacidad — sin anuncios, sin cookies, sin rastreo de datos, sin vender tu identidad a nadie.

Identidad de usuario y rating de peers compartidos entre las apps de Dotrino. Funciona aunque las apps vivan en orígenes distintos: usa un **vault iframe** alojado en un origin estable que guarda la información en su propio `localStorage` y expone una API por `postMessage`.

## Cómo funciona

```
┌────────────────────┐    postMessage    ┌────────────────────────┐
│  app (cualquier    │ ◀───────────────▶ │  vault iframe          │
│  origin: chat,     │                   │  origin: id.dotrino    │
│  qrshare, chess…)  │                   │  .com                  │
│                    │                   │  - keypair ECDSA P-256 │
│  import {Identity} │                   │  - keypair ECDH P-256  │
└────────────────────┘                   │  - peers + ratings     │
                                         └────────────────────────┘
```

Como todas las apps cargan el vault desde el mismo origin, comparten el mismo `localStorage` aunque ellas estén en orígenes distintos. **Las claves privadas nunca salen del vault** — las apps reciben firmas (de la ECDSA) y plaintext descifrado (de la ECDH) pero nunca las llaves.

## Instalación

```bash
npm install @dotrino/identity
```

## Uso

```js
import { Identity } from '@dotrino/identity'

const id = await Identity.connect({
  vaultUrl: 'https://id.dotrino.com/'   // por defecto
})

console.log('my publickey JWK:', id.me.publickey)

// Identificar a un peer (handshake challenge/response)
const { nonce } = await id.makeChallenge()
// envía nonce al peer por el canal que sea (proxy, postMessage, etc.)
// el peer ejecuta await id.signChallenge(nonce) y te devuelve { nonce, publickey, signature }
const verification = await id.verifyResponse(response)
if (verification.ok) {
  console.log('peer verificado:', verification.publickey)
  await id.setNickname(verification.publickey, 'Bob de chess')
  await id.setRating(verification.publickey, 4, 'buen rival')
}

const peers = await id.listPeers()
```

## Hosting del vault

Para que distintas apps compartan datos, todas deben apuntar al **mismo `vaultUrl`**. La carpeta `vault/` de este paquete es un sitio estático (HTML + JS) listo para subir a:

- Un dominio dedicado: `id.dotrino.com`
- O temporalmente: `https://id.dotrino.com/vault/`

Importante: subir vía HTTPS y configurar `Content-Security-Policy: frame-ancestors *` (o lista de orígenes permitidos) para permitir que las apps lo embeban.

## API

### `Identity.connect(options?)`
Inicializa el iframe y resuelve cuando el vault está listo.

| opción       | tipo     | default                       |
|--------------|----------|-------------------------------|
| `vaultUrl`   | string   | `https://id.dotrino.com/` |
| `timeoutMs`  | number   | `5000`                        |

### Identidad propia

- `id.me`                            → `{ publickey, nickname? }`
- `id.setMyNickname(nickname)`

### Handshake

- `id.makeChallenge()`               → `{ nonce }`
- `id.signChallenge(nonce)`          → `{ nonce, publickey, encryptionPubkey, signature }`
- `id.verifyResponse(response)`      → `{ ok, publickey?, encryptionPubkey?, peer? }`

### Peer book

- `id.getPeer(publickey)`
- `id.setNickname(publickey, nickname)`
- `id.setRating(publickey, rating, notes?)` — produce un envelope firmado y lo guarda como `peer.myRating` (rating 0–5).
- `id.mergeEndorsements(subject, [signedRatings], askerPubkey?)` — para web-of-trust: valida firmas, dedupea por `(ratedBy, subject)`, cap 50.
- `id.getRatingsForSubject(subject)` → `{ mine, endorsements }` para responder a un `RATING_QUERY`.
- `id.recordQuery(askerPubkey, subject?)` — contabiliza consultas para el suspicion modifier.
- `id.listPeers()`, `id.forgetPeer(publickey)`

### Contactos compartidos (0.6.0+)

Mismo registro de `peers` que arriba, pero filtrado por flag `isContact: true`. Cualquier app del ecosistema (chat, chess, messenger, extensión) puede añadir/leer contactos del mismo address book.

- `id.addContact({ publickey, nickname?, encryptionPubkey?, lastToken?, notes? })`
- `id.updateContact(publickey, patch)` — patch limitado a `nickname`, `encryptionPubkey`, `lastToken`, `contactNotes`.
- `id.removeContact(publickey)` — quita el flag `isContact` pero conserva ratings/endorsements.
- `id.listContacts()` → array filtrado, ordenado por `lastSeen` desc.

### Encripción E2E (0.5.0+)

- `id.getEncryptionPubkey()` → JWK string del propio peer.
- `id.encrypt(recipients, plaintext)` → `{v:1, iv, ct, wrap}` envelope. `recipients` = `[{token, encryptionPubkey}]`. AES-256-GCM con clave efímera por mensaje, envuelta para cada destinatario vía ECDH(P-256). El campo `token` puede ser cualquier identificador estable (en messenger se usa la pubkey del destinatario para sobrevivir cambios de token del proxy).
- `id.decrypt(senderEncryptionPubkey, myToken, envelope)` → `{ plaintext }`. Forward-secrecy por mensaje (clave simétrica nueva cada vez).

### Firma genérica (0.7.0+)

- `id.signData(data)` → `{ signature, publickey }` con encoding canonical-JSON. Lo usa el messenger para construir sobres `identify` que el proxy verifica con su `verifySignatureWithJWK`.

### Backup / migración

- `id.exportIdentity()` → blob JSON con `privateJwk` (ECDSA), `encPrivateJwk` (ECDH), `me`, `peers`. **Sensible** — el host app es responsable de guardarlo de manera segura.
- `id.importIdentity(blob)` → reemplaza la identidad local. Soporta blobs v1 (sin ECDH) y v2 (con ambas keys).

### Auto-sync con Google Drive (0.8.0+)

Backup automático y sincronización multi-dispositivo de la identidad (claves + contactos + ratings + endorsements) usando Google Drive como almacén opaco. **Google nunca ve tus datos en claro**: el blob se cifra en el navegador con AES-256-GCM y una clave derivada por PBKDF2 (600 000 iteraciones) de una passphrase elegida por el usuario.

Topología:
- El blob se guarda en la carpeta especial `appDataFolder` de Drive (oculta para el usuario, no contamina su Drive).
- Scope OAuth requerido: solo `https://www.googleapis.com/auth/drive.appdata`.
- El cliente OAuth (Google Cloud Console → Web application) debe tener `https://id.dotrino.com` (y/o `http://localhost:5173` para dev) como Authorized JavaScript Origin.
- El sync corre **dentro del iframe del vault**: las claves privadas nunca cruzan el postMessage boundary.

```js
// 1. Conectar Google (popup OAuth, una vez por origen)
await id.syncConnect('123456789-abc...apps.googleusercontent.com')

// 2. Desbloquear con passphrase (≥12 chars). Se guarda en sessionStorage del vault
//    (per-tab) y se borra al cerrar la pestaña.
await id.syncUnlock('mi-passphrase-larga-y-secreta')

// 3. A partir de aquí: pull-on-unlock + push debounced (5s) + pull periódico (2 min).
//    Cualquier mutación local (setRating, addContact, mergeEndorsements...) marca
//    dirty automáticamente.

// Eventos de estado
id.onSync(({ status, error }) => console.log('sync:', status, error || ''))
// status: connected | unlocked | syncing | synced | conflict | offline | error | locked | disconnected

// Forzar pull+push inmediato
await id.syncNow()

// Bloquear (limpia la passphrase de memoria)
await id.syncLock()
```

**Estrategia de merge** (al hacer pull, si remoto tiene cambios):
- Keypairs ECDSA/ECDH: **nunca se sobreescriben**. Solo se adopta el remoto si local está vacío (primer setup en device nuevo).
- Contact metadata (nickname, notes, encryptionPubkey, rating): last-writer-wins por `lastSeen`.
- `myRating`: el envelope firmado con mayor `issuedAt` gana.
- `endorsements`: unión dedup por `ratedBy`; firmas re-verificadas antes de aceptar.
- Concurrencia: optimistic-lock con `If-Match: <etag>` en Drive. Si 412, pull → merge → push (3 reintentos).

**Trade-off**: si el usuario pierde la passphrase, el blob es irrecuperable. Es coherente con E2E — ni Google ni el desarrollador pueden recuperarlo.

## Diseño

- **Una sola identidad por navegador**, persistente entre apps que apuntan al mismo vault.
- **Sin servidor**: todo en `localStorage` del vault.
- **Replay protection**: cada `makeChallenge` registra el nonce; `verifyResponse` exige que el nonce sea reciente (≤ 5 min).
- **Privacidad**: la clave privada vive solo en el vault, las apps nunca la ven.

## Licencia

MIT
