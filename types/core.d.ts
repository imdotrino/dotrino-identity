/** @param {any} v @returns {string} */
export function canonicalStringify(v: any): string;
/** @param {ArrayBuffer | ArrayLike<number>} buf @returns {string} */
export function bufToBase64(buf: ArrayBuffer | ArrayLike<number>): string;
/** @param {string} b64 @returns {ArrayBuffer} */
export function base64ToBuf(b64: string): ArrayBuffer;
/**
 * QUÉ CLASE ES CADA DATO DEL PERFIL: `public` o `private`
 * (`dotrino-vault/docs/datos-del-perfil.md` §2).
 *
 * La regla no es nueva —es la que ya decidía `publicMe()`: lo que marcaste visible es lo
 * que ve quien pregunta desde fuera—. Lo que cambia es que ahora decide **cómo se guarda**:
 * en claro o en sobre. Por eso vive aquí, exportada y a nivel de módulo, en vez de escondida
 * dentro de una función: es política y hay que poder mirarla y probarla.
 *
 * Sensibles (teléfono, dirección) OCULTOS salvo que su marca diga que sí, explícitamente.
 * El resto se comparte salvo que digas que no.
 */
/**
 * @param {Record<string, any>} [m]
 * @returns {Record<string, 'public' | 'private'>}
 */
export function profileFieldClasses(m?: Record<string, any>): Record<string, "public" | "private">;
/**
 * `askConsent` es CÓMO SE PREGUNTA, y lo pone quien monta el núcleo (el iframe pinta su
 * propio panel; en Node no hay a quién preguntar). Se inyecta en vez de vivir aquí porque
 * este módulo no toca interfaz — y porque QUIÉN pinta importa: un panel dibujado por la
 * aplicación que pide sería la aplicación aprobándose a sí misma.
 *
 * Si no se inyecta, no se concede nada nuevo: sin forma de preguntar, la respuesta es no.
 *
 * @param {CoreDeps} deps
 */
export function createIdentityCore({ kv: hostKv, peers, makeSync, keyStore: hostKeyStore, sessionKv, removeAccountOnExpulsion, keyLock, askConsent }: CoreDeps): Promise<{
    handlers: {
        profileLockStatus(): Promise<{
            protected: boolean;
            locked: boolean;
        }>;
        /** @param {HandlerParams} params  lo que llega por `postMessage` o la API: sin comprobar todavía */
        unlockProfile({ password }: HandlerParams): Promise<{
            ok: boolean;
            locked: boolean;
        }>;
        /** @param {HandlerParams} params  lo que llega por `postMessage` o la API: sin comprobar todavía */
        setProfilePassword({ password }: HandlerParams): Promise<{
            ok: boolean;
        }>;
        removeProfilePassword(): Promise<{
            ok: boolean;
        }>;
        makeChallenge(): Promise<{
            nonce: `${string}-${string}-${string}-${string}-${string}`;
        }>;
        /** @param {HandlerParams} params  lo que llega por `postMessage` o la API: sin comprobar todavía */
        signChallenge({ nonce }: HandlerParams): Promise<{
            nonce: string;
            publickey: string;
            encryptionPubkey: string;
            signature: string;
        }>;
        /** @param {HandlerParams} params  lo que llega por `postMessage` o la API: sin comprobar todavía */
        verifyResponse({ nonce, publickey, signature, encryptionPubkey }: HandlerParams): Promise<{
            ok: boolean;
            reason?: undefined;
            publickey?: undefined;
            encryptionPubkey?: undefined;
            peer?: undefined;
        } | {
            ok: boolean;
            reason: string;
            publickey?: undefined;
            encryptionPubkey?: undefined;
            peer?: undefined;
        } | {
            ok: boolean;
            publickey: any;
            encryptionPubkey: any;
            peer: import("./peerStore.js").PeerRecord;
            reason?: undefined;
        }>;
        /** @param {HandlerParams} params  lo que llega por `postMessage` o la API: sin comprobar todavía */
        getPeer({ publickey }: HandlerParams): Promise<import("./peerStore.js").PeerRecord>;
        /**
         * BLOQUEAR a alguien (dueño, 2026-10-05): un indicador PRIVADO, aparte de la calificación.
         * No se firma ni se publica —no es una opinión sobre esa persona, es tu decisión de no
         * recibirla—, viaja con el libro de contactos a tu bóveda y a tus aparatos, y lo respeta
         * cada app que recibe mensajes (el messenger, el primero). Desbloquear deja `false` y no
         * borra el campo: así el cambio también llega a los demás aparatos.
         * @param {HandlerParams} params  lo que llega por `postMessage` o la API: sin comprobar todavía
         */
        setBlocked({ publickey, blocked }: HandlerParams): Promise<import("./peerStore.js").PeerRecord>;
        /** @param {HandlerParams} params  lo que llega por `postMessage` o la API: sin comprobar todavía */
        setNickname({ publickey, nickname }: HandlerParams): Promise<import("./peerStore.js").PeerRecord>;
        /** @param {HandlerParams} params  lo que llega por `postMessage` o la API: sin comprobar todavía */
        setRating({ publickey, rating, notes }: HandlerParams): Promise<import("./peerStore.js").PeerRecord>;
        /** @param {HandlerParams} params  lo que llega por `postMessage` o la API: sin comprobar todavía */
        mergeEndorsements({ subject, endorsements, askerPubkey }: HandlerParams): Promise<{
            merged: number;
            total: number;
        }>;
        /** @param {HandlerParams} params  lo que llega por `postMessage` o la API: sin comprobar todavía */
        getRatingsForSubject({ subject }: HandlerParams): Promise<{
            mine: any;
            endorsements: any[];
        }>;
        /** @param {HandlerParams} params  lo que llega por `postMessage` o la API: sin comprobar todavía */
        recordQuery({ askerPubkey, subject }: HandlerParams): Promise<import("./peerStore.js").PeerRecord>;
        listPeers(): Promise<import("./peerStore.js").PeerRecord[]>;
        /** @param {HandlerParams} params  lo que llega por `postMessage` o la API: sin comprobar todavía */
        forgetPeer({ publickey }: HandlerParams): Promise<void>;
        /** @param {HandlerParams} params  lo que llega por `postMessage` o la API: sin comprobar todavía */
        addContact({ publickey, nickname, encryptionPubkey, lastToken, notes }: HandlerParams): Promise<import("./peerStore.js").PeerRecord>;
        /** @param {HandlerParams} params  lo que llega por `postMessage` o la API: sin comprobar todavía */
        updateContact({ publickey, patch }: HandlerParams): Promise<import("./peerStore.js").PeerRecord>;
        /** @param {HandlerParams} params  lo que llega por `postMessage` o la API: sin comprobar todavía */
        removeContact({ publickey }: HandlerParams): Promise<import("./peerStore.js").PeerRecord>;
        /**
         * Firma. Con `sign` en el acta, firma aquí mismo (como siempre). Si este dispositivo
         * RENUNCIÓ a firmar —o el master se lo quitó— la petición se re-enruta a quien sí
         * firma (tu bóveda) y vuelve su firma: la identidad de cara a los demás sigue siendo
         * UNA, y este aparato deja de poder firmar por ti aunque lo roben.
         *
         * El `identify` del transporte es la excepción y SIEMPRE se firma en local: es lo que
         * identifica esta conexión ante el proxy, no una firma tuya de cara a nadie, y sin él
         * el dispositivo no podría ni hablar con la bóveda para pedirle que firme.
         * @param {HandlerParams} params  lo que llega por `postMessage` o la API: sin comprobar todavía
         */
        signData({ data }: HandlerParams): Promise<{
            signature: string;
            publickey: string;
            profileId: string;
            chain: Acta.Acta[];
        }>;
        /**
         * UNA PRUEBA PARA ALGUIEN EN CONCRETO, Y POR UN RATO (`vault/assertion.js`).
         *
         * `signData` firma «esto lo firmé yo» y no dice para quién: el mismo sobre valía ante
         * el proxio y ante geo. Esto firma «esto lo firmé yo, PARA `aud`, contestando a
         * `nonce`, y vale hasta `exp`».
         *
         * Firma por el camino de siempre —`signData`—, y eso no es un atajo: así hereda el
         * re-enrutado a la bóveda cuando este aparato ya no firma por ti, y la prueba sale
         * igual desde el teléfono que desde el PC.
         *
         * QUÉ DATOS LLEVA. Solo los que el perfil YA comparte (`publicMe`), y nunca más de lo
         * que dan los alcances pedidos. La pantalla de permiso —donde se podrá conceder algo
         * oculto a un destinatario concreto— es la fase siguiente
         * (`dotrino-vault/docs/inicio-de-sesion.md`); hasta entonces esto no entrega nada que
         * no se entregue ya, que es la forma de no adelantar una decisión del usuario.
         */
        /**
         * QUÉ LE HAS CONCEDIDO A CADA APLICACIÓN. Es la mitad que hace que el permiso sea del
         * usuario y no un trámite: si no se puede ver ni retirar, conceder no significa nada.
         */
        listGrants(): Promise<{
            onBehalfOf?: string;
            origin: string;
            scopes: string[];
            at: number;
            lastUsed: number;
        }[]>;
        /**
         * Retirar lo concedido a una aplicación. La próxima vez que pida, se vuelve a preguntar.
         * `onBehalfOf` es obligatorio para las que piden por otro (el puente): retirar el permiso
         * de UNA no puede quitárselo a todas las que entran por el mismo sitio.
         * @param {HandlerParams} params  lo que llega por `postMessage` o la API: sin comprobar todavía
         */
        revokeGrant({ origin, onBehalfOf }?: HandlerParams): Promise<{
            ok: boolean;
        }>;
        /**
         * `onBehalfOf` es EN NOMBRE DE QUIÉN dice pedir el origen. Lo usa el puente OIDC, que
         * pide por una aplicación de fuera: sin esto, todas ellas se verían como una sola
         * entrada («Sso») y el usuario no sabría a quién le está dejando entrar.
         *
         * Es una AFIRMACIÓN del origen, no un hecho comprobable — y por eso se enseña siempre
         * subordinado a él («sso.dotrino.com dice: Tal App»), nunca en su lugar. Quien
         * responde por lo que pase sigue siendo el origen.
         * @param {HandlerParams} params  lo que llega por `postMessage` o la API: sin comprobar todavía
         */
        requestAssertion({ audience, nonce, scopes, ttlMs, onBehalfOf, __origin }?: HandlerParams): Promise<{
            assertion: {
                signature: string;
                publickey: string;
                chain: Acta.Acta[];
                v: number;
                op: string;
                sub: string;
                aud: string;
                nonce: string;
                iat: number;
                exp: number;
                scopes: string[];
                claims: Record<string, unknown>;
            };
        }>;
        /**
         * EL PAPEL NO CADUCA POR RELOJ: lleva el `seq` del acta con el que se emitió.
         *
         * `ttlMs`/`exp` se aceptan y se IGNORAN a propósito, para no romper a quien todavía los
         * pasa (el daemon, `enroll.js`). Reventar ahí dejaría sin emparejar a media cadena por
         * un parámetro que ya no significa nada.
         * @param {HandlerParams} params  lo que llega por `postMessage` o la API: sin comprobar todavía
         */
        signDelegation({ sub, scope, nonce, label, supersede }: HandlerParams): Promise<{
            cert: import("./capabilities.js").Delegation;
        }>;
        /**
         * Retira TODOS los certificados vigentes de un dispositivo (por su llave `sub`).
         * Es lo que significa «quitar el dispositivo»: revocar por `nonce` retira un papel,
         * no al aparato, que puede tener otros.
         * @param {HandlerParams} params  lo que llega por `postMessage` o la API: sin comprobar todavía
         */
        revokeDevice({ sub }: HandlerParams): Promise<{
            ok: boolean;
            seq: number;
            nonces: string[];
            rotated: {
                gen: number;
                sinLlave: Array<string | undefined>;
            };
            revokedAt: number;
        }>;
        /** @param {HandlerParams} params  lo que llega por `postMessage` o la API: sin comprobar todavía */
        revokeDelegation({ nonce }: HandlerParams): Promise<{
            ok: boolean;
            revokedAt: any;
        }>;
        listDelegations(): Promise<{
            issued: any[];
            revokedCerts: any[];
            revoked: {
                nonce: string;
                revokedAt: any;
            }[];
        }>;
        /**
         * Los perfiles de este dispositivo, para el conmutador. Incluye el AVATAR de cada uno:
         * sin él, la lista caía siempre al identicon automático y tu foto no aparecía —aunque la
         * hubieras subido— porque el avatar vive en el `me` de cada perfil, no en el registro.
         */
        listProfiles(): Promise<{
            login?: {
                user: any;
                address: any;
                volatile: boolean;
            };
            id: string;
            name: string;
            pubkey: string;
            avatar: any;
            current: boolean;
            pendingJoin: boolean;
            vault: boolean;
            approve: boolean;
            vaults: {
                comm: string | null;
                master: string;
                id: string;
                label: string;
            }[];
        }[]>;
        currentProfile(): Promise<{
            id: string;
            name: any;
            pubkey: string;
        }>;
        /**
         * Crea una cuenta más en este dispositivo, con su propia llave.
         *
         * `forVault: true` la marca como **nacida para adoptar** la cuenta de una bóveda
         * (camino B): es el único permiso que acepta `joinProfile`, y se consume al unirse.
         * Sin la marca, la cuenta es de este dispositivo y nadie se la puede llevar.
         * @param {HandlerParams} params  lo que llega por `postMessage` o la API: sin comprobar todavía
         */
        createProfile({ name, forVault }?: HandlerParams): Promise<{
            id: string;
            name: any;
            pubkey: string;
            pendingJoin: boolean;
        }>;
        /** @param {HandlerParams} params  lo que llega por `postMessage` o la API: sin comprobar todavía */
        switchProfile({ id }?: HandlerParams): Promise<{
            id: any;
        }>;
        /** @param {HandlerParams} params  lo que llega por `postMessage` o la API: sin comprobar todavía */
        renameProfile({ id, name }?: HandlerParams): Promise<{
            id: string;
            name: string;
        }>;
        /**
         * BORRAR UNA CUENTA, también la activa y también la única (dueño, 2026-10-05): borrar tu
         * cuenta desde la app es un derecho del usuario, y la App Store lo exige (norma 5.1.1(v)).
         * La alerta es de la INTERFAZ, que pregunta antes. Si era la activa, `current` dice cuál
         * queda, y la app tiene que RECARGAR; si no queda ninguna, el arranque estrena una nueva
         * y vacía (ver `purgeProfile`).
         * @param {HandlerParams} params  lo que llega por `postMessage` o la API: sin comprobar todavía
         */
        deleteProfile({ id }?: HandlerParams): Promise<{
            wasCurrent: boolean;
            ok: boolean;
            current: string;
        }>;
        /**
         * ENTRAR en un aparato de tu cuenta desde un navegador que no te conoce, con
         * `nombre@AB12-CD34-EF56` y la contraseña. Al volver, ESTE navegador es ese aparato y la
         * app tiene que RECARGAR, como con cualquier cambio de cuenta.
         *
         * `remember: false` (lo normal en un equipo prestado) deja la cuenta en MEMORIA: se va
         * al cerrar o recargar esta pestaña, y el disco de esa máquina queda como estaba. Con
         * `true` se guarda como cualquier otra cuenta de este navegador —la llave como
         * `CryptoKey` no extraíble, nunca en claro— hasta que salgas.
         *
         * La contraseña NO viaja: lo que viaja son los mensajes de OPAQUE, que no la llevan ni
         * dejan adivinarla (`@dotrino/vault/login-client`).
         * @param {HandlerParams} params  lo que llega por `postMessage` o la API: sin comprobar todavía
         */
        loginWithPassword({ address, password, remember, label, proxyUrl }?: HandlerParams): Promise<{
            id: string;
            name: any;
            address: any;
            user: any;
            sid: any;
            volatile: boolean;
        }>;
        /**
         * SALIR del inicio de sesión con contraseña: se le dice a la bóveda que suelte la plaza
         * y la cuenta desaparece de este navegador. Sin `id`, el activo.
         * @param {HandlerParams} params  lo que llega por `postMessage` o la API: sin comprobar todavía
         */
        logoutLogin({ id }?: HandlerParams): Promise<{
            ok: boolean;
            told: any;
            current: string;
        }>;
        profileActa(): Promise<{
            acta: Acta.Acta;
            isMaster: boolean;
            myCaps: string[];
        }>;
        /**
         * LA CADENA DE SELLADORES, para mandarla junto con una firma.
         *
         * Es lo que deja a un EXTRAÑO comprobar que quien firmó habla por esta identidad, sin
         * preguntarle a nadie: `[génesis, …cambios de sellador…, acta actual]`. No son todas
         * las actas —eso crecería con cada emparejamiento— sino solo los eslabones donde
         * cambió quién sella, que casi nunca pasa. Lo normal es longitud 1: el génesis.
         *
         * Una cuenta de una sola bóveda devuelve SIEMPRE eso y nada más, y no puede quedarse
         * obsoleta: su conjunto de selladores no puede cambiar, porque el único no puede
         * quitarse a sí mismo y no hay otro que se lo quite.
         *
         * SIN GÉNESIS, la cadena es `[acta actual]` y vale igual mientras la actual esté firmada
         * por la llave del perfil: la raíz la ancla esa llave, no el número 1 (`verifySealerChain`).
         * Pasa en las cuentas anteriores a v5, cuyo génesis se podó sin la marca de eslabón.
         */
        sealerChain(): Promise<Acta.Acta[]>;
        /**
         * Quien sella sobres de secretos (la bóveda) registra aquí cómo estrenar su LLAVE DE
         * SELLADO: una función que crea el par, se guarda la privada y devuelve la pública. Se
         * llama al sellar cada acta, que es cuando esa llave rota (§8.9).
         *
         * Es opt-in a propósito: una identidad de navegador no sella nada, y un acta sin llave
         * de sellado es perfectamente válida.
         * @param {HandlerParams} params  lo que llega por `postMessage` o la API: sin comprobar todavía
         */
        setSealKeyProvider({ provider }?: HandlerParams): {
            ok: boolean;
            set: boolean;
        };
        /**
         * Estrena la llave de sellado sin tocar a nadie más: pide una al proveedor y la nombra
         * en un acta nueva. Es lo que hace la bóveda al arrancar si el acta no tiene llave, o
         * si la que nombra no es suya (el disco se restauró, otro master la puso…).
         */
        rotateSealKey(): Promise<{
            ok: boolean;
            seq: number;
            sealPub: string;
        }>;
        /**
         * La llave con la que se firmaron los sobres de un acta dada. Para VERIFICARLOS.
         * @param {HandlerParams} params  lo que llega por `postMessage` o la API: sin comprobar todavía
         */
        sealKeyAt({ seq, vault }?: HandlerParams): string;
        profileMembers(): Promise<{
            members: any[];
            profileId: any;
            seq: number;
            sealers: any[];
            updatedAt?: undefined;
        } | {
            members: {
                pub: string;
                id: string;
                label: string;
                cn: string;
                isService: boolean;
                caps: string[];
                addedAt: number;
                machine: {
                    kind: string;
                    os: string;
                    name: string;
                };
                vault: string;
                isMe: boolean;
                isMaster: boolean;
                encPub: string;
                canSeal: boolean;
            }[];
            profileId: string;
            seq: number;
            sealers: string[];
            updatedAt: number;
        }>;
        myMembership(): Promise<{
            inProfile: boolean;
            profileId?: undefined;
            seq?: undefined;
            isMaster?: undefined;
            caps?: undefined;
            id?: undefined;
        } | {
            inProfile: boolean;
            profileId: string;
            seq: number;
            isMaster: boolean;
            caps: string[];
            id: string;
        }>;
        isMaster(): Promise<boolean>;
        /**
         * Registra la llave de CIFRADO de un miembro ya admitido (solo el master).
         *
         * Es la alternativa a expulsarlo y volver a admitirlo: un servicio re-enrolado
         * estrena pubkey, y su cajón de variables va indexado por la vieja, así que
         * arrancaría sin configuración y sin decirlo. Esto le pone la llave sin moverle
         * nada más.
         * @param {HandlerParams} params  lo que llega por `postMessage` o la API: sin comprobar todavía
         */
        setMemberEncPub({ pub, encPub }?: HandlerParams): Promise<{
            ok: boolean;
            seq: number;
        }>;
        /**
         * Admite un miembro (solo el master). El cert lo emite quien llama, antes o después.
         * `continuity`: si esa identidad ya existía por su cuenta, su puente firmado (F3).
         * @param {HandlerParams} params  lo que llega por `postMessage` o la API: sin comprobar todavía
         */
        admitMember({ pub, encPub, label, cn, caps, cert, continuity, machine, vault }?: HandlerParams): Promise<{
            ok: boolean;
            seq: number;
            wrapped: boolean;
        }>;
        /**
         * DE QUÉ BÓVEDA ES una llave de comunicación (`vault`: su maestra). La pone la propia
         * bóveda a la llave que entró antes de existir el campo; sin él, con dos bóvedas en la
         * cuenta no hay forma de escribirle a una sola.
         * @param {HandlerParams} params  lo que llega por `postMessage` o la API: sin comprobar todavía
         */
        setMemberVault({ pub, vault }?: HandlerParams): Promise<{
            ok: boolean;
            seq: number;
        }>;
        /** @param {HandlerParams} params  lo que llega por `postMessage` o la API: sin comprobar todavía */
        setCaps({ pub, caps }?: HandlerParams): Promise<{
            ok: boolean;
            seq: number;
        }>;
        /**
         * LOS PERMISOS DE VARIOS APARATOS EN UNA SOLA ACTA (dueño, 2026-09-26). Editar tres
         * aparatos eran tres actas y tres avisos; ahora el borrador entero se sella de golpe.
         * `changes`: `[{ pub, caps }]`, cada `caps` la lista COMPLETA de ese aparato.
         * @param {{ changes?: Array<{ pub: string, caps?: string[], cn?: string | null }> }} [args]  lo que llega por `postMessage` o la API: sin comprobar todavía
         */
        setCapsMany({ changes }?: {
            changes?: Array<{
                pub: string;
                caps?: string[];
                cn?: string | null;
            }>;
        }): Promise<{
            ok: boolean;
            seq: number;
            wrapped: number;
        }>;
        /**
         * RENOMBRA un miembro (el nombre con el que lo reconoces). Se escribe en el acta y
         * TAMBIÉN en la delegación: son dos registros distintos —el acta dice quién es del
         * perfil, las delegaciones qué certs se emitieron— y las listas de dispositivos leen
         * la segunda, así que tocar solo una deja el nombre viejo a la vista.
         * @param {HandlerParams} params  lo que llega por `postMessage` o la API: sin comprobar todavía
         */
        setLabel({ pub, label }?: HandlerParams): Promise<{
            ok: boolean;
            seq: number;
            label: string;
            delegations: number;
        }>;
        /** @param {HandlerParams} params  lo que llega por `postMessage` o la API: sin comprobar todavía */
        removeMember({ pub }?: HandlerParams): Promise<{
            ok: boolean;
            seq: number;
            nonces: string[];
            rotated: {
                gen: number;
                sinLlave: Array<string | undefined>;
            };
            revokedAt: number;
        }>;
        /**
         * Traspasa el master a otro miembro. Admitir y nombrar van en el MISMO seq: el nuevo
         * sellador tiene que ser miembro para poder serlo, y así no hay ventana intermedia.
         * Cubre igual dispositivo → bóveda y bóveda → bóveda (mudarse de PC).
         */
        /**
         * CEDER EL MANDO = CONCEDER `sella`. Ya no hay traspaso: sellar es un permiso, así que
         * «pasarle el mando a otro» es dárselo, y punto. Lo que ANTES hacía esto —dejar de
         * poder sellar uno mismo, en el mismo acto— ya no se puede: nadie se quita el sello a
         * sí mismo (dejaría un acta que él firma sin poder firmarla). Si quieres salir, se lo
         * pides al otro cuando ya pueda sellar.
         * @param {HandlerParams} params  lo que llega por `postMessage` o la API: sin comprobar todavía
         */
        handoverMaster({ to, member }?: HandlerParams): Promise<{
            ok: boolean;
            seq: number;
            sealers: string[];
        }>;
        /**
         * RENUNCIA (§2.2): este dispositivo se quita capacidades a sí mismo. No pasa por el
         * master —por eso funciona con la bóveda apagada, que es justo cuando hace falta (te
         * robaron el aparato)— y solo puede QUITAR, así que cualquiera puede honrarla.
         * @param {HandlerParams} params  lo que llega por `postMessage` o la API: sin comprobar todavía
         */
        renounceCaps({ caps }?: HandlerParams): Promise<{
            ok: boolean;
            record: Acta.RenounceRecord;
            caps: string[];
        }>;
        /**
         * Absorbe en el acta una renuncia ajena ya verificada (solo el master).
         * @param {HandlerParams} params  lo que llega por `postMessage` o la API: sin comprobar todavía
         */
        absorbRenounce({ record }?: HandlerParams): Promise<{
            ok: boolean;
            seq: number;
        }>;
        /**
         * La clave de contenido de este perfil, ya abierta con la llave de cifrado de este
         * dispositivo. `null` si todavía no te la han envuelto (o si te expulsaron).
         */
        contentKey(): Promise<{
            gen: number;
            cek: string;
        }>;
        /**
         * Cifra algo con la clave de contenido del perfil. Devuelve el sobre MARCADO
         * `{ t: 'dotrino-cek', gen, iv, ct }` (la marca deja a la bóveda reconocerlo y volver a
         * cerrarlo al rotar). La llave privada de cifrado NUNCA sale de aquí.
         * @param {HandlerParams} params  lo que llega por `postMessage` o la API: sin comprobar todavía
         */
        sealContent({ plaintext }?: HandlerParams): Promise<Content.CekEnvelope>;
        /**
         * Abre un sobre SELLADO A ESTE APARATO: primero la envoltura de la llave —con la
         * privada de cifrado de este dispositivo, que nunca sale de aquí— y con ella el sobre.
         *
         * Es lo que deja a un aparato de administración VER un secreto de la bóveda **sin
         * teclear ninguna contraseña** (§8.2 de `dotrino-vault/docs/secretos-sellados.md`):
         * la capacidad de leer deja de ser una frase que se escribe en cualquier parte y pasa
         * a ser una llave que no se mueve del aparato.
         *
         * Distinto de `openContent`, que usa el llavero del PERFIL (el contenido del usuario);
         * aquí la envoltura viene suelta, del llavero de un cajón de secretos.
         * @param {HandlerParams} params  lo que llega por `postMessage` o la API: sin comprobar todavía
         */
        openSealedValue({ wrap, envelope }?: HandlerParams): Promise<string>;
        /**
         * RE-ENVUELVE para otro miembro una llave que este aparato ya puede abrir.
         *
         * Es lo que permite completar a un aparato que entró tarde **sin la frase del
         * perfil y sin que la bóveda tenga que abrir nada**: quien administra ya tiene su
         * envoltura de ese cajón —por eso puede pulsar «Ver»—, así que abre la llave con la
         * suya, que no sale de este dispositivo, y la vuelve a envolver para la pública del
         * recién llegado.
         *
         * No regala nada: quien hace esto ya podía leer ese cajón, y a quien se lo entrega
         * es a alguien que el ACTA —firmada por la maestra— ya reconoce como miembro. La
         * autorización es el acta; esto solo es el sobre.
         *
         * @param {{ wrap?: any, encPub?: string }} [o] `wrap`: mi envoltura · `encPub`: la
         *   pública de cifrado del miembro al que hay que envolvérsela. Llega sin comprobar.
         * @returns {Promise<any>} la envoltura nueva, para que la bóveda la guarde.
         */
        rewrapFor({ wrap, encPub }?: {
            wrap?: any;
            encPub?: string;
        }): Promise<any>;
        /**
         * Abre un sobre de contenido con el llavero del perfil (todas las generaciones).
         * @param {HandlerParams} params  lo que llega por `postMessage` o la API: sin comprobar todavía
         */
        openContent({ envelope }?: HandlerParams): Promise<string>;
        /**
         * Rota la clave de contenido: generación nueva envuelta solo a los miembros de ahora.
         * Corta el acceso al contenido FUTURO de quien ya no está; lo que ya leyó, ya lo leyó.
         */
        rotateContentKey(): Promise<{
            gen: number;
            sinLlave: string[];
            ok: boolean;
        }>;
        /**
         * Las actas que este master conserva desde `sinceSeq` (sin incluirla), para que un
         * miembro que volvió pueda comprobar el encadenamiento. Vacío si se salió de la ventana.
         *
         * SOLO SE MANDA CUANDO HACE FALTA, que es casi nunca. `canAdopt` adopta el acta actual
         * DE UN SALTO —sin mirar un solo eslabón— siempre que la haya sellado quien el que
         * pregunta tiene por sellador; el `prev` solo se comprueba cuando la nueva es contigua,
         * donde por definición no hay cadena que mandar. El único caso en que los eslabones
         * resuelven algo es un TRASPASO de master durante el hueco: ahí el acta actual la firmó
         * alguien que él no conoce, y el acta del traspaso —firmada por el sellador que sí
         * conocía— es el puente.
         *
         * No es una optimización cosmética: cada acta es un snapshot COMPLETO de los miembros
         * (~940 bytes por miembro), así que la ventana crece con cambios × miembros y llegó a
         * pesar 991 KB de una respuesta de 1,03 MB. El proxio corta el frame a 1 MB, cerraba la
         * conexión de la bóveda con un 1009 y la dejaba muda para TODO el ecosistema, sin un
         * solo log de su lado (2026-08-24: el bot social dejó de publicar y eco se quedó sin un
         * eco que mostrar).
         * @param {HandlerParams} params  lo que llega por `postMessage` o la API: sin comprobar todavía
         */
        actaHistory({ sinceSeq }?: HandlerParams): Promise<{
            chain: Acta.Acta[];
            window: number;
        }>;
        /**
         * LOS QUE ESTUVIERON Y YA NO ESTÁN: las llaves de las actas que guarda la ventana del
         * historial (`ACTA_WINDOW`) que el acta actual ya no nombra. La bóveda les contesta, solo
         * a ellos y solo con su aviso de expulsión, para que se borren aunque no les llegara.
         * Fuera de la ventana no se sabe nada, y no se inventa.
         */
        pastMembers(): Promise<{
            members: {
                pub: any;
                lastSeq: any;
            }[];
        }>;
        /**
         * MI tarjeta de perfil: lo mínimo que se le pasa a un contacto para que pueda cifrarme a
         * todos mis dispositivos (perfil, versión y llaves de cifrado). Sin etiquetas, sin
         * permisos, sin certificados: lo demás no es asunto de nadie.
         */
        profileCard(): Promise<Acta.ProfileCard>;
        /**
         * Guarda la tarjeta de OTRA persona en su ficha de contacto. La primera vez se acepta
         * (es el mismo criterio con el que agregaste el contacto); después solo si no retrocede
         * y la firmó el mismo master. Si el master cambió, se avisa en vez de aceptarlo callando.
         * @param {HandlerParams} params  lo que llega por `postMessage` o la API: sin comprobar todavía
         */
        adoptPeerCard({ card }?: HandlerParams): Promise<{
            adopted: boolean;
            reason: string;
            devices: any;
        }>;
        /**
         * Adopta un acta que llega de otro miembro (gana el seq mayor; a igual seq, el traspaso).
         * @param {HandlerParams} params  lo que llega por `postMessage` o la API: sin comprobar todavía
         */
        adoptActa({ acta }?: HandlerParams): Promise<{
            adopted: boolean;
            expelled: boolean;
            reason: string;
            seq: number;
        } | {
            adopted: boolean;
            reason: string;
            seq: number;
        }>;
        /**
         * Adopta una cadena completa (para ponerse al día tras estar apagado).
         * @param {HandlerParams} params  lo que llega por `postMessage` o la API: sin comprobar todavía
         */
        adoptActaChain({ chain }?: HandlerParams): Promise<any>;
        /**
         * Se pone al día por la cadena de selladoras (`adoptSealerChainNow`).
         * @param {HandlerParams} params  lo que llega por `postMessage` o la API: sin comprobar todavía
         */
        adoptActaBySealerChain({ sealerChain }?: HandlerParams): Promise<{
            adopted: boolean;
            expelled: boolean;
            reason: string;
            seq: number;
        } | {
            adopted: boolean;
            reason: string;
            seq: number;
            expelled?: undefined;
        }>;
        /**
         * Completa el historial con las actas que falten detrás de la vigente (`fillHistoryNow`).
         * @param {HandlerParams} params  lo que llega por `postMessage` o la API: sin comprobar todavía
         */
        fillActaHistory({ actas }?: HandlerParams): Promise<{
            added: number;
        }>;
        /**
         * Las últimas actas que guardo, con la vigente: lo que otra bóveda necesita para rellenar.
         * @param {HandlerParams} params  lo que llega por `postMessage` o la API: sin comprobar todavía
         */
        recentActas({ count }?: HandlerParams): Promise<{
            actas: Acta.Acta[];
        }>;
        /**
         * Une este dispositivo al perfil de otra bóveda (solo si aquí no hay nada que perder).
         * @param {HandlerParams} params  lo que llega por `postMessage` o la API: sin comprobar todavía
         */
        joinProfile({ acta }?: HandlerParams): Promise<{
            joined: boolean;
            reason: string;
            profileId?: undefined;
            seq?: undefined;
            members?: undefined;
        } | {
            joined: boolean;
            reason: string;
            profileId: any;
            seq: number;
            members?: undefined;
        } | {
            joined: boolean;
            reason: string;
            profileId: string;
            seq: number;
            members: number;
        } | {
            joined: boolean;
            profileId: any;
            seq: any;
            reason?: undefined;
            members?: undefined;
        }>;
        /**
         * Empareja este dispositivo con una bóveda.
         *
         * `join` dice **de qué cuenta estamos hablando** (V7: la intención es explícita, nunca
         * se adivina):
         *   · `'new'`     → camino B: crea aquí una cuenta más, con llave nueva, y ES ESA la que
         *                   entra al acta de la bóveda. La que estabas usando **no se toca**.
         *                   Con dos frenos, porque una cuenta más solo vale si de verdad es
         *                   otra: si ESTE dispositivo ya tiene la cuenta de esa bóveda, no nace
         *                   ninguna (se re-empareja la que hay, o se avisa con `ALREADY_PAIRED`
         *                   de que vive en otra cuenta de aquí); y si el intento falla, la que
         *                   nació para él se descarta en vez de quedarse de fantasma.
         *   · `'current'` → sigue con la cuenta abierta. Solo vale si nació para adoptar
         *                   (`forVault`) o si ya está emparejada con ESA misma bóveda
         *                   (re-emparejar). En cualquier otro caso falla **antes de tocar la
         *                   red**, en vez de traerse un acta ajena y pisar la tuya.
         *   · `'adopt'`    → camino A: la cuenta que YA vive en este aparato pasa a vivir en la
         *                   bóveda. Sigue siendo la misma cuenta para todo el mundo (mismo
         *                   `profileId`); lo que cambia es quién sella. Solo puede hacerlo el
         *                   master: si esta cuenta ya la manda otra bóveda, no hay nada que
         *                   regalar y falla en voz alta.
         * @param {HandlerParams} params  lo que llega por `postMessage` o la API: sin comprobar todavía
         */
        vaultPair({ qr, label, join, machine, account, requireCaps }: HandlerParams): Promise<{
            ok: boolean;
            adopted: boolean;
            profileId: string;
            seq: any;
            master: string;
            deviceId: string;
        } | {
            ok: boolean;
            deviceId: string;
            master: string;
            seq: any;
            scope: any;
            join: {
                joined: boolean;
                reason: string;
                profileId?: undefined;
                seq?: undefined;
                members?: undefined;
            } | {
                joined: boolean;
                reason: string;
                profileId: any;
                seq: number;
                members?: undefined;
            } | {
                joined: boolean;
                reason: string;
                profileId: string;
                seq: number;
                members: number;
            } | {
                joined: boolean;
                profileId: any;
                seq: any;
                reason?: undefined;
                members?: undefined;
            };
        }>;
        /**
         * CAMINO A — «esta cuenta que tengo aquí, que la guarde mi computadora».
         *
         * La cuenta no se muda ni se copia: sigue siendo la misma (mismo `profileId`, misma
         * reputación, lo mismo firmado). Lo único que cambia es **quién sella el acta**. Este
         * aparato admite a la bóveda como miembro, le envuelve la clave de contenido para que
         * pueda leer lo que ya hay, y le traspasa el mando — los tres cambios en un **único
         * `seq`**, que es la regla que existe justamente para que no haya un momento raro en
         * el que la cuenta tenga dos sellador​es o ninguno.
         *
         * Requisito (§2 del doc): solo puede hacerlo el master. Si esta cuenta ya la manda otra
         * bóveda, este aparato no puede regalar lo que no tiene; el traspaso se hace desde la
         * que manda hoy.
         * @param {HandlerParams} params  lo que llega por `postMessage` o la API: sin comprobar todavía
         */
        vaultAdopt({ qr, label, machine }?: HandlerParams): Promise<{
            ok: boolean;
            adopted: boolean;
            profileId: string;
            seq: any;
            master: string;
            deviceId: string;
        }>;
        /**
         * Marca este perfil como **nacido para adoptar** la cuenta de otro (la marca que
         * `joinProfile` exige, §5.1). Lo usa la BÓVEDA al abrir un perfil vacío para el camino
         * A: sin la marca, adoptar la cuenta del aparato se leería como pisar una cuenta con
         * datos y se rechazaría, que es exactamente lo que tiene que pasar cuando nadie lo pidió.
         */
        prepareForAdoption(): Promise<{
            ok: boolean;
            pending: boolean;
        }>;
        /**
         * La página dice dónde corre (`machine.js`); se manda con los pedidos a la bóveda.
         * @param {HandlerParams} [args]  lo que llega por `postMessage` o la API: sin comprobar todavía
         */
        setMachine({ machine }?: HandlerParams): Promise<{
            ok: boolean;
        }>;
        vaultStatus(): Promise<{
            paired: boolean;
            deviceId?: undefined;
            master?: undefined;
            proxy?: undefined;
            scope?: undefined;
            seq?: undefined;
            pairedAt?: undefined;
        } | {
            paired: boolean;
            deviceId: string;
            master: string;
            proxy: string;
            scope: any;
            seq: any;
            pairedAt: number;
        }>;
        vaultUnpair(): Promise<{
            ok: boolean;
        }>;
        /** @param {HandlerParams} params  lo que llega por `postMessage` o la API: sin comprobar todavía */
        vaultSign({ payload }: HandlerParams): Promise<{
            signature: string;
            publickey: string;
        }>;
        /**
         * Store DELEGADO, CIFRADO de punta a punta. Los argumentos y el resultado viajan
         * cifrados con la clave de contenido del perfil: el proxy transporta pero no ve nada
         * de lo que guardas.
         *
         * Sin la clave NO se manda nada. Antes iba en claro «como antes», y eso era dejar que
         * el proxio leyera el almacén entero justo en el aparato al que todavía no le habían
         * envuelto la clave. Ahora falla con `no-content-key`, que se arregla entrando al
         * perfil desde un aparato que ya la tenga — y se ve, en vez de viajar a la vista.
         * Por lo mismo, una respuesta sin cifrar tampoco se acepta.
         * @param {HandlerParams} params  lo que llega por `postMessage` o la API: sin comprobar todavía
         */
        vaultStore({ method, args, wake }: HandlerParams): Promise<any>;
        /**
         * CONSOLA REMOTA: administrar el perfil desde este dispositivo (ver
         * `dotrino-vault/docs/consola-remota.md`). Requiere que el cert de este aparato
         * lleve `vault:admin`, que **no se recibe al emparejar**: se concede a mano en la
         * bóveda (`dotrino-vault caps <ID> +admin`).
         *
         * `op`: `pending` · `pair` · `approve` · `reject` · `revoke` · `audit`. Cambiar
         * permisos y traspasar el mando NO están, y no es un olvido: eso sigue siendo del
         * master, en su máquina.
         * @param {HandlerParams} params  lo que llega por `postMessage` o la API: sin comprobar todavía
         */
        vaultAdmin({ op, to, ...rest }?: HandlerParams): Promise<any>;
        /**
         * PEDIDOS DE APROBACIÓN: lo que le toca al teléfono cuando un cajón de la bóveda exige
         * el visto bueno por uso. `op`: `approvals` (listar) · `approve` · `deny` (con `id`).
         * Requiere `vault:approve` en el cert, que se concede a mano (`caps <ID> +approve`).
         *
         * `profile` apunta a OTRA cuenta de este mismo dispositivo (ver `vaultApprovalsAll`):
         * sin él es la activa, como siempre.
         * @param {HandlerParams} params  lo que llega por `postMessage` o la API: sin comprobar todavía
         */
        vaultApprovals({ op, id, profile, notify }?: HandlerParams): Promise<any>;
        /**
         * LOS PEDIDOS DE TODAS TUS CUENTAS, SIN CAMBIARTE DE CUENTA.
         *
         * El timbre del teléfono no dice a qué perfil llamó —viaja por FCM, o sea por Google, y
         * ahí no se mete nada que identifique al dueño—, así que la pantalla de Pedidos tiene
         * que mirar en todos los que aprueban. Antes lo hacía cambiando el perfil activo y
         * recargando la página una vez por cuenta: funcionaba y era insufrible, porque el avatar
         * y el icono de la app cambiaban dos o tres veces por abrir la pantalla (dueño,
         * 2026-09-10: «rotan los perfiles, cambia el icono y es molesto»).
         *
         * Y era innecesario: **este iframe tiene las llaves de todos los perfiles**. Cada cuenta
         * guarda la suya en el mismo almacén, bajo su propio nombre, y son `CryptoKey` NO
         * EXTRAÍBLES: se puede firmar con ellas sin verlas y sin tocar cuál es la activa. Eso es
         * justo lo que hace falta, y es lo único que se hace aquí.
         *
         * Lo que NO hace, a propósito: no renueva certificados ajenos ni borra enlaces ajenos
         * (eso escribe, y escribir en otra cuenta desde la pantalla de otra es pedir un lío).
         * Mirar es de solo lectura; si el papel de una cuenta está desfasado, se dice y punto.
         *
         * @param {HandlerParams} params  lo que llega por `postMessage` o la API: sin comprobar todavía
         * @returns {Promise<Array<{ profile: string, name: string, current: boolean, items: any[], notices?: any[], error?: string }>>} una entrada por cuenta que
         *   aprueba — con sus pedidos, o con el motivo por el que no se pudo preguntar.
         */
        vaultApprovalsAll({ notify }?: HandlerParams): Promise<Array<{
            profile: string;
            name: string;
            current: boolean;
            items: any[];
            notices?: any[];
            error?: string;
        }>>;
        /**
         * PUSH DE LA APP NATIVA: registra el token (FCM/APNs) de este aparato en el proxio,
         * bajo la llave del dispositivo, para que la bóveda pueda «timbrarlo» cuando haya
         * un pedido. La app nativa le pasa el token a la página; la página lo trae aquí.
         * @param {HandlerParams} params  lo que llega por `postMessage` o la API: sin comprobar todavía
         */
        registerPush({ kind, token }?: HandlerParams): Promise<{
            ok: boolean;
            kind: any;
        }>;
        /** ¿Puede ESTE dispositivo aprobar pedidos? Mismo criterio que `canAdminVault`. */
        canApproveVault(): Promise<any>;
        /**
         * ¿Puede ESTE dispositivo administrar el perfil a distancia? Sale del scope del
         * cert que le dio la bóveda, no de una preferencia: la interfaz pregunta para
         * saber qué pintar, pero quien decide es la bóveda al recibir la petición.
         */
        canAdminVault(): Promise<any>;
        /**
         * `to`: A UNA BÓVEDA CONCRETA de la cuenta (su llave de comunicación), la que la pantalla
         * administra. Sin él contesta la que emitió mi papel. Antes la lista iba siempre a esa,
         * aunque la consola administrara la otra: la cabecera era de la Nube y los aparatos, sus
         * papeles y sus versiones eran del PC (2026-10-27: «parece que mezcla cosas»).
         * @param {HandlerParams} params  lo que llega por `postMessage` o la API: sin comprobar todavía
         */
        listVaultDevices({ to }?: HandlerParams): Promise<{
            acta: Acta.Acta;
            devices: any;
            siblingCerts: any;
            revoked: any;
            chain: any;
            sealerChain: any;
        }>;
        /**
         * Lo que este dispositivo presenta al identificarse ante el proxy: su cert de
         * delegación y su ACTA de perfil. Con el cert, el proxy enruta lo dirigido a la
         * maestra; con el acta, lo dirigido a la PERSONA (cualquiera de sus dispositivos).
         * Sin secretos: las dos cosas son públicas y auto-verificables.
         */
        getVaultCert(): Promise<{
            cert: any;
            master: string;
            acta: Acta.Acta;
        }>;
        listContacts(): Promise<import("./peerStore.js").PeerRecord[]>;
        /** @param {HandlerParams} params  lo que llega por `postMessage` o la API: sin comprobar todavía */
        setMyNickname({ nickname }: HandlerParams): Promise<{
            me: Record<string, any>;
        }>;
        /** @param {HandlerParams} params  lo que llega por `postMessage` o la API: sin comprobar todavía */
        updateMe({ patch }?: HandlerParams): Promise<{
            me: Record<string, any>;
        }>;
        getMe(): Promise<Record<string, any>>;
        /**
         * CÓMO FUE EL ÚLTIMO EMPUJÓN del perfil a la bóveda. Existe para que la interfaz pueda
         * decir «esto no se guardó» en vez de enseñar tan tranquila un perfil que solo vive en
         * este aparato — que es lo que pasaba cuando el fallo se tragaba.
         * `{ ok, at, error }`.
         */
        profilePushState(): Promise<{
            ok: boolean | null;
            at: number;
            error: string | null;
        }>;
        publicMe(): Promise<Record<string, any>>;
        getEncryptionPubkey(): Promise<string>;
        /**
         * Cifra para uno o varios destinatarios. Dos cosas que cambian respecto de antes:
         *
         * 1. **El sobre va atado a la LLAVE, no a la conexión.** Cada envoltura se indexa por un
         *    id derivado de la llave de cifrado del destinatario, en vez del token del proxy: así
         *    puede abrirla también un dispositivo que no estaba conectado cuando se envió.
         * 2. **Se cifra a TODOS los dispositivos de esa persona**, si conocemos su tarjeta de
         *    perfil (§tarjeta). Le escribes a la persona, no al aparato desde el que te habló.
         * @param {HandlerParams} params  lo que llega por `postMessage` o la API: sin comprobar todavía
         */
        encrypt({ recipients, plaintext }: HandlerParams): Promise<{
            v: number;
            iv: string;
            ct: string;
            wrap: Record<string, {
                iv: string;
                ct: string;
            }>;
        }>;
        /**
         * Descifra. Busca MI envoltura por el id de mi llave de cifrado (v2); `myToken` ya no
         * hace falta y se acepta solo por compatibilidad de llamada.
         * @param {HandlerParams} params  lo que llega por `postMessage` o la API: sin comprobar todavía
         */
        decrypt({ senderEncryptionPubkey, myToken, envelope }: HandlerParams): Promise<{
            plaintext: string;
        }>;
        exportIdentity(): Promise<{
            version: number;
            privateJwk: any;
            publicJwk: any;
            encPrivateJwk: any;
            encPublicJwk: any;
            me: Record<string, any>;
            peers: import("./peerStore.js").PeerBook;
            exportedAt: string;
        }>;
        /** @param {HandlerParams} params  lo que llega por `postMessage` o la API: sin comprobar todavía */
        syncConnect({ clientId }: HandlerParams): Promise<any>;
        syncDisconnect(): Promise<any>;
        /** @param {HandlerParams} params  lo que llega por `postMessage` o la API: sin comprobar todavía */
        syncUnlock({ passphrase }: HandlerParams): Promise<any>;
        syncLock(): Promise<any>;
        syncStatus(): Promise<any>;
        syncNow(): Promise<any>;
        /** @param {HandlerParams} params  lo que llega por `postMessage` o la API: sin comprobar todavía */
        importIdentity({ privateJwk, publicJwk, encPrivateJwk, encPublicJwk, me: meIn, peers: peersIn }: HandlerParams): Promise<{
            me: any;
        }>;
    };
    readonly me: Record<string, any>;
    /** ¿Está la maestra bajo llave? Cerrada, esta identidad NO puede firmar nada. */
    readonly masterLocked: boolean;
    /** Echa el candado a la maestra que ya existía (al abrir el perfil). Idempotente. */
    sealMasterKey: () => Promise<{
        ok: boolean;
        reason: string;
        already?: undefined;
        sealed?: undefined;
    } | {
        ok: boolean;
        already: boolean;
        reason?: undefined;
        sealed?: undefined;
    } | {
        ok: boolean;
        sealed: boolean;
        reason?: undefined;
        already?: undefined;
    }>;
    /** Quita del acta, en una sola, los aparatos cuyo papel ya no tiene vuelta atrás. */
    pruneExpiredDevices: (now?: number) => Promise<{
        removed: {
            pub: string;
            label: any;
        }[];
        seq: number;
    }>;
    /** Al abrir: nombra mi llave de cifrado y envuelve la clave de contenido a quien le falte. */
    completeKeyring: () => Promise<{
        named: boolean;
        wrapped: string[];
        seq: number;
    }>;
    /** Recarga el par tras abrir el candado, sin reabrir la identidad entera. */
    reloadMasterKey(): Promise<{
        locked: boolean;
    }>;
    sync: any;
    /**
     * Adoptar un aparato que acaba de entrar con usuario y contraseña. Lo normal es llamar
     * al handler `loginWithPassword`, que primero HABLA con la bóveda; esto es solo la
     * segunda mitad —instalar lo que salió de ahí—, y vive en el objeto del núcleo (no en
     * `handlers`) porque ninguna aplicación tiene por qué poder instalar una identidad.
     */
    adoptLogin: (entrada: any, { remember, proxy }?: {
        remember?: boolean;
        proxy?: string | null;
    }) => Promise<{
        id: string;
        name: any;
        address: any;
        user: any;
        sid: any;
        volatile: boolean;
    }>;
    /**
     * La bóveda que corre aquí mismo se presenta (`startBrowserVault`): `{ cert, proxy, open }`
     * —`open` es su canal local, ver `registerLocalVault` en `remote.js`—, o `null` al
     * pararse (ver `adminLink`). En el núcleo y no en `handlers`: ninguna
     * aplicación tiene por qué poder decir dónde está la bóveda de esta cuenta.
     */
    /** @param {{ cert: any, proxy: string, open: (onReply: (reply: any) => void) => { send (payload: any): void, close (): void } } | null} [self] */
    setSelfVault(self?: {
        cert: any;
        proxy: string;
        open: (onReply: (reply: any) => void) => {
            send(payload: any): void;
            close(): void;
        };
    } | null): void;
    /** @param {(status: any) => void} fn */
    onSyncStatus(fn: (status: any) => void): void;
    /** @param {(payload: any) => void} fn */
    onVaultEvent(fn: (payload: any) => void): () => boolean;
}>;
/**
 * Almacén clave → texto, síncrono (localStorage, o lo que lo imite en Node y en la app).
 * @typedef {{ getItem (k: string): string | null, setItem (k: string, v: string): void, removeItem (k: string): void }} Kv
 */
/**
 * Una llave que firma o deriva: una CryptoKey, o un asa de una llave que vive fuera (el chip).
 * @typedef {import('./capabilities.js').SigningKey | { external: true, kid?: string, sign: (bytes: Uint8Array) => Promise<string>, deriveBits?: (peerPubJwkStr: string) => Promise<ArrayBuffer>, paired?: (account: any) => Promise<any> }} PrivateKeyLike
 */
/**
 * Lo que se guarda de un par en el almacén de llaves.
 * @typedef {{ privateKey: PrivateKeyLike, publicJwk: JsonWebKey }} StoredPair
 */
/**
 * Dónde viven las llaves privadas: IndexedDB en el navegador (CryptoKey no extraíble), o el
 * chip del teléfono (`externalKeys.js`), que además sabe crearlas e importarlas.
 * @typedef {object} KeyStore
 * @property {(name: string) => Promise<any>} get
 * @property {(name: string, rec: any) => Promise<void>} set
 * @property {(name: string) => Promise<void>} remove
 * @property {(kind: 'sign' | 'enc', name: string) => Promise<StoredPair>} [create]
 * @property {(pair: { sign: { name: string, privateJwk: JsonWebKey, publickey: string }, enc: { name: string, privateJwk: JsonWebKey | null, publickey: string | null } }) => Promise<void>} [importPair]
 */
/**
 * El libro de contactos que usa el núcleo: la interfaz de `vault/peerStore.js`.
 * @typedef {{ initPeerStorage (): Promise<import('./peerStore.js').PeerBook>,
 *   loadPeers (): import('./peerStore.js').PeerBook, savePeers (p: import('./peerStore.js').PeerBook): void,
 *   setPeersDirect (p: import('./peerStore.js').PeerBook): void,
 *   upsertPeer (publickey: string, patch: Record<string, any>): import('./peerStore.js').PeerRecord,
 *   onDirty (fn: (() => void) | null): void,
 *   setProfile? (pid: string | null, opts?: { volatile?: boolean }): void | Promise<void>,
 *   adoptLegacy? (pid: string): void | Promise<void> }} CorePeers
 */
/**
 * El candado de la maestra: sella y abre con la llave que sale de la contraseña del perfil.
 * Cerrado, `open` devuelve `null`.
 * @typedef {{ seal? (plaintext: string): Promise<any>, open? (sealed: any): Promise<string | null> }} KeyLock
 */
/**
 * Lo que el núcleo necesita de quien lo monta (el iframe, Node o la app).
 * @typedef {object} CoreDeps
 * @property {Kv} kv  almacén síncrono estilo localStorage (keypairs, me, nonces)
 * @property {CorePeers} peers  el libro de contactos
 * @property {((cfg: { fileName: string, kind: string, exportLocal: () => Promise<any>, applyMerged: (merged: any) => Promise<void>, mergeFn: (local: any, remote: any) => Promise<{ merged: any, changed: boolean }> }) => any) | null} [makeSync]
 *   fábrica del respaldo en Drive (`createSync`); sin ella, los `sync*` lanzan
 * @property {KeyStore | null} [keyStore]  dónde viven las llaves privadas; sin él, JWK en `kv`
 * @property {Kv | null} [sessionKv]  lo de esta pestaña (`sessionStorage`)
 * @property {boolean} [removeAccountOnExpulsion]
 * @property {KeyLock | null} [keyLock]
 * @property {((q: { origin: string, scopes: string[], already: string[], onBehalfOf: string | null }) => Promise<boolean> | boolean) | null} [askConsent]
 */
/**
 * Un perfil de la lista de este aparato.
 * @typedef {{ id: string, name?: string, pubkey?: string | null, pendingJoin?: boolean } & Record<string, any>} ProfileEntry
 */
/**
 * Un par cargado: la privada (CryptoKey o el asa del chip; `null` con el candado echado) y la pública.
 * @typedef {{ privateKey: any, publicKey: CryptoKey, publicJwk: JsonWebKey, locked?: boolean }} LoadedPair
 */
/**
 * El emparejamiento guardado con la bóveda: su papel, a quién y por dónde.
 * @typedef {{ cert: any, master: string, proxy: string, deviceId?: string, pairedAt?: number, account?: string } & Record<string, any>} VaultLink
 */
/** @typedef {import('./remote.js').DeviceKey} DeviceKey */
/** @typedef {import('./acta.js').Acta} Acta */
/**
 * Los parámetros de un manejador: llegan por `postMessage` (de cualquier aplicación) o por la
 * API de Node, sin comprobar. Cada manejador valida lo que usa.
 * @typedef {Record<string, any>} HandlerParams
 */
export const KEY_STORAGE: "dotrino.identity.keypair";
export const ENC_KEY_STORAGE: "dotrino.identity.enc-keypair";
export const ME_STORAGE: "dotrino.identity.me";
export const NONCE_STORAGE: "dotrino.identity.nonces";
export const DELEGATIONS_STORAGE: "dotrino.identity.delegations";
export const REVOCATIONS_STORAGE: "dotrino.identity.revocations";
export const VAULT_DEVICE_STORAGE: "dotrino.identity.vault.device";
export const VAULT_CERT_STORAGE: "dotrino.identity.vault.cert";
export const ACTA_STORAGE: "dotrino.identity.acta";
export const ACTA_HISTORY_STORAGE: "dotrino.identity.acta.history";
export const PENDING_JOIN_STORAGE: "dotrino.identity.pendingJoin";
export const RENOUNCE_STORAGE: "dotrino.identity.renounced";
export const GRANTS_STORAGE: "dotrino.identity.grants";
export const LOGIN_STORAGE: "dotrino.identity.login";
export const PROFILES_STORAGE: "dotrino.identity.profiles";
export const CURRENT_STORAGE: "dotrino.identity.current";
/**
 * Almacén clave → texto, síncrono (localStorage, o lo que lo imite en Node y en la app).
 */
export type Kv = {
    getItem(k: string): string | null;
    setItem(k: string, v: string): void;
    removeItem(k: string): void;
};
/**
 * Una llave que firma o deriva: una CryptoKey, o un asa de una llave que vive fuera (el chip).
 */
export type PrivateKeyLike = import("./capabilities.js").SigningKey | {
    external: true;
    kid?: string;
    sign: (bytes: Uint8Array) => Promise<string>;
    deriveBits?: (peerPubJwkStr: string) => Promise<ArrayBuffer>;
    paired?: (account: any) => Promise<any>;
};
/**
 * Lo que se guarda de un par en el almacén de llaves.
 */
export type StoredPair = {
    privateKey: PrivateKeyLike;
    publicJwk: JsonWebKey;
};
/**
 * Dónde viven las llaves privadas: IndexedDB en el navegador (CryptoKey no extraíble), o el
 * chip del teléfono (`externalKeys.js`), que además sabe crearlas e importarlas.
 */
export type KeyStore = {
    get: (name: string) => Promise<any>;
    set: (name: string, rec: any) => Promise<void>;
    remove: (name: string) => Promise<void>;
    create?: (kind: "sign" | "enc", name: string) => Promise<StoredPair>;
    importPair?: (pair: {
        sign: {
            name: string;
            privateJwk: JsonWebKey;
            publickey: string;
        };
        enc: {
            name: string;
            privateJwk: JsonWebKey | null;
            publickey: string | null;
        };
    }) => Promise<void>;
};
/**
 * El libro de contactos que usa el núcleo: la interfaz de `vault/peerStore.js`.
 */
export type CorePeers = {
    initPeerStorage(): Promise<import("./peerStore.js").PeerBook>;
    loadPeers(): import("./peerStore.js").PeerBook;
    savePeers(p: import("./peerStore.js").PeerBook): void;
    setPeersDirect(p: import("./peerStore.js").PeerBook): void;
    upsertPeer(publickey: string, patch: Record<string, any>): import("./peerStore.js").PeerRecord;
    onDirty(fn: (() => void) | null): void;
    setProfile?(pid: string | null, opts?: {
        volatile?: boolean;
    }): void | Promise<void>;
    adoptLegacy?(pid: string): void | Promise<void>;
};
/**
 * El candado de la maestra: sella y abre con la llave que sale de la contraseña del perfil.
 * Cerrado, `open` devuelve `null`.
 */
export type KeyLock = {
    seal?(plaintext: string): Promise<any>;
    open?(sealed: any): Promise<string | null>;
};
/**
 * Lo que el núcleo necesita de quien lo monta (el iframe, Node o la app).
 */
export type CoreDeps = {
    /**
     * almacén síncrono estilo localStorage (keypairs, me, nonces)
     */
    kv: Kv;
    /**
     * el libro de contactos
     */
    peers: CorePeers;
    /**
     * fábrica del respaldo en Drive (`createSync`); sin ella, los `sync*` lanzan
     */
    makeSync?: ((cfg: {
        fileName: string;
        kind: string;
        exportLocal: () => Promise<any>;
        applyMerged: (merged: any) => Promise<void>;
        mergeFn: (local: any, remote: any) => Promise<{
            merged: any;
            changed: boolean;
        }>;
    }) => any) | null;
    /**
     * dónde viven las llaves privadas; sin él, JWK en `kv`
     */
    keyStore?: KeyStore | null;
    /**
     * lo de esta pestaña (`sessionStorage`)
     */
    sessionKv?: Kv | null;
    removeAccountOnExpulsion?: boolean;
    keyLock?: KeyLock | null;
    askConsent?: ((q: {
        origin: string;
        scopes: string[];
        already: string[];
        onBehalfOf: string | null;
    }) => Promise<boolean> | boolean) | null;
};
/**
 * Un perfil de la lista de este aparato.
 */
export type ProfileEntry = {
    id: string;
    name?: string;
    pubkey?: string | null;
    pendingJoin?: boolean;
} & Record<string, any>;
/**
 * Un par cargado: la privada (CryptoKey o el asa del chip; `null` con el candado echado) y la pública.
 */
export type LoadedPair = {
    privateKey: any;
    publicKey: CryptoKey;
    publicJwk: JsonWebKey;
    locked?: boolean;
};
/**
 * El emparejamiento guardado con la bóveda: su papel, a quién y por dónde.
 */
export type VaultLink = {
    cert: any;
    master: string;
    proxy: string;
    deviceId?: string;
    pairedAt?: number;
    account?: string;
} & Record<string, any>;
export type DeviceKey = import("./remote.js").DeviceKey;
export type Acta = import("./acta.js").Acta;
/**
 * Los parámetros de un manejador: llegan por `postMessage` (de cualquier aplicación) o por la
 * API de Node, sin comprobar. Cada manejador valida lo que usa.
 */
export type HandlerParams = Record<string, any>;
import * as Acta from './acta.js';
import * as Content from './content.js';
