/**
 * Scope del cert que corresponde a cada capacidad. El del cajón no sale de aquí: lo da el
 * CN (`cnScope`).
 */
export function capScope(cap: any): any;
/**
 * El acta SIN la firma ni la tarjeta: es lo que se sella y sobre lo que se calcula el hash.
 * La `card` va aparte porque lleva su propia firma y se comparte sola (ver `makeProfileCard`).
 */
export function actaBody(acta: any): any;
/** Hash del acta (hex de SHA-256 sobre el cuerpo canónico). Es lo que apunta el `prev`. */
export function actaHash(acta: any): Promise<string>;
/** Hash del eslabón. Es a esto a lo que apunta el `prev` del siguiente. */
export function sealerLinkHash(link: any): Promise<string>;
/**
 * ¿Es este eslabón coherente con el acta que lo lleva? Es lo que hace verdad la frase «ya
 * está validado dentro del acta»: la firma del acta cubre el eslabón, pero eso solo prueba
 * que está ahí — que DIGA lo mismo que el acta hay que comprobarlo.
 */
export function checkSealerLink(acta: any): "link-missing" | "link-version" | "link-unsigned" | "link-other-profile" | "link-other-seq" | "link-other-sealer" | "link-from-future" | "link-mismatch";
/** Firma del eslabón por quien sella. Se hace ANTES de firmar el acta que lo lleva. */
export function verifySealerLink(link: any): Promise<{
    ok: boolean;
    reason: string;
} | {
    ok: boolean;
    reason?: undefined;
}>;
/**
 * VERIFICA LA CADENA PUBLICADA — la que vive en el registro, sin actas de por medio.
 *
 * Es la hermana de `verifySealerChain`, que hace lo mismo con actas enteras para quien las
 * tiene. Lo que comprueba, y por qué basta:
 *   1. el primero está firmado por `profileId` — el ancla, que no se puede fabricar sin la
 *      llave que da nombre al perfil. Normalmente es el génesis (`seq 1`, sin `prev`), pero
 *      no tiene por qué: una cuenta que perdió su génesis ancla en un eslabón posterior;
 *   2. cada siguiente lo firmó alguien a quien el ANTERIOR autorizaba;
 *   3. y apunta al anterior por `seq` + hash, así que no se cuela uno de otra rama.
 *
 * Lo que NO resuelve, y no lo esconde: la frescura. Quien guardó una cadena vieja sigue
 * aceptando a un sellador retirado; para eso está mirar el registro, no más firmas.
 */
export function verifySealerLinkChain(chain: any, { expectedProfileId }?: {
    expectedProfileId?: any;
}): Promise<{
    ok: boolean;
    reason: string;
    profileId?: undefined;
    seq?: undefined;
    sealers?: undefined;
} | {
    ok: boolean;
    profileId: any;
    seq: any;
    sealers: any[];
    reason?: undefined;
}>;
/** Id legible de un miembro (mismo formato que el deviceId del emparejamiento). */
export function memberId(pub: any): Promise<string>;
/**
 * Acta de génesis: un perfil recién nacido tiene UN miembro (esta llave), que además es el
 * sellador, con todas las capacidades. `profileId` = su pubkey → el nombre del perfil es
 * estable para siempre y coincide con la identidad que el usuario ya tenía (cero migración).
 */
export function genesisActa({ pub, encPub, sealPub, label, chainUrl, now }: {
    pub: any;
    encPub?: any;
    sealPub?: any;
    label?: string;
    chainUrl?: any;
    now?: number;
}): {
    v: number;
    profileId: any;
    sealedBy: any;
    /**
     * DÓNDE PREGUNTAR SI ESTA CADENA SIGUE VIGENTE. Va en el GÉNESIS y en ningún otro
     * sitio, y esa es toda la idea.
     *
     * La cadena que te llega prueba quién puede sellar, pero no que no haya algo más
     * nuevo — si retiraste una bóveda, quien tenga la cadena vieja la sigue aceptando.
     * Para enterarse hay que poder mirar a algún lado.
     *
     * Si la dirección viajara en la parte cambiable, el sellador expulsado la cambiaría
     * a la suya y te mandaría a mirar su rama. En el génesis no puede: está autofirmada
     * por la llave que da nombre al perfil, y cambiarla exige esa llave.
     *
     * `null` es lo normal y no es un defecto: una cuenta de una sola bóveda no tiene nada
     * que pueda quedar obsoleto —su conjunto de selladores no puede cambiar— así que no
     * hay a dónde preguntar ni falta que hace.
     */
    chainUrl: any;
    seq: number;
    prev: any;
    sealerAnchor: any;
    sealerChanged: boolean;
    sealerLink: {
        v: number;
        profileId: any;
        seq: number;
        by: any;
        sealers: any[];
        prev: any;
        iat: number;
    };
    members: {
        sealPub?: any;
        sealSince?: number;
        pub: any;
        encPub: any;
        label: string;
        cn: any;
        caps: string[];
        addedAt: number;
        cert: any;
    }[];
    revoked: any[];
    renounced: any[];
    keyring: any[];
    sealPub: any;
    sealSince: number;
    sealKeys: any[];
    updatedAt: number;
};
/** Comprobaciones de FORMA (sin cripto): que el acta sea un acta. */
export function checkShape(acta: any): "no-record" | "version" | "shape" | "chainurl" | "sealer-not-in-v3" | "seq" | "prev" | "members" | "member" | "invalid-cn" | "invalid-encpub" | "invalid-vault" | "invalid-sealpub" | "sealsince" | "sealkeys" | "invalid-sealkey" | "sealkey-range" | "duplicate-member" | "no-sealer" | "sealeranchor" | "no-signer";
/** Sella (firma) un acta. `privateKey` puede ser una CryptoKey no extractable. */
export function sealActa({ acta, privateKey, privateJwk }: {
    acta: any;
    privateKey: any;
    privateJwk: any;
}): Promise<any>;
/**
 * Verifica un acta: forma + firma de `sealedBy`. Que ESE firmante estuviera autorizado no se
 * decide aquí sino al adoptarla (`canAdopt`), comparándola con la que ya tienes.
 * @returns {{ok:boolean, reason?:string}}
 */
/**
 * ¿HABLA ESTA ACTA POR ESTA IDENTIDAD? Lo que comprueba un EXTRAÑO, sin saber nada de ti.
 *
 * Recibe la cadena de selladores: `[génesis, …cambios de sellador…, acta actual]`. No son
 * todas tus actas —eso crecería con cada emparejamiento— sino solo los eslabones donde
 * cambió quién sella, que casi nunca pasa. Lo normal es longitud 1 o 2.
 *
 * Qué se comprueba, y por qué basta:
 *   1. el primer eslabón es el GÉNESIS y está autofirmado por `profileId`. Ese es el
 *      ancla: sin esa llave no se puede fabricar, y el `profileId` ya lo conoce quien
 *      verifica (viaja en cada firma tuya);
 *   2. cada eslabón siguiente lo selló alguien a quien el ANTERIOR autorizaba;
 *   3. y apunta al anterior por `seq` + hash, así que no se puede colar uno de otra rama.
 *
 * Sin esto, un acta suelta es falsificable: con tu `profileId` cualquiera fabrica una
 * donde él sella, y `verifyActa` la da por buena — está firmada, solo que por él.
 *
 * Lo que NO resuelve, y no lo esconde: la frescura. Quien guardó una cadena vieja sigue
 * aceptando a un sellador que ya retiraste. Es el problema de siempre y hace falta un
 * oráculo, no más firmas.
 */
/**
 * ¿DE QUIÉN ES ESTO? La pregunta que se hacen geo, reputación y cualquiera que reciba algo
 * firmado de un desconocido. Es lo único que necesitan llamar.
 *
 * Devuelve el `profileId` —la identidad— o por qué no.
 *
 * EL CERTIFICADO NO HACE FALTA AQUÍ, y conviene decirlo porque es lo que uno espera:
 * el acta ya dice quién puede firmar por la identidad, y la cadena prueba el acta. El
 * certificado es del protocolo aparato↔bóveda (autenticar peticiones), no de atribuir
 * contenido. Mezclarlos obligaba a que cada post arrastrara un papel que no aporta nada.
 *
 * Lo que SÍ hay que entender: esto dice «esta identidad firmó esto», no «esto es
 * reciente». Si la cadena que te llega es vieja, sigue verificando — para eso está el
 * registro público, que es otra capa.
 */
/**
 * @param {{ data?: any, signature?: string, publickey?: string, chain?: any[], expectedProfileId?: string|null }} [args]
 */
export function verifySignedBy(args?: {
    data?: any;
    signature?: string;
    publickey?: string;
    chain?: any[];
    expectedProfileId?: string | null;
}): Promise<{
    ok: boolean;
    reason: string;
    profileId?: undefined;
    seq?: undefined;
    signer?: undefined;
} | {
    ok: boolean;
    profileId: any;
    seq: any;
    signer: string;
    reason?: undefined;
}>;
/**
 * ¿ESTA INVITACIÓN ES DE LA CUENTA QUE ESPERO? Para un aparato que solo puede entrar en una
 * cuenta (la réplica o la bóveda alojadas, que van atadas a la cuenta que las pagó). El reto del
 * alta trae la cadena de selladoras de la bóveda que invita: se verifica, se comprueba que quien
 * contestó sella esa cuenta y se compara el id del perfil con el esperado (`pubkeyId`, 64 hex).
 * Devuelve `null` si es la cuenta, o el porqué si no.
 */
export function accountMismatch(chain: any, iss: any, account: any): Promise<string>;
export function verifySealerChain(chain: any, { expectedProfileId }?: {
    expectedProfileId?: any;
}): Promise<{
    ok: boolean;
    reason: string;
    profileId?: undefined;
    seq?: undefined;
    sealers?: undefined;
} | {
    ok: boolean;
    profileId: any;
    seq: any;
    sealers: any;
    reason?: undefined;
}>;
export function verifyActa({ acta, expectedProfileId }?: {}): Promise<{
    ok: boolean;
    reason: string;
} | {
    ok: boolean;
    reason?: undefined;
}>;
/**
 * ¿ES DE FIAR LO QUE CONTESTA LA BÓVEDA CON LA QUE TE EMPAREJASTE? El papel y el acta que
 * llegan al enrolarse o al renovar, juzgados contra la llave de ESA bóveda (`vault`: la
 * `iss` del QR, o la que quedó guardada al enrolarse).
 *
 * Antes cada cliente comparaba `acta.profileId` con esa llave. Eso solo es verdad en una
 * cuenta de una bóveda que además nació en ella: el `profileId` es la llave del GÉNESIS, y
 * en una cuenta que la bóveda ADOPTÓ, o en la SEGUNDA bóveda de un multivault, la llave de
 * la bóveda es otra. Ahí ningún aparato podía entrar ni renovar. Y encima no protegía: el
 * acta no se verificaba, así que bastaba con escribir ese `profileId` en una inventada.
 *
 * Lo que se comprueba ahora, y por qué alcanza:
 *   1. el acta está bien firmada por quien dice haberla sellado;
 *   2. esa bóveda PUEDE SELLAR esta acta — es de la cuenta, con el permiso, y una llave
 *      está en una sola cuenta, así que esto también fija la cuenta;
 *   3. el papel lo firmó ESA bóveda y no otra selladora: la respuesta es suya, porque nadie
 *      por el camino puede firmar con su llave;
 *   4. y el papel vale según esa acta (para esta llave, este permiso, un `seq` que no viene
 *      del futuro).
 *
 * `justSealed` es para el ENROLAMIENTO: aprobar es admitir al aparato, así que el acta que
 * vuelve la acaba de sellar esa misma bóveda. Exigirlo ata el acta a su llave y no solo el
 * papel — el llavero que el aparato va a usar viaja ahí dentro. Al RENOVAR no se pide: la
 * última acta pudo sellarla otra selladora de la cuenta.
 *
 * @returns {Promise<{ok:true}|{ok:false, reason:string}>}
 */
export function checkVaultReply({ acta, cert, vault, sub, scope, justSealed }?: {
    scope?: any;
    justSealed?: boolean;
}): Promise<{
    ok: true;
} | {
    ok: false;
    reason: string;
}>;
/**
 * Aplica cambios y devuelve el acta SIGUIENTE, **sin firmar** (hay que `sealActa`).
 * `by` es quien va a sellar: si no es el sellador vigente, se rechaza (regla 1).
 *
 * Cambios: `{op:'admit', member}` · `{op:'caps', pub, caps}` · `{op:'remove', pub}` ·
 * `{op:'handover', to}` · `{op:'revoke', nonce, until}` · `{op:'renounce', record}`.
 * Sellar se concede con `{op:'caps'}` como cualquier otro permiso.
 * Van en ARRAY porque hay combinaciones que deben ser atómicas: admitir al nuevo sellador y
 * traspasarle el master ocurre en el MISMO `seq` (§2.1.3).
 */
export function applyChanges(acta: any, changes: any, { by, now, sealPub }?: {
    now?: number;
    sealPub?: any;
}): Promise<any>;
/**
 * La llave que firmaba los sobres cuando el acta iba por `seq`. Es lo que necesita quien
 * VERIFICA un sobre: el sobre dice con qué acta se selló, y esto dice con qué llave hay
 * que comprobarlo. `null` si no había ninguna (perfil que no sellaba) o si el `seq` viene
 * del futuro, que es un sobre que no puede ser bueno.
 */
export function sealKeyAt(acta: any, seq: any, vault?: any): any;
/** Crea el registro firmado con el que un miembro se QUITA capacidades a sí mismo. */
export function makeRenounce({ member, caps, privateKey, privateJwk, now }: {
    member: any;
    caps: any;
    privateKey: any;
    privateJwk: any;
    now?: number;
}): Promise<{
    sig: any;
    op: string;
    member: any;
    caps: any[];
    ts: number;
}>;
/**
 * ¿Es válida esta renuncia? La firma tiene que ser del PROPIO miembro. Como solo puede
 * quitar, cualquiera puede honrarla sin riesgo, sin esperar a que el master la selle.
 */
export function verifyRenounce(record: any): Promise<boolean>;
/**
 * ¿Es NUEVA esta renuncia? Lo es si su `ts` es posterior a la última renuncia de ese miembro
 * que el acta ya vio (`renouncedAt`). Así un registro capturado no sirve para volver a quitar
 * un permiso que el master devolvió después: monotonía, como el `seq`. Sin `ts` numérico no
 * es nueva: no hay con qué ordenarla.
 */
export function renounceIsFresh(acta: any, record: any): boolean;
/**
 * Capacidad EFECTIVA de un miembro: lo que dice el acta menos lo que haya renunciado.
 * `extraRenounces` son renuncias sueltas ya verificadas que todavía no absorbió el master.
 */
export function effectiveCaps(acta: any, pub: any, extraRenounces?: any[]): any;
/**
 * ¿Puede este miembro leer el cajón de secretos `ns`? Solo si su CN es exactamente ése.
 * Es la frontera que pediste: la llave del proxy no ve nada más que lo del proxy.
 */
/**
 * ¿PUEDE ESTE MIEMBRO FIRMAR POR LA IDENTIDAD, Y QUÉ?
 *
 * Manda el acta, no el certificado (dueño, 2026-08-31). Y el matiz que hace falta decir en
 * voz alta: `sign` **no** es «firma lo que quiera». Va enmascarado, igual que `secrets` lo
 * va por el `cn` — *«puede firmar por identidad pero solo lo que permitan los permisos»*.
 *
 * Por qué existe con nombre propio en vez de un `memberCan(acta, pub, 'sign')` suelto: la
 * regla se comprueba en DOS bóvedas (el daemon y la de navegador) y se comprobaba mal en
 * las dos —miraban el papel—. Con un solo sitio, cuando el enmascarado crezca, crece una
 * vez y las dos lo heredan.
 *
 * `ns` es opcional y es para lo que va atado a un cajón: un servicio (miembro con `cn`)
 * solo firma dentro del suyo. Sin `ns`, se pregunta por la capacidad a secas.
 */
export function memberCanSign(acta: any, pub: any, ns?: any, extraRenounces?: any[]): boolean;
/**
 * ¿PUEDE ESTE MIEMBRO LO QUE PIDE EL SCOPE? La misma pregunta para todos los mostradores.
 *
 * El certificado dice a qué se comprometió la bóveda cuando conectó el aparato; el ACTA
 * dice lo que puede hoy. Y no coinciden: cambiar los permisos sella el acta pero NO
 * reemite ni revoca el papel, que vive hasta 30 días. Quitarle `lee` a un aparato y que
 * siguiera leyendo un mes es el mismo fallo que estaba en `sign`, en cada mostrador que
 * se olvidara de preguntar.
 *
 * Por eso esto existe y por eso traduce el SCOPE (el idioma del certificado) a la
 * capacidad (el idioma del acta): así el guardia se pone UNA vez, junto a la verificación
 * de la cadena, y un mostrador nuevo lo hereda en lugar de tener que acordarse.
 *
 * Devuelve `false` ante un scope que no reconoce: si aparece uno nuevo, lo que toca es
 * añadirlo aquí, no que se cuele por no estar en la lista.
 */
export function memberCanScope(acta: any, pub: any, scope: any, extraRenounces?: any[]): any;
export function memberCanReadSecrets(acta: any, pub: any, ns: any, extraRenounces?: any[]): boolean;
/** Los scopes de cert que le corresponden a un miembro según el acta. */
export function memberScopes(acta: any, pub: any, extraRenounces?: any[]): any[];
/**
 * ¿SON LA MISMA LLAVE? Nunca `===` sobre el JWK serializado: no es canónico, así que la
 * misma llave escrita por dos piezas distintas da dos strings distintos y `===` dice que
 * no. Lo que identifica a una P-256 es el punto (`kty`, `crv`, `x`, `y`); lo demás del
 * JWK es cómo se usa, no cuál es.
 */
export function samePubkey(a: any, b: any): boolean;
/**
 * LA LLAVE DE CIFRADO DE UN MIEMBRO, que es lo que hace falta para sellarle algo.
 *
 * Existía el dato —cada aparato la publica al enrolarse y queda escrita en el acta— pero
 * no la función, así que cada consumidor repetía el `.find()` a mano y cada copia
 * comparaba pubkeys con `===`. Esto es esa lectura, una vez y en el pilar.
 *
 * Devuelve `null` cuando no la hay, y eso NO es un repliegue: es el dato que falta dicho
 * en voz alta. Quien llama tiene que parar ahí, no mandar en claro — un miembro sin
 * `encPub` (un acta vieja, un servicio) simplemente no puede recibir nada sellado.
 *
 * @param {any} acta
 * @param {string} pub
 * @returns {string|null}
 */
export function memberEncPub(acta: any, pub: string): string | null;
/** ¿Puede este miembro hacer `cap` según el acta? (con el cert se cruza aparte: cert ∩ acta). */
export function memberCan(acta: any, pub: any, cap: any, extraRenounces?: any[]): any;
/**
 * Para escribirle a alguien cifrado hay que conocer las llaves de CIFRADO de todos sus
 * dispositivos — si no, el mensaje solo lo abre el aparato desde el que hablaste. Pero
 * pasarle el ACTA a un contacto le contaría de más: cuántos dispositivos tienes, cómo se
 * llaman y qué puede cada uno. Nada de eso es asunto suyo.
 *
 * Así que se comparte una TARJETA: el mínimo imprescindible —el perfil, su versión y las
 * llaves— firmada por el master, y por lo tanto verificable sin tener el acta. Sin
 * etiquetas, sin permisos, sin certificados.
 *
 * La firma el MASTER al sellar, y viaja con el acta, para que cualquier miembro pueda
 * entregarla aunque no sea él quien manda.
 */
export function cardBody(acta: any): {
    v: number;
    profileId: any;
    seq: any;
    sealedBy: any;
    keys: any;
    iat: any;
};
/** Firma la tarjeta de este acta (lo hace el master al sellar). */
export function makeProfileCard({ acta, privateKey, privateJwk }: {
    acta: any;
    privateKey: any;
    privateJwk: any;
}): Promise<{
    sig: any;
    v: number;
    profileId: any;
    seq: any;
    sealedBy: any;
    keys: any;
    iat: any;
}>;
/** Verifica que la tarjeta la firmó quien dice (`sealedBy`). Que ÉSE sea el master de esa
 * persona se decide al adoptarla, comparándola con la que ya tenías (`canAdoptCard`). */
export function verifyProfileCard(card: any): Promise<boolean>;
/**
 * ¿Me quedo con esta tarjeta en vez de la que tenía de esa persona?
 *   · la primera vez, sí (confías en el contacto que agregaste: es el mismo criterio
 *     que ya usas al añadirlo);
 *   · después, solo si el `seq` es mayor o igual Y la firmó el mismo master que la
 *     anterior — así nadie te cuela dispositivos ajenos en el perfil de tu contacto,
 *     y nunca se retrocede a una versión vieja.
 * Si el master cambió legítimamente (traspaso), la tarjeta nueva la firma el entrante y
 * hay que re-confirmarla: se devuelve `master-changed` para que la app lo diga en vez de
 * aceptarlo en silencio.
 */
export function canAdoptCard({ card, current }: {
    card: any;
    current: any;
}): Promise<{
    adopt: boolean;
    reason: string;
}>;
/**
 * CERTIFICADO DE CONTINUIDAD. Cuando una identidad que ya existía entra en otro perfil,
 * firma —con su propia llave— que a partir de ahora es miembro de él. Sirve de puente:
 * lo que hizo antes (su reputación, lo que firmó, quien la tenía de contacto) se puede
 * seguir atribuyendo a la misma persona en vez de quedar huérfano.
 *
 * No otorga nada por sí solo: es una declaración del que se une, y solo tiene efecto
 * dentro del acta donde el master la mete.
 */
export function makeContinuity({ member, from, privateKey, privateJwk, now }: {
    member: any;
    from: any;
    privateKey: any;
    privateJwk: any;
    now?: number;
}): Promise<{
    sig: any;
    op: string;
    member: any;
    from: any;
    ts: number;
}>;
/** ¿La firmó de verdad la identidad que dice venir? (única comprobación posible). */
export function verifyContinuity(record: any): Promise<boolean>;
/**
 * ¿Adopto `candidate` en lugar de `current`?
 *
 *   · `seq` mayor y contigua → sí, si encadena (`prev` = hash de la mía) y la firmó quien
 *     era master en la mía (`sealedBy === current.sealer`).
 *   · `seq` mayor con HUECO (estuve apagado) → solo si la firmó el master que conozco; si
 *     hubo un traspaso durante el hueco no puedo comprobarlo y toca re-admitirse (§1.3).
 *   · MISMO `seq` → gana la que TRASPASA. Es el caso del master obsoleto: un vault restaurado
 *     de un respaldo anterior al traspaso sella su propio `seq` creyéndose master, pero el
 *     acta del traspaso la firmó él mismo y esa firma prueba su degradación. Si las dos
 *     traspasan a destinos distintos (master mintiendo), desempata el hash menor —
 *     determinista, y nada salva de un master hostil.
 *   · `seq` menor → nunca (jamás retroceder).
 *
 * @returns {Promise<{adopt:boolean, reason:string}>}
 */
export function canAdopt({ candidate, current }: {
    candidate: any;
    current: any;
}): Promise<{
    adopt: boolean;
    reason: string;
}>;
export { cleanMachine };
export const ACTA_V: 5;
/**
 * Lista CERRADA de capacidades.
 *
 * `sealer` es SELLAR EL ACTA, y desde 2026-08-30 es un permiso como los demás — se da y se
 * quita con `caps <ID> +sealer`. Antes no existía: sellar era «ser el master», y punto. Se
 * abrió para el **multivault**: que una segunda bóveda pueda sellar hace que perder una
 * máquina no se lleve la cuenta por delante. Cuidado con no confundirlo con el CAMPO
 * `acta.sealer`, que es otra cosa: el campo dice **quién manda** (y solo cambia en un
 * traspaso); el permiso dice **quién puede firmar el acta**. Admitir sigue sin ser un
 * permiso: se admite sellando.
 *
 * El cajón de un servicio NO está en la lista: lo abre su **CN**, no un permiso. Ver
 * `cnScope` abajo.
 *
 * `admin` es la rendija que se le abre a la consola remota (`dotrino-vault/docs/
 * consola-remota.md`): deja **admitir y expulsar** miembros a distancia, y nada más.
 * NO deja cambiar permisos, traspasar el mando ni conceder `admin` — eso sigue siendo
 * el rol de master, que no se delega. Así un dispositivo con `admin` robado hace daño
 * acotado y **reversible** (se le revoca), en vez de poder dejarte fuera de tu cuenta.
 */
export const CAPS: readonly string[];
/** Capacidades de un DISPOSITIVO (sin CN): acceso a todo lo del usuario. */
/**
 * `approve` es el aparato que APRUEBA: cuando un cajón exige aprobación por uso, el
 * vault le avisa y solo su firma libera los secretos (normalmente el teléfono). Como
 * `admin`, no viaja en un QR: se concede a mano (`dotrino-vault caps <ID> +approve`).
 *
 * `passwords` es el aparato que puede PEDIR CREDENCIALES de la bóveda de contraseñas
 * (el gestor: la extensión del navegador, la app del teléfono). Pide de a una y por
 * dominio; nunca lista la bóveda. Va aquí y no en una lista aparte porque quién puede
 * pedirle algo a la bóveda es exactamente lo que decide el acta — tener dos registros
 * de lo mismo obliga a acordarse de los dos al quitar un aparato.
 *
 * Y `passwords` cubre TAMBIÉN LAS PASSKEYS (dueño, 2026-10-16: «realmente deberían ser uno
 * solo»). Hasta la 0.117 había un `passkeys` aparte para abrir la privada de una passkey;
 * se fusionó en este. Un acta vieja que todavía lo nombre sigue valiendo: un permiso
 * desconocido se ignora (ver `checkShape`), y al siguiente cambio del acta desaparece.
 * Lo que distingue una passkey es la POLÍTICA de la bóveda, no un permiso: añadirla es
 * directo, reemplazarla o borrarla pide aprobación (`@dotrino/passmanager`).
 *
 * `replica` es REPARTIR, NO DECIDIR. Un replicador no tiene maestra: guarda el acta y los
 * sobres —que ya vienen sellados a su destinatario, así que tampoco puede abrirlos— y los
 * entrega cuando la bóveda no está. Firma su respuesta con su propia llave de aparato, y
 * es este permiso el que hace que un cliente la acepte como respondedor.
 *
 * Lo que NO le concede, y por eso es estrecho: no sella actas, no emite certificados, no
 * abre nada. Un replicador comprometido cuesta disponibilidad, no confidencialidad.
 * Diseño: `dotrino-vault/docs/replicas.md` §8.bis.
 *
 * `unattended` es RECIBIR CLAVES PRIVADAS SIN QUE NADIE APRUEBE. Sin él, la bóveda no
 * entrega nada hasta que un aparato con `approve` lo firme — una vez por arranque del
 * servicio, no por petición.
 *
 * El defecto es al revés que antes, y esa es la gracia (dueño, 2026-09-01): antes había
 * que marcar a mano quién NECESITA aprobación, así que un aparato nuevo nacía pudiendo
 * llevarse las claves y nadie se enteraba de que esa era la elección. Ahora hay que
 * conceder a propósito quién puede llevárselas SOLO — y si el dato falta, se pide permiso,
 * que es lo que hay que hacer cuando no se sabe.
 *
 * Y va EN EL ACTA, no en una marca local de una máquina: así lo respeta cualquier bóveda
 * de la cuenta, se ve en la pantalla de permisos como los demás, y se quita quitándolo —
 * sin acordarse de un segundo registro escondido.
 */
export const DEVICE_CAPS: readonly string[];
/**
 * Lo que recibe un dispositivo recién emparejado. `admin` **no está**: no se
 * empareja, se concede después y a mano (`dotrino-vault caps <ID> +admin`), para que
 * ningún QR que circule pueda otorgar administración.
 */
export const PAIRED_CAPS: readonly string[];
export function allowedCaps(): string[];
export function isValidCn(cn: any): boolean;
/**
 * EL NOMBRE DE LA PROPIA BÓVEDA NO ES UN SERVICIO, Y NO TIENE CAJÓN.
 *
 * La llave de comunicación de la bóveda entra en el acta con este `cn` para hablar por la
 * bóveda y no firmar por la persona. Es la que firma con el perfil CERRADO, así que un sobre
 * dirigido a ella sería leer secretos sin abrir la bóveda. Mientras existió la capacidad
 * `secrets` lo impedía no tenerla; ahora que el cajón lo abre el `cn`, se dice aquí y por
 * su nombre: este `cn` no abre ninguno, tampoco uno que se llame igual.
 */
export const VAULT_CN: "vault";
export function cnScope(cn: any): string;
/** Compat: el mapa directo, para las capacidades de dispositivo. */
export const CAP_SCOPE: Readonly<{
    sign: "vault:sign";
    store: "vault:store";
    read: "vault:read";
    admin: "vault:admin";
    approve: "vault:approve";
    passwords: "vault:passwords";
    sealer: "vault:sealer";
    replica: "vault:replica";
}>;
export function isEncPub(v: any): boolean;
/**
 * EL ESLABÓN DE LA CADENA DE SELLADORES: lo ÚNICO que se publica.
 *
 * El problema que resuelve (dueño, 2026-08-31). Publicar «los eslabones donde cambia quién
 * sella» sonaba a publicar poco, pero un eslabón ERA un acta entera: se fue a un repo
 * público con los `label` y los `cn` de cada aparato y el llavero. Recortar el acta no
 * vale, porque su firma cubre el acta entera y dejaría de verificar.
 *
 * La salida es del dueño y es mejor que tener dos documentos que puedan discrepar: se
 * construye el eslabón, **se firma**, se mete en el acta, y **se firma el acta encima**.
 * Resultado: uno solo, firmado dos veces.
 *
 *   · quien tiene el acta la verifica y con eso el eslabón de dentro queda validado —
 *     no hay nada aparte en lo que confiar;
 *   · quien solo tiene el registro verifica la firma del eslabón, que es de la misma
 *     llave y dice lo mismo. Discrepar es imposible por construcción.
 *
 * ENCADENA CONTRA EL ESLABÓN ANTERIOR, no contra el acta anterior. El `sealerAnchor` del
 * acta apunta al hash del ACTA previa, y quien solo lee el registro no la tiene ni puede
 * calcularla — la cadena publicada tiene que sostenerse sola.
 *
 * Lo que lleva es lo mínimo para responder «¿esta llave sigue pudiendo sellar?»: nada de
 * miembros, ni etiquetas, ni cajones, ni llavero.
 */
export const SEALER_LINK_V: 1;
export function sealerLinkBody(link: any): any;
export function sealerLinkOf(acta: any): any;
export function sealersOf(acta: any, renounces?: any[]): any;
export function canSeal(acta: any, pub: any, renounces?: any[]): any;
export function isService(acta: any, pub: any): boolean;
declare namespace _default {
    export { ACTA_V };
    export { CAPS };
    export { CAP_SCOPE };
    export { genesisActa };
    export { actaBody };
    export { actaHash };
    export { memberId };
    export { checkShape };
    export { verifySealerChain };
    export { accountMismatch };
    export { verifySignedBy };
    export { sealActa };
    export { verifyActa };
    export { checkVaultReply };
    export { applyChanges };
    export { makeRenounce };
    export { verifyRenounce };
    export { makeContinuity };
    export { verifyContinuity };
    export { cardBody };
    export { makeProfileCard };
    export { verifyProfileCard };
    export { canAdoptCard };
    export { sealersOf };
    export { canSeal };
    export { effectiveCaps };
    export { memberCan };
    export { memberCanSign };
    export { memberCanScope };
    export { memberCanReadSecrets };
    export { memberScopes };
    export { isService };
    export { capScope };
    export { cnScope };
    export { VAULT_CN };
    export { isValidCn };
    export { canAdopt };
    export { samePubkey };
    export { memberEncPub };
    export { isEncPub };
}
export default _default;
import { cleanMachine } from './machine.js';
