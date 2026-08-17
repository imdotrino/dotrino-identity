/**
 * Protocolo de mensajes entre un dispositivo y el vault (viajan por el proxy,
 * direccionados por pubkey con `sendByPubkey`). El cuerpo va JSON-serializado en
 * el campo `message` del sobre del proxy; el cliente lo entrega ya parseado.
 *
 * Emparejamiento ENDURECIDO (ver dotrino-vault/docs/pairing-protocol.md):
 *   1. dispositivo → vault   ENROLL { data:{op,dpub,token,sn,label,ts}, signature }
 *      (la firma es del dispositivo con su llave D = PRUEBA DE POSESION; un token
 *       robado ya NO basta para enrolar).
 *   2. vault → dispositivo   ENROLL_CHALLENGE { deviceId, sas }   (aun NO firma cert)
 *   3. el dueño compara el SAS (pantalla del dispositivo ↔ del PC) y APRUEBA en el PC
 *   4. vault → dispositivo   ENROLLED { cert, iss, sas }   (recien aqui firma el cert)
 *   5. el dispositivo VALIDA la cadena: cert.iss === el iss que vio, cert.sub === D.
 *
 * Revocacion (robo): el vault envia REVOKED { body, signature } FIRMADO por la
 * maestra → el dispositivo se autoborra SOLO si la firma valida contra la maestra
 * pineada (cierra el wipe-DoS; un ERROR plano jamas borra).
 */
export const MSG = Object.freeze({
  // La invitación corta no lleva la llave: el aparato la pide presentando el `sn` de
  // la sesión. Una pública es pública — esto no la esconde, solo evita abrirle la
  // puerta a quien acertó el token de conexión a ciegas.
  HELLO: 'vault.hello',                       // dispositivo → vault: { sn }
  HELLO_OK: 'vault.hello.ok',                 // vault → dispositivo: { iss, acct }
  ENROLL: 'vault.enroll',                     // dispositivo → vault: { data, signature }
  ENROLL_CHALLENGE: 'vault.enroll.challenge', // vault → dispositivo: { deviceId, sas }
  ENROLLED: 'vault.enrolled',                 // vault → dispositivo (tras aprobar): { cert, iss, sas }
  // Camino A (la cuenta del aparato pasa a vivir en la bóveda): en vez de un cert, la
  // bóveda manda QUIÉN es para que el aparato la admita, le envuelva la clave de
  // contenido y le traspase el mando; el aparato devuelve el acta sellada y la bóveda
  // responde con la definitiva. Ver docs/vinculacion-de-cuentas.md §2.
  ENROLL_ADOPT: 'vault.enroll.adopt',         // vault → dispositivo: { code, pub, encPub, label }
  ACTA_SEALED: 'vault.acta.sealed',           // dispositivo → vault: { acta, code }
  ACTA_ADOPTED: 'vault.acta.adopted',         // vault → dispositivo: { acta }
  REVOKED: 'vault.revoked',                   // vault → dispositivo: { body:{op,sub,nonce,iat,exp}, signature }
  // «¿sigo siendo de esta casa?» — la ÚNICA pregunta que se puede hacer SIN certificado:
  // va firmada con la llave del propio aparato, que es lo que el acta nombra. Existe para
  // el aparato que perdió su papel: sin ella no tiene forma de enterarse de que lo echaron.
  CHECK: 'vault.check',                       // dispositivo → vault: { data:{op:'check',publickey,ts}, signature }
  CHECKED: 'vault.checked',                   // vault → dispositivo: { in:boolean } — y si no, el REVOKED firmado
  SIGN: 'vault.sign',                         // dispositivo → vault: { data, signature, cert }
  SIGNED: 'vault.signed',                     // vault → dispositivo: { signature, publickey, device }
  GET: 'vault.get',                           // dispositivo → vault: { data, signature, cert }
  DATA: 'vault.data',                         // vault → dispositivo: { id, node }
  STORE: 'vault.store',                       // dispositivo → vault: { data:{method,args,publickey,ts}, signature, cert }
  STORE_RESULT: 'vault.store.result',         // vault → dispositivo: { method, result }
  DEVICES: 'vault.devices',                   // dispositivo → vault: { data:{publickey,ts}, signature, cert }
  DEVICES_RESULT: 'vault.devices.result',     // vault → dispositivo: { devices, revoked }
  RENEW: 'vault.renew',                       // dispositivo → vault: { data:{op,publickey,ts}, signature, cert }
  RENOUNCE: 'vault.renounce',                 // dispositivo → vault: { record }  (RENUNCIA firmada por el propio miembro)
  RENOUNCE_RESULT: 'vault.renounce.result',   // vault → dispositivo: { ok, seq }
  RENEWED: 'vault.renewed',                   // vault → dispositivo: { cert }  (cert fresco, misma sub-clave/scope)
  SECRETS: 'vault.secrets',                   // servicio → vault: { data:{op,ns,ek,publickey,ts}, signature, cert }
  SECRETS_RESULT: 'vault.secrets.result',     // vault → servicio: { body:{op,ns,enc,ts}, signature } (enc SELLADO a ek; body firmado por la maestra)
  // AVISO DE CAMBIO (no lleva valores): la bóveda dice «la configuración del ns
  // cambió». El agente no la recarga en caliente — SALE limpio y su supervisor lo
  // levanta. Dos razones, y la segunda es la de peso:
  //   · Lee todo fresco. Recargar en caliente exige que cada sitio que leyó una
  //     variable sepa releerla, y esa lista hay que mantenerla para siempre.
  //   · BORRA DE MEMORIA EL VALOR VIEJO. En JavaScript un secreto no se puede
  //     borrar: los strings son inmutables, no hay zeroize, y el valor queda en el
  //     heap hasta que al recolector le apetezca — más lo que capturó cada closure
  //     y cada caché derivada. Una llave se rota casi siempre PORQUE SE FILTRÓ, así
  //     que dejarla viva en el proceso anula la razón de rotarla. Un proceso nuevo
  //     empieza con el heap limpio.
  // Va FIRMADO por la maestra y el agente lo verifica contra su `iss` pineada: un
  // aviso de reinicio sin autenticar ES un ataque de denegación.
  SECRETS_CHANGED: 'vault.secrets.changed',   // vault → servicio: { body:{op,ns,ts}, signature }
  // --- CONSOLA REMOTA (docs/consola-remota.md) — requiere cert `vault:admin` ---
  // Un solo mensaje con `data.op`: pending · pair · approve · reject · revoke · audit.
  // Admitir y expulsar, nada más: cambiar permisos, traspasar el mando y los secretos
  // NO se exponen aquí, y no es un olvido — es el límite (§2 del diseño).
  ADMIN: 'vault.admin',                       // admin → vault: { data:{op,…,ts,nonce}, signature, cert }
  ADMIN_RESULT: 'vault.admin.result',         // vault → admin: { op, result }
  // Aviso a TODOS los miembros de que el perfil cambió (alguien entró o salió). Es la
  // contrapartida de administrar a distancia: sin esto, un enrolamiento remoto sería
  // invisible para el resto de tus dispositivos.
  ADMIN_EVENT: 'vault.admin.event',           // vault → todos: { body:{ev,deviceId,by,ts}, signature }
  ERROR: 'vault.error'                        // vault → dispositivo: { error }
})

/** Capacidades que puede llevar un `cert` (scope). Mínimo por defecto. */
export const SCOPE = Object.freeze({
  SIGN: 'vault:sign',   // pedir a la maestra que firme datos (identidad)
  READ: 'vault:read',   // leer nodos del árbol de contenidos
  STORE: 'vault:store', // leer/escribir el store de hilos + aperturas del usuario
  // Consola remota (docs/consola-remota.md): admitir y expulsar miembros a distancia.
  // NO incluye cambiar permisos, traspasar el mando ni conceder `admin`: eso es el rol
  // de master y sigue siendo local. No se empareja — se concede desde el PC.
  ADMIN: 'vault:admin'
})

/**
 * Scope de SECRETOS por namespace de servicio: un cert con `vault:secrets:proxy`
 * solo puede leer los secretos del ns `proxy` — un VPS comprometido no puede
 * pedir los de otro servicio. ns válido: [a-z0-9-]{1,32}.
 */
export const SECRETS_SCOPE_PREFIX = 'vault:secrets:'
export const secretsScope = (ns) => SECRETS_SCOPE_PREFIX + ns
export const isValidSecretsNs = (ns) => typeof ns === 'string' && /^[a-z0-9-]{1,32}$/.test(ns)

/**
 * Nombre de una variable de entorno: `MAYUSCULAS_CON_GUION_BAJO`, hasta 64. Vive aquí
 * —y no en el cajón que la guarda— porque la comprueban también la TUI, la consola
 * remota y el lector de `.env`, y tres copias de una regla son tres reglas.
 */
export const isValidVarKey = (key) => typeof key === 'string' && /^[A-Z0-9_]{1,64}$/.test(key)
