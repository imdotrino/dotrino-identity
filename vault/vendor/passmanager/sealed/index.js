// CONTRASEÑAS SELLADAS POR APARATO — la puerta del subpath `@dotrino/passmanager/sealed`.
//
// Va por su propio subpath y NO desde el índice del paquete: esto arrastra
// `@dotrino/identity/content` (la cripto de los sobres) y no todo el que usa el gestor
// necesita cargarla. Quien sella, la pide.
//
// Las tres piezas, y quién usa cada una:
//
//   · `SealedStore` — la BÓVEDA (el demonio, la pestaña, la extensión cuando hace de
//     bóveda, `serve`). Guarda sobres que no puede abrir y comprueba destinatarios.
//   · `buildSealedEntry` / `openSealedEntry` — el APARATO que pide. Cifra, envuelve, firma;
//     y al leer, abre con su envoltura.
//   · `profileKeys` y las huellas — las dos puntas: con ellas se busca por sitio y se
//     compara sin abrir.
export * from './store.js'
export * from './device.js'
export * from './entry.js'
export * from './keys.js'
export * from './recovery.js'
export * from './convert.js'
