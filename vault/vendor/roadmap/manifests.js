/**
 * GENERADO — no se edita a mano. La fuente son los JSON de `manifests/`.
 * Regenerar:  node scripts/build-manifests.mjs
 *
 * Van dentro del código y no se leen del disco a propósito: los consumen ~30 PWAs, varios
 * daemons y un ejecutable único. Un registro que hay que leer del disco no sirve para eso.
 */
export const MANIFESTS = Object.freeze({
  "dotrino": {
    "manifest": "dotrino",
    "seq": 37,
    "issued": "2026-10-18",
    "note": "Registro comun de compatibilidad del ecosistema. Se edita a mano en este repo y se consulta con @dotrino/roadmap. Rangos: ver @dotrino/compat/ranges (x.y.z, >= > <= <, «a - b», «*», o una lista que es un O).",
    "products": {
      "compat": {
        "repo": "imdotrino/dotrino-compat",
        "npm": "@dotrino/compat",
        "current": "0.4.1",
        "protocol": 1,
        "requires": {}
      },
      "env": {
        "repo": "imdotrino/dotrino-vault",
        "npm": "@dotrino/env",
        "current": "0.93.1",
        "protocol": 1,
        "requires": {
          "vault": ">=0.93.0"
        }
      },
      "identity": {
        "repo": "imdotrino/dotrino-identity",
        "npm": "@dotrino/identity",
        "current": "0.121.8",
        "protocol": 1,
        "requires": {
          "proxy-client": ">=0.13.1"
        }
      },
      "lobby": {
        "repo": "imdotrino/dotrino-lobby",
        "npm": "@dotrino/lobby",
        "current": "0.10.4",
        "protocol": 2,
        "requires": {
          "proxy-client": ">=0.22.0",
          "identity": ">=0.53.0"
        }
      },
      "messenger": {
        "repo": "imdotrino/dotrino-messenger",
        "current": "0.8.1",
        "protocol": 2,
        "requires": {
          "identity": ">=0.117.0",
          "proxy-client": ">=0.36.1",
          "store": ">=0.12.3",
          "proxy": "1.6.1+"
        }
      },
      "messenger-android": {
        "repo": "imdotrino/dotrino-messenger",
        "current": "0.5.2",
        "protocol": 2,
        "requires": {
          "proxy": "1.1.0+"
        }
      },
      "messenger-ios": {
        "repo": "imdotrino/dotrino-messenger",
        "current": "0.5.2",
        "protocol": 2,
        "requires": {
          "proxy": "1.1.0+"
        }
      },
      "messenger-extension": {
        "repo": "imdotrino/dotrino-messenger-extension",
        "current": "1.9.0",
        "protocol": 1,
        "requires": {
          "proxy": "1.1.0+"
        }
      },
      "notifications": {
        "repo": "imdotrino/dotrino-notifications",
        "npm": "@dotrino/notifications",
        "current": "0.7.2",
        "protocol": 2,
        "requires": {
          "proxy-client": ">=0.20.0"
        }
      },
      "opaque": {
        "repo": "imdotrino/dotrino-opaque",
        "npm": "@dotrino/opaque",
        "current": "0.1.0",
        "protocol": 1,
        "requires": {}
      },
      "profile": {
        "repo": "imdotrino/dotrino-profile",
        "npm": "@dotrino/profile",
        "current": "0.20.3",
        "protocol": 1,
        "requires": {
          "identity": ">=0.33.0"
        }
      },
      "proxy": {
        "repo": "imdotrino/dotrino-proxy",
        "current": "1.8.0",
        "protocol": 2,
        "requires": {
          "vault": ">=0.87.0",
          "identity": ">=0.117.2",
          "proxy-client": ">=0.36.1",
          "content": "0.5.3+"
        }
      },
      "proxy-client": {
        "repo": "imdotrino/dotrino-proxy-client",
        "npm": "@dotrino/proxy-client",
        "current": "0.39.0",
        "protocol": 2,
        "requires": {
          "identity": ">=0.53.0",
          "proxy": "1.1.0+"
        }
      },
      "remote-agent": {
        "repo": "imdotrino/dotrino-remote-agent",
        "npm": "@dotrino/remote-agent",
        "current": "0.22.5",
        "protocol": 1,
        "requires": {
          "identity": ">=0.121.7",
          "vault": ">=0.85.0",
          "proxy-client": ">=0.36.1",
          "vaultd": ">=0.154.0"
        }
      },
      "terminal-agent": {
        "repo": "imdotrino/dotrino-terminal",
        "npm": "@dotrino/terminal-agent",
        "current": "0.49.1",
        "protocol": 2,
        "requires": {
          "remote-agent": ">=0.22.5",
          "identity": ">=0.121.7",
          "vault": ">=0.93.0",
          "proxy-client": ">=0.38.4",
          "vaultd": ">=0.142.0"
        }
      },
      "terminal-ios": {
        "repo": "imdotrino/dotrino-terminal",
        "current": "0.13.7",
        "protocol": 1,
        "requires": {
          "terminal-agent": ">=0.37.0"
        }
      },
      "terminal-android": {
        "repo": "imdotrino/dotrino-terminal",
        "current": "0.13.7",
        "protocol": 1,
        "requires": {
          "terminal-agent": ">=0.37.0"
        }
      },
      "terminal-desktop": {
        "repo": "imdotrino/dotrino-terminal",
        "current": "0.2.80",
        "protocol": 1,
        "requires": {
          "terminal-agent": ">=0.37.0"
        }
      },
      "ia-agent": {
        "repo": "imdotrino/dotrino-ia",
        "npm": "@dotrino/ia-agent",
        "deprecated": "2026-10-07: retired, replaced by terminal-agent (dotrino-terminal)",
        "current": "0.9.1",
        "protocol": 1,
        "requires": {
          "remote-agent": ">=0.20.1",
          "identity": ">=0.117.2",
          "vault": ">=0.87.0",
          "proxy-client": ">=0.36.1"
        }
      },
      "content": {
        "repo": "imdotrino/dotrino-content",
        "npm": "@dotrino/content",
        "current": "0.6.9",
        "protocol": 1,
        "requires": {
          "remote-agent": ">=0.22.2",
          "identity": ">=0.120.0",
          "vault": ">=0.87.0",
          "proxy-client": ">=0.36.1"
        }
      },
      "sealers": {
        "repo": "imdotrino/dotrino-sealers",
        "npm": "@dotrino/sealers",
        "current": "0.10.4",
        "protocol": 1,
        "requires": {
          "remote-agent": ">=0.22.4",
          "identity": ">=0.121.7",
          "vault": ">=0.93.1",
          "proxy-client": ">=0.38.4"
        }
      },
      "roadmap": {
        "repo": "imdotrino/dotrino-roadmap",
        "npm": "@dotrino/roadmap",
        "current": "0.4.32",
        "protocol": 1,
        "requires": {
          "compat": "0.4.0+"
        }
      },
      "store": {
        "repo": "imdotrino/dotrino-store",
        "npm": "@dotrino/store",
        "current": "0.12.4",
        "protocol": 1,
        "requires": {
          "identity": ">=0.91.0",
          "vaultd": ">=0.115.0"
        }
      },
      "theme": {
        "repo": "imdotrino/dotrino-theme",
        "npm": "@dotrino/theme",
        "current": "0.1.0",
        "protocol": 1,
        "requires": {}
      },
      "topbar": {
        "repo": "imdotrino/dotrino-topbar",
        "npm": "@dotrino/topbar",
        "current": "0.16.3",
        "protocol": 1,
        "requires": {
          "identity": ">=0.96.1",
          "theme": ">=0.1.0"
        }
      },
      "vault": {
        "repo": "imdotrino/dotrino-vault",
        "npm": "@dotrino/vault",
        "current": "0.94.0",
        "protocol": 1,
        "requires": {
          "vaultd": ">=0.105.0",
          "proxy-client": ">=0.39.0",
          "identity": ">=0.118.0",
          "opaque": ">=0.1.0",
          "compat": ">=0.4.0",
          "roadmap": ">=0.4.26",
          "passmanager": ">=0.18.4",
          "store": ">=0.12.3"
        }
      },
      "vaultd": {
        "repo": "imdotrino/dotrino-vault",
        "npm": "@dotrino/vaultd",
        "current": "0.166.2",
        "protocol": 1,
        "requires": {
          "identity": ">=0.118.0",
          "proxy-client": ">=0.39.0",
          "store": ">=0.11.0",
          "passmanager": ">=0.18.4",
          "compat": ">=0.4.0",
          "opaque": ">=0.1.0",
          "roadmap": ">=0.4.26"
        }
      },
      "verifier": {
        "repo": "imdotrino/dotrino-verifier",
        "npm": "@dotrino/verifier",
        "current": "0.3.1",
        "protocol": 1,
        "requires": {
          "identity": "0.87.0+"
        }
      },
      "passmanager": {
        "repo": "imdotrino/dotrino-passmanager",
        "npm": "@dotrino/passmanager",
        "current": "0.18.5",
        "protocol": 1,
        "requires": {
          "identity": ">=0.117.2",
          "proxy-client": ">=0.36.1"
        }
      },
      "passmanager-android": {
        "repo": "imdotrino/dotrino-passmanager",
        "current": "0.1.0",
        "protocol": 1,
        "requires": {
          "proxy": "1.1.0+",
          "vaultd": ">=0.160.2"
        }
      },
      "passmanager-ios": {
        "repo": "imdotrino/dotrino-passmanager",
        "current": "0.1.0",
        "protocol": 1,
        "requires": {
          "proxy": "1.1.0+",
          "vaultd": ">=0.125.0"
        }
      },
      "passmanager-extension": {
        "repo": "imdotrino/dotrino-passmanager",
        "current": "0.54.0",
        "protocol": 1,
        "requires": {
          "identity": ">=0.118.0",
          "proxy-client": ">=0.36.1",
          "vault": ">=0.90.0",
          "proxy": "1.1.0+",
          "vaultd": ">=0.160.2"
        }
      },
      "app": {
        "repo": "imdotrino/dotrino-app",
        "current": "0.4.24",
        "protocol": 1,
        "requires": {
          "proxy": "1.4.7+",
          "vaultd": ">=0.114.0",
          "identity": ">=0.110.1"
        }
      },
      "app-ios": {
        "repo": "imdotrino/dotrino-app",
        "current": "0.4.14",
        "protocol": 1,
        "requires": {
          "proxy": "1.4.7+",
          "vaultd": ">=0.114.0",
          "identity": ">=0.110.1"
        }
      },
      "social-bot": {
        "repo": "imdotrino/dotrino-social-bot",
        "current": "0.3.0",
        "protocol": 1,
        "requires": {
          "vault": ">=0.87.0",
          "identity": ">=0.117.2",
          "proxy-client": ">=0.36.1",
          "remote-agent": ">=0.20.1"
        }
      },
      "accounts": {
        "repo": "imdotrino/dotrino-accounts",
        "npm": null,
        "current": "0.3.2",
        "protocol": 1,
        "requires": {
          "identity": ">=0.116.0",
          "remote-agent": ">=0.19.0",
          "vault": ">=0.94.0",
          "pay": ">=0.2.0",
          "vaultd": ">=0.166.2"
        }
      },
      "ai": {
        "repo": "imdotrino/dotrino-ai",
        "npm": "@dotrino/ai",
        "current": "0.1.1",
        "protocol": 1,
        "requires": {}
      },
      "pay": {
        "repo": "imdotrino/dotrino-pay",
        "npm": "@dotrino/pay",
        "current": "0.2.0",
        "protocol": 1,
        "requires": {}
      }
    },
    "broken": [
      {
        "product": "passmanager-extension",
        "versions": "0.50.0",
        "why": "la página que pide una passkey decía ella misma de qué sitio era (rpId y origen salían del mensaje, no del remitente): un sitio cualquiera podía pedir la firma de la passkey de otro sitio guardada en Dotrino",
        "fix": "sube a la extensión 0.51.0 (se actualiza sola desde pass.dotrino.com/app)"
      },
      {
        "product": "passmanager-extension",
        "versions": "0.49.1",
        "why": "la página que pide una passkey decía ella misma de qué sitio era (rpId y origen salían del mensaje, no del remitente): un sitio cualquiera podía pedir la firma de la passkey de otro sitio guardada en Dotrino",
        "fix": "sube a la extensión 0.51.0 (se actualiza sola desde pass.dotrino.com/app)"
      },
      {
        "product": "passmanager-extension",
        "versions": "0.49.0",
        "why": "la página que pide una passkey decía ella misma de qué sitio era (rpId y origen salían del mensaje, no del remitente): un sitio cualquiera podía pedir la firma de la passkey de otro sitio guardada en Dotrino",
        "fix": "sube a la extensión 0.51.0 (se actualiza sola desde pass.dotrino.com/app)"
      },
      {
        "product": "passmanager-extension",
        "versions": "0.48.4",
        "why": "la página que pide una passkey decía ella misma de qué sitio era (rpId y origen salían del mensaje, no del remitente): un sitio cualquiera podía pedir la firma de la passkey de otro sitio guardada en Dotrino",
        "fix": "sube a la extensión 0.51.0 (se actualiza sola desde pass.dotrino.com/app)"
      },
      {
        "product": "terminal-agent",
        "versions": "0.46.4",
        "why": "manda la pantalla y el historial en trozos de 64 KB que sellados miden 122 KB: no caben en un mensaje del canal directo (64 KiB), el pilar los manda por el proxio y el trozo pequeño que sí va directo los adelanta; en el teléfono la pantalla queda a medio historial o pintada dos veces",
        "fix": "sube a @dotrino/terminal-agent 0.46.5"
      },
      {
        "product": "terminal-agent",
        "versions": "0.46.3",
        "why": "el mismo fallo que la 0.46.4 (trozos de 64 KB que no caben en el canal directo), y además el historial de la consola que se deja seguía saliendo tras cambiarse a otra",
        "fix": "sube a @dotrino/terminal-agent 0.46.5"
      },
      {
        "product": "store",
        "versions": "0.12.2",
        "why": "el mismo fallo que la 0.12.1 (salió sin el arreglo): cuando la bóveda rechaza el respaldo, el motivo (error.reason) llega vacío al estado y a la barra",
        "fix": "sube a @dotrino/store 0.12.3"
      },
      {
        "product": "store",
        "versions": "0.12.1",
        "why": "se publicó diciendo que el estado del respaldo lleva el motivo del rechazo (error.reason), y el cambio que lo hace llegar no iba dentro: el motivo llega vacío",
        "fix": "sube a @dotrino/store 0.12.3"
      },
      {
        "product": "terminal-agent",
        "versions": "0.19.0",
        "why": "salió a npm sin access.js (faltaba en files): dotrino-terminal no arranca (ERR_MODULE_NOT_FOUND) y la app de escritorio no ve perfiles",
        "fix": "sube a @dotrino/terminal-agent 0.19.1"
      },
      {
        "product": "terminal-agent",
        "versions": "0.16.0",
        "why": "el mismo fallo que la 0.15.x (salió sin el arreglo): un cambio de consola que falla (no-console) cierra la ventana, y una consola cerrada desde otra pantalla se lleva la ventana",
        "fix": "sube a @dotrino/terminal-agent 0.16.1"
      },
      {
        "product": "terminal-agent",
        "versions": "0.15.1",
        "why": "el cliente de la ventana trata como fatal que la consola pedida ya no exista (no-console): elegir en el panel una entrada caducada cierra la ventana; y si otra pantalla cierra la consola, la ventana se va sin forma de abrir otra",
        "fix": "sube a @dotrino/terminal-agent 0.16.1"
      },
      {
        "product": "terminal-agent",
        "versions": "0.15.0",
        "why": "el mismo fallo que la 0.15.1: un cambio de consola que falla (no-console) cierra la ventana, y una consola cerrada desde otra pantalla se lleva la ventana",
        "fix": "sube a @dotrino/terminal-agent 0.16.1"
      },
      {
        "product": "remote-agent",
        "versions": [
          "0.1.0",
          "0.2.0",
          "0.2.1",
          "0.3.0",
          "0.3.1",
          "0.3.2",
          "0.4.0",
          "0.4.1",
          "0.5.0",
          "0.5.1",
          "0.5.2",
          "0.5.3",
          "0.5.4",
          "0.6.0",
          "0.6.1",
          "0.6.2",
          "0.7.0",
          "0.7.1",
          "0.8.0",
          "0.9.0",
          "0.9.1",
          "0.9.2",
          "0.10.0",
          "0.11.0",
          "0.12.0",
          "0.12.1"
        ],
        "why": "el agente guardaba sin comprobar el acta que llegaba en vault.devices.result, de cualquier remitente, y esa acta decide quien abre sesion: alguien de fuera de la cuenta podia nombrarse miembro. Afecta a todo lo que arranca con startRemoteAgent (terminal, ia, content, sealers)",
        "fix": "sube a @dotrino/remote-agent 0.13.0 (terminal-agent 0.15.1, ia-agent 0.7.3, content 0.4.3, sealers 0.8.1). Si la ultima acta de la cuenta no la sello la boveda con la que se enrolo la maquina, hay que enrolarla de nuevo"
      },
      {
        "product": "terminal-agent",
        "versions": "0.14.0",
        "why": "cuando se va la pantalla que manda en el tamano de una consola, el tamano no pasa a otra (calculaba quien mandaba despues de quitarla), y la eleccion del tamano se borra al pasar a otra consola y volver",
        "fix": "sube a @dotrino/terminal-agent 0.15.0"
      },
      {
        "product": "vault",
        "versions": "<=0.33.2",
        "why": "es anterior al acta de perfil: al enrolar contesta «invalid cert: no-acta», que es verdad y no es la causa",
        "fix": "sube @dotrino/env y @dotrino/vault a la version de vaultd que corre"
      },
      {
        "product": "vault",
        "versions": "0.62.0",
        "why": "se publico declarando proxy-client >=0.17.0, y el identifyAs que usa nacio en 0.18.0: con 0.17.x muere con «client.identifyAs is not a function», que es un fallo mudo",
        "fix": "sube a @dotrino/vault 0.62.1, que ya pide >=0.18.0"
      },
      {
        "product": "store",
        "versions": [
          "0.8.0",
          "0.9.0"
        ],
        "why": "connect({ identity }) devuelve el singleton tal cual si ya existia: la moneda de <dotrino-support> lo abre SIN identidad al montarse y suele llegar antes que la app, asi que la app recibe un almacen sin setProfile y todo lo suyo va al espacio comun de todos los perfiles del aparato, sin ningun error. Ademas, una identidad sin perfil activo caia en silencio al espacio por defecto",
        "fix": "sube a @dotrino/store 0.10.0"
      },
      {
        "product": "store",
        "versions": "0.8.0",
        "why": "abrir el almacen es un saludo de un solo mensaje: el iframe manda `ready` al cargar y, si se pierde o la pagina tarda mas de 8 s, connect() falla; peor, la promesa rechazada se queda cacheada en el singleton, asi que el boton «Reintentar» que enseñan las apps devuelve el mismo error sin intentar nada y el almacen queda inservible hasta recargar",
        "fix": "sube a @dotrino/store 0.9.0"
      },
      {
        "product": "store",
        "versions": "0.7.0",
        "why": "soltar la boveda (vaultUnpair) borraba todos los hilos del perfil, igual que una expulsion; y desde 0.6.0 dejo de adoptar lo que guardo la version anterior a IndexedDB, asi que al actualizar se perdian los hilos en silencio",
        "fix": "sube a @dotrino/store 0.8.0"
      },
      {
        "product": "proxy-client",
        "versions": "0.18.2",
        "why": "el Service Worker del push se publicaba como sw/closer-click-push-sw.js mientras el README mandaba copiarlo como dotrino-push-sw.js: quien seguia el README importaba un 404, y eso deja el SW de Workbox VACIO (sin precache, sin offline y sin actualizarse), no solo sin push",
        "fix": "sube a @dotrino/proxy-client 0.19.0 y copia sw/dotrino-push-sw.js a public/"
      },
      {
        "product": "notifications",
        "versions": "0.3.0",
        "why": "el acuse de apertura salia con sendByPubkey, o sea EN CLARO: la url del contenido, su nombre y el apodo de quien lo abrio cruzaban el proxio tal cual. Y contra un 0.4.0 no se entiende: lo suyo llega sin sellar y el otro lo descarta, asi que el acuse no aparece y no hay error en ninguna de las dos puntas",
        "fix": "sube @dotrino/notifications a 0.4.0 y dale al cliente con que sellar (myEncPub + sealing), con @dotrino/proxy-client >=0.20.0"
      },
      {
        "product": "store",
        "versions": [
          "0.7.0",
          "0.8.0",
          "0.9.0",
          "0.10.0"
        ],
        "why": "con la boveda emparejada, el respaldo manda el almacen ENTERO en un mensaje (exportThreads/importThreads) y el proxio corta en 1 MB: pasado ese tamano deja de llegar, el error se traga en un catch vacio y el almacen sigue solo en el navegador sin avisar. Ademas, un borrado vuelve desde la boveda o desde otro aparato, y la boveda recortaba cada hilo a 1000 entradas",
        "fix": "sube a @dotrino/store 0.11.0 (y dotrino-vault 0.115.0 en la boveda)"
      },
      {
        "product": "identity",
        "versions": [
          "0.73.0",
          "0.73.1",
          "0.74.0",
          "0.74.1",
          "0.75.0",
          "0.76.0",
          "0.77.0",
          "0.78.0",
          "0.79.0",
          "0.80.0",
          "0.81.0",
          "0.82.0",
          "0.83.0",
          "0.83.1",
          "0.84.0",
          "0.85.0",
          "0.86.0",
          "0.86.1",
          "0.86.2",
          "0.87.0",
          "0.88.0",
          "0.89.0",
          "0.89.1",
          "0.90.0",
          "0.91.0"
        ],
        "why": "enrollDevice comparaba acta.profileId con la llave de la boveda al emparejar y al renovar, y eso solo es verdad en una cuenta que nacio en esa boveda: con una SEGUNDA boveda (multivault) o con una que adopto la cuenta, ningun aparato ni servicio puede emparejarse ni renovar por ella («the record is from a profile other than the one you saw»). Y no protegia: el acta no se verificaba. Ademas requestRenew guardaba el papel renovado sin comprobarlo",
        "fix": "sube a @dotrino/identity 0.92.0 (checkVaultReply)"
      },
      {
        "product": "vault",
        "versions": [
          "0.43.0",
          "0.44.0",
          "0.45.0",
          "0.45.1",
          "0.46.0",
          "0.47.0",
          "0.47.1",
          "0.48.0",
          "0.49.0",
          "0.49.1",
          "0.50.0",
          "0.51.0",
          "0.52.0",
          "0.53.0",
          "0.54.0",
          "0.60.1",
          "0.60.2",
          "0.60.3",
          "0.60.4",
          "0.61.0",
          "0.62.0",
          "0.62.1",
          "0.63.0"
        ],
        "why": "el enrolamiento de servicios (enrollWithVault) comparaba acta.profileId con la llave de la boveda al emparejar y al renovar, y eso solo es verdad en una cuenta que nacio en esa boveda: con una SEGUNDA boveda (multivault) o con una que adopto la cuenta, ningun aparato ni servicio puede emparejarse ni renovar por ella («the record is from a profile other than the one you saw»). Y no protegia: el acta no se verificaba; y al renovar se guardaba el papel sin verificar su firma",
        "fix": "sube a @dotrino/vault 0.64.0 (y @dotrino/env 0.64.0)"
      },
      {
        "product": "vaultd",
        "versions": [
          "0.73.0",
          "0.74.0",
          "0.75.0",
          "0.75.1",
          "0.76.0",
          "0.77.0",
          "0.78.0",
          "0.79.0",
          "0.80.0",
          "0.80.1",
          "0.80.2",
          "0.81.0",
          "0.82.0",
          "0.83.0",
          "0.84.0",
          "0.85.0",
          "0.86.0",
          "0.87.0",
          "0.88.0",
          "0.89.0",
          "0.90.0",
          "0.91.0",
          "0.92.0",
          "0.93.0",
          "0.93.1",
          "0.94.0",
          "0.94.1",
          "0.95.0",
          "0.96.0",
          "0.97.0",
          "0.98.0",
          "0.105.1",
          "0.105.2",
          "0.105.3",
          "0.106.0",
          "0.106.1",
          "0.106.2",
          "0.107.0",
          "0.107.1",
          "0.107.2",
          "0.108.0",
          "0.109.0",
          "0.111.0",
          "0.111.1",
          "0.112.0",
          "0.112.1",
          "0.113.0",
          "0.114.0",
          "0.115.0",
          "0.116.0",
          "0.117.0"
        ],
        "why": "trae @dotrino/identity 0.81.0 dentro: una boveda que hace `join` contra otra que no es la del genesis no puede entrar, y el cliente de referencia (src/client.js) comparaba acta.profileId con la llave de la boveda al emparejar y al renovar, y eso solo es verdad en una cuenta que nacio en esa boveda: con una SEGUNDA boveda (multivault) o con una que adopto la cuenta, ningun aparato ni servicio puede emparejarse ni renovar por ella («the record is from a profile other than the one you saw»). Y no protegia: el acta no se verificaba",
        "fix": "sube a @dotrino/vaultd 0.118.0"
      },
      {
        "product": "remote-agent",
        "versions": [
          "0.6.0",
          "0.6.1",
          "0.6.2",
          "0.7.0",
          "0.7.1",
          "0.8.0",
          "0.9.0",
          "0.9.1",
          "0.9.2"
        ],
        "why": "la renovacion del papel comparaba acta.profileId con la llave de la boveda al emparejar y al renovar, y eso solo es verdad en una cuenta que nacio en esa boveda: con una SEGUNDA boveda (multivault) o con una que adopto la cuenta, ningun aparato ni servicio puede emparejarse ni renovar por ella («the record is from a profile other than the one you saw»). Y no protegia: el acta no se verificaba: el agente no renueva nunca contra una segunda boveda, y los permisos que le cambies no le llegan",
        "fix": "sube a @dotrino/remote-agent 0.10.0"
      },
      {
        "product": "env",
        "versions": [
          "0.60.2",
          "0.60.3",
          "0.60.4",
          "0.61.0",
          "0.62.0",
          "0.62.1",
          "0.63.0"
        ],
        "why": "es un envoltorio de @dotrino/vault y pide ^0.6x.y, o sea que se queda en una version rota de vault: un servicio no puede emparejarse con una segunda boveda ni con una que adopto la cuenta, y al renovar guardaba el papel sin verificar su firma",
        "fix": "sube a @dotrino/env 0.64.0"
      },
      {
        "product": "env",
        "versions": [
          "0.33.2"
        ],
        "why": "pide @dotrino/vault ^0.33.2, que es anterior al acta de perfil: al enrolar contesta «invalid cert: no-acta», que es verdad y no es la causa",
        "fix": "sube a @dotrino/env 0.64.0"
      },
      {
        "product": "identity",
        "versions": [
          "0.96.0"
        ],
        "why": "core.js importa @dotrino/vault/login-client con el nombre escrito, y ese archivo lo empaqueta cada app: el build se cae con «Rollup failed to resolve import», sin llegar a ejecutar esa linea",
        "fix": "sube a @dotrino/identity 0.96.1, que pone el especificador en una variable"
      },
      {
        "product": "passmanager",
        "versions": [
          "0.12.0",
          "0.13.0",
          "0.14.0",
          "0.14.1",
          "0.15.0",
          "0.16.0"
        ],
        "why": "SealedResponder leía la llave de quien pregunta en meta.pubkey, que el cliente del proxio no pone (es meta.fromPubkey), y caía al token: la bóveda no sabía a quién sellar la respuesta y no contestaba; del otro lado se veía «nadie respondió a tiempo». Además tres códigos de error (NOT_ALLOWED, NOT_SEALED, UNKNOWN) no existían y esos errores cruzaban sin código",
        "fix": "sube a @dotrino/passmanager 0.17.0"
      },
      {
        "product": "vaultd",
        "versions": [
          "0.123.0",
          "0.123.1",
          "0.124.0",
          "0.124.1",
          "0.124.2"
        ],
        "why": "sirve las contraseñas selladas con @dotrino/passmanager 0.12.0-0.16.0: no le contesta a ningún aparato remoto que pida una contraseña (el gestor ve «nadie respondió a tiempo»)",
        "fix": "sube a @dotrino/vaultd 0.125.0"
      },
      {
        "product": "proxy",
        "versions": "1.4.2",
        "why": "el aviso de iOS llama a ringName(), que 1.4.2 renombró a RING: cada timbre por APNs falla y el iPhone no suena",
        "fix": "sube el proxio a 1.4.3"
      },
      {
        "product": "identity",
        "versions": "0.107.0",
        "why": "pone la marca de sobre de la cuenta (t: 'dotrino-cek') en encryptWithCek, que es genérica: marca como de la cuenta sobres de cajones, contraseñas y transporte que la cuenta no abre, y la bóveda pararía al volver a cerrarlos",
        "fix": "sube @dotrino/identity a 0.107.1"
      },
      {
        "product": "vaultd",
        "versions": "0.139.0",
        "why": "no migra los sobres de la cuenta anteriores a la marca ({ gen, iv, ct } a secas): tras una rotación, un aparato nuevo no los abre",
        "fix": "dotrino-vault update (vaultd 0.139.1)"
      },
      {
        "product": "vaultd",
        "versions": [
          "0.73.0",
          "0.74.0",
          "0.75.0",
          "0.75.1",
          "0.76.0",
          "0.77.0",
          "0.78.0",
          "0.79.0",
          "0.80.0",
          "0.80.1",
          "0.80.2",
          "0.81.0",
          "0.82.0",
          "0.83.0",
          "0.84.0",
          "0.85.0",
          "0.86.0",
          "0.87.0",
          "0.88.0",
          "0.89.0",
          "0.90.0",
          "0.91.0",
          "0.92.0",
          "0.93.0",
          "0.93.1",
          "0.94.0",
          "0.94.1",
          "0.95.0",
          "0.96.0",
          "0.97.0",
          "0.98.0",
          "0.105.1",
          "0.105.2",
          "0.105.3",
          "0.106.0",
          "0.106.1",
          "0.106.2",
          "0.107.0",
          "0.107.1",
          "0.107.2",
          "0.108.0",
          "0.109.0",
          "0.111.0",
          "0.111.1",
          "0.112.0",
          "0.112.1",
          "0.113.0",
          "0.114.0",
          "0.115.0",
          "0.116.0",
          "0.117.0",
          "0.118.0",
          "0.119.0",
          "0.121.0",
          "0.122.0",
          "0.123.0",
          "0.123.1",
          "0.124.0",
          "0.124.1",
          "0.124.2",
          "0.125.0",
          "0.126.0",
          "0.127.0",
          "0.128.0",
          "0.129.0",
          "0.129.1",
          "0.130.0",
          "0.131.0",
          "0.131.1",
          "0.131.2",
          "0.131.3",
          "0.131.4",
          "0.131.5",
          "0.131.6",
          "0.132.0",
          "0.133.0",
          "0.134.0",
          "0.135.0",
          "0.136.0",
          "0.137.0",
          "0.138.0",
          "0.139.0",
          "0.139.1"
        ],
        "why": "quitar o cambiar la contraseña del perfil cambiaba la llave del perfil sin volver a sellar la maestra: tras reiniciar, el perfil decía «desbloqueado» y no podía volver a firmar el acta (con 0.140.0 se recupera poniendo la misma contraseña de antes)",
        "fix": "sube a @dotrino/vaultd 0.140.0"
      },
      {
        "product": "messenger-extension",
        "versions": "1.9.0",
        "why": "no tiene UI propia: sus tres superficies son iframes a messenger.dotrino.com con ?embed=, y el soporte de ese modo (puente de identidad, espejo de conversaciones, cola de salida, aviso de DM) se quitó del messenger después de la 0.1.0; la PWA servida siempre es la última, así que el panel se inventa una cuenta en cada sitio y no recibe nada",
        "fix": "no hay versión que funcione: hay que elegir el camino del README de dotrino-messenger-extension (extensión autónoma con los pilares, o un modo embed del ecosistema)"
      },
      {
        "product": "proxy",
        "versions": "1.6.0",
        "why": "pasa a base64 los mensajes binarios para cruzar la malla, y una parte de 768 KB así pasa de la trama de 1 MB del otro nodo: el enlace se cae en cada reconexión al reenviarla y todo lo que va detrás entre los dos nodos se queda atascado",
        "fix": "websocket-proxy 1.6.1"
      },
      {
        "product": "proxy-client",
        "versions": "0.36.0",
        "why": "por token frena los bytes por lo recordado de la identidad (que puede ser de antes de que el otro se actualizara), y no solo por lo que dijo esa conexión en su saludo",
        "fix": "@dotrino/proxy-client 0.36.1"
      },
      {
        "product": "vaultd",
        "versions": [
          "0.160.0",
          "0.160.1"
        ],
        "why": "la bóveda recordaba el sí de aprobación por aparato: después de aprobar un borrado, o de leer una contraseña, ese aparato podía borrar o pisar una passkey sin que se pidiera nada ni le llegara aviso a nadie",
        "fix": "sube a @dotrino/vaultd 0.160.2"
      },
      {
        "product": "content",
        "versions": [
          "0.6.1",
          "0.6.2",
          "0.6.3",
          "0.6.4"
        ],
        "why": "el paquete no traía lib/cid.js, que lib/public.js importa: el node no arranca (ERR_MODULE_NOT_FOUND)",
        "fix": "sube a @dotrino/content 0.6.6"
      }
    ]
  }
})
