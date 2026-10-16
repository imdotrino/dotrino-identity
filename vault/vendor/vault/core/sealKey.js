/**
 * La LLAVE DE SELLADO de esta bóveda: con ella FIRMA los sobres de los secretos, para
 * que se sepa que salieron de aquí. Diseño: `docs/secretos-sellados.md` §8.8 y §8.9.
 *
 * Tres cosas que la hacen distinta de todo lo demás que hay en este directorio:
 *
 *   · **Firmar no es leer.** Esta llave no abre ningún valor. Por eso puede vivir
 *     cifrada en reposo con la llave de la máquina y usarse **sin la frase** — que es
 *     justo lo que hace posible administrar sin contraseña.
 *   · **Su autoridad la da el ACTA**, que la nombra (`sealPub`) y que sella únicamente
 *     la maestra. Ella no se autoriza a sí misma.
 *   · **Rota con el acta.** Cada acta nueva puede estrenar una, así que aquí se guarda
 *     un puñado: la vigente para firmar, y las anteriores porque un sobre se firmó con
 *     la que mandaba entonces y hay que poder seguir firmando… no, seguir
 *     **identificando** cuál era. Verificar se hace con la pública que dice el acta.
 *
 * No guarda ninguna correspondencia con `seq`: quién mandaba y cuándo lo dice el acta
 * (`sealKeys` con su tramo). Aquí solo están las privadas, indexadas por su pública.
 */
import { readJson, writeJson } from './disk.js'
import { signWithDevice } from '@dotrino/identity/capabilities'

/**
 * Cuántas llaves anteriores se conservan. Firmar solo usa la vigente; las viejas se
 * guardan por si hay que re-firmar algo sellado con ellas (recoger el histórico), y
 * porque tirarlas no ahorra nada: son cuatro líneas de JSON.
 */
const MAX_KEYS = 8

/** Abre (o estrena) el llavero de sellado del perfil. */
export function openSealKeys (disk) {
  const file = 'sealkeys.json'
  const data = readJson(disk, file, null) || { v: 1, keys: [] }
  if (!Array.isArray(data.keys)) data.keys = []

  const save = () => writeJson(disk, file, data)
  const find = (pub) => data.keys.find((k) => k.pub === pub) || null

  return {
    /** La pública de la llave vigente (la última estrenada), o `null` si no hay ninguna. */
    current: () => data.keys[data.keys.length - 1]?.pub || null,

    /** ¿Tenemos la privada de esta pública? Es lo que decide si podemos firmar por ella. */
    has: (pub) => !!find(pub),

    /**
     * Estrena una llave y devuelve su PÚBLICA, para que el acta la nombre. La privada
     * se queda aquí; no sale de esta máquina ni viaja a ninguna parte.
     *
     * Es lo que se le pasa a `identity.setSealKeyProvider`, así que se llama una vez
     * por acta sellada.
     */
    async mint () {
      const pair = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify'])
      const pub = JSON.stringify(await crypto.subtle.exportKey('jwk', pair.publicKey))
      const priv = await crypto.subtle.exportKey('jwk', pair.privateKey)
      data.keys.push({ pub, priv, createdAt: Date.now() })
      if (data.keys.length > MAX_KEYS) data.keys = data.keys.slice(-MAX_KEYS)
      save()
      return pub
    },

    /**
     * Firma un cuerpo con la llave que el acta nombra. Devuelve `null` si esa llave no es
     * nuestra —el disco se restauró, o el acta la puso otro master—: entonces el sobre
     * sale SIN firma, que es peor que firmado pero mucho mejor que no poder guardar.
     */
    async sign (sealPub, body) {
      const k = sealPub ? find(sealPub) : null
      if (!k) return null
      const { signature } = await signWithDevice({ privateJwk: k.priv, publickey: k.pub, data: body })
      return signature
    }
  }
}

export default { openSealKeys }
