/**
 * subacta.js — LO DECIDIDO QUE TODAVÍA NO SELLÓ EL ACTA.
 *
 * Idea del dueño (2026-09-04): *«una subacta efímera que se comparte entre todos los
 * dispositivos y puede tener decisiones a futuro que se aceptan cuando el acta se abre»*.
 *
 * EL AGUJERO QUE TAPA. Sellar el acta es de la maestra, y con el perfil cerrado la maestra
 * no está. Así que una renuncia —«me quito estos permisos»— no surtía NINGÚN efecto hasta
 * que alguien iba a la máquina y tecleaba la contraseña. Justo el caso que la renuncia
 * existe para cubrir: te roban el teléfono, renuncias desde él, y el ladrón sigue siendo
 * admin hasta que llegues. El pilar ya tenía la pieza (`extraRenounces`) y no la pasaba
 * nadie.
 *
 * LA REGLA DURA, y es la que sostiene todo lo demás:
 *
 *     LA SUBACTA SOLO PUEDE QUITAR, NUNCA DAR.
 *
 * De ahí salen las tres propiedades que la hacen segura sin maestra:
 *
 *   · **Se autentica sola.** Cada entrada la firma EL MIEMBRO AL QUE AFECTA. No hace falta
 *     sellador, así que no hay una segunda autoridad al lado del acta.
 *   · **Una entrada falsa o repetida cuesta disponibilidad, no autoridad.** Lo peor que
 *     consigue quien cuele una es quitarle permisos a alguien: molesto y reversible.
 *   · **Nadie puede quitarle nada a otro.** Si valiera la firma de cualquiera, un servicio
 *     con `secrets` en un VPS alquilado podría dejar sin `admin` a tu teléfono.
 *
 * Y por eso el catálogo de operaciones es una LISTA BLANCA de una sola: `renounce`. La
 * lista es la regla — si algún día entra otra, tiene que quitar y venir firmada por su
 * sujeto, y se escribe aquí a propósito, no se cuela.
 *
 * JUNTAR DOS ES UNIR. Dos entradas nunca se contradicen porque las dos quitan, así que no
 * hay conflictos ni hace falta un `seq`. Y **solo salen al absorberse** en el acta: nunca
 * por reloj, o un aparato apagado perdería justo la que lo protege.
 */
import { verifyRenounce } from '@dotrino/identity/acta'
import { readJson, writeJson } from './disk.js'

/** Las operaciones que caben. La lista ES la regla: todas quitan, todas las firma su sujeto. */
export const OPS = Object.freeze(['renounce'])

/** Identidad de una entrada, para no guardar dos veces la misma. */
const idOf = (e) => `${e.op}|${e.member}|${[...(e.caps || [])].sort().join(',')}|${e.ts}`

/**
 * ¿Es una entrada que se puede aceptar? Comprueba la FORMA y la FIRMA; que quite es
 * estructural (el catálogo) y no una comprobación aparte.
 */
export async function isAcceptable (e) {
  if (!e || !OPS.includes(e.op)) return false
  if (e.op === 'renounce') return verifyRenounce(e).catch(() => false)
  return false
}

/**
 * La subacta de un perfil. Vive en su directorio y va cifrada en reposo como todo lo
 * demás: sus entradas dicen qué aparatos se quedaron sin qué, y eso es material de la
 * cuenta aunque no sea un secreto.
 */
export function openSubacta (disk) {
  const file = 'subacta.json'
  let data = readJson(disk, file, null) || { v: 1, entries: [] }
  const guardar = () => writeJson(disk, file, data)

  return {
    /** Las entradas vigentes, tal cual se le pasan a `memberCan` y compañía. */
    entries () { return [...data.entries] },
    get count () { return data.entries.length },

    /** Las de UN miembro. Es lo que se mira al decidir sobre él. */
    forMember (pub) { return data.entries.filter((e) => e.member === pub) },

    /**
     * Acepta una entrada. Devuelve `{ok, reason}` — y un `false` aquí no es un fallo del
     * que la manda: puede ser que ya la tuviéramos, que es el caso normal cuando dos
     * aparatos se cuentan lo mismo.
     */
    async add (e) {
      if (!(await isAcceptable(e))) return { ok: false, reason: 'no-aceptable' }
      const id = idOf(e)
      if (data.entries.some((x) => idOf(x) === id)) return { ok: false, reason: 'ya-estaba' }
      data.entries = [...data.entries, e]
      guardar()
      return { ok: true, reason: 'nueva' }
    },

    /**
     * SACA TODO para absorberlo en el acta, y vacía. Se llama con la bóveda ABIERTA, que es
     * la única que puede sellar. Vaciar aquí y fallar el sellado perdería la entrada, así
     * que quien llama tiene que absorber primero y vaciar después (`clear`).
     */
    drain () { return [...data.entries] },

    /** Vacía lo ya absorbido. Se le pasa lo que se absorbió, no «todo»: mientras se sella
     *  puede haber entrado una nueva, y tirarla sería perder una renuncia sin aplicar. */
    clear (absorbidas) {
      const ids = new Set(absorbidas.map(idOf))
      data.entries = data.entries.filter((e) => !ids.has(idOf(e)))
      guardar()
    }
  }
}
