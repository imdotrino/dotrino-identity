/**
 * LOS MIEMBROS DEL ACTA, EN TRES GRUPOS (dueño, 2026-10-26: «me confunde, no sé qué es
 * dispositivo, qué es servicio, qué es bóveda, qué es llave de comunicación»). Una lista plana
 * mezclaba cuatro cosas que no se administran igual:
 *
 *   · BÓVEDAS: las que sellan el acta. Debajo de cada una, su llave de comunicación, que es parte
 *     de ella (habla por la red con el candado echado) y no un aparato.
 *   · APARATOS: teléfonos, navegadores, terminales, agentes.
 *   · SERVICIOS: los que solo leen su cajón de secretos (`cn` = su espacio).
 *
 * Una sola regla para la TUI y la consola (dueño, 2026-10-27: el administrador «organizado como
 * está la TUI»): dos copias de esto acaban enseñando cosas distintas.
 *
 * Sin dependencias y sin red. Cada miembro trae `isMaster` (sella), `cn`, `vault` (en una llave
 * de comunicación, la llave de su bóveda) e `isMe`; `keyOf` dice cuál es su llave (`sub` en la
 * TUI, `pub` en la consola).
 *
 * @returns {{ group: 'vaults'|'devices'|'services', items: object[] }[]} solo los grupos con
 *   algo; en `vaults`, las llaves de comunicación van detrás de su bóveda con `child: true`.
 */
export const isCommKey = (m) => m?.cn === 'vault'

export function groupMembers (members, { keyOf = (m) => m.pub } = {}) {
  const list = members || []
  const vaults = list.filter((m) => m.isMaster && !isCommKey(m))
  const comms = list.filter(isCommKey)
  const services = list.filter((m) => m.cn && !isCommKey(m) && !m.isMaster)
  const devices = list.filter((m) => !m.isMaster && !m.cn)
  // La de esta máquina primero: es la que se está administrando.
  vaults.sort((a, b) => (b.isMe ? 1 : 0) - (a.isMe ? 1 : 0))
  const placed = new Set()
  const vaultBlock = []
  for (const v of vaults) {
    vaultBlock.push(v)
    for (const c of comms) if (c.vault === keyOf(v)) { vaultBlock.push({ ...c, child: true }); placed.add(keyOf(c)) }
  }
  // Una llave de comunicación de antes de que el acta dijera de qué bóveda es: va con la bóveda
  // de aquí, que es quien la acuñaba entonces.
  const orphans = comms.filter((c) => !placed.has(keyOf(c))).map((c) => ({ ...c, child: true }))
  const meAt = vaultBlock.findIndex((m) => m.isMe)
  if (meAt >= 0) {
    let at = meAt + 1
    while (vaultBlock[at]?.child) at++
    vaultBlock.splice(at, 0, ...orphans)
  } else vaultBlock.push(...orphans)
  return [
    { group: 'vaults', items: vaultBlock },
    { group: 'devices', items: devices },
    { group: 'services', items: services }
  ].filter((g) => g.items.length)
}
