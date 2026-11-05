/**
 * Canonical JSON serialization (sorted keys recursively).
 * Necessary so that signatures match across implementations.
 *
 * @param {unknown} value
 * @returns {string}
 */
export function canonicalStringify (value) {
  if (value === null || typeof value !== 'object') {
    return JSON.stringify(value)
  }
  if (Array.isArray(value)) {
    return '[' + value.map(canonicalStringify).join(',') + ']'
  }
  const obj = /** @type {Record<string, unknown>} */ (value)
  const keys = Object.keys(obj).sort()
  const parts = keys.map((k) => JSON.stringify(k) + ':' + canonicalStringify(obj[k]))
  return '{' + parts.join(',') + '}'
}
