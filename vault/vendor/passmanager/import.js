// Importar desde otros gestores. Sin esto nadie migra, por bueno que sea el resto
// (DISENO §8, paso 1).
//
// Devuelve entradas EN CLARO, listas para `sealEntry`. Esta función no cifra ni
// guarda: quien importa es quien tiene la CEK, y es él quien decide.

import { normalizeSites } from './model.js'
import { hostOf } from './match.js'

/** CSV con comillas, comas y saltos de línea dentro de campo (RFC 4180). */
export function parseCsv (text) {
  const rows = []
  let row = []
  let field = ''
  let quoted = false
  const s = String(text || '').replace(/^﻿/, '')

  for (let i = 0; i < s.length; i++) {
    const c = s[i]
    if (quoted) {
      if (c === '"') {
        if (s[i + 1] === '"') { field += '"'; i++ } else { quoted = false }
      } else field += c
      continue
    }
    if (c === '"') { quoted = true; continue }
    if (c === ',') { row.push(field); field = ''; continue }
    if (c === '\r') continue
    if (c === '\n') { row.push(field); rows.push(row); row = []; field = ''; continue }
    field += c
  }
  if (field !== '' || row.length) { row.push(field); rows.push(row) }
  return rows.filter(r => r.some(v => v !== ''))
}

function csvObjects (text) {
  const rows = parseCsv(text)
  if (!rows.length) return []
  const head = rows[0].map(h => h.trim().toLowerCase())
  return rows.slice(1).map(r => {
    const o = {}
    head.forEach((h, i) => { o[h] = r[i] ?? '' })
    return o
  })
}

function sitesFrom (...urls) {
  const out = []
  for (const u of urls.flat()) {
    const h = hostOf(u)
    if (h) out.push(h)
  }
  return normalizeSites(out)
}

function entryFrom ({ title, sites, username, secret, totp, notes }) {
  return {
    type: 'login',
    title: String(title || '').trim() || (sites[0] || 'sin nombre'),
    sites,
    username: String(username || ''),
    secret: String(secret || ''),
    totp: String(totp || ''),
    notes: String(notes || ''),
  }
}

/** Chrome / Edge: `name,url,username,password,note`. */
export function fromChromeCsv (text) {
  return csvObjects(text)
    .map(o => entryFrom({
      title: o.name,
      sites: sitesFrom(o.url),
      username: o.username,
      secret: o.password,
      notes: o.note || o.notes,
    }))
    .filter(e => e.secret || e.username)
}

/** 1Password: `Title,Url,Username,Password,OTPAuth,Favorite,Archived,Tags,Notes`. */
export function from1PasswordCsv (text) {
  return csvObjects(text)
    .map(o => entryFrom({
      title: o.title,
      sites: sitesFrom(o.url, o.urls),
      username: o.username,
      secret: o.password,
      totp: o.otpauth,
      notes: o.notes,
    }))
    .filter(e => e.secret || e.username)
}

/** Bitwarden CSV (`login_uri`, `login_username`, `login_password`, `login_totp`). */
export function fromBitwardenCsv (text) {
  return csvObjects(text)
    .filter(o => !o.type || o.type === 'login')
    .map(o => entryFrom({
      title: o.name,
      sites: sitesFrom((o.login_uri || '').split(',')),
      username: o.login_username,
      secret: o.login_password,
      totp: o.login_totp,
      notes: o.notes,
    }))
    .filter(e => e.secret || e.username)
}

/** Bitwarden JSON (export sin cifrar). */
export function fromBitwardenJson (json) {
  const data = typeof json === 'string' ? JSON.parse(json) : json
  if (data?.encrypted) {
    const e = new Error('el export de Bitwarden está cifrado: expórtalo sin cifrar')
    e.code = 'encrypted-export'
    throw e
  }
  return (data?.items || [])
    .filter(it => it.type === 1 && it.login)
    .map(it => entryFrom({
      title: it.name,
      sites: sitesFrom((it.login.uris || []).map(u => u.uri)),
      username: it.login.username,
      secret: it.login.password,
      totp: it.login.totp,
      notes: it.notes,
    }))
}

/**
 * Detecta el formato por su cabecera y lo importa. Es lo que consume la UI: el
 * usuario suelta el archivo y no tiene por qué saber qué formato es.
 *
 * `1pux` (el export nativo de 1Password) NO entra: es un zip. Se descomprime en la
 * UI y se le pasa aquí el JSON de dentro.
 */
export function importAuto (text) {
  const t = String(text || '').trim()
  if (!t) return { format: 'vacío', entries: [] }

  if (t.startsWith('{')) return { format: 'bitwarden-json', entries: fromBitwardenJson(t) }

  const head = (parseCsv(t)[0] || []).map(h => h.trim().toLowerCase())
  if (head.includes('login_password') || head.includes('login_username')) {
    return { format: 'bitwarden-csv', entries: fromBitwardenCsv(t) }
  }
  if (head.includes('otpauth') || (head.includes('title') && head.includes('url'))) {
    return { format: '1password-csv', entries: from1PasswordCsv(t) }
  }
  if (head.includes('name') && head.includes('url') && head.includes('password')) {
    return { format: 'chrome-csv', entries: fromChromeCsv(t) }
  }
  const e = new Error('no reconozco el formato del archivo')
  e.code = 'unknown-format'
  throw e
}
