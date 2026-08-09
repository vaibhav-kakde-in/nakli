/**
 * Permutation engine - generates lookalike domain candidates for a brand.
 *
 * Direct port of tools/phishscan.py, which was validated locally against
 * hdfcbank.com: 4000 candidates generated in <0.1s, 86 of them live.
 *
 * Dependency-free on purpose so both `api` and `probe` can import it without
 * duplicating a node_modules tree.
 */

const KEYBOARD = {
  q: 'wa', w: 'qes', e: 'wrd', r: 'etf', t: 'ryg', y: 'tuh', u: 'yij',
  i: 'uok', o: 'ipl', p: 'ol', a: 'qsz', s: 'awdx', d: 'serfc', f: 'drtgv',
  g: 'ftyhb', h: 'gyujn', j: 'huikm', k: 'jiol', l: 'kop', z: 'asx',
  x: 'zsdc', c: 'xdfv', v: 'cfgb', b: 'vghn', n: 'bhjm', m: 'njk',
  0: '9o', 1: '2ql', 2: '13w', 3: '24e', 4: '35r', 5: '46t', 6: '57y',
  7: '68u', 8: '79i', 9: '80o',
}

/** Visually confusable substitutions, ASCII and Unicode (Cyrillic etc). */
const HOMOGLYPHS = {
  a: ['4', '@', 'а', 'à', 'á', 'ä'],
  b: ['6', '8', 'в'],
  c: ['с', 'ç'],
  d: ['ԁ', 'cl'],
  e: ['3', 'е', 'é', 'è'],
  g: ['9', 'q', 'ġ'],
  h: ['һ'],
  i: ['1', 'l', 'і', 'í'],
  j: ['ј'],
  k: ['к'],
  l: ['1', 'i', 'Ӏ'],
  m: ['rn', 'м'],
  n: ['ո'],
  o: ['0', 'о', 'ó', 'ö', 'օ'],
  p: ['р'],
  q: ['9', 'g'],
  s: ['5', '$', 'ѕ'],
  t: ['7', '+'],
  u: ['v', 'υ', 'ü'],
  v: ['u', 'ѵ'],
  w: ['vv', 'ш'],
  x: ['х'],
  y: ['у', 'ý'],
  z: ['2'],
}

const VOWELS = 'aeiou'

export const TLDS = [
  'com', 'net', 'org', 'co', 'io', 'info', 'biz', 'online', 'site', 'xyz',
  'top', 'live', 'app', 'shop', 'club', 'in', 'co.in', 'cm', 'co.com', 'org.in',
]

/** Words attackers bolt onto a brand. */
const COMBO_WORDS = [
  'login', 'secure', 'verify', 'account', 'support', 'help', 'online',
  'portal', 'banking', 'kyc', 'update', 'alert', 'auth', 'signin', 'my',
  'web', 'customer', 'service', 'official', 'app', 'care', 'id', 'net',
]

const MULTI_TLDS = ['co.in', 'co.uk', 'com.au', 'co.jp', 'com.br', 'co.za']

/** Split "https://www.hdfcbank.co.in/x" -> { name: 'hdfcbank', tld: 'co.in' } */
export function splitDomain(input) {
  let d = String(input).trim().toLowerCase()
  d = d.replace(/^https?:\/\//, '').split('/')[0].replace(/^www\./, '')
  const parts = d.split('.')
  if (parts.length === 1) return { name: parts[0], tld: 'com', origin: `${parts[0]}.com` }
  for (const m of MULTI_TLDS) {
    if (d.endsWith('.' + m)) {
      const name = d.slice(0, -(m.length + 1))
      return { name, tld: m, origin: d }
    }
  }
  return { name: parts.slice(0, -1).join('.'), tld: parts.at(-1), origin: d }
}

/**
 * Generate candidate lookalike domains.
 * @returns {string[]} sorted, deduped, excluding the original
 */
export function permute(name, tld, limit = 4000) {
  const variants = new Set()
  const add = (v) => {
    if (v && v !== name && v.length > 1) variants.add(v)
  }
  const n = name.length

  // omission: hdfcbank -> hdfcbnk
  for (let i = 0; i < n; i++) add(name.slice(0, i) + name.slice(i + 1))

  // repetition: hdfcbank -> hdffcbank
  for (let i = 0; i < n; i++) add(name.slice(0, i) + name[i] + name[i] + name.slice(i + 1))

  // transposition: hdfcbank -> hdcfbank
  for (let i = 0; i < n - 1; i++)
    add(name.slice(0, i) + name[i + 1] + name[i] + name.slice(i + 2))

  // keyboard-adjacent replacement and insertion
  for (let i = 0; i < n; i++) {
    for (const adj of KEYBOARD[name[i]] ?? '') {
      add(name.slice(0, i) + adj + name.slice(i + 1))
      add(name.slice(0, i) + adj + name.slice(i))
      add(name.slice(0, i + 1) + adj + name.slice(i + 1))
    }
  }

  // homoglyph substitution
  for (let i = 0; i < n; i++) {
    for (const g of HOMOGLYPHS[name[i]] ?? []) {
      add(name.slice(0, i) + g + name.slice(i + 1))
    }
  }

  // vowel swap
  for (let i = 0; i < n; i++) {
    if (VOWELS.includes(name[i])) {
      for (const v of VOWELS) if (v !== name[i]) add(name.slice(0, i) + v + name.slice(i + 1))
    }
  }

  // bitsquatting: single bit flip. Lowercased because DNS is case-insensitive -
  // without this the 0x20 flip yields the same domain and pads the set with dupes.
  for (let i = 0; i < n; i++) {
    for (let bit = 0; bit < 8; bit++) {
      const f = String.fromCharCode(name.charCodeAt(i) ^ (1 << bit)).toLowerCase()
      if (/^[a-z0-9-]$/.test(f) && f !== name[i]) add(name.slice(0, i) + f + name.slice(i + 1))
    }
  }

  // hyphenation
  for (let i = 1; i < n; i++) add(name.slice(0, i) + '-' + name.slice(i))

  // Candidates are emitted in PRIORITY TIERS, not alphabetically.
  //
  // This matters: an alphabetical sort followed by slice(0, limit) silently
  // drops the highest-signal candidates. On hdfcbank.com it cut `hdfcbank.net`
  // - which serves a byte-identical clone of the real site and scores 82 - just
  // because 'h' sorts late. Tiers guarantee the strongest classes survive the
  // limit, and every tier is still fully covered when limit allows.
  const tiers = []

  // tier 1: untouched brand on another TLD - the strongest single signal
  tiers.push(TLDS.filter((t) => t !== tld).map((t) => `${name}.${t}`))

  // tier 2: combosquats (brand + phishing keyword)
  const comboTlds = ['com', 'net', 'online', 'site', 'xyz', 'in', 'co']
  const combos = []
  for (const w of COMBO_WORDS) {
    for (const t of comboTlds) {
      combos.push(`${name}${w}.${t}`, `${name}-${w}.${t}`, `${w}${name}.${t}`, `${w}-${name}.${t}`)
    }
  }
  tiers.push(combos)

  // tier 3: every string variant on the common TLDs
  const common = ['com', 'net', 'org', 'co', 'in', 'io']
  const rest = TLDS.filter((t) => !common.includes(t))
  const sorted = [...variants].sort()
  tiers.push(sorted.flatMap((v) => common.map((t) => `${v}.${t}`)))

  // tier 4: the long tail of TLDs
  tiers.push(sorted.flatMap((v) => rest.map((t) => `${v}.${t}`)))

  const seen = new Set([`${name}.${tld}`])
  const out = []
  for (const tier of tiers) {
    for (const d of tier) {
      if (out.length >= limit) return out
      if (!seen.has(d)) {
        seen.add(d)
        out.push(d)
      }
    }
  }
  return out
}
