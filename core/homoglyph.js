/**
 * Homograph analysis.
 *
 * The most dangerous lookalikes are the ones the eye cannot catch. `pаypal.com`
 * with a Cyrillic 'а' renders identically to `paypal.com` in every browser and
 * every email client, and a user comparing them character by character will
 * still get it wrong.
 *
 * A scanner that prints such a domain as ordinary text hides its single most
 * important property. So: detect the non-ASCII characters, say which Latin
 * letter each one imitates and which script it comes from, and surface the
 * punycode - the only form in which the deception is visible.
 */

import { domainToASCII } from 'node:url'

/** Confusable -> { latin, script }. Covers the characters actually used in
 *  registrable homograph attacks (Cyrillic and Greek carry almost all of it). */
const CONFUSABLES = {
  'а': ['a', 'Cyrillic'], 'е': ['e', 'Cyrillic'], 'о': ['o', 'Cyrillic'],
  'р': ['p', 'Cyrillic'], 'с': ['c', 'Cyrillic'], 'у': ['y', 'Cyrillic'],
  'х': ['x', 'Cyrillic'], 'і': ['i', 'Cyrillic'], 'ј': ['j', 'Cyrillic'],
  'ѕ': ['s', 'Cyrillic'], 'һ': ['h', 'Cyrillic'], 'ԁ': ['d', 'Cyrillic'],
  'ո': ['n', 'Armenian'], 'ս': ['u', 'Armenian'], 'օ': ['o', 'Armenian'],
  'α': ['a', 'Greek'], 'ο': ['o', 'Greek'], 'ρ': ['p', 'Greek'],
  'ν': ['v', 'Greek'], 'κ': ['k', 'Greek'], 'τ': ['t', 'Greek'], 'υ': ['u', 'Greek'],
  '４': ['4', 'Fullwidth'], '０': ['0', 'Fullwidth'],
  'à': ['a', 'Latin-1'], 'á': ['a', 'Latin-1'], 'ä': ['a', 'Latin-1'], 'â': ['a', 'Latin-1'],
  'é': ['e', 'Latin-1'], 'è': ['e', 'Latin-1'], 'ê': ['e', 'Latin-1'],
  'í': ['i', 'Latin-1'], 'ì': ['i', 'Latin-1'],
  'ó': ['o', 'Latin-1'], 'ö': ['o', 'Latin-1'], 'ò': ['o', 'Latin-1'],
  'ú': ['u', 'Latin-1'], 'ü': ['u', 'Latin-1'], 'ý': ['y', 'Latin-1'],
  'ç': ['c', 'Latin-1'], 'ġ': ['g', 'Latin-1'], 'ʐ': ['z', 'Latin-1'],
  'Ӏ': ['l', 'Cyrillic'],
}

/** Reduce a string to the Latin letters it *appears* to be. */
export function skeleton(s) {
  return [...s].map((ch) => CONFUSABLES[ch]?.[0] ?? ch).join('')
}

/**
 * @returns {{
 *   hasUnicode: boolean, punycode: string|null,
 *   confusables: {char:string,mimics:string,script:string}[],
 *   scripts: string[], visuallyIdentical: boolean, mixedScript: boolean
 * }}
 */
export function analyzeHomograph(domain, brandOrigin = '') {
  const hasUnicode = [...domain].some((c) => c.charCodeAt(0) > 127)
  const confusables = []

  for (const ch of domain) {
    const hit = CONFUSABLES[ch]
    if (hit) confusables.push({ char: ch, mimics: hit[0], script: hit[1] })
  }

  const scripts = [...new Set(confusables.map((c) => c.script))]
  let punycode = null
  if (hasUnicode) {
    try {
      const a = domainToASCII(domain)
      if (a && a !== domain) punycode = a
    } catch { /* unrepresentable; leave null */ }
  }

  // The sharpest signal: strip the disguise and it IS the brand.
  const visuallyIdentical =
    !!brandOrigin && hasUnicode && skeleton(domain) === skeleton(brandOrigin)

  return {
    hasUnicode,
    punycode,
    confusables,
    scripts,
    visuallyIdentical,
    // Mixing scripts inside one label is a strong deception signal in its own
    // right - legitimate domains do not usually do it.
    mixedScript: scripts.length > 1 || (hasUnicode && confusables.length > 0),
  }
}

/** One-line human summary, or null when there is nothing to say. */
export function homographNote(h) {
  if (!h?.hasUnicode) return null
  if (h.visuallyIdentical) {
    const s = h.scripts.join('/') || 'non-Latin'
    return `renders identically to the real domain - uses ${s} characters`
  }
  if (h.confusables.length) {
    const c = h.confusables[0]
    return `contains ${c.script} "${c.char}" imitating "${c.mimics}"`
  }
  return 'contains non-ASCII characters'
}
