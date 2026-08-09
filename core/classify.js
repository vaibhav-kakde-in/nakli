/**
 * Threat classification.
 *
 * A score of 97 tells you something is wrong; it does not tell you what kind of
 * wrong, and those are very different problems with very different responses.
 * A cloned login page steals credentials today. A registered domain with MX and
 * no website is waiting to send mail as you. A parked domain is speculation.
 *
 * So the score ranks, and this names. The distinction is the difference between
 * a scanner and something a security team can act on.
 *
 * Order matters: the first pattern that matches wins, most-dangerous first.
 */

const PARKED_HINTS = /(for sale|buy this domain|domain is parked|coming soon|under construction|default page|godaddy|sedo|afternic|namecheap parking)/i

export const CLASSES = {
  'homograph-attack': {
    label: 'Homograph attack',
    detail: 'Visually indistinguishable from your domain. No user can catch this by reading it.',
  },
  'credential-harvester': {
    label: 'Credential harvester',
    detail: 'Imitates your site and asks for a password. Built to take logins.',
  },
  'active-clone': {
    label: 'Active clone',
    detail: 'Serving a copy of your page right now.',
  },
  'email-spoofer': {
    label: 'Email spoofer',
    detail: 'Can receive and send mail as your brand, with no website to give it away.',
  },
  redirector: {
    label: 'Redirector',
    detail: 'Bounces visitors elsewhere - often traffic resale or a staging step.',
  },
  'brand-squat': {
    label: 'Brand squat',
    detail: 'Live site trading on your name.',
  },
  parked: {
    label: 'Parked',
    detail: 'Registered and held, not yet weaponised. Worth watching.',
  },
  dormant: {
    label: 'Dormant',
    detail: 'Resolves but serves nothing. No immediate threat.',
  },
}

export function classify(f, baseline = {}) {
  const title = (f.title ?? '').toLowerCase()
  const brand = (baseline.name ?? '').toLowerCase()
  const brandInTitle = brand && title.replace(/[^a-z0-9]/g, '').includes(brand.replace(/[^a-z0-9]/g, ''))
  const looksLikeUs = f.titleSimilarity > 0.6 || f.bodySimilarity > 0.6 || f.faviconMatch
  const serves = f.httpStatus && f.httpStatus < 400

  if (f.homograph?.visuallyIdentical) return 'homograph-attack'
  if (serves && f.hasLoginForm && (looksLikeUs || brandInTitle)) return 'credential-harvester'
  if (serves && (f.bodySimilarity > 0.8 || f.titleSimilarity > 0.9 || f.faviconMatch)) return 'active-clone'
  if (!serves && f.mx?.length) return 'email-spoofer'
  if (serves && /redirect/i.test(title)) return 'redirector'
  if (serves && PARKED_HINTS.test(title)) return 'parked'
  if (serves && (brandInTitle || looksLikeUs)) return 'brand-squat'
  if (serves) return 'parked'
  return 'dormant'
}

export const describe = (key) => CLASSES[key] ?? CLASSES.dormant
