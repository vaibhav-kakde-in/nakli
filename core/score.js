/**
 * Threat scoring.
 *
 * Weights were tuned against the local validation run on hdfcbank.com. Two are
 * deliberately counter-intuitive and worth defending:
 *
 *  - MX is weighted LOW (12). Parked and squatted domains routinely carry a
 *    catch-all MX, so on its own it is weak evidence of intent.
 *  - Favicon identity is weighted HIGH (30). A byte-identical favicon is very
 *    hard to hit by accident and usually means a cloned front end.
 *
 * Every points award carries a human-readable reason. A score with no
 * explanation is not actionable, and this tool surfaces candidates for human
 * review rather than issuing verdicts.
 */

export function score(f, baseline) {
  let s = 0
  const reasons = []

  if (f.ips?.length) {
    s += 15
    reasons.push('resolves')
  }
  if (f.mx?.length) {
    s += 12
    reasons.push(`has MX (${f.mx.length}) - can send mail`)
  }
  if (f.httpStatus && f.httpStatus < 400) {
    s += 15
    reasons.push(`serves HTTP ${f.httpStatus}`)
  }
  if (f.hasLoginForm) {
    s += 25
    reasons.push('password field present')
  }
  if (f.faviconMatch) {
    s += 30
    reasons.push('favicon identical to brand')
  }

  if (f.titleSimilarity > 0.6) {
    s += 20
    reasons.push(`title ${Math.round(f.titleSimilarity * 100)}% similar`)
  } else if (f.titleSimilarity > 0.35) {
    s += 10
    reasons.push(`title ${Math.round(f.titleSimilarity * 100)}% similar`)
  }

  if (f.bodySimilarity > 0.5) {
    s += 20
    reasons.push(`page content ${Math.round(f.bodySimilarity * 100)}% similar`)
  }

  // Compare with non-alphanumerics stripped: the real title reads
  // "... | HDFC Bank" while the brand is "hdfcbank", so a literal substring
  // test misses the most obvious impersonation signal there is.
  const flat = (x) => (x ?? '').toLowerCase().replace(/[^a-z0-9]/g, '')
  if (baseline?.name && f.title && flat(f.title).includes(flat(baseline.name))) {
    s += 15
    reasons.push('brand name in title')
  }

  return { score: Math.min(s, 100), reasons }
}

export const band = (n) => (n >= 50 ? 'high' : n >= 25 ? 'medium' : 'low')
