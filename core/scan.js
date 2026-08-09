/**
 * Scan orchestration.
 *
 * Stage 0  wildcard-DNS calibration   (per TLD, twice, cheap)
 * Stage 1  DNS across all candidates  (~4000 lookups, the wide part)
 * Stage 2  HTTP/favicon/MX on survivors only (~2% of the set)
 *
 * `onEvent` is called as work completes so callers can stream progress; the
 * API pipes it straight into SSE.
 */

import { permute, splitDomain, TLDS } from './permute.js'
import {
  makeResolver, makeResolverPool, resolveA, resolveMx, detectWildcards,
  isWildcard, fetchProfile, similarity,
} from './probe.js'
import { score, band } from './score.js'

/** Run `worker` over `items` with a bounded number in flight. */
async function pool(items, limit, worker) {
  const out = []
  let i = 0
  const runners = Array.from({ length: Math.min(limit, items.length) }, async () => {
    while (i < items.length) {
      const idx = i++
      out[idx] = await worker(items[idx], idx)
    }
  })
  await Promise.all(runners)
  return out
}

export async function runScan(input, opts = {}) {
  const {
    limit = 4000,
    // 60, not 200. Public resolvers silently drop answers when hammered:
    // at 200-wide a scan of hdfcbank.com found 82 live hosts and ZERO
    // high-risk, missing hdfcbank.net entirely. At 60 the same scan finds
    // hdfcbank.net at score 97 and is ~10x faster overall, because the
    // dropped queries were being retried on timeout. More concurrency was
    // strictly worse on both accuracy and latency.
    dnsConcurrency = 80,
    httpConcurrency = 50,
    onEvent = () => {},
  } = opts

  const t0 = Date.now()
  const { name, tld, origin } = splitDomain(input)
  const candidates = permute(name, tld, limit)
  onEvent({ type: 'permuted', origin, candidates: candidates.length })

  const resolver = makeResolver()
  const rpool = makeResolverPool(12)

  // --- stage 0: which TLDs answer everything? ---
  const wildcards = await detectWildcards(resolver, TLDS)
  if (wildcards.size) {
    onEvent({ type: 'wildcards', tlds: [...wildcards.keys()] })
  }

  // --- baseline: what the real brand looks like ---
  const baseRaw = await fetchProfile(origin, { patient: true })
  const baseline = {
    name,
    title: baseRaw.title ?? null,
    text: baseRaw.text ?? '',
    favicon: baseRaw.favicon ?? null,
  }
  onEvent({ type: 'baseline', baseline: { title: baseline.title, favicon: baseline.favicon } })

  // --- stage 1: DNS, in two passes ---
  //
  // Pass 1 goes wide. At that rate public resolvers start rate-limiting, and a
  // rate-limited query is indistinguishable from a dead domain unless you look
  // at the error code. Pass 2 re-runs only the UNKNOWN failures (timeout /
  // servfail / refused) at a gentle concurrency. NXDOMAIN answers are final and
  // never retried, so the retry set stays small.
  const tDns = Date.now()
  let done = 0
  let wildcardFiltered = 0
  const live = []
  const unknown = []

  const record = (domain, ips) => {
    if (!ips.length) return
    if (isWildcard(wildcards, domain, ips)) {
      wildcardFiltered++
      return
    }
    live.push({ domain, ips })
  }

  await pool(candidates, dnsConcurrency, async (domain) => {
    const r = await resolveA(rpool.next(), domain)
    if (++done % 250 === 0) onEvent({ type: 'dns_progress', done, total: candidates.length })
    if (r.unknown) unknown.push(domain)
    else record(domain, r.ips)
  })

  if (unknown.length) {
    onEvent({ type: 'dns_retry', count: unknown.length })
    await pool(unknown, 15, async (domain) => {
      const r = await resolveA(rpool.next(), domain)
      record(domain, r.ips)
    })
  }

  const dnsMs = Date.now() - tDns
  onEvent({
    type: 'dns_done',
    live: live.length,
    wildcardFiltered,
    retried: unknown.length,
    ms: dnsMs,
  })

  // --- stage 2: HTTP + favicon + MX on survivors ---
  const tHttp = Date.now()
  const findings = await pool(live, httpConcurrency, async ({ domain, ips }) => {
    const [prof, mx] = await Promise.all([fetchProfile(domain), resolveMx(rpool.next(), domain)])
    const f = {
      domain,
      ips,
      mx,
      httpStatus: prof.status ?? null,
      title: prof.title ?? null,
      faviconSha: prof.favicon ?? null,
      faviconMatch: !!(baseline.favicon && prof.favicon && baseline.favicon === prof.favicon),
      hasLoginForm: !!prof.login,
      titleSimilarity: similarity(baseline.title?.toLowerCase(), prof.title?.toLowerCase()),
      bodySimilarity: similarity(baseline.text?.slice(0, 2000), prof.text?.slice(0, 2000)),
    }
    Object.assign(f, score(f, baseline))
    f.band = band(f.score)
    onEvent({ type: 'finding', finding: f })
    return f
  })
  const httpMs = Date.now() - tHttp

  findings.sort((a, b) => b.score - a.score || a.domain.localeCompare(b.domain))

  const stats = {
    origin,
    candidates: candidates.length,
    resolved: live.length,
    wildcardFiltered,
    wildcardTlds: [...wildcards.keys()],
    high: findings.filter((f) => f.band === 'high').length,
    medium: findings.filter((f) => f.band === 'medium').length,
    low: findings.filter((f) => f.band === 'low').length,
    dnsMs,
    httpMs,
    totalMs: Date.now() - t0,
  }
  onEvent({ type: 'done', stats })
  return { stats, baseline, findings }
}
