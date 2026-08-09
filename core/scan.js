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
import { getMany, setMany, getWildcards, setWildcards, cacheEnabled } from './cache.js'
import { analyzeHomograph, homographNote } from './homoglyph.js'
import { classify } from './classify.js'
import { archive, archiveManifest, evidenceEnabled } from './evidence.js'

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
    // 1800, not 4000. Because candidates are emitted in priority tiers, cutting
    // the limit removes the long tail of unlikely variants and keeps every
    // exact-brand-on-another-TLD and combosquat - the classes that actually
    // score high. Cheaper than raising concurrency and it costs no recall
    // where it matters.
    limit = 1800,

    // DNS stays deliberately modest. Public resolvers silently drop answers
    // when hammered, and a dropped answer is indistinguishable from "no such
    // domain": at 200-wide, a scan of hdfcbank.com found ZERO high-risk and
    // missed hdfcbank.net entirely. Going wider is worse on BOTH accuracy and
    // latency, because the losses come back as timeouts that must be retried.
    dnsConcurrency = 80,

    // 50. Raising this to 150 cut the HTTP stage from 85s to 10.5s and was
    // still WRONG: high-risk findings collapsed from 17 to 2. Lookalikes of one
    // brand overwhelmingly resolve to the same CDN, so 150 parallel connections
    // read as an attack and get throttled - every probe came back status=None
    // while the baseline stayed healthy. The ceiling here belongs to the target,
    // not to us, so scan volume is the lever instead (see `limit`).
    httpConcurrency = 50,
    onEvent = () => {},
    // Injectable so the api can route this through NATS to the probe workers.
    // Defaults to probing in-process, which keeps the module testable and means
    // a broker outage degrades performance rather than breaking the scan.
    probeHost = null,
    scanId = null,
  } = opts

  const t0 = Date.now()
  const { name, tld, origin } = splitDomain(input)
  const candidates = permute(name, tld, limit)
  onEvent({ type: 'permuted', origin, candidates: candidates.length, domains: candidates })

  const resolver = makeResolver()
  const rpool = makeResolverPool(12)

  // --- stage 0: which TLDs answer everything? ---
  let wildcards = await getWildcards()
  if (!wildcards) {
    wildcards = await detectWildcards(resolver, TLDS)
    await setWildcards(wildcards)
  }
  if (wildcards.size) {
    onEvent({ type: 'wildcards', tlds: [...wildcards.keys()] })
  }

  // --- baseline: what the real brand looks like ---
  //
  // EVERY similarity score is measured against this one fetch. When it fails,
  // titleSimilarity and bodySimilarity are 0 for every candidate and the scan
  // confidently reports zero high-risk domains for a brand riddled with clones.
  // A paypal.com run did exactly that. So: retry, and if it still fails, say so
  // loudly rather than publishing a clean-looking wrong answer.
  let baseRaw = {}
  for (let attempt = 1; attempt <= 3; attempt++) {
    baseRaw = await fetchProfile(origin, { patient: true })
    if (baseRaw.title || baseRaw.text) break
    if (attempt < 3) await new Promise((r) => setTimeout(r, attempt * 1200))
  }
  const baseline = {
    name,
    title: baseRaw.title ?? null,
    text: baseRaw.text ?? '',
    favicon: baseRaw.favicon ?? null,
  }
  const baselineOk = !!(baseline.title || baseline.text)
  if (!baselineOk) {
    console.warn(`[scan] baseline unreachable for ${origin} - similarity scoring disabled`)
  }
  onEvent({
    type: 'baseline',
    ok: baselineOk,
    baseline: { title: baseline.title, favicon: baseline.favicon },
  })

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

  // Per-candidate results are streamed in small batches so the UI can render
  // every lookup as it lands. One event per candidate would be 1800 messages;
  // batching keeps the stream cheap while still looking continuous.
  let batch = []
  const flush = () => {
    if (!batch.length) return
    onEvent({ type: 'dns_batch', cells: batch })
    batch = []
  }
  const mark = (i, state) => {
    cellState[i] = CODE[state] ?? '.'
    batch.push([i, state])
    if (batch.length >= 25) flush()
  }

  // One character per candidate, in candidate order. 1800 bytes, and it lets a
  // stored scan redraw its real grid later instead of a fabricated one.
  const cellState = new Array(candidates.length).fill('.')
  const CODE = { dead: 'd', wildcard: 'w', live: 'l', low: 'o', medium: 'm', high: 'h' }

  const record = (domain, ips, i) => {
    if (!ips.length) return mark(i, 'dead')
    if (isWildcard(wildcards, domain, ips)) {
      wildcardFiltered++
      return mark(i, 'wildcard')
    }
    live.push({ domain, ips, i })
    mark(i, 'live')
  }

  // Bulk cache read before touching a resolver. On a repeat scan this answers
  // almost everything and the DNS stage collapses to near-zero.
  const cached = await getMany(candidates)
  const toResolve = []
  candidates.forEach((domain, i) => {
    if (cached.has(domain)) {
      done++
      record(domain, cached.get(domain), i)
    } else {
      toResolve.push([domain, i])
    }
  })
  flush()
  if (cached.size) onEvent({ type: 'cache_hits', hits: cached.size, total: candidates.length })

  const fresh = []
  await pool(toResolve, dnsConcurrency, async ([domain, i]) => {
    const r = await resolveA(rpool.next(), domain)
    if (++done % 250 === 0) onEvent({ type: 'dns_progress', done, total: candidates.length })
    if (r.unknown) unknown.push([domain, i])
    else {
      // Only definitive answers are cacheable - see cache.js.
      fresh.push([domain, r.ips])
      record(domain, r.ips, i)
    }
  })
  flush()

  if (unknown.length) {
    onEvent({ type: 'dns_retry', count: unknown.length })
    await pool(unknown, 15, async ([domain, i]) => {
      const r = await resolveA(rpool.next(), domain)
      if (!r.unknown) fresh.push([domain, r.ips])
      record(domain, r.ips, i)
    })
    flush()
  }

  await setMany(fresh)

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
  const localProbe = async (domain) => {
    const [prof, mx] = await Promise.all([fetchProfile(domain), resolveMx(rpool.next(), domain)])
    return { prof, mx, via: 'local' }
  }
  const probe = probeHost ?? localProbe
  let viaWorker = 0

  const findings = await pool(live, httpConcurrency, async ({ domain, ips, i }) => {
    const { prof, mx, via } = await probe(domain)
    if (via === 'worker') viaWorker++
    const f = {
      domain,
      i,
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
    // Homograph analysis before scoring: a visually identical domain is the
    // single most dangerous case and must be able to influence both.
    f.homograph = analyzeHomograph(domain, origin)
    f.homographNote = homographNote(f.homograph)

    Object.assign(f, score(f, baseline))
    if (f.homograph.visuallyIdentical) {
      f.score = Math.min(100, f.score + 25)
      f.reasons.unshift('visually identical to the real domain')
    } else if (f.homograph.confusables.length) {
      f.score = Math.min(100, f.score + 10)
      f.reasons.unshift(f.homographNote)
    }
    f.band = band(f.score)
    f.threat = classify(f, baseline)
    cellState[i] = CODE[f.band] ?? 'l'

    if (scanId && f.band !== 'low' && prof.html) {
      f.evidenceKey = await archive(scanId, f, prof.html)
    }
    delete prof.html

    onEvent({ type: 'finding', finding: f })
    return f
  })
  // --- stage 2b: retry hosts that gave no HTTP response at all ---
  //
  // Same lesson as DNS pass 2: a host that did not answer is UNKNOWN, not dead.
  // Lookalikes of one brand share a CDN, so a burst of 50 concurrent probes gets
  // some of them throttled - and those are exactly the ones serving clones. Two
  // consecutive walmart.com scans returned 0 and then 2 high-risk purely from
  // this. Retried gently, one pass, so a scan converges instead of drifting.
  const noAnswer = findings.filter((f) => f.httpStatus === null && f.ips?.length)
  let recovered = 0
  if (noAnswer.length) {
    onEvent({ type: 'http_retry', count: noAnswer.length })
    await pool(noAnswer, 10, async (f) => {
      const { prof } = await probe(f.domain)
      if (!prof?.status) return
      f.httpStatus = prof.status
      f.title = prof.title ?? null
      f.faviconSha = prof.favicon ?? null
      f.faviconMatch = !!(baseline.favicon && prof.favicon && baseline.favicon === prof.favicon)
      f.hasLoginForm = !!prof.login
      f.titleSimilarity = similarity(baseline.title?.toLowerCase(), prof.title?.toLowerCase())
      f.bodySimilarity = similarity(baseline.text?.slice(0, 2000), prof.text?.slice(0, 2000))
      Object.assign(f, score(f, baseline))
      if (f.homograph?.visuallyIdentical) {
        f.score = Math.min(100, f.score + 25)
        f.reasons.unshift('visually identical to the real domain')
      }
      f.band = band(f.score)
      f.threat = classify(f, baseline)
      cellState[f.i] = { high: 'h', medium: 'm', low: 'o' }[f.band] ?? 'l'
      recovered++
      onEvent({ type: 'finding', finding: f, updated: true })
    })
  }

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
    probedByWorkers: viaWorker,
    probedLocally: live.length - viaWorker,
    cacheHits: cached.size,
    cacheEnabled: cacheEnabled(),
    baselineOk,
    httpRetried: noAnswer.length,
    httpRecovered: recovered,
    evidenceArchived: findings.filter((f) => f.evidenceKey).length,
  }
  if (scanId && evidenceEnabled()) {
    await archiveManifest(scanId, stats, findings.filter((f) => f.band !== 'low'))
  }

  onEvent({ type: 'done', stats })
  return { stats, baseline, findings, cells: cellState.join('') }
}
