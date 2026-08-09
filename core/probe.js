/**
 * Probe stage - turns candidate domains into evidence.
 *
 * The funnel is the whole trick: DNS filters ~4000 candidates down to ~2% live
 * hosts, so the expensive HTTP work only ever touches a small fraction. That is
 * what keeps a full scan inside 30 seconds.
 */

import { Resolver } from 'node:dns/promises'
import { createHash, randomBytes } from 'node:crypto'
import { Agent, interceptors, request } from 'undici'

// Spread load across several independent operators. A single provider
// rate-limits well below the query volume a full scan produces.
const NAMESERVERS = [
  '1.1.1.1', '1.0.0.1',      // Cloudflare
  '8.8.8.8', '8.8.4.4',      // Google
  '9.9.9.9', '149.112.112.112', // Quad9
  '208.67.222.222', '208.67.220.220', // OpenDNS
]

/** Suspected phishing hosts routinely have broken or self-signed certs - a
 *  rejected handshake would hide exactly the domains we care about.
 *
 *  undici v7 dropped `maxRedirections` on request(); redirects must be composed
 *  onto the dispatcher as an interceptor instead. Squatted domains almost always
 *  redirect, so following them is not optional. */
// 4s/5s, not 2.5s/3.5s. Tightening these to shave wall-clock dropped the
// high-risk count from 8 to 2: the cloned bank sites sit behind CDNs and simply
// need longer than a dead parking domain does. Missing a real clone to save
// eight seconds is the wrong trade for this tool.
const insecure = new Agent({
  connect: { rejectUnauthorized: false, timeout: 4000 },
  headersTimeout: 5000,
  bodyTimeout: 5000,
}).compose(interceptors.redirect({ maxRedirections: 3 }))

/**
 * The baseline fetch gets a much longer leash than candidate probes.
 *
 * It is a single request that ALL scoring depends on: with no baseline title
 * every similarity drops to zero and the clone cluster becomes invisible.
 * Tightening the shared timeout to 2.5s took hdfcbank.com's high-risk count
 * from 8 to 1, because the real site is slower than the squatters copying it.
 * Candidate probes stay aggressive - there are 80+ of them and dead hosts
 * dominate the wall clock.
 */
const patient = new Agent({
  connect: { rejectUnauthorized: false, timeout: 10000 },
  headersTimeout: 12000,
  bodyTimeout: 12000,
}).compose(interceptors.redirect({ maxRedirections: 5 }))

const UA = 'Mozilla/5.0 (compatible; nakli/1.0; +brand-protection-research)'

export function makeResolver(offset = 0) {
  const r = new Resolver({ timeout: 3000, tries: 2 })
  // Rotate the server order per resolver so the pool does not stampede one
  // operator; each socket prefers a different upstream.
  const n = NAMESERVERS.length
  r.setServers([...NAMESERVERS.slice(offset % n), ...NAMESERVERS.slice(0, offset % n)])
  return r
}

/**
 * A round-robin pool of resolvers.
 *
 * A single Resolver multiplexes every query over one UDP socket. Pushing ~200
 * concurrent lookups through it silently drops real answers - a scan of
 * hdfcbank.com found only 82 live hosts while `hdfcbank.net`, `.org`, `.in` and
 * `.biz` all resolved fine when queried individually. Those are exactly the
 * high-scoring clones, so the losses were not random noise. Spreading queries
 * over several sockets fixes it.
 */
export function makeResolverPool(size = 8) {
  const pool = Array.from({ length: size }, (_, i) => makeResolver(i))
  let i = 0
  return {
    next: () => pool[i++ % pool.length],
    all: pool,
  }
}

/** Definitive "this name does not exist" answers. Anything else is unknown. */
const DEFINITIVE = new Set(['ENOTFOUND', 'ENODATA', 'NXDOMAIN'])

/**
 * Resolve A records, reporting *why* a lookup failed.
 *
 * This distinction is the difference between a working scan and a broken one.
 * Treating a rate-limit timeout as "domain does not exist" silently deleted
 * hdfcbank.net - a byte-identical clone of the real bank - from the results.
 * @returns {{ips: string[], unknown: boolean}}
 */
export async function resolveA(resolver, domain) {
  try {
    return { ips: await resolver.resolve4(domain), unknown: false }
  } catch (e) {
    return { ips: [], unknown: !DEFINITIVE.has(e?.code) }
  }
}

export async function resolveMx(resolver, domain) {
  try {
    const mx = await resolver.resolveMx(domain)
    return mx.map((m) => m.exchange).slice(0, 3)
  } catch {
    return []
  }
}

/**
 * Detect TLDs whose registry answers *every* lookup.
 *
 * Without this the scan is worthless: in the first local run every single
 * `.co.in` candidate "resolved" to one parking IP, producing 169 phantom
 * findings. Probe two random labels per TLD; if both answer identically,
 * treat those addresses as wildcard noise.
 */
export async function detectWildcards(resolver, tlds) {
  const out = new Map()
  await Promise.all(
    tlds.map(async (tld) => {
      const sets = []
      for (let i = 0; i < 2; i++) {
        const rand = 'zq' + randomBytes(8).toString('hex')
        sets.push(new Set((await resolveA(resolver, `${rand}.${tld}`)).ips))
      }
      const [a, b] = sets
      if (a.size && a.size === b.size && [...a].every((ip) => b.has(ip))) {
        out.set(tld, a)
      }
    })
  )
  return out
}

export function isWildcard(wildcards, domain, ips) {
  const tld = domain.slice(domain.indexOf('.') + 1)
  const w = wildcards.get(tld)
  return !!w && ips.length > 0 && ips.every((ip) => w.has(ip))
}

const TITLE_RE = /<title[^>]*>([\s\S]*?)<\/title>/i
const PW_RE = /type\s*=\s*["']?password/i

const ENTITIES = { amp: '&', lt: '<', gt: '>', quot: '"', apos: "'", nbsp: ' ', '#39': "'" }
const decode = (s) =>
  s.replace(/&(#?\w+);/g, (m, e) => ENTITIES[e] ?? (/^#\d+$/.test(e) ? String.fromCharCode(+e.slice(1)) : m))

const stripTags = (html) =>
  html.replace(/<[^>]+>/g, ' ').replace(/\s+/g, ' ').trim().toLowerCase().slice(0, 4000)

/**
 * Fetch title / body text / favicon hash for a domain.
 * https and http are raced rather than tried in sequence - a sequential
 * fallback doubles the worst case on dead hosts, and dead hosts dominate.
 */
export async function fetchProfile(domain, { patient: usePatient = false } = {}) {
  const dispatcher = usePatient ? patient : insecure
  const out = {}

  // Racing https against http needs the LOSER cancelled. An undici response
  // whose body is never read holds its socket open, so leaked losers steadily
  // exhaust the connection pool and every later request queues behind them:
  // a 2500-candidate scan spent 724 SECONDS in this stage before the aborts
  // were added, against ~15s after. Silent, and catastrophic at scale.
  const controllers = new Map()
  const attempt = async (scheme) => {
    const ac = new AbortController()
    controllers.set(scheme, ac)
    const res = await request(`${scheme}://${domain}`, {
      dispatcher,
      headers: { 'user-agent': UA },
      signal: ac.signal,
    })
    return { scheme, res }
  }

  const tasks = [attempt('https'), attempt('http')]
  let got = null
  try {
    got = await Promise.any(tasks)
  } catch {
    /* both schemes failed */
  }

  for (const [scheme, ac] of controllers) {
    if (!got || scheme !== got.scheme) ac.abort()
  }
  // Anything that still lands after we picked a winner gets drained explicitly.
  Promise.allSettled(tasks).then((rs) => {
    for (const r of rs) {
      if (r.status === 'fulfilled' && r.value !== got) {
        try { r.value.res.body.dump() } catch { /* already aborted */ }
      }
    }
  })

  if (!got) return out

  const { res } = got
  out.status = res.statusCode
  let html = ''
  try {
    html = (await res.body.text()).slice(0, 200_000)
  } catch {
    /* body may abort mid-read; status alone is still evidence */
    try { res.body.dump() } catch { /* nothing to drain */ }
  }

  const m = TITLE_RE.exec(html)
  out.title = m ? decode(m[1].replace(/\s+/g, ' ').trim()).slice(0, 120) : null
  out.text = stripTags(html)
  out.login = PW_RE.test(html)

  try {
    const fav = await request(`https://${domain}/favicon.ico`, {
      dispatcher,
      headers: { 'user-agent': UA },
    })
    if (fav.statusCode === 200) {
      const buf = Buffer.from(await fav.body.arrayBuffer())
      if (buf.length > 60) out.favicon = createHash('sha256').update(buf).digest('hex').slice(0, 16)
    } else {
      fav.body.dump()
    }
  } catch {
    /* no favicon is normal */
  }
  return out
}

/** Cheap similarity on two short strings (Dice coefficient over bigrams). */
export function similarity(a, b) {
  if (!a || !b) return 0
  if (a === b) return 1
  const grams = (s) => {
    const set = new Map()
    for (let i = 0; i < s.length - 1; i++) {
      const g = s.slice(i, i + 2)
      set.set(g, (set.get(g) ?? 0) + 1)
    }
    return set
  }
  const ga = grams(a)
  const gb = grams(b)
  let hits = 0
  for (const [g, n] of ga) hits += Math.min(n, gb.get(g) ?? 0)
  const total = a.length - 1 + (b.length - 1)
  return total > 0 ? (2 * hits) / total : 0
}
