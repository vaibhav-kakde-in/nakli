/**
 * Valkey DNS cache.
 *
 * DNS dominates a scan - 20-50s of a 40-70s run - and the resolvers are the
 * bottleneck, not us. Caching turns a repeat scan into an almost instant one and
 * takes sustained load off the public resolvers, which is what was causing the
 * rate-limit drops in the first place.
 *
 * Two deliberate choices:
 *
 *  - NEGATIVE answers get the LONGER ttl. ~95% of candidates are NXDOMAIN, and
 *    a domain that does not exist tends to keep not existing. That is where the
 *    hit rate lives.
 *  - UNKNOWN answers (timeout / servfail) are never cached. Caching "we could
 *    not tell" would make a transient rate-limit look permanent, which is the
 *    exact bug that hid hdfcbank.net for hours.
 *
 * Degrades to a no-op if Valkey is unreachable.
 */

import { createClient } from 'redis'

const TTL_POSITIVE = 3600      // 1h  - live domains can move
const TTL_NEGATIVE = 21600     // 6h  - absence is stable, and this is the bulk
const TTL_WILDCARD = 86400     // 24h - registry behaviour barely changes

let client = null
let ready = false
export const stats = { hits: 0, misses: 0, writes: 0 }

function redisUrl() {
  const raw = process.env.CACHE_URL
  if (!raw) {
    const host = process.env.CACHE_HOST
    if (!host) return null
    const port = process.env.CACHE_PORT || '6379'
    const pass = process.env.CACHE_PASSWORD
    return pass
      ? `redis://:${encodeURIComponent(pass)}@${host}:${port}`
      : `redis://${host}:${port}`
  }
  // Zerops may hand back a valkey:// scheme; node-redis only knows redis://.
  // Unlike nats.js, node-redis DOES parse credentials out of the URL.
  return raw.replace(/^valkey(s?):\/\//, 'redis$1://')
}

export async function initCache() {
  const shape = ['CACHE_URL', 'CACHE_HOST', 'CACHE_PORT', 'CACHE_PASSWORD']
    .map((k) => `${k}=${process.env[k] === undefined ? 'unset' : `len:${String(process.env[k]).length}`}`)
    .join(' ')
  console.log('[cache] env shape:', shape)

  const url = redisUrl()
  if (!url) return console.log('[cache] no CACHE_URL - caching disabled')

  try {
    client = createClient({ url, socket: { connectTimeout: 4000, reconnectStrategy: (n) => Math.min(n * 200, 3000) } })
    client.on('error', (e) => {
      if (ready) console.error('[cache] error:', e.message)
      ready = false
    })
    client.on('ready', () => { ready = true })
    await client.connect()
    ready = true
    console.log('[cache] connected')
  } catch (e) {
    console.error('[cache] connect failed, continuing without cache:', e.message)
    client = null
  }
}

export const cacheEnabled = () => ready

const key = (d) => `dns:a:${d}`

/**
 * Bulk-read cached DNS answers.
 * @returns {Map<string, string[]>} domain -> ips ([] means known-nonexistent)
 */
export async function getMany(domains) {
  const out = new Map()
  if (!ready || !domains.length) return out
  try {
    // Chunked MGET: 1800 individual round trips would cost more than the
    // lookups they replace.
    for (let i = 0; i < domains.length; i += 500) {
      const slice = domains.slice(i, i + 500)
      const vals = await client.mGet(slice.map(key))
      vals.forEach((v, j) => {
        if (v === null) return
        out.set(slice[j], v === '' ? [] : v.split(','))
      })
    }
    stats.hits += out.size
    stats.misses += domains.length - out.size
  } catch (e) {
    console.error('[cache] getMany failed:', e.message)
  }
  return out
}

/** Store definitive answers only. `entries` is [domain, ips[]][]. */
export async function setMany(entries) {
  if (!ready || !entries.length) return
  try {
    const pipe = client.multi()
    for (const [domain, ips] of entries) {
      pipe.setEx(key(domain), ips.length ? TTL_POSITIVE : TTL_NEGATIVE, ips.join(','))
    }
    await pipe.exec()
    stats.writes += entries.length
  } catch (e) {
    console.error('[cache] setMany failed:', e.message)
  }
}

export async function getWildcards() {
  if (!ready) return null
  try {
    const raw = await client.get('dns:wildcards')
    return raw ? new Map(Object.entries(JSON.parse(raw)).map(([k, v]) => [k, new Set(v)])) : null
  } catch { return null }
}

export async function setWildcards(map) {
  if (!ready) return
  try {
    const obj = Object.fromEntries([...map].map(([k, v]) => [k, [...v]]))
    await client.setEx('dns:wildcards', TTL_WILDCARD, JSON.stringify(obj))
  } catch { /* non-fatal */ }
}

export async function cacheHealth() {
  if (!client) return { enabled: false }
  if (!ready) return { enabled: true, ok: false }
  try {
    const n = await client.dbSize()
    return { enabled: true, ok: true, keys: n, ...stats }
  } catch (e) {
    return { enabled: true, ok: false, error: e.message }
  }
}
