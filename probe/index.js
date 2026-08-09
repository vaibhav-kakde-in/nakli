/**
 * Probe worker.
 *
 * Subscribes to the NATS queue group and does the expensive per-host work:
 * HTTP fetch, favicon hash, MX lookup. NATS delivers each request to exactly
 * one member of the group, so scaling this service horizontally scales the
 * scan - no coordination, no shared state, no leader.
 *
 * This service listens on no port and serves no traffic. It exists purely to
 * consume work.
 */

import { connectBus, SUBJECT, QUEUE, encode, decode } from '../core/bus.js'
import { fetchProfile, makeResolver, resolveMx } from '../core/probe.js'

const CONCURRENCY = Number(process.env.PROBE_CONCURRENCY) || 25

const nc = await connectBus({ name: 'nakli-probe' })
if (!nc) {
  console.error('[probe] no NATS connection - nothing to do, exiting so the platform restarts us')
  process.exit(1)
}

const resolver = makeResolver()
let inFlight = 0
let handled = 0
let failed = 0

const sub = nc.subscribe(SUBJECT, { queue: QUEUE })
console.log(`[probe] subscribed to ${SUBJECT} (queue: ${QUEUE}), concurrency ${CONCURRENCY}`)

setInterval(() => {
  if (handled || failed) console.log(`[probe] handled=${handled} failed=${failed} inFlight=${inFlight}`)
}, 30_000).unref()

/** Crude backpressure: NATS has no per-consumer flow control here, so if we are
 *  saturated we let the request time out and the api falls back rather than
 *  queueing work we cannot start promptly. */
async function handle(msg) {
  if (inFlight >= CONCURRENCY) return
  inFlight++
  try {
    const { domain } = decode(msg)
    const [prof, mx] = await Promise.all([
      fetchProfile(domain),
      resolveMx(resolver, domain),
    ])
    msg.respond(encode({ prof, mx }))
    handled++
  } catch (e) {
    failed++
    try { msg.respond(encode({ error: String(e?.message ?? e) })) } catch { /* requester gone */ }
  } finally {
    inFlight--
  }
}

for await (const msg of sub) handle(msg)

console.log('[probe] subscription closed')
