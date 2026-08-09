import { serve } from '@hono/node-server'
import { Hono } from 'hono'
import { cors } from 'hono/cors'
import { randomUUID } from 'node:crypto'
import { runScan } from '../core/scan.js'
import { splitDomain } from '../core/permute.js'
import { initDb, saveScan, loadScan, recentScans, dbHealth, dbEnabled } from '../core/db.js'
import { connectBus, makeBusProbe } from '../core/bus.js'
import { initCache, cacheHealth } from '../core/cache.js'
import { initEvidence, evidenceEnabled } from '../core/evidence.js'
import { describe } from '../core/classify.js'
import { fetchProfile, makeResolver, resolveMx } from '../core/probe.js'

const app = new Hono()
app.use('/api/*', cors())

const startedAt = new Date().toISOString()

/**
 * Scan jobs.
 *
 * A full scan takes 30-90s, but the Zerops L7 balancer returns 504 at exactly
 * 60s - so a blocking request CANNOT be the public interface, however well it
 * works over the private network. Scans therefore run as background jobs:
 * callers either poll the job or subscribe to the SSE stream, which stays alive
 * because it is continuously producing events.
 *
 * In-memory for now; Postgres next, which is what makes scan links shareable.
 */
const jobs = new Map()
const byBrand = new Map()
const JOB_TTL_MS = 30 * 60 * 1000

function reapOldJobs() {
  const cutoff = Date.now() - JOB_TTL_MS
  for (const [id, job] of jobs) {
    if (job.finishedAt && job.finishedAt < cutoff) {
      jobs.delete(id)
      if (byBrand.get(job.origin) === id) byBrand.delete(job.origin)
    }
  }
}

function startJob(origin, limit) {
  const id = randomUUID()
  const job = {
    id,
    origin,
    limit,
    status: 'running',
    startedAt: Date.now(),
    finishedAt: null,
    progress: { stage: 'permuting' },
    result: null,
    error: null,
  }
  jobs.set(id, job)
  byBrand.set(origin, id)

  runScan(origin, {
    limit,
    probeHost,
    scanId: id,
    onEvent: (ev) => {
      if (ev.type === 'permuted') job.progress = { stage: 'dns', candidates: ev.candidates }
      else if (ev.type === 'dns_progress') job.progress = { stage: 'dns', ...ev }
      else if (ev.type === 'dns_done') job.progress = { stage: 'probing', live: ev.live }
      else if (ev.type === 'finding') job.progress.found = (job.progress.found ?? 0) + 1
    },
  })
    .then(async (result) => {
      job.result = result
      job.status = 'done'
      // Persistence must never be able to fail a scan the user already has.
      saveScan(id, origin, result).catch((e) => console.error('[db] save:', e.message))
    })
    .catch((err) => {
      job.error = String(err?.message ?? err)
      job.status = 'error'
    })
    .finally(() => {
      job.finishedAt = Date.now()
      reapOldJobs()
    })

  return job
}

app.get('/health', (c) => c.json({ ok: true }))
app.get('/api/health', async (c) =>
  c.json({
    ok: true,
    db: await dbHealth(),
    bus: { connected: !!nc && !nc.isClosed(), server: nc?.getServer() ?? null },
    cache: await cacheHealth(),
    evidence: { enabled: evidenceEnabled() },
  }))
app.get('/api/recent', async (c) => c.json({ scans: await recentScans(12) }))

app.get('/', (c) =>
  c.json({
    service: 'nakli-api',
    tagline: 'Finds the domains pretending to be you.',
    startedAt,
    jobs: jobs.size,
    endpoints: {
      'GET /api/scan?brand=': 'start a scan; returns a job (202) or a cached result (200)',
      'GET /api/scan/:id': 'poll a scan job',
      'GET /api/scan/stream?brand=': 'server-sent events, live results',
    },
  })
)

/** Reject anything not plausibly a hostname before doing ~1800 lookups. */
function parseBrand(raw) {
  if (!raw) return { error: 'brand is required' }
  const { name, tld, origin } = splitDomain(raw)
  if (!name || name.length < 2 || name.length > 63) return { error: 'brand looks invalid' }
  if (!/^[a-z0-9-]+(\.[a-z0-9-]+)*$/.test(name)) return { error: 'brand has invalid characters' }
  return { name, tld, origin }
}

const wantLimit = (c) => Math.min(Number(c.req.query('limit')) || 1800, 5000)

app.get('/api/scan', (c) => {
  const parsed = parseBrand(c.req.query('brand'))
  if (parsed.error) return c.json({ error: parsed.error }, 400)
  const limit = wantLimit(c)

  // Reuse an in-flight or recent scan of the same brand rather than launching
  // thousands of duplicate lookups.
  const existingId = byBrand.get(parsed.origin)
  const existing = existingId && jobs.get(existingId)
  if (existing && existing.limit === limit) {
    if (existing.status === 'done') {
      return c.json({ scanId: existing.id, status: 'done', ...existing.result })
    }
    return c.json({ scanId: existing.id, status: existing.status, progress: existing.progress }, 202)
  }

  const job = startJob(parsed.origin, limit)
  return c.json(
    {
      scanId: job.id,
      status: 'running',
      brand: parsed.origin,
      poll: `/api/scan/${job.id}`,
      stream: `/api/scan/stream?brand=${encodeURIComponent(parsed.origin)}`,
      note: 'a scan takes 30-90s; poll this job or use the stream endpoint',
    },
    202
  )
})

// NOTE: this literal route MUST be registered before '/api/scan/:id',
// otherwise Hono matches 'stream' as a scan id and returns 404.
app.get('/api/scan/stream', (c) => {
  const parsed = parseBrand(c.req.query('brand'))
  if (parsed.error) return c.json({ error: parsed.error }, 400)
  const limit = wantLimit(c)

  // The stream runs its own scan rather than attaching to a job, so it has to
  // mint an id and persist the result itself - otherwise a scan started from
  // the UI would never be shareable.
  const scanId = randomUUID()

  const encoder = new TextEncoder()
  const stream = new ReadableStream({
    async start(controller) {
      let open = true
      const send = (ev) => {
        if (!open) return
        try {
          controller.enqueue(encoder.encode(`data: ${JSON.stringify(ev)}\n\n`))
        } catch {
          open = false
        }
      }
      // A heartbeat keeps the proxy from idling the connection out during the
      // quiet stretch between DNS batches.
      const beat = setInterval(() => send({ type: 'ping', t: Date.now() }), 10_000)
      send({ type: 'scan_id', scanId })
      try {
        const result = await runScan(parsed.origin, { limit, probeHost, scanId, onEvent: send })
        await saveScan(scanId, parsed.origin, result).catch(() => false)
        send({ type: 'result', scanId, stats: result.stats, findings: result.findings })
      } catch (err) {
        send({ type: 'error', message: String(err?.message ?? err) })
      } finally {
        clearInterval(beat)
        try { controller.close() } catch { /* already closed */ }
      }
    },
  })

  return new Response(stream, {
    headers: {
      'content-type': 'text/event-stream',
      'cache-control': 'no-cache',
      connection: 'keep-alive',
      // the Zerops L7 balancer buffers responses by default; SSE needs it off
      'x-accel-buffering': 'no',
    },
  })
})

/** Export a finished scan. CSV for spreadsheets and ticketing, JSON for tools. */
app.get('/api/scan/:id/export', async (c) => {
  const id = c.req.param('id')
  const job = jobs.get(id)
  const data = job?.status === 'done' ? { ...job.result, scanId: id } : await loadScan(id)
  if (!data) return c.json({ error: 'unknown scan id' }, 404)

  const fmt = (c.req.query('format') || 'csv').toLowerCase()
  const stamp = (data.stats.origin || 'scan').replace(/[^a-z0-9.-]/gi, '_')

  if (fmt === 'json') {
    return new Response(JSON.stringify(data, null, 2), {
      headers: {
        'content-type': 'application/json',
        'content-disposition': `attachment; filename="nakli-${stamp}.json"`,
      },
    })
  }

  const esc = (v) => {
    const s = v == null ? '' : String(v)
    return /[",\n]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s
  }
  const head = ['domain', 'score', 'band', 'threat', 'ips', 'mx', 'http_status',
                'title', 'title_match', 'content_match', 'login_form',
                'favicon_match', 'punycode', 'reasons']
  const rows = (data.findings || []).map((f) => [
    f.domain, f.score, f.band, describe(f.threat).label,
    (f.ips || []).join(' '), (f.mx || []).join(' '), f.httpStatus, f.title,
    f.titleSimilarity != null ? Math.round(f.titleSimilarity * 100) + '%' : '',
    f.bodySimilarity != null ? Math.round(f.bodySimilarity * 100) + '%' : '',
    f.hasLoginForm ? 'yes' : 'no', f.faviconMatch ? 'yes' : 'no',
    f.homograph?.punycode || '', (f.reasons || []).join('; '),
  ].map(esc).join(','))

  return new Response([head.join(','), ...rows].join('\n'), {
    headers: {
      'content-type': 'text/csv; charset=utf-8',
      'content-disposition': `attachment; filename="nakli-${stamp}.csv"`,
    },
  })
})

app.get('/api/scan/:id', async (c) => {
  const job = jobs.get(c.req.param('id'))
  // Jobs are reaped after 30 minutes; a persisted scan outlives them, which is
  // what makes a shared link keep working.
  if (!job) {
    const saved = await loadScan(c.req.param('id'))
    return saved ? c.json(saved) : c.json({ error: 'unknown scan id' }, 404)
  }
  if (job.status === 'error') return c.json({ scanId: job.id, status: 'error', error: job.error }, 500)
  if (job.status === 'running') {
    return c.json({
      scanId: job.id,
      status: 'running',
      brand: job.origin,
      elapsedMs: Date.now() - job.startedAt,
      progress: job.progress,
    })
  }
  return c.json({ scanId: job.id, status: 'done', ...job.result })
})


await initDb()
await initCache()
initEvidence()

// Route per-host probing through the NATS workers when the broker is up.
const nc = await connectBus({ name: 'nakli-api' })
const apiResolver = makeResolver()
const localProbe = async (domain) => {
  const [prof, mx] = await Promise.all([fetchProfile(domain), resolveMx(apiResolver, domain)])
  return { prof, mx, via: 'local' }
}
const probeHost = nc ? makeBusProbe(nc, localProbe) : null
console.log(probeHost ? '[api] probing via NATS workers' : '[api] probing in-process (no NATS)')

const port = Number(process.env.PORT) || 3000
serve({ fetch: app.fetch, port, hostname: '::' })
console.log(`[nakli-api] listening on :${port}`)
