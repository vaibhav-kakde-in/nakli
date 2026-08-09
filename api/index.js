import { serve } from '@hono/node-server'
import { Hono } from 'hono'
import { cors } from 'hono/cors'
import { runScan } from '../core/scan.js'
import { splitDomain } from '../core/permute.js'

const app = new Hono()
app.use('/api/*', cors())

const startedAt = new Date().toISOString()
let scansRun = 0

app.get('/health', (c) => c.json({ ok: true }))

app.get('/', (c) =>
  c.json({
    service: 'nakli-api',
    tagline: 'Finds the domains pretending to be you.',
    startedAt,
    scansRun,
    endpoints: {
      'GET /api/scan?brand=': 'blocking JSON scan',
      'GET /api/scan/stream?brand=': 'server-sent events, results as they land',
    },
  })
)

/** Reject anything that is not plausibly a hostname before doing 2500 lookups. */
function parseBrand(raw) {
  if (!raw) return { error: 'brand is required' }
  const { name, tld, origin } = splitDomain(raw)
  if (!name || name.length < 2 || name.length > 63) return { error: 'brand looks invalid' }
  if (!/^[a-z0-9-]+(\.[a-z0-9-]+)*$/.test(name)) return { error: 'brand has invalid characters' }
  return { name, tld, origin }
}

app.get('/api/scan', async (c) => {
  const parsed = parseBrand(c.req.query('brand'))
  if (parsed.error) return c.json({ error: parsed.error }, 400)

  const limit = Math.min(Number(c.req.query('limit')) || 1800, 5000)
  scansRun++
  const result = await runScan(parsed.origin, { limit })
  return c.json(result)
})

app.get('/api/scan/stream', async (c) => {
  const parsed = parseBrand(c.req.query('brand'))
  if (parsed.error) return c.json({ error: parsed.error }, 400)

  const limit = Math.min(Number(c.req.query('limit')) || 1800, 5000)
  scansRun++

  const encoder = new TextEncoder()
  const stream = new ReadableStream({
    async start(controller) {
      const send = (ev) => {
        try {
          controller.enqueue(encoder.encode(`data: ${JSON.stringify(ev)}\n\n`))
        } catch {
          /* client went away mid-scan */
        }
      }
      try {
        await runScan(parsed.origin, { limit, onEvent: send })
      } catch (err) {
        send({ type: 'error', message: String(err?.message ?? err) })
      } finally {
        try { controller.close() } catch { /* already closed */ }
      }
    },
  })

  return new Response(stream, {
    headers: {
      'content-type': 'text/event-stream',
      'cache-control': 'no-cache',
      connection: 'keep-alive',
      // the Zerops L7 balancer buffers by default; SSE needs this off
      'x-accel-buffering': 'no',
    },
  })
})

const port = Number(process.env.PORT) || 3000
serve({ fetch: app.fetch, port, hostname: '::' })
console.log(`[nakli-api] listening on :${port}`)
