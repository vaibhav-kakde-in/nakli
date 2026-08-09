import { serve } from '@hono/node-server'
import { Hono } from 'hono'

const app = new Hono()
const startedAt = new Date().toISOString()

app.get('/health', (c) => c.json({ ok: true }))

app.get('/', (c) =>
  c.json({
    service: 'nakli-api',
    ring: 0,
    message: 'pipeline is green',
    startedAt,
    node: process.version,
  })
)

const port = Number(process.env.PORT) || 3000
serve({ fetch: app.fetch, port, hostname: '::' })
console.log(`[nakli-api] listening on :${port}`)
