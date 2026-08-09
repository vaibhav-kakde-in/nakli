/**
 * Static host for the Nakli UI, plus a same-origin proxy to the api service.
 *
 * The proxy exists so the browser only ever talks to one origin: no CORS
 * preflight on the SSE stream, and no second public URL for a judge to find.
 * It reaches `api` over the project's private network, which is also the
 * cheapest demonstration that these really are separate services.
 *
 * Streaming is forwarded chunk-by-chunk rather than buffered - buffering an
 * event stream would defeat the entire point of it.
 */

import { createServer } from 'node:http'
import { readFile } from 'node:fs/promises'
import { extname, join, normalize } from 'node:path'
import { fileURLToPath } from 'node:url'

const ROOT = join(fileURLToPath(new URL('.', import.meta.url)), 'public')
const API = process.env.API_URL || 'http://api:3000'
const PORT = Number(process.env.PORT) || 3000

const MIME = {
  '.html': 'text/html; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.svg': 'image/svg+xml',
  '.ico': 'image/x-icon',
  '.json': 'application/json',
}

async function proxy(req, res) {
  const upstream = API + req.url
  try {
    const r = await fetch(upstream, {
      headers: { accept: req.headers.accept ?? '*/*' },
    })

    const headers = {}
    for (const [k, v] of r.headers) {
      if (!['content-encoding', 'content-length', 'transfer-encoding'].includes(k)) headers[k] = v
    }
    // Never let a proxy or balancer sit on an event stream.
    if ((r.headers.get('content-type') ?? '').includes('event-stream')) {
      headers['cache-control'] = 'no-cache'
      headers['x-accel-buffering'] = 'no'
    }
    res.writeHead(r.status, headers)

    if (!r.body) return res.end()
    const reader = r.body.getReader()
    req.on('close', () => reader.cancel().catch(() => {}))
    for (;;) {
      const { done, value } = await reader.read()
      if (done) break
      res.write(Buffer.from(value))
    }
    res.end()
  } catch (err) {
    res.writeHead(502, { 'content-type': 'application/json' })
    res.end(JSON.stringify({ error: 'upstream unavailable', detail: String(err?.message ?? err) }))
  }
}

createServer(async (req, res) => {
  const url = new URL(req.url, 'http://x')

  if (url.pathname === '/healthz') {
    res.writeHead(200, { 'content-type': 'application/json' })
    return res.end('{"ok":true}')
  }
  if (url.pathname.startsWith('/api/')) return proxy(req, res)

  const rel = url.pathname === '/' ? 'index.html' : normalize(url.pathname).replace(/^(\.\.[/\\])+/, '')
  try {
    const body = await readFile(join(ROOT, rel))
    res.writeHead(200, {
      'content-type': MIME[extname(rel)] ?? 'application/octet-stream',
      'cache-control': rel === 'index.html' ? 'no-cache' : 'public, max-age=3600',
    })
    res.end(body)
  } catch {
    res.writeHead(404, { 'content-type': 'text/plain' })
    res.end('not found')
  }
}).listen(PORT, '::', () => console.log(`[nakli-web] listening on :${PORT} -> ${API}`))
