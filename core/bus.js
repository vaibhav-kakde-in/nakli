/**
 * NATS request/reply between the api and the probe workers.
 *
 * Why a broker at all: a scan fans out to hundreds of live hosts, each needing
 * an HTTP fetch, a favicon fetch and an MX lookup. That work is IO-bound, bursty
 * and completely independent per host - exactly what a queue group distributes
 * well. Workers scale horizontally (1..5 containers) while the api stays single
 * and cheap.
 *
 * Request/reply rather than fire-and-forget because the api needs the answer to
 * score it, and NATS handles the correlation and load balancing for us.
 *
 * If NATS is unreachable the caller falls back to probing in-process. A broker
 * outage should slow a scan down, not break it.
 */

import { connect, StringCodec } from 'nats'

export const SUBJECT = 'nakli.probe'
export const QUEUE = 'probes'

const sc = StringCodec()

export function natsUrl() {
  const raw = process.env.NATS_URL || process.env.NATS_HOSTNAME
  if (!raw) return null
  if (raw.startsWith('nats://')) return raw
  const port = process.env.NATS_PORT || '4222'
  return `nats://${raw}:${port}`
}

export async function connectBus({ name = 'nakli', timeout = 5000 } = {}) {
  // Presence + length only. These are credentials; their values must never be
  // logged, and a length is enough to tell "unset" from "set but wrong".
  const shape = ['NATS_URL', 'NATS_USER', 'NATS_PASSWORD', 'NATS_HOSTNAME', 'NATS_PORT']
    .map((k) => `${k}=${process.env[k] === undefined ? 'unset' : `len:${String(process.env[k]).length}`}`)
    .join(' ')
  console.log('[bus] env shape:', shape)

  const servers = natsUrl()
  if (!servers) return null
  // Scheme + host only - a connection string can carry credentials.
  console.log('[bus] target:', servers.replace(/\/\/[^@]*@/, '//***@'))

  // nats.js does NOT read credentials out of the connection URL - userinfo in
  // `servers` is ignored, and it connects anonymously. Zerops' connectionString
  // embeds them (nats://user:pass@bus:4222), so relying on the URL alone fails
  // with 'Authorization Violation'. Strip the URL down to host:port and always
  // pass credentials explicitly.
  let host = servers
  let urlUser = null
  let urlPass = null
  try {
    const u = new URL(servers)
    host = `nats://${u.hostname}:${u.port || 4222}`
    if (u.username) {
      urlUser = decodeURIComponent(u.username)
      urlPass = decodeURIComponent(u.password || '')
    }
  } catch {
    /* not a parseable URL; use it as given */
  }

  const opts = { servers: host, name, timeout, maxReconnectAttempts: -1, reconnectTimeWait: 1000 }
  const user = process.env.NATS_USER || urlUser
  const pass = process.env.NATS_PASSWORD || urlPass
  if (user) {
    opts.user = user
    opts.pass = pass
  }

  try {
    const nc = await connect(opts)
    console.log(`[bus] connected to ${nc.getServer()}`)
    return nc
  } catch (e) {
    console.error('[bus] connect failed, will probe in-process:', e.message)
    return null
  }
}

export const encode = (obj) => sc.encode(JSON.stringify(obj))
export const decode = (msg) => JSON.parse(sc.decode(msg.data))

/**
 * Build a probe function backed by NATS.
 * Falls back to `local` on timeout or transport error so one flaky worker
 * cannot take findings away from a scan.
 */
export function makeBusProbe(nc, local, { timeout = 20000 } = {}) {
  return async function probeHost(domain) {
    try {
      const reply = await nc.request(SUBJECT, encode({ domain }), { timeout })
      const out = decode(reply)
      if (out?.error) throw new Error(out.error)
      return { prof: out.prof ?? {}, mx: out.mx ?? [], via: 'worker' }
    } catch (e) {
      const res = await local(domain)
      return { ...res, via: 'local-fallback', fallbackReason: e.message }
    }
  }
}
