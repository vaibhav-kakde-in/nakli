/**
 * Evidence archive (S3-compatible object storage, MinIO under the hood).
 *
 * A finding is a claim: "this domain was serving a copy of your login page."
 * Claims decay - phishing sites are taken down, rotated, or cleaned up, often
 * within hours. By the time anyone acts on a report the proof is frequently
 * gone.
 *
 * So the page as we saw it is archived at scan time, immutably, and served back
 * beside the finding. That is the difference between telling someone they have
 * a problem and showing them.
 *
 * Only high and medium findings are archived: low is dominated by parked
 * domains and would be almost all the bytes for almost none of the value.
 * Degrades to a no-op when storage is unavailable.
 */

import { S3Client, PutObjectCommand } from '@aws-sdk/client-s3'

const BUCKET = process.env.EVIDENCE_BUCKET
let s3 = null

export function initEvidence() {
  const shape = ['EVIDENCE_URL', 'EVIDENCE_BUCKET', 'EVIDENCE_KEY', 'EVIDENCE_SECRET']
    .map((k) => `${k}=${process.env[k] === undefined ? 'unset' : `len:${String(process.env[k]).length}`}`)
    .join(' ')
  console.log('[evidence] env shape:', shape)

  if (!process.env.EVIDENCE_URL || !BUCKET) {
    return console.log('[evidence] not configured - archiving disabled')
  }
  try {
    s3 = new S3Client({
      endpoint: process.env.EVIDENCE_URL,
      region: 'us-east-1',
      credentials: {
        accessKeyId: process.env.EVIDENCE_KEY,
        secretAccessKey: process.env.EVIDENCE_SECRET,
      },
      // MinIO needs path-style addressing; virtual-host style 404s.
      forcePathStyle: true,
    })
    console.log('[evidence] archive ready, bucket', BUCKET)
  } catch (e) {
    console.error('[evidence] init failed:', e.message)
    s3 = null
  }
}

export const evidenceEnabled = () => !!s3

async function put(key, body, contentType) {
  if (!s3) return null
  try {
    await s3.send(new PutObjectCommand({
      Bucket: BUCKET, Key: key, Body: body, ContentType: contentType,
    }))
    return key
  } catch (e) {
    console.error('[evidence] put failed:', key, e.message)
    return null
  }
}

/**
 * Archive one finding's captured page.
 * @returns {string|null} object key, stored on the finding for retrieval
 */
export async function archive(scanId, finding, html) {
  if (!s3 || !html) return null
  const safe = finding.domain.replace(/[^a-z0-9.-]/gi, '_')
  const key = `scans/${scanId}/${safe}.html`

  // A note prepended to the capture so the artifact is self-describing months
  // later, and so nobody mistakes an archived phishing page for a live one.
  const header =
    `<!-- nakli evidence capture\n` +
    `     domain:   ${finding.domain}\n` +
    `     captured: ${new Date().toISOString()}\n` +
    `     score:    ${finding.score} (${finding.band})\n` +
    `     status:   HTTP ${finding.httpStatus ?? 'none'}\n` +
    `     NOTE: archived copy of a suspected impersonation page. Not live. -->\n`

  return put(key, header + html.slice(0, 500_000), 'text/html; charset=utf-8')
}

export async function archiveManifest(scanId, stats, findings) {
  if (!s3) return null
  return put(
    `scans/${scanId}/manifest.json`,
    JSON.stringify({ scanId, capturedAt: new Date().toISOString(), stats, findings }, null, 2),
    'application/json'
  )
}
