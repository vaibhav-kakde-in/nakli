# Nakli — spec & build plan

> **nakli** (नकली) — Hindi for *counterfeit, fake*.
>
> Name checked against the field: Doppel, ZeroFox, Bolster, BrandShield, PhishLabs,
> Patrowl and HookPhish all occupy this space. Nakli collides with none of them.

**The Zerops Challenge · solo · deadline Sunday 9 Aug, end of day IST**

---

## 1. The three-second pitch

> **Type your brand. In under 30 seconds, see every lookalike domain that exists
> right now — ranked, with evidence.**

Tagline: *Nakli finds the domains pretending to be you.*

Francesco's single biggest criticism on the kickoff stream was that projects failed
to say what they did in three seconds. That line goes at the top of the README, the
landing page and the social post, unchanged.

## 2. The problem

Brand-impersonation phishing starts with a domain: `hdfcbank.net`, `hdfc-bank.co`,
`dhfcbank.com`. Security teams find out when a customer gets robbed. The data to
find them first is public — DNS, HTTP, MX, favicons — but nobody correlates it on
demand for an arbitrary brand.

Existing tools are either offline CLIs (dnstwist) or paid platforms. Nothing gives
you an instant, evidence-backed answer from a browser, for free.

## 3. How it works

```
brand: "hdfcbank.com"
  ↓  permutation engine        homoglyph · typo · bitsquat · TLD-swap · combosquat
  ↓  4,000 candidate domains
  ↓  wildcard-DNS calibration  discard TLDs whose registry answers everything
  ↓  NATS fan-out → workers
  ↓  DNS resolve → (survivors only) HTTP · favicon hash · title/content similarity · MX
  ↓  scored + ranked
  86 live domains · 6 high-risk · with evidence
```

**Validated locally before any infrastructure was written** (`phishscan.py`):
4,000 candidates → DNS 5.0s → probe 9.1s → **16.0s total**, 169 wildcard false
positives filtered, 6 domains serving a byte-identical copy of the real homepage.

### The funnel is the whole trick
4,000 candidates collapse to ~86 live hosts. Expensive HTTP work touches **2%** of
the set. That is what fits the job inside 30 seconds.

## 4. Architecture on Zerops

| Service | Type | Job | Why it is load-bearing |
|---|---|---|---|
| `web` | Next.js SSR | UI, live results | — |
| `api` | Hono/TS | scan orchestration, SSE | — |
| `permute` | worker | candidate generation | pure CPU, <0.1s |
| `probe` | worker ×N | DNS · HTTP · favicon · MX | **5,000 probes/scan under a 30s deadline** |
| `nats` | broker | fan-out + result collection | the parallelism *is* the product |
| `db` | PostgreSQL | scans, findings, watchlists | — |
| `cache` | Valkey | DNS memo, wildcard table, rate limit | repeat scans must be instant |
| `storage` | object store | evidence artifacts (HTML, favicon, screenshots) | evidence must outlive the scan |
| `ct-tail` | worker + cron | sampled CT-log tail → new-cert alerts | ongoing monitoring half |

### Why this cannot run on serverless
Five thousand concurrent DNS+HTTP probes with a hard 30-second deadline, plus
long-lived SSE connections streaming partial results, plus a background CT tailer.
Function timeouts and cold starts kill all three. **The honest answer to "why not
Vercel" is "it would not run."**

## 5. Scope decisions (be ready to defend these)

- **Scan on demand, do not archive.** An earlier design tailed Certificate
  Transparency logs into a corpus. Measured: 1,135 entries/s across all logs,
  ~98M/day, 6 KB/entry, and `get-entries` caps at **23 entries per request** —
  backfilling one day would take 782,000 requests / 21 hours. Worse, a judge
  searching an unseen brand would get an empty screen. Generating candidates
  ourselves removes the corpus entirely.
- **Wildcard-DNS calibration is mandatory, not a nicety.** Some registries resolve
  every name. Without it the tool reports hundreds of phantom domains.
- **MX scored low (12).** Parked domains routinely carry catch-all MX, so alone it
  is weak evidence of intent.
- **Favicon hash scored high (30).** Very hard to match by accident.
- **One CT log, sampled.** Coverage over cost; `SAMPLE_RATE` is an env var so it
  can be dialled without a redeploy.
- **No auth on the demo path.** Judges said plainly they will not create accounts.

## 6. Build rings — each ends deployable

| Ring | Hours | Contents | State |
|---|---|---|---|
| 0 | 1.0 | ZCP project, 3 services green, hello-world live | deployed |
| 1 | 4.0 | permute + NATS + probe workers + Postgres + results UI | **submittable** |
| 2 | 2.5 | favicon hash, similarity scoring, evidence → object storage | strong |
| 3 | 2.0 | CT tailer + Valkey bloom watch + live alerts | complete |
| 4 | 2.0 | UI polish, seeded examples, README, AI disclosure | winning |
|  | **1.5** | **video + social post + submission form** | **reserved — do not spend** |

Feature freeze at **T-5h**. Non-negotiable.

## 7. Submission checklist (rules 9–14)

- [ ] Registered on the event page *before* submitting — rule 6
- [ ] Live URL, reachable by a stranger, **no sign-in**
- [ ] Public repo
- [ ] Demo video — a plain screen walkthrough, kept short. Upload to YouTube
      (Kunal: *"just for the safety net, keep a YouTube video in the submission"*)
- [ ] Public post: name · what it does · video · live link · how Zerops is used ·
      **tags @WeMakeDevs and @zeropsio**
- [ ] Submission form on the event page — **the post alone is not a submission**
- [ ] README: what it is · architecture · how Zerops is used · what I learned ·
      **AI tools disclosed** · decisions and tradeoffs
- [ ] Deployment stays up through judging

## 8. AI disclosure (draft — required, and Kunal encouraged it)

Built with Claude Code inside Zerops ZCP. AI was used for scaffolding, the
permutation tables, UI, and this document. The architecture, the scope decisions in
§5, and the local validation in `phishscan.py` were driven and verified by me —
including two bugs the AI's first pass missed: case-insensitive bitsquat duplicates,
and wildcard-DNS false positives that made the first run's output worthless.

## 9. Ethics

Read-only fetching of publicly served pages, rate-limited — the same behaviour as
dnstwist and urlscan.io. No exploitation, no credential interaction, no automated
reporting or takedown. Findings are candidates for human review, not verdicts.
