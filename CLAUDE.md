<!-- ZCP:BEGIN -->
@AGENTS.md
<!-- ZCP:END -->

# nakli

Lookalike-domain scanner. Type a brand, get every impersonating domain that
exists right now, ranked, with evidence. Built for The Zerops Challenge.

Live: https://web-2ca4-3000.prg1.zerops.app · Repo: vaibhav-kakde-in/nakli

## Layout

```
core/       shared, dependency-light, imported by api and probe
  permute   candidate generation (priority tiers)
  probe     DNS + HTTP + favicon + MX
  score     additive scoring with stated reasons
  classify  threat pattern naming
  homoglyph confusable / punycode analysis
  scan      orchestration - the only place stages are sequenced
  db        Postgres persistence
  cache     Valkey DNS cache
  bus       NATS request/reply
  evidence  S3 archive of captured pages
api/        Hono: jobs, SSE, exports
probe/      NATS queue-group worker (no ports, consumes only)
web/        static UI + same-origin proxy to api. NO external deps
tools/      phishscan.py - the original local proof of concept
```

Dependencies live in the **root** `package.json` so `core/` can resolve them.
A per-app `node_modules` is invisible to a sibling directory.

## Invariants — do not "optimise" these away

Each was established by measurement, and each has already been broken once.
Changing any of them without re-measuring will silently lose findings.

**More concurrency is worse, twice over.**
- `dnsConcurrency = 80`. At 200, a scan of hdfcbank.com found ZERO high-risk and
  missed `hdfcbank.net` — a byte-identical clone. Public resolvers drop answers
  when hammered.
- `httpConcurrency = 50`. At 150 the HTTP stage went 85s → 10.5s while high-risk
  findings went 17 → 2. A brand's lookalikes share one CDN; 150 parallel
  connections read as an attack.

**"No answer" is UNKNOWN, never "does not exist."** True for DNS (`ETIMEOUT` vs
`ENOTFOUND`) and for HTTP (no status vs a 4xx). Both get a gentle retry pass.
Collapsing that distinction hid real clones in both stages.

**Never cache an unknown.** `cache.js` stores definitive answers only. Caching
"we could not tell" makes a transient rate-limit look permanent.

**The baseline gets a patient timeout and retries.** Every similarity score is
measured against that single fetch. When it fails, all similarity is 0 and the
scan confidently reports no impersonation. If it still fails the UI must say so —
an honest failure beats a clean-looking wrong answer.

**Candidates are emitted in priority tiers, never sorted alphabetically.**
`slice(0, limit)` after a sort cut `hdfcbank.net` purely because 'h' sorts late.

**`fetchProfile` must abort the losing scheme.** It races https against http, and
an unread undici body holds its socket and exhausts the pool. One scan spent 724
seconds in the HTTP stage before the aborts went in, versus ~16s after.

**Wildcard calibration is mandatory.** Some registries resolve every name. Without
the two-random-probe check, a scan reports hundreds of domains that do not exist.

**Persistence must store derived fields.** `threat`, `homograph` and `evidenceKey`
live in `findings.extra`; the per-cell grid string lives in `scans.cells`.
Restored scans mislabelled every finding as "Dormant" when those were missing.

## Colour

`--pink` is action only (input, buttons, links). `--high` red is verdict only,
never decoration — that separation is why red means exactly one thing here.
Status colour never carries meaning alone; labels and the legend back it up.

## Working on this

**Deploys take 6–9 minutes**, and that is platform-side: ~3 min build container,
~6 min app-version rollout. Trimming the artifact does not help — a 23 KiB push
took the same time as a 30 MB one. So do not deploy in order to test.

```bash
# UI iteration - instant, against the live backend (needs `zcli vpn up`)
API_URL=http://api.zerops:3000 PORT=8099 node web/server.js

# scan logic - no infrastructure needed
node -e "import('./core/scan.js').then(async m => {
  const r = await m.runScan('paypal.com', { limit: 400 }); console.log(r.stats)
})"
```

`web/` has no external dependencies and ships only the `web` folder, so its build
step is intentionally empty. Keep it that way.

Deploy: `zcli push --projectId gv0EOA7YQou5AOSYkQHblw --serviceId <id> --setup <name>`

| service | id |
|---|---|
| api | `EtVOLgKoTi6HIqxt1DAStw` |
| web | `NxIaoLfDQKCo7eA7ZRyE5A` |
| probe | `l6MEIPHCTVmUX7QKSUB3Ig` |

`curl -s http://api.zerops:3000/api/health` reports db, bus, cache and evidence
in one call.

## Judging context

Judged on idea, execution, and how Zerops is used. All eight services do real
work — that is deliberate and worth protecting. If a change would leave a
service idle, it is probably the wrong change.

Counts are a floor, not a total: when a target throttles us we under-report,
never over-report, and every finding carries evidence. A domain scoring 97 may
be the brand's own defensive registration — the tool surfaces evidence, a person
decides.
