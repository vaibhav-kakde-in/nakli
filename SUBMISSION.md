# Submission pack

Everything needed to file. Not part of the app.

---

## 1. Links

| | |
|---|---|
| Live app | https://web-2ca4-3000.prg1.zerops.app |
| API | https://api-2ca4-3000.prg1.zerops.app |
| Repo | https://github.com/vaibhav-kakde-in/nakli |

**Best demo brands** (checked, they produce strong results):
`paypal.com` · `stripe.com` · `twitch.tv` · `netflix.com`

Avoid `walmart.com` in the video — well-policed, returns 0–4. Good for the
honesty story, bad for a 60-second demo.

---

## 2. Demo video — 75 seconds

Francesco on the kickoff stream: *"The video should not be super long. A simple
walkthrough of the application… even just a screen recording."* And:
*"most projects didn't tell you exactly what it does in three seconds."*

So: no intro, no face, no slides. Open on the product working.

**0:00–0:08 — the claim**
> "This is nakli. You type your brand, and it finds every domain pretending to
> be you — right now, with evidence."

Landing page on screen. Type `paypal.com`. Hit scan.

**0:08–0:30 — the grid (do not cut away)**
Say nothing for a beat. Let the grid fill.
> "Every square is one real DNS lookup. Eighteen hundred of them, live."

Point at the ticker as it moves.
> "White means the domain exists. It's telling you what it's doing —
> and there's the wildcard check, discarding a registry that answers everything."

**0:30–0:42 — the verdict**
Number lands.
> "Thirteen domains are impersonating PayPal. paypal-secure.net.
> paypal-support.net. Each one serving PayPal's actual page."

Click into a high-risk row.
> "Title match, content match, MX records, and the page we captured as proof."

**0:42–0:55 — the category strip**
> "It doesn't just score them, it names what they are. Credential harvesters
> ask for a password. Email spoofers can send mail as you with no website at all."

**0:55–1:10 — Zerops**
Show the project dashboard, eight services.
> "Eight services on Zerops, all doing real work. NATS fans probing out to
> workers that scale one to five. Valkey caches DNS. Postgres makes every scan a
> shareable link. Object storage keeps the evidence — because phishing sites
> disappear in hours."

**1:10–1:15 — close**
> "A scan takes about ninety seconds, needs hundreds of concurrent probes and a
> live stream. It could not run on serverless. That's why it's on Zerops."

### Rules for the recording
- **Never cut during the scan.** The wait is the proof.
- If a scan disappoints, stop and re-record. Do not narrate over a bad result.
- Upload to YouTube — Kunal: *"just for the safety net, keep a YouTube video in
  the submission."*

---

## 3. Social post

Tag **@WeMakeDevs** and **@zeropsio**. X, LinkedIn or Medium all count.

```
I built nakli — it finds the domains pretending to be you.

Type a brand. In ~90 seconds it generates 1,800 lookalike domains
(homoglyphs, typos, bitsquats, combosquats), probes every one, and shows
you which are real — ranked, with evidence.

paypal.com → 13 domains serving PayPal's exact page
stripe.com → support-stripe.com, update-stripe.com, stripe-account.com
netflix.com → netflix.org and netflix.xyz, both scoring 100

No paid APIs. No datasets. Public DNS, the public web, and one Zerops project.

Eight services, all doing real work: NATS fans probing out to workers that
scale 1→5, Valkey caches DNS (99% hit rate on repeat scans), Postgres makes
every scan a shareable link, object storage archives the evidence — phishing
sites vanish within hours, so the proof is captured at scan time.

A scan needs hundreds of concurrent probes, a long-lived SSE stream, and
background workers. Function timeouts kill all three. The honest answer to
"why not serverless" is: it wouldn't run.

Try it on your own domain 👇
https://web-2ca4-3000.prg1.zerops.app
Code: https://github.com/vaibhav-kakde-in/nakli

@WeMakeDevs @zeropsio
```

**Attach the video.** A post with a video outperforms one with a screenshot,
and the Social track is judged on *"clarity of the story, the demo, and reach."*

---

## 4. Submission form checklist

- [ ] Registered on the event page (rule 6 — before submitting)
- [ ] Live URL — reachable, **no sign-in**
- [ ] Repo link — public
- [ ] Demo video — YouTube
- [ ] Social post link
- [ ] How Zerops is used — see below
- [ ] **AI tools disclosed** (rules 12–14)

**"How is Zerops used" — paste this:**

> Eight services in one Zerops project, all load-bearing. Node.js runtimes for
> the UI, API and probe workers; NATS for queue-group fan-out; PostgreSQL for
> scans and shareable permalinks; Valkey as a DNS cache; S3-compatible object
> storage for archived evidence; ZCP with Claude Code authorised in-project.
> Probe workers scale horizontally 1→5. The web service proxies to the API over
> the private network, so the browser only ever sees one origin. Deployed with
> zerops.yml via zcli.
>
> Two platform behaviours shaped the design: the L7 balancer returns 504 at
> exactly 60s, so scans run as background jobs streaming results over SSE rather
> than blocking; and probe work is bursty and per-host independent, which is why
> it fans out over NATS to workers that scale.

**AI disclosure — paste this:**

> Built with Claude Code, running against the Zerops project with ZCP authorised
> (AGENTS.md and CLAUDE.md in the repo were generated by ZCP itself). AI wrote
> most of the code, the permutation tables and the UI. The architecture, scoping
> decisions and every engineering judgement in the README's "What I learned"
> section were mine — each was a measurement that contradicted what the code
> assumed, including several the AI's first pass got wrong. The proof of concept
> in tools/phishscan.py was written first, deliberately, to validate the idea
> before committing to infrastructure. The commit history records the failures
> and reverts honestly.

---

## 5. Before you hit submit

- [ ] Open the live URL **in a private window** — confirm no login, no errors
- [ ] Run one scan end to end and watch it complete
- [ ] Open a `?scan=` permalink — confirm it loads instantly
- [ ] Check the repo renders (README, no secrets)
- [ ] Leave the deployment **up** — rule 3, judging runs after the deadline
