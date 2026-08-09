#!/usr/bin/env python3
# /// script
# requires-python = ">=3.11"
# dependencies = ["httpx", "dnspython", "rich"]
# ///
"""
phishscan - local proof of concept for the lookalike-domain scanner.

Mirrors the production pipeline exactly, minus the broker:

    brand  ->  permutation engine  ->  parallel probe  ->  score  ->  rank

Locally the fan-out is an asyncio semaphore. On Zerops that same fan-out
becomes NATS -> autoscaled workers; nothing else about the pipeline changes.

Usage:
    uv run phishscan.py                     # prompts for a brand
    uv run phishscan.py hdfcbank.com
    uv run phishscan.py hdfcbank.com --limit 6000 --json out.json
"""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
import re
import sys
import time
from dataclasses import dataclass, field, asdict
from difflib import SequenceMatcher

import dns.asyncresolver
import dns.resolver
import httpx
from rich.console import Console
from rich.live import Live
from rich.panel import Panel
from rich.progress import BarColumn, Progress, SpinnerColumn, TextColumn, TimeElapsedColumn
from rich.table import Table

console = Console()

# --------------------------------------------------------------------------
# 1. PERMUTATION ENGINE
# --------------------------------------------------------------------------

KEYBOARD = {
    "q": "wa", "w": "qes", "e": "wrd", "r": "etf", "t": "ryg", "y": "tuh",
    "u": "yij", "i": "uok", "o": "ipl", "p": "ol", "a": "qsz", "s": "awdx",
    "d": "serfc", "f": "drtgv", "g": "ftyhb", "h": "gyujn", "j": "huikm",
    "k": "jiol", "l": "kop", "z": "asx", "x": "zsdc", "c": "xdfv",
    "v": "cfgb", "b": "vghn", "n": "bhjm", "m": "njk",
    "0": "9o", "1": "2ql", "2": "13w", "3": "24e", "4": "35r", "5": "46t",
    "6": "57y", "7": "68u", "8": "79i", "9": "80o",
}

# visually confusable characters, ASCII and Unicode
HOMOGLYPHS = {
    "a": ["4", "@", "а", "à", "á", "ä"],   # cyrillic a, accented
    "b": ["6", "8", "в"],
    "c": ["с", "ç", "("],
    "d": ["ԁ", "cl"],
    "e": ["3", "е", "é", "è"],
    "g": ["9", "q", "ġ"],
    "h": ["һ"],
    "i": ["1", "l", "!", "і", "í"],
    "j": ["ј"],
    "k": ["к"],
    "l": ["1", "i", "|", "Ӏ"],
    "m": ["rn", "м"],
    "n": ["ո"],
    "o": ["0", "о", "ó", "ö", "օ"],
    "p": ["р"],
    "q": ["9", "g"],
    "s": ["5", "$", "ѕ"],
    "t": ["7", "+"],
    "u": ["v", "υ", "ü"],
    "v": ["u", "ѵ"],
    "w": ["vv", "ш"],
    "x": ["х"],
    "y": ["у", "ý"],
    "z": ["2", "ʐ"],
}

VOWELS = "aeiou"

TLDS = [
    "com", "net", "org", "co", "io", "info", "biz", "online", "site", "xyz",
    "top", "live", "app", "shop", "club", "in", "co.in", "cm", "co.com", "org.in",
]

# words attackers bolt on to a brand
COMBO_WORDS = [
    "login", "secure", "verify", "account", "support", "help", "online",
    "portal", "banking", "kyc", "update", "alert", "auth", "signin", "my",
    "web", "customer", "service", "official", "app", "care", "id", "net",
]


def _split_domain(domain: str) -> tuple[str, str]:
    """Split into (name, tld) handling multi-part TLDs like co.in."""
    domain = domain.strip().lower().removeprefix("http://").removeprefix("https://")
    domain = domain.split("/")[0].removeprefix("www.")
    parts = domain.split(".")
    if len(parts) == 1:
        return parts[0], "com"
    for multi in ("co.in", "co.uk", "com.au", "co.jp", "com.br", "co.za"):
        if domain.endswith("." + multi):
            return domain[: -(len(multi) + 1)], multi
    return ".".join(parts[:-1]), parts[-1]


def permutations(name: str, tld: str, limit: int) -> list[str]:
    """Generate lookalike candidates. Returns sorted, deduped, minus the original."""
    variants: set[str] = set()

    def add(v: str) -> None:
        if v and v != name and len(v) > 1:
            variants.add(v)

    n = len(name)

    # omission: hdfcbank -> hdfcbnk
    for i in range(n):
        add(name[:i] + name[i + 1:])

    # repetition: hdfcbank -> hdffcbank
    for i in range(n):
        add(name[:i] + name[i] * 2 + name[i + 1:])

    # transposition: hdfcbank -> hdcfbank
    for i in range(n - 1):
        add(name[:i] + name[i + 1] + name[i] + name[i + 2:])

    # keyboard-adjacent replacement
    for i, ch in enumerate(name):
        for adj in KEYBOARD.get(ch, ""):
            add(name[:i] + adj + name[i + 1:])

    # keyboard-adjacent insertion
    for i, ch in enumerate(name):
        for adj in KEYBOARD.get(ch, ""):
            add(name[:i] + adj + name[i:])
            add(name[:i + 1] + adj + name[i + 1:])

    # homoglyph substitution
    for i, ch in enumerate(name):
        for glyph in HOMOGLYPHS.get(ch, []):
            add(name[:i] + glyph + name[i + 1:])

    # vowel swap
    for i, ch in enumerate(name):
        if ch in VOWELS:
            for v in VOWELS:
                if v != ch:
                    add(name[:i] + v + name[i + 1:])

    # bitsquatting: single bit flip, printable results only.
    # lowercase the result - DNS is case-insensitive, so a flip of the 0x20
    # bit yields the same domain and would otherwise pad the set with dupes.
    for i, ch in enumerate(name):
        for bit in range(8):
            flipped = chr(ord(ch) ^ (1 << bit)).lower()
            if (flipped.isalnum() or flipped == "-") and flipped != ch:
                add(name[:i] + flipped + name[i + 1:])

    # hyphenation and dot insertion
    for i in range(1, n):
        add(name[:i] + "-" + name[i:])

    base = sorted(variants)

    # cross every variant with the TLD list
    candidates: set[str] = set()
    for v in base:
        for t in TLDS:
            candidates.add(f"{v}.{t}")

    # the original name on every other TLD
    for t in TLDS:
        if t != tld:
            candidates.add(f"{name}.{t}")

    # combosquatting: brand + keyword, both orders, hyphenated and joined
    for word in COMBO_WORDS:
        for t in ("com", "net", "online", "site", "xyz", "in", "co"):
            candidates.add(f"{name}{word}.{t}")
            candidates.add(f"{name}-{word}.{t}")
            candidates.add(f"{word}{name}.{t}")
            candidates.add(f"{word}-{name}.{t}")

    candidates.discard(f"{name}.{tld}")
    out = sorted(candidates)
    return out[:limit]


# --------------------------------------------------------------------------
# 2. PROBE  (DNS -> HTTP -> favicon -> similarity -> MX)
# --------------------------------------------------------------------------

@dataclass
class Finding:
    domain: str
    ips: list[str] = field(default_factory=list)
    mx: list[str] = field(default_factory=list)
    http_status: int | None = None
    final_url: str | None = None
    title: str | None = None
    favicon_sha: str | None = None
    favicon_match: bool = False
    title_similarity: float = 0.0
    body_similarity: float = 0.0
    has_login_form: bool = False
    score: int = 0
    reasons: list[str] = field(default_factory=list)


TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.I | re.S)
TAG_RE = re.compile(r"<[^>]+>")
PW_RE = re.compile(r'type\s*=\s*["\']?password', re.I)


def _text(html: str) -> str:
    return " ".join(TAG_RE.sub(" ", html).split()).lower()[:4000]


async def resolve(domain: str, resolver, sem: asyncio.Semaphore) -> tuple[str, list[str]]:
    async with sem:
        try:
            ans = await resolver.resolve(domain, "A")
            return domain, [r.address for r in ans]
        except Exception:
            return domain, []


async def detect_wildcards(tlds: list[str], resolver, sem: asyncio.Semaphore) -> dict[str, set[str]]:
    """Find TLDs whose registry resolves *any* name to a parking IP.

    Several registries (.cm and .co.in among them) answer every lookup, so
    without this every candidate on those TLDs looks alive and the results
    are worthless. Probe two random labels per TLD; if both answer with the
    same address set, treat those addresses as wildcard noise.
    """
    import secrets

    async def probe(tld: str) -> tuple[str, set[str]]:
        results = []
        for _ in range(2):
            rand = "zq" + secrets.token_hex(8)
            _, ips = await resolve(f"{rand}.{tld}", resolver, sem)
            results.append(frozenset(ips))
        if results[0] and results[0] == results[1]:
            return tld, set(results[0])
        return tld, set()

    pairs = await asyncio.gather(*[probe(t) for t in tlds])
    return {t: ips for t, ips in pairs if ips}


async def get_mx(domain: str, resolver) -> list[str]:
    try:
        ans = await resolver.resolve(domain, "MX")
        return [str(r.exchange).rstrip(".") for r in ans][:3]
    except Exception:
        return []


async def fetch_profile(client: httpx.AsyncClient, domain: str) -> dict:
    """Fetch title, body text and favicon hash for a domain.

    https and http are raced concurrently rather than tried in sequence - a
    sequential fallback doubles the worst case on dead hosts, which is what
    dominates the wall clock when most candidates are parked or unreachable.
    """
    out: dict = {}

    async def one(scheme: str):
        r = await client.get(f"{scheme}://{domain}", follow_redirects=True)
        return scheme, r

    tasks = [asyncio.create_task(one(s)) for s in ("https", "http")]
    resp = None
    try:
        for fut in asyncio.as_completed(tasks):
            try:
                _, resp = await fut
                break
            except Exception:
                continue
    finally:
        for t in tasks:
            t.cancel()

    if resp is None:
        return out

    out["status"] = resp.status_code
    out["final_url"] = str(resp.url)
    html = resp.text[:200_000]
    m = TITLE_RE.search(html)
    out["title"] = " ".join(m.group(1).split())[:120] if m else None
    out["text"] = _text(html)
    out["login"] = bool(PW_RE.search(html))

    # single favicon attempt - a second path is rarely worth the extra RTT
    try:
        fr = await client.get(f"https://{domain}/favicon.ico", follow_redirects=True)
        if fr.status_code == 200 and len(fr.content) > 60:
            out["favicon"] = hashlib.sha256(fr.content).hexdigest()[:16]
    except Exception:
        pass
    return out


def score(f: Finding, baseline: dict) -> None:
    s, why = 0, []
    if f.ips:
        s += 15
        why.append("resolves")
    if f.mx:
        # weighted low on purpose: parked/squatted domains very often carry a
        # catch-all MX, so on its own this is weak evidence of intent
        s += 12
        why.append("has MX (can send mail)")
    if f.http_status and f.http_status < 400:
        s += 15
        why.append(f"serves HTTP {f.http_status}")
    if f.has_login_form:
        s += 25
        why.append("password field present")
    if f.favicon_match:
        s += 30
        why.append("favicon identical to brand")
    if f.title_similarity > 0.6:
        s += 20
        why.append(f"title {int(f.title_similarity * 100)}% similar")
    elif f.title_similarity > 0.35:
        s += 10
        why.append(f"title {int(f.title_similarity * 100)}% similar")
    if f.body_similarity > 0.5:
        s += 20
        why.append(f"page content {int(f.body_similarity * 100)}% similar")
    brand = baseline.get("name", "")
    if f.title and brand and brand in f.title.lower():
        s += 15
        why.append("brand name in title")
    f.score = min(s, 100)
    f.reasons = why


async def run(brand: str, limit: int, concurrency: int) -> tuple[list[Finding], dict, dict]:
    name, tld = _split_domain(brand)
    origin = f"{name}.{tld}"

    t0 = time.time()
    cands = permutations(name, tld, limit)
    t_perm = time.time() - t0

    resolver = dns.asyncresolver.Resolver()
    resolver.nameservers = ["1.1.1.1", "8.8.8.8", "9.9.9.9"]
    resolver.lifetime = 4.0
    resolver.timeout = 2.0

    limits = httpx.Limits(max_connections=concurrency, max_keepalive_connections=40)
    headers = {"User-Agent": "Mozilla/5.0 (compatible; phishscan/0.1; research)"}

    async with httpx.AsyncClient(
        timeout=httpx.Timeout(connect=3.0, read=4.0, write=4.0, pool=10.0),
        verify=False, limits=limits, headers=headers, follow_redirects=True,
    ) as client:

        # baseline: what the real brand looks like
        base_raw = await fetch_profile(client, origin)
        baseline = {
            "name": name,
            "title": base_raw.get("title"),
            "text": base_raw.get("text", ""),
            "favicon": base_raw.get("favicon"),
        }

        # --- stage 0: which TLDs wildcard-resolve everything? ---
        sem = asyncio.Semaphore(concurrency)
        with console.status("[bold]checking TLDs for wildcard DNS..."):
            wildcards = await detect_wildcards(TLDS, resolver, sem)
        if wildcards:
            console.print(
                "[yellow]wildcard DNS on:[/] "
                + ", ".join(f".{t}" for t in sorted(wildcards))
                + " [dim](results on these are discounted)[/]"
            )

        # --- stage 1: DNS across every candidate ---
        t1 = time.time()
        with Progress(SpinnerColumn(), TextColumn("[bold]DNS[/] resolving {task.completed}/{task.total}"),
                      BarColumn(), TimeElapsedColumn(), console=console, transient=True) as p:
            task = p.add_task("dns", total=len(cands))
            live: list[tuple[str, list[str]]] = []
            skipped_wildcard = 0
            coros = [resolve(d, resolver, sem) for d in cands]
            for fut in asyncio.as_completed(coros):
                d, ips = await fut
                p.advance(task)
                if not ips:
                    continue
                tld = d.split(".", 1)[1]
                if wildcards.get(tld) and set(ips) <= wildcards[tld]:
                    skipped_wildcard += 1
                    continue
                live.append((d, ips))
        t_dns = time.time() - t1

        # --- stage 2: HTTP + favicon + MX, survivors only ---
        t2 = time.time()
        findings: list[Finding] = []
        http_sem = asyncio.Semaphore(min(concurrency, 150))

        async def deep(domain: str, ips: list[str]) -> Finding:
            async with http_sem:
                f = Finding(domain=domain, ips=ips)
                prof, mx = await asyncio.gather(
                    fetch_profile(client, domain), get_mx(domain, resolver)
                )
                f.mx = mx
                f.http_status = prof.get("status")
                f.final_url = prof.get("final_url")
                f.title = prof.get("title")
                f.favicon_sha = prof.get("favicon")
                f.has_login_form = prof.get("login", False)
                if baseline["favicon"] and f.favicon_sha:
                    f.favicon_match = f.favicon_sha == baseline["favicon"]
                if baseline["title"] and f.title:
                    f.title_similarity = SequenceMatcher(
                        None, baseline["title"].lower(), f.title.lower()
                    ).ratio()
                if baseline["text"] and prof.get("text"):
                    f.body_similarity = SequenceMatcher(
                        None, baseline["text"][:2000], prof["text"][:2000]
                    ).ratio()
                score(f, baseline)
                return f

        with Progress(SpinnerColumn(), TextColumn("[bold]PROBE[/] {task.completed}/{task.total} live hosts"),
                      BarColumn(), TimeElapsedColumn(), console=console, transient=True) as p:
            task = p.add_task("probe", total=len(live))
            for fut in asyncio.as_completed([deep(d, ips) for d, ips in live]):
                findings.append(await fut)
                p.advance(task)
        t_http = time.time() - t2

    findings.sort(key=lambda f: (-f.score, f.domain))
    stats = {
        "brand": origin,
        "candidates": len(cands),
        "resolved": len(live),
        "wildcard_filtered": skipped_wildcard,
        "wildcard_tlds": sorted(wildcards),
        "t_permute": round(t_perm, 2),
        "t_dns": round(t_dns, 1),
        "t_probe": round(t_http, 1),
        "t_total": round(time.time() - t0, 1),
    }
    return findings, stats, baseline


# --------------------------------------------------------------------------
# 3. OUTPUT
# --------------------------------------------------------------------------

def render(findings: list[Finding], stats: dict, baseline: dict) -> None:
    console.print()
    console.print(Panel.fit(
        f"[bold]{stats['brand']}[/]\n"
        f"baseline title: [dim]{(baseline.get('title') or '-')[:70]}[/]\n"
        f"baseline favicon: [dim]{baseline.get('favicon') or 'none'}[/]",
        title="target", border_style="cyan",
    ))

    hi = [f for f in findings if f.score >= 50]
    med = [f for f in findings if 25 <= f.score < 50]

    t = Table(title=f"lookalike domains that exist  ({len(findings)} live of {stats['candidates']} probed)",
              header_style="bold")
    t.add_column("score", justify="right", width=5)
    t.add_column("domain", style="bold", max_width=34)
    t.add_column("ip", max_width=15)
    t.add_column("http", justify="right", width=4)
    t.add_column("title", max_width=28)
    t.add_column("evidence", max_width=44)

    for f in findings[:40]:
        colour = "red" if f.score >= 50 else "yellow" if f.score >= 25 else "dim"
        t.add_row(
            f"[{colour}]{f.score}[/]",
            f.domain,
            (f.ips[0] if f.ips else "-"),
            str(f.http_status or "-"),
            (f.title or "-")[:28],
            ", ".join(f.reasons[:3]) or "-",
        )
    console.print(t)

    console.print(
        f"\n[bold]{len(hi)}[/] high-risk   "
        f"[bold]{len(med)}[/] medium   "
        f"[dim]{len(findings) - len(hi) - len(med)} low[/]"
    )
    if stats.get("wildcard_filtered"):
        console.print(
            f"[dim]{stats['wildcard_filtered']} false positives removed by "
            f"wildcard-DNS detection[/]"
        )
    console.print(
        f"[dim]permute {stats['t_permute']}s · dns {stats['t_dns']}s "
        f"({stats['candidates']} domains) · probe {stats['t_probe']}s "
        f"({stats['resolved']} hosts) · [bold]total {stats['t_total']}s[/][/]"
    )


def main() -> None:
    ap = argparse.ArgumentParser(description="lookalike domain scanner (local PoC)")
    ap.add_argument("brand", nargs="?", help="e.g. hdfcbank.com")
    ap.add_argument("--limit", type=int, default=4000, help="max candidates (default 4000)")
    ap.add_argument("--concurrency", type=int, default=200, help="parallel probes (default 200)")
    ap.add_argument("--json", help="also write full results to this file")
    a = ap.parse_args()

    brand = a.brand or console.input("[bold cyan]brand or domain[/] (e.g. hdfcbank.com): ").strip()
    if not brand:
        console.print("[red]nothing to scan[/]")
        sys.exit(1)

    import warnings
    warnings.filterwarnings("ignore")

    findings, stats, baseline = asyncio.run(run(brand, a.limit, a.concurrency))
    render(findings, stats, baseline)

    if a.json:
        with open(a.json, "w") as fh:
            json.dump({"stats": stats, "baseline": baseline,
                       "findings": [asdict(f) for f in findings]}, fh, indent=2)
        console.print(f"[dim]wrote {a.json}[/]")


if __name__ == "__main__":
    main()
