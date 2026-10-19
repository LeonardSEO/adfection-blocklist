#!/usr/bin/env python3
"""Bouwt alle blocklist formaten uit sources/*.txt en candidates/approved.txt.

Gebruik:  python3 scripts/build.py
Output:   lists/<formaat>/adfection*.txt in Hagezi stijl
"""
from __future__ import annotations

import argparse
import datetime as dt
import pathlib
import os
import re
import subprocess
import sys
import tempfile

ROOT = pathlib.Path(__file__).resolve().parent.parent
SOURCES = ROOT / "sources"
APPROVED = ROOT / "candidates" / "approved.txt"
ALLOWLIST = ROOT / "allowlist.txt"
OUT = ROOT / "lists"

DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)((?!-)[a-z0-9-]{1,63}(?<!-)\.)+[a-z]{2,63}$"
)


def parse(path: pathlib.Path) -> dict[str, str]:
    """Leest 'domein  # categorie: toelichting' regels. Defanged [.] wordt hersteld."""
    result: dict[str, str] = {}
    if not path.exists():
        return result
    for n, raw in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        domain, _, comment = line.partition("#")
        domain = domain.strip().lower().replace("[.]", ".").rstrip(".")
        if not DOMAIN_RE.match(domain):
            sys.exit(f"Ongeldig domein in {path.name}:{n}: {domain!r}")
        category = comment.split(":", 1)[0].strip() or "overig"
        result.setdefault(domain, category)
    return result


def load_domains() -> dict[str, str]:
    allow = set(parse(ALLOWLIST))
    domains: dict[str, str] = {}
    for src in sorted(SOURCES.glob("*.txt")):
        for d, cat in parse(src).items():
            if cat not in CATEGORIES:
                raise ValueError(f"Onbekende categorie {cat!r} in {src.name}: {d}")
            if d in domains and domains[d] != cat:
                raise ValueError(f"Conflicterende categorie voor {d}")
            domains.setdefault(d, cat)
    for d, cat in parse(APPROVED).items():
        if cat not in CATEGORIES:
            raise ValueError(f"Onbekende categorie {cat!r} in approved.txt: {d}")
        if d in domains and domains[d] != cat:
            raise ValueError(f"Conflicterende categorie voor {d}")
        domains.setdefault(d, cat)

    blocked = sorted(d for d in domains if d not in allow)
    skipped = sorted(d for d in domains if d in allow)
    if skipped:
        print("Overgeslagen door allowlist:", ", ".join(skipped))

    if not blocked:
        raise ValueError("Geen domeinen: weiger lege lijsten te publiceren")
    return {d: domains[d] for d in blocked}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--check', action='store_true', help='Controleer output zonder bestanden te wijzigen')
    args = parser.parse_args()
    domains = load_domains()
    if args.check:
        check_output(domains)
    else:
        write_all(sorted(domains), domains)


def compress(domains: list[str]) -> list[str]:
    """Wildcard compressie zoals Hagezi: laat subdomeinen weg die al door een parent gedekt worden."""
    keep, s = [], set(domains)
    for d in domains:
        parts = d.split(".")
        if not any(".".join(parts[i:]) in s for i in range(1, len(parts) - 1)):
            keep.append(d)
    return keep


LISTS = {
    "adfection": ("AdFection Full", "Published indicators associated with Discover-Tech, Candiru, Bindecy and Intelos"),
    "adfection-candiru": ("AdFection Candiru", "Candiru / Integrity Labs validator, C2 and delivery servers"),
    "adfection-discover-tech": ("AdFection Discover-Tech", "Controlium, MyDSP, NOAS servers and ID syncing"),
    "adfection-bindecy": ("AdFection Bindecy", "Published Bindecy-associated infrastructure"),
    "adfection-intelos": ("AdFection Intelos", "Published Intelos ADINT-associated infrastructure"),
}
CATEGORIES = {slug.removeprefix('adfection-') for slug in LISTS if slug != 'adfection'}

# formaat: (map, commentaarteken, syntax label, compressie, regel builder)
FORMATS = {
    "adblock":   ("adblock",  "!", "Adblock domain rules (AdGuard Home, uBlock Origin)", True,  lambda d: f"||{d}^"),
    "dnsmasq":   ("dnsmasq",  "#", "DNSMasq (local=/domain/, includes subdomains)",                     True,  lambda d: f"local=/{d}/"),
    "wildcard":  ("wildcard", "#", "Compressed root domains; importer must match subdomains",                    True,  lambda d: d),
    "asterisk":  ("wildcard", "#", "Explicit root and wildcard pairs (domain and *.domain)",                    True,  lambda d: f"{d}\n*.{d}"),
    "domains":   ("domains",  "#", "Plain domains, all explicit hosts",               False, lambda d: d),
    "hosts":     ("hosts",    "#", "Hosts (0.0.0.0 domain)",                                                    False, lambda d: f"0.0.0.0 {d}"),
    "rpz":       ("rpz",      ";", "Response Policy Zone (BIND, PowerDNS, Knot, Technitium)",                   True,  None),
    "unbound":   ("unbound",  "#", "Unbound local-zone always_nxdomain",                                        True,  None),
}



def repo_slug() -> str | None:
    """owner/repo uit GitHub Actions of de git remote, zodat er geen URL hardcoded staat."""
    if os.environ.get("GITHUB_REPOSITORY"):
        return os.environ["GITHUB_REPOSITORY"]
    try:
        url = subprocess.run(["git", "-C", str(ROOT), "remote", "get-url", "origin"],
                             capture_output=True, text=True, check=True).stdout.strip()
    except (subprocess.CalledProcessError, FileNotFoundError):
        return None
    m = re.search(r"github\.com[:/]([^/]+/[^/]+?)(?:\.git)?$", url)
    return m.group(1) if m else None


SLUG = repo_slug()
REPO = f"https://github.com/{SLUG}" if SLUG else "lokale build (nog geen GitHub remote)"
RAW = f"https://raw.githubusercontent.com/{SLUG}/main/lists" if SLUG else "lists"


def write_all(blocked: list[str], domains: dict[str, str], now: dt.datetime | None = None) -> None:
    if now is None:
        epoch = os.environ.get('SOURCE_DATE_EPOCH')
        now = dt.datetime.fromtimestamp(int(epoch), dt.timezone.utc) if epoch else dt.datetime.now(dt.timezone.utc)
    version = now.strftime("%Y.%m%d.%H%M%S")
    expected = set()

    for slug, (title, desc) in LISTS.items():
        cat = slug.removeprefix("adfection").lstrip("-")
        sel = [d for d in blocked if not cat or domains[d] == cat]
        if not sel:
            continue
        wild = compress(sel)
        for fmt, (folder, c, syntax, use_wild, fn) in FORMATS.items():
            entries = wild if use_wild else sel
            if fmt == "rpz":
                body = ["$TTL 300", f"@ IN SOA localhost. root.localhost. {int(now.timestamp())} 43200 3600 259200 300",
                        "@ IN NS localhost.", ""]
                for d in entries:
                    body += [f"{d} CNAME .", f"*.{d} CNAME ."]
            elif fmt == "unbound":
                body = ["server:"] + [f'    local-zone: "{d}." always_nxdomain' for d in entries]
            else:
                body = [fn(d) for d in entries]
            name = f"{slug}-onlydomains.txt" if fmt == "wildcard" else f"{slug}.txt"
            head = ["[Adblock Plus]"] if fmt == "adblock" else []
            head += [f"{c} {line}" for line in (
                f"Title: {title}",
                f"Description: {desc}",
                f"Homepage: {REPO}",
                "License: CC BY-NC-SA 4.0",
                "Sources: Citizen Lab Report 195, Confiant, Recorded Future CTA-2025-0805",
                "Issues: " + REPO + "/issues",
                "Expires: 1 day",
                f"Last modified: {now:%d %b %Y %H:%M} UTC",
                f"Version: {version}",
                f"Syntax: {syntax}",
                f"Number of entries: {len(entries) * (2 if fmt in ('rpz', 'asterisk') else 1)}",
                f"Number of domains: {len(entries)}",
            )]
            path = OUT / folder / name
            expected.add(path)
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("\n".join(head + [c] + body) + "\n", encoding="utf-8")

    for old in OUT.glob('**/adfection*.txt'):
        if old not in expected:
            old.unlink()

    update_readme(blocked)
    cats = sorted({domains[d] for d in blocked})
    print(f"{len(blocked)} domeinen ({len(compress(blocked))} na wildcard compressie), "
          + ", ".join(f"{c}: {sum(domains[d]==c for d in blocked)}" for c in cats))


def update_readme(blocked: list[str]) -> None:
    """Schrijft de abonneertabel met raw links tussen de markers in README.md."""
    readme = ROOT / "README.md"
    text = readme.read_text(encoding="utf-8")
    start, end = "<!-- LISTS:START -->", "<!-- LISTS:END -->"
    if start not in text:
        return
    rows = [
        ("Adblock", "AdGuard Home, uBlock Origin; root + subdomains", "adblock/{s}.txt"),
        ("DNSMasq", "dnsmasq, OpenWrt, Pi-hole (dnsmasq.d)", "dnsmasq/{s}.txt"),
        ("Wildcard", "Compressed roots; importer must match subdomains", "wildcard/{s}-onlydomains.txt"),
        ("Asterisk Wildcard", "Explicit root + *.domain pairs; check importer support", "wildcard/{s}.txt"),
        ("Domains", "Pi-hole / plain domain import; all explicit hosts", "domains/{s}.txt"),
        ("Hosts", "OS hosts file; exact hostnames", "hosts/{s}.txt"),
        ("RPZ", "BIND, PowerDNS, Knot, Technitium", "rpz/{s}.txt"),
        ("Unbound", "Unbound local-zone configuration", "unbound/{s}.txt"),
    ]
    out = [start, "", f"**{len(blocked)} unique domains**, **{len(compress(blocked))} after wildcard compression**.", ""]
    for slug, (title, desc) in LISTS.items():
        if not (OUT / "domains" / f"{slug}.txt").exists():
            continue
        out += [f"### {title}", "", desc, "", "| Format | Intended use | Download / subscription |", "| --- | --- | --- |"]
        out += [f"| {f} | {u} | [{p.format(s=slug)}]({RAW}/{p.format(s=slug)}) |" for f, u, p in rows]
        out.append("")
    out.append(end)
    pre, rest = text.split(start, 1)
    post = rest.split(end, 1)[1]
    readme.write_text(pre + "\n".join(out) + post, encoding="utf-8")


def check_output(domains: dict[str, str]) -> None:
    """Rebuild in a temporary directory using the published timestamp; compare all bytes."""
    global ROOT, OUT
    original_root, original_out = ROOT, OUT
    current = (OUT / 'adblock/adfection.txt').read_text(encoding='utf-8')
    match = re.search(r'^! Version: (\d{4}\.\d{4}\.\d{6})$', current, re.M)
    if not match:
        raise ValueError('Missing or invalid generated version')
    now = dt.datetime.strptime(match[1], '%Y.%m%d.%H%M%S').replace(tzinfo=dt.timezone.utc)
    try:
        with tempfile.TemporaryDirectory() as directory:
            ROOT = pathlib.Path(directory)
            OUT = ROOT / 'lists'
            (ROOT / 'README.md').write_text((original_root / 'README.md').read_text(encoding='utf-8'), encoding='utf-8')
            write_all(sorted(domains), domains, now=now)
            expected = {p.relative_to(OUT): p.read_bytes() for p in OUT.glob('**/*.txt')}
            actual = {p.relative_to(original_out): p.read_bytes() for p in original_out.glob('**/*.txt')}
            if actual != expected:
                raise ValueError('Generated lists are stale; run python3 scripts/build.py')
            if (ROOT / 'README.md').read_bytes() != (original_root / 'README.md').read_bytes():
                raise ValueError('README download table is stale; run python3 scripts/build.py')
    finally:
        ROOT, OUT = original_root, original_out
    print('All generated lists and README links match the sources.')


if __name__ == "__main__":
    main()
