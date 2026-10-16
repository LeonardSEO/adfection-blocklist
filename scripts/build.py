#!/usr/bin/env python3
"""Bouwt alle blocklist formaten uit sources/*.txt en candidates/approved.txt.

Gebruik:  python3 scripts/build.py
Output:   lists/<formaat>/adfection*.txt in Hagezi stijl
"""
from __future__ import annotations

import datetime as dt
import pathlib
import os
import re
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
SOURCES = ROOT / "sources"
APPROVED = ROOT / "candidates" / "approved.txt"
ALLOWLIST = ROOT / "allowlist.txt"
OUT = ROOT / "lists"

DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)([a-z0-9-]{1,63}(?<!-)\.)+[a-z]{2,63}$"
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


def main() -> None:
    allow = set(parse(ALLOWLIST))
    domains: dict[str, str] = {}
    for src in sorted(SOURCES.glob("*.txt")):
        for d, cat in parse(src).items():
            domains.setdefault(d, cat)
    for d, cat in parse(APPROVED).items():
        domains.setdefault(d, cat)

    blocked = sorted(d for d in domains if d not in allow)
    skipped = sorted(d for d in domains if d in allow)
    if skipped:
        print("Overgeslagen door allowlist:", ", ".join(skipped))

    write_all(blocked, domains)


def compress(domains: list[str]) -> list[str]:
    """Wildcard compressie zoals Hagezi: laat subdomeinen weg die al door een parent gedekt worden."""
    keep, s = [], set(domains)
    for d in domains:
        parts = d.split(".")
        if not any(".".join(parts[i:]) in s for i in range(1, len(parts) - 1)):
            keep.append(d)
    return keep


LISTS = {
    "adfection": ("AdFection Full", "Alle bekende infrastructuur: Discover-Tech, Candiru, Bindecy, Intelos"),
    "adfection-candiru": ("AdFection Candiru", "Candiru / Integrity Labs validator, C&C en delivery servers"),
    "adfection-discover-tech": ("AdFection Discover-Tech", "Controlium, MyDSP, NOAS servers en ID syncing"),
    "adfection-bindecy": ("AdFection Bindecy", "Bindecy spyware infrastructuur"),
    "adfection-intelos": ("AdFection Intelos", "Intelos ADINT infrastructuur"),
}

# formaat: (map, commentaarteken, syntax label, compressie, regel builder)
FORMATS = {
    "adblock":   ("adblock",  "!", "Adblock Plus (AdGuard, AdGuard Home, uBlock Origin, Pi-hole v6, NextDNS)", True,  lambda d: f"||{d}^"),
    "dnsmasq":   ("dnsmasq",  "#", "DNSMasq (local=/domain/, blokkeert ook subdomeinen)",                     True,  lambda d: f"local=/{d}/"),
    "wildcard":  ("wildcard", "#", "Wildcard domains, root domeinen die subdomeinen dekken",                    True,  lambda d: d),
    "asterisk":  ("wildcard", "#", "Asterisk wildcard (*.domain)",                                              True,  lambda d: f"*.{d}"),
    "domains":   ("domains",  "#", "Domains (Pi-hole, Technitium, pfBlockerNG), volledige lijst",               False, lambda d: d),
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
    m = re.search(r"github\.com[:/]([^/]+/[^/.]+)", url)
    return m.group(1) if m else None


SLUG = repo_slug()
REPO = f"https://github.com/{SLUG}" if SLUG else "lokale build (nog geen GitHub remote)"
RAW = f"https://raw.githubusercontent.com/{SLUG}/main/lists" if SLUG else "lists"


def write_all(blocked: list[str], domains: dict[str, str]) -> None:
    now = dt.datetime.now(dt.timezone.utc)
    version = now.strftime("%Y.%m%d.%H%M%S")
    for old in OUT.glob("**/*.txt"):
        old.unlink()

    for slug, (title, desc) in LISTS.items():
        cat = slug.removeprefix("adfection").lstrip("-")
        sel = [d for d in blocked if not cat or domains[d] == cat]
        if not sel:
            continue
        wild = compress(sel)
        for fmt, (folder, c, syntax, use_wild, fn) in FORMATS.items():
            entries = wild if use_wild else sel
            if fmt == "rpz":
                body = ["$TTL 300", f"@ IN SOA localhost. root.localhost. {now:%Y%m%d%H} 43200 3600 259200 300",
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
                f"Number of entries: {len(entries)}",
            )]
            path = OUT / folder / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("\n".join(head + [c] + body) + "\n", encoding="utf-8")

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
        ("Adblock", "AdGuard, AdGuard Home, uBlock Origin, Pi-hole v6, NextDNS", "adblock/{s}.txt"),
        ("DNSMasq", "dnsmasq, OpenWrt, Pi-hole (dnsmasq.d)", "dnsmasq/{s}.txt"),
        ("Wildcard", "Wildcard domains (root dekt subdomeinen), Technitium, Blocky", "wildcard/{s}-onlydomains.txt"),
        ("Asterisk Wildcard", "*.domain syntax, pfBlockerNG, Blocky, Diversion", "wildcard/{s}.txt"),
        ("Domains", "Pi-hole, plain lijsten, volledige set incl. subdomeinen", "domains/{s}.txt"),
        ("Hosts", "/etc/hosts, Windows, oudere Pi-hole", "hosts/{s}.txt"),
        ("RPZ", "BIND, PowerDNS, Knot, Technitium", "rpz/{s}.txt"),
        ("Unbound", "Unbound, OPNsense, pfSense", "unbound/{s}.txt"),
    ]
    out = [start, "", f"Totaal: **{len(blocked)}** domeinen, **{len(compress(blocked))}** na wildcard compressie.", ""]
    for slug, (title, desc) in LISTS.items():
        if not (OUT / "domains" / f"{slug}.txt").exists():
            continue
        out += [f"### {title}", "", desc, "", "| Formaat | Voor | Link |", "| --- | --- | --- |"]
        out += [f"| {f} | {u} | [{p.format(s=slug)}]({RAW}/{p.format(s=slug)}) |" for f, u, p in rows]
        out.append("")
    out.append(end)
    pre, rest = text.split(start, 1)
    post = rest.split(end, 1)[1]
    readme.write_text(pre + "\n".join(out) + post, encoding="utf-8")


if __name__ == "__main__":
    main()
