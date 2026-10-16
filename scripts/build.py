#!/usr/bin/env python3
"""Bouwt alle blocklist formaten uit sources/*.txt en candidates/approved.txt.

Gebruik:  python3 scripts/build.py
Output:   lists/domains.txt, hosts.txt, adblock.txt, dnsmasq.conf, unbound.conf, rpz.zone
"""
from __future__ import annotations

import datetime as dt
import pathlib
import re
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

    now = dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    header = [
        "AdFection / Discover-Tech / Candiru / Bindecy / Intelos blocklist",
        f"Gegenereerd: {now}",
        f"Aantal domeinen: {len(blocked)}",
        "Bronnen: Citizen Lab Report 195, Confiant, Recorded Future CTA-2025-0805",
        "Licentie: CC BY-NC-SA 4.0",
    ]

    OUT.mkdir(exist_ok=True)

    def write(name: str, comment: str, lines: list[str]) -> None:
        head = [f"{comment} {h}" for h in header]
        (OUT / name).write_text("\n".join(head + [""] + lines) + "\n", encoding="utf-8")

    write("domains.txt", "#", blocked)
    write("hosts.txt", "#", [f"0.0.0.0 {d}" for d in blocked])
    # Adblock syntax blokkeert ook alle subdomeinen (AdGuard Home, uBlock, NextDNS import)
    write("adblock.txt", "!", [f"||{d}^" for d in blocked])
    write("dnsmasq.conf", "#", [f"address=/{d}/0.0.0.0" for d in blocked])
    write("unbound.conf", "#", ["server:"] + [f'    local-zone: "{d}." always_nxdomain' for d in blocked])

    serial = dt.datetime.now(dt.timezone.utc).strftime("%Y%m%d%H")
    rpz = [
        "$TTL 300",
        f"@ IN SOA localhost. root.localhost. {serial} 3600 600 86400 300",
        "@ IN NS localhost.",
    ]
    for d in blocked:
        rpz += [f"{d} CNAME .", f"*.{d} CNAME ."]
    write("rpz.zone", ";", rpz)

    # Per categorie, handig voor wie alleen de spyware infra wil blokkeren
    cats = sorted({domains[d] for d in blocked})
    for cat in cats:
        sel = [d for d in blocked if domains[d] == cat]
        write(f"domains-{cat}.txt", "#", sel)

    print(f"{len(blocked)} domeinen geschreven naar {OUT.relative_to(ROOT)}/ "
          f"({', '.join(f'{c}: {sum(domains[d]==c for d in blocked)}' for c in cats)})")


if __name__ == "__main__":
    main()
