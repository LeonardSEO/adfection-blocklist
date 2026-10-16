#!/usr/bin/env python3
"""Zoekt gerelateerde domeinen rond de bekende AdFection infrastructuur.

Pivots (alleen publieke, passieve bronnen, er wordt niets aangevallen of gescand):
  1. crt.sh            subdomeinen uit Certificate Transparency logs per bekend apex
  2. urlscan.io        pagina's die bekende domeinen of het tracking pixel script laden
  3. DNS over HTTPS    CNAME's die naar de Discover-Tech load balancer wijzen
  4. Censys (optioneel) hosts met het Bindecy "cupid-ca" certificaat of speedtest body hash
                        zet CENSYS_API_ID en CENSYS_API_SECRET om dit aan te zetten

Resultaat: candidates/candidates-YYYYMMDD.txt
Niets wordt automatisch geblokkeerd. Controleer de kandidaten en verplaats wat klopt
naar candidates/approved.txt, draai daarna scripts/build.py.

Gebruik:  python3 scripts/discover.py [--skip crtsh,urlscan,dns,censys]
"""
from __future__ import annotations

import argparse
import base64
import datetime as dt
import json
import os
import pathlib
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from build import ALLOWLIST, APPROVED, DOMAIN_RE, ROOT, SOURCES, parse  # noqa: E402

UA = "adfection-blocklist-discovery/1.0 (defensive research)"
ALB = "discovertech-alb-100966113.us-east-1.elb.amazonaws.com"

# Apexen waarvan het zinvol is om subdomeinen en co-hosting te zoeken.
# Bewust geen gedeelde platforms (cloudfront, azure, heroku).
PIVOT_APEXES = [
    "mtrtb.com", "powerium.net", "controlium.net", "myweb3id.io", "platc-tester.com",
    "discover-tech.io", "myipinfo.io", "tracookiepixel.xyz", "cookie-sync.xyz",
    "adtimizer.co", "adtimizer.com", "volasim.com", "tekma-dmp.ai", "trustlayersdk.com",
    "mydsp.io", "globaldatapoints.com", "ads-monitor.xyz",
]
URLSCAN_QUERIES = [
    'filename:"c_tracking_pixel_gdpr.js"',
    'filename:"c_tracking_pixel_gdpr_enhanced.js"',
    "domain:tracookiepixel.xyz",
    "domain:cookie-sync.xyz",
    "domain:myweb3id.io",
    "domain:mtrtb.com",
    "domain:adtimizer.co",
]
CENSYS_QUERIES = [
    'services.tls.certificates.leaf_data.issuer.common_name: "cupid-ca"',
    'services.http.response.body_hashes: "sha256:63c2963a7abc1e4ee083275e5582a52f1101dba9905fd35498726359abf95a71"',
]


def get_json(url: str, headers: dict | None = None, retries: int = 3):
    req = urllib.request.Request(url, headers={"User-Agent": UA, **(headers or {})})
    for attempt in range(retries):
        try:
            with urllib.request.urlopen(req, timeout=60) as r:
                return json.loads(r.read().decode("utf-8", "replace") or "null")
        except urllib.error.HTTPError as e:
            if e.code in (429, 502, 503, 504) and attempt < retries - 1:
                time.sleep(5 * (attempt + 1))
                continue
            print(f"  ! {e.code} bij {url}", file=sys.stderr)
            return None
        except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as e:
            if attempt < retries - 1:
                time.sleep(3)
                continue
            print(f"  ! {e} bij {url}", file=sys.stderr)
            return None


def clean(name: str) -> str | None:
    name = name.strip().lower().lstrip("*.").rstrip(".")
    return name if DOMAIN_RE.match(name) else None


def crtsh(found: dict[str, str]) -> None:
    print("[crt.sh] Certificate Transparency subdomeinen")
    for apex in PIVOT_APEXES:
        data = get_json(f"https://crt.sh/?q={urllib.parse.quote('%.' + apex)}&output=json")
        for row in data or []:
            for n in (row.get("name_value", "") + "\n" + row.get("common_name", "")).splitlines():
                d = clean(n)
                if d and (d == apex or d.endswith("." + apex)):
                    found.setdefault(d, f"crt.sh: certificaat onder {apex}")
        time.sleep(2)


def urlscan(found: dict[str, str]) -> None:
    print("[urlscan] pagina's die de infrastructuur laden")
    key = os.environ.get("URLSCAN_API_KEY")
    headers = {"API-Key": key} if key else {}
    known = set(PIVOT_APEXES)
    for q in URLSCAN_QUERIES:
        data = get_json(
            "https://urlscan.io/api/v1/search/?" + urllib.parse.urlencode({"q": q, "size": 100}),
            headers,
        )
        for res in (data or {}).get("results", []):
            page = res.get("page", {})
            for d in (page.get("domain"), page.get("apexDomain")):
                d = clean(d or "")
                if not d:
                    continue
                # Alleen domeinen die zelf onder een bekend apex vallen tellen als infra.
                # Uitgevers (nieuwssites die het pixel laden) zijn slachtoffer, geen infra.
                if any(d == a or d.endswith("." + a) for a in known):
                    found.setdefault(d, f"urlscan: {q}")
        time.sleep(3)


def doh(name: str, rtype: str) -> list[str]:
    url = "https://cloudflare-dns.com/dns-query?" + urllib.parse.urlencode({"name": name, "type": rtype})
    data = get_json(url, {"Accept": "application/dns-json"})
    return [a.get("data", "") for a in (data or {}).get("Answer", [])]


def dns(found: dict[str, str], known: set[str]) -> None:
    print("[dns] CNAME controle op de Discover-Tech load balancer")
    alb_ips = set(doh(ALB, "A"))
    for name in sorted(set(found) | known):
        if name.endswith("cloudfront.net") or name.endswith("amazonaws.com"):
            continue
        cnames = [c.rstrip(".").lower() for c in doh(name, "CNAME")]
        if ALB in cnames:
            found[name] = "dns: CNAME naar Discover-Tech ALB (bevestigd)"
        elif alb_ips and set(doh(name, "A")) & alb_ips:
            found[name] = "dns: A record deelt IP met Discover-Tech ALB (bevestigd)"
        time.sleep(0.2)


def censys(found: dict[str, str]) -> None:
    api_id, secret = os.environ.get("CENSYS_API_ID"), os.environ.get("CENSYS_API_SECRET")
    if not (api_id and secret):
        print("[censys] overgeslagen, geen CENSYS_API_ID / CENSYS_API_SECRET")
        return
    print("[censys] Bindecy certificaat en body hash")
    auth = base64.b64encode(f"{api_id}:{secret}".encode()).decode()
    for q in CENSYS_QUERIES:
        url = "https://search.censys.io/api/v2/hosts/search?" + urllib.parse.urlencode(
            {"q": q, "per_page": 100}
        )
        data = get_json(url, {"Authorization": f"Basic {auth}"})
        for hit in ((data or {}).get("result") or {}).get("hits", []):
            for n in hit.get("dns", {}).get("names", []) or []:
                d = clean(n)
                if d:
                    found.setdefault(d, f"censys: {q[:60]}")
        time.sleep(2)


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--skip", default="", help="komma gescheiden: crtsh,urlscan,dns,censys")
    args = ap.parse_args()
    skip = set(filter(None, args.skip.split(",")))

    known: set[str] = set(parse(APPROVED))
    for src in SOURCES.glob("*.txt"):
        known |= set(parse(src))
    allow = set(parse(ALLOWLIST))

    found: dict[str, str] = {}
    if "crtsh" not in skip:
        crtsh(found)
    if "urlscan" not in skip:
        urlscan(found)
    if "censys" not in skip:
        censys(found)
    if "dns" not in skip:
        dns(found, known)

    new = {d: why for d, why in found.items() if d not in known and d not in allow}
    stamp = dt.date.today().strftime("%Y%m%d")
    out = ROOT / "candidates" / f"candidates-{stamp}.txt"
    lines = [
        f"# Discovery run {dt.datetime.now(dt.timezone.utc):%Y-%m-%d %H:%M UTC}",
        f"# {len(new)} nieuwe kandidaten (niet in sources/, approved.txt of allowlist.txt)",
        "# Controleer elke regel. Wat klopt: kopieer naar candidates/approved.txt",
        "# met een categorie, bijvoorbeeld:  foo.mtrtb.com  # discover-tech: crt.sh",
        "",
    ] + [f"{d:<55} # {why}" for d, why in sorted(new.items(), key=lambda x: (x[1], x[0]))]
    out.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"{len(new)} nieuwe kandidaten in {out.relative_to(ROOT)}")


if __name__ == "__main__":
    main()
