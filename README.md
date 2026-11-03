# AdFection blocklist

A focused domain blocklist for infrastructure associated with **AdFection**, ad-based spyware delivery and related advertising surveillance. It combines published indicators concerning Discover-Tech, Candiru / Integrity Labs, Bindecy and Intelos.

**Coverage reviewed: 3 November 2026. This is a curated, partial dataset, not a complete inventory or a guarantee against spyware.** An entry can identify delivery, profiling, tracking, administration or associated corporate infrastructure; it does not mean every listed host delivered malware.

Independent community project. Not affiliated with Citizen Lab, Confiant, Recorded Future or HaGeZi. The directory layout and list metadata are inspired by [HaGeZi DNS blocklists](https://github.com/hagezi/dns-blocklists).

## Quick start

Use **Full** unless you deliberately want one category only. Subscribe to one format supported by your blocker; adding all formats provides no extra coverage.

- **AdGuard Home:** add the raw Adblock Full URL below under *Filters → DNS blocklists*.
- **uBlock Origin:** import the raw Adblock Full URL under *Filter lists → Import*, then apply changes.
- **Pi-hole:** add the raw Domains Full URL below as an adlist and update Gravity. Importing a file into Pi-hole is different from using it as a literal hosts file; subdomain handling depends on the product/version.
- **Unbound, dnsmasq or RPZ:** use the corresponding configuration format and validate it before reloading your resolver. These are not interchangeable with a plain domain list. RPZ must be attached to your resolver's response policy.

The download links below point to raw text, suitable for subscription where the client supports custom URLs. `Expires: 1 day` is a refresh hint for compatible clients, **not** a guarantee that every client updates daily. Local hosts and resolver configuration files need their own update process. NextDNS custom URL import is not assumed to be supported.

## Independent source and optional unverified list

Daily Actions now produce this project's own evidence dataset. Community and published indicators remain a frozen starting set; daily runs do not download other blocklists.

**`adfection-unverified.txt` is a separate, opt-in blocklist.** It automatically includes candidates with concrete infrastructure/measurement evidence before full actor attribution is verified. It has greater false-positive risk. Use it alongside the regular list if you want this broader coverage. All eight formats are linked below. Each inclusion has a reproducible rule and evidence IDs in [research/unverified.json](research/unverified.json); it does not claim verified malware or current actor control.

Research runs daily at **06:17 UTC**, with a ten-minute budget and a persistent queue. A read-only collector and separate offline publisher validate observations, tests, output consistency and resolver syntax, then push generated updates **directly to `main`**. No maintenance PR or per-domain human approval is required for the opt-in tier. Qualified detector rules remain available for automatic admission to the regular discovered list.

See [architecture and evidence rules](docs/ARCHITECTURE.md), [research policy](research/project.json), [persistent register](research/registry.json) and [latest report](candidates/latest.json). Historical source dates and actual measurement dates are distinct.

<!-- LISTS:START -->

**211 unique domains**, **159 after wildcard compression**.

### AdFection Unverified

Opt-in: evidence-backed candidates with unverified attribution; higher false-positive risk

| Format | Intended use | Download / subscription |
| --- | --- | --- |
| Adblock | AdGuard Home, uBlock Origin; root + subdomains | [adblock/adfection-unverified.txt](https://raw.githubusercontent.com/LeonardSEO/adfection-blocklist/main/lists/adblock/adfection-unverified.txt) |
| DNSMasq | dnsmasq, OpenWrt, Pi-hole (dnsmasq.d) | [dnsmasq/adfection-unverified.txt](https://raw.githubusercontent.com/LeonardSEO/adfection-blocklist/main/lists/dnsmasq/adfection-unverified.txt) |
| Wildcard | Compressed roots; importer must match subdomains | [wildcard/adfection-unverified-onlydomains.txt](https://raw.githubusercontent.com/LeonardSEO/adfection-blocklist/main/lists/wildcard/adfection-unverified-onlydomains.txt) |
| Asterisk Wildcard | Explicit root + *.domain pairs; check importer support | [wildcard/adfection-unverified.txt](https://raw.githubusercontent.com/LeonardSEO/adfection-blocklist/main/lists/wildcard/adfection-unverified.txt) |
| Domains | Pi-hole / plain domain import; all explicit hosts | [domains/adfection-unverified.txt](https://raw.githubusercontent.com/LeonardSEO/adfection-blocklist/main/lists/domains/adfection-unverified.txt) |
| Hosts | OS hosts file; exact hostnames | [hosts/adfection-unverified.txt](https://raw.githubusercontent.com/LeonardSEO/adfection-blocklist/main/lists/hosts/adfection-unverified.txt) |
| RPZ | BIND, PowerDNS, Knot, Technitium | [rpz/adfection-unverified.txt](https://raw.githubusercontent.com/LeonardSEO/adfection-blocklist/main/lists/rpz/adfection-unverified.txt) |
| Unbound | Unbound local-zone configuration | [unbound/adfection-unverified.txt](https://raw.githubusercontent.com/LeonardSEO/adfection-blocklist/main/lists/unbound/adfection-unverified.txt) |

### AdFection Full

Published indicators associated with Discover-Tech, Candiru, Bindecy and Intelos

| Format | Intended use | Download / subscription |
| --- | --- | --- |
| Adblock | AdGuard Home, uBlock Origin; root + subdomains | [adblock/adfection.txt](https://raw.githubusercontent.com/LeonardSEO/adfection-blocklist/main/lists/adblock/adfection.txt) |
| DNSMasq | dnsmasq, OpenWrt, Pi-hole (dnsmasq.d) | [dnsmasq/adfection.txt](https://raw.githubusercontent.com/LeonardSEO/adfection-blocklist/main/lists/dnsmasq/adfection.txt) |
| Wildcard | Compressed roots; importer must match subdomains | [wildcard/adfection-onlydomains.txt](https://raw.githubusercontent.com/LeonardSEO/adfection-blocklist/main/lists/wildcard/adfection-onlydomains.txt) |
| Asterisk Wildcard | Explicit root + *.domain pairs; check importer support | [wildcard/adfection.txt](https://raw.githubusercontent.com/LeonardSEO/adfection-blocklist/main/lists/wildcard/adfection.txt) |
| Domains | Pi-hole / plain domain import; all explicit hosts | [domains/adfection.txt](https://raw.githubusercontent.com/LeonardSEO/adfection-blocklist/main/lists/domains/adfection.txt) |
| Hosts | OS hosts file; exact hostnames | [hosts/adfection.txt](https://raw.githubusercontent.com/LeonardSEO/adfection-blocklist/main/lists/hosts/adfection.txt) |
| RPZ | BIND, PowerDNS, Knot, Technitium | [rpz/adfection.txt](https://raw.githubusercontent.com/LeonardSEO/adfection-blocklist/main/lists/rpz/adfection.txt) |
| Unbound | Unbound local-zone configuration | [unbound/adfection.txt](https://raw.githubusercontent.com/LeonardSEO/adfection-blocklist/main/lists/unbound/adfection.txt) |

### AdFection Candiru

Candiru / Integrity Labs validator, C2 and delivery servers

| Format | Intended use | Download / subscription |
| --- | --- | --- |
| Adblock | AdGuard Home, uBlock Origin; root + subdomains | [adblock/adfection-candiru.txt](https://raw.githubusercontent.com/LeonardSEO/adfection-blocklist/main/lists/adblock/adfection-candiru.txt) |
| DNSMasq | dnsmasq, OpenWrt, Pi-hole (dnsmasq.d) | [dnsmasq/adfection-candiru.txt](https://raw.githubusercontent.com/LeonardSEO/adfection-blocklist/main/lists/dnsmasq/adfection-candiru.txt) |
| Wildcard | Compressed roots; importer must match subdomains | [wildcard/adfection-candiru-onlydomains.txt](https://raw.githubusercontent.com/LeonardSEO/adfection-blocklist/main/lists/wildcard/adfection-candiru-onlydomains.txt) |
| Asterisk Wildcard | Explicit root + *.domain pairs; check importer support | [wildcard/adfection-candiru.txt](https://raw.githubusercontent.com/LeonardSEO/adfection-blocklist/main/lists/wildcard/adfection-candiru.txt) |
| Domains | Pi-hole / plain domain import; all explicit hosts | [domains/adfection-candiru.txt](https://raw.githubusercontent.com/LeonardSEO/adfection-blocklist/main/lists/domains/adfection-candiru.txt) |
| Hosts | OS hosts file; exact hostnames | [hosts/adfection-candiru.txt](https://raw.githubusercontent.com/LeonardSEO/adfection-blocklist/main/lists/hosts/adfection-candiru.txt) |
| RPZ | BIND, PowerDNS, Knot, Technitium | [rpz/adfection-candiru.txt](https://raw.githubusercontent.com/LeonardSEO/adfection-blocklist/main/lists/rpz/adfection-candiru.txt) |
| Unbound | Unbound local-zone configuration | [unbound/adfection-candiru.txt](https://raw.githubusercontent.com/LeonardSEO/adfection-blocklist/main/lists/unbound/adfection-candiru.txt) |

### AdFection Discover-Tech

Controlium, MyDSP, NOAS servers and ID syncing

| Format | Intended use | Download / subscription |
| --- | --- | --- |
| Adblock | AdGuard Home, uBlock Origin; root + subdomains | [adblock/adfection-discover-tech.txt](https://raw.githubusercontent.com/LeonardSEO/adfection-blocklist/main/lists/adblock/adfection-discover-tech.txt) |
| DNSMasq | dnsmasq, OpenWrt, Pi-hole (dnsmasq.d) | [dnsmasq/adfection-discover-tech.txt](https://raw.githubusercontent.com/LeonardSEO/adfection-blocklist/main/lists/dnsmasq/adfection-discover-tech.txt) |
| Wildcard | Compressed roots; importer must match subdomains | [wildcard/adfection-discover-tech-onlydomains.txt](https://raw.githubusercontent.com/LeonardSEO/adfection-blocklist/main/lists/wildcard/adfection-discover-tech-onlydomains.txt) |
| Asterisk Wildcard | Explicit root + *.domain pairs; check importer support | [wildcard/adfection-discover-tech.txt](https://raw.githubusercontent.com/LeonardSEO/adfection-blocklist/main/lists/wildcard/adfection-discover-tech.txt) |
| Domains | Pi-hole / plain domain import; all explicit hosts | [domains/adfection-discover-tech.txt](https://raw.githubusercontent.com/LeonardSEO/adfection-blocklist/main/lists/domains/adfection-discover-tech.txt) |
| Hosts | OS hosts file; exact hostnames | [hosts/adfection-discover-tech.txt](https://raw.githubusercontent.com/LeonardSEO/adfection-blocklist/main/lists/hosts/adfection-discover-tech.txt) |
| RPZ | BIND, PowerDNS, Knot, Technitium | [rpz/adfection-discover-tech.txt](https://raw.githubusercontent.com/LeonardSEO/adfection-blocklist/main/lists/rpz/adfection-discover-tech.txt) |
| Unbound | Unbound local-zone configuration | [unbound/adfection-discover-tech.txt](https://raw.githubusercontent.com/LeonardSEO/adfection-blocklist/main/lists/unbound/adfection-discover-tech.txt) |

### AdFection Bindecy

Published Bindecy-associated infrastructure

| Format | Intended use | Download / subscription |
| --- | --- | --- |
| Adblock | AdGuard Home, uBlock Origin; root + subdomains | [adblock/adfection-bindecy.txt](https://raw.githubusercontent.com/LeonardSEO/adfection-blocklist/main/lists/adblock/adfection-bindecy.txt) |
| DNSMasq | dnsmasq, OpenWrt, Pi-hole (dnsmasq.d) | [dnsmasq/adfection-bindecy.txt](https://raw.githubusercontent.com/LeonardSEO/adfection-blocklist/main/lists/dnsmasq/adfection-bindecy.txt) |
| Wildcard | Compressed roots; importer must match subdomains | [wildcard/adfection-bindecy-onlydomains.txt](https://raw.githubusercontent.com/LeonardSEO/adfection-blocklist/main/lists/wildcard/adfection-bindecy-onlydomains.txt) |
| Asterisk Wildcard | Explicit root + *.domain pairs; check importer support | [wildcard/adfection-bindecy.txt](https://raw.githubusercontent.com/LeonardSEO/adfection-blocklist/main/lists/wildcard/adfection-bindecy.txt) |
| Domains | Pi-hole / plain domain import; all explicit hosts | [domains/adfection-bindecy.txt](https://raw.githubusercontent.com/LeonardSEO/adfection-blocklist/main/lists/domains/adfection-bindecy.txt) |
| Hosts | OS hosts file; exact hostnames | [hosts/adfection-bindecy.txt](https://raw.githubusercontent.com/LeonardSEO/adfection-blocklist/main/lists/hosts/adfection-bindecy.txt) |
| RPZ | BIND, PowerDNS, Knot, Technitium | [rpz/adfection-bindecy.txt](https://raw.githubusercontent.com/LeonardSEO/adfection-blocklist/main/lists/rpz/adfection-bindecy.txt) |
| Unbound | Unbound local-zone configuration | [unbound/adfection-bindecy.txt](https://raw.githubusercontent.com/LeonardSEO/adfection-blocklist/main/lists/unbound/adfection-bindecy.txt) |

### AdFection Independently Discovered

Own findings supported by qualified detectors

| Format | Intended use | Download / subscription |
| --- | --- | --- |
| Adblock | AdGuard Home, uBlock Origin; root + subdomains | [adblock/adfection-discovered.txt](https://raw.githubusercontent.com/LeonardSEO/adfection-blocklist/main/lists/adblock/adfection-discovered.txt) |
| DNSMasq | dnsmasq, OpenWrt, Pi-hole (dnsmasq.d) | [dnsmasq/adfection-discovered.txt](https://raw.githubusercontent.com/LeonardSEO/adfection-blocklist/main/lists/dnsmasq/adfection-discovered.txt) |
| Wildcard | Compressed roots; importer must match subdomains | [wildcard/adfection-discovered-onlydomains.txt](https://raw.githubusercontent.com/LeonardSEO/adfection-blocklist/main/lists/wildcard/adfection-discovered-onlydomains.txt) |
| Asterisk Wildcard | Explicit root + *.domain pairs; check importer support | [wildcard/adfection-discovered.txt](https://raw.githubusercontent.com/LeonardSEO/adfection-blocklist/main/lists/wildcard/adfection-discovered.txt) |
| Domains | Pi-hole / plain domain import; all explicit hosts | [domains/adfection-discovered.txt](https://raw.githubusercontent.com/LeonardSEO/adfection-blocklist/main/lists/domains/adfection-discovered.txt) |
| Hosts | OS hosts file; exact hostnames | [hosts/adfection-discovered.txt](https://raw.githubusercontent.com/LeonardSEO/adfection-blocklist/main/lists/hosts/adfection-discovered.txt) |
| RPZ | BIND, PowerDNS, Knot, Technitium | [rpz/adfection-discovered.txt](https://raw.githubusercontent.com/LeonardSEO/adfection-blocklist/main/lists/rpz/adfection-discovered.txt) |
| Unbound | Unbound local-zone configuration | [unbound/adfection-discovered.txt](https://raw.githubusercontent.com/LeonardSEO/adfection-blocklist/main/lists/unbound/adfection-discovered.txt) |

### AdFection Intelos

Published Intelos ADINT-associated infrastructure

| Format | Intended use | Download / subscription |
| --- | --- | --- |
| Adblock | AdGuard Home, uBlock Origin; root + subdomains | [adblock/adfection-intelos.txt](https://raw.githubusercontent.com/LeonardSEO/adfection-blocklist/main/lists/adblock/adfection-intelos.txt) |
| DNSMasq | dnsmasq, OpenWrt, Pi-hole (dnsmasq.d) | [dnsmasq/adfection-intelos.txt](https://raw.githubusercontent.com/LeonardSEO/adfection-blocklist/main/lists/dnsmasq/adfection-intelos.txt) |
| Wildcard | Compressed roots; importer must match subdomains | [wildcard/adfection-intelos-onlydomains.txt](https://raw.githubusercontent.com/LeonardSEO/adfection-blocklist/main/lists/wildcard/adfection-intelos-onlydomains.txt) |
| Asterisk Wildcard | Explicit root + *.domain pairs; check importer support | [wildcard/adfection-intelos.txt](https://raw.githubusercontent.com/LeonardSEO/adfection-blocklist/main/lists/wildcard/adfection-intelos.txt) |
| Domains | Pi-hole / plain domain import; all explicit hosts | [domains/adfection-intelos.txt](https://raw.githubusercontent.com/LeonardSEO/adfection-blocklist/main/lists/domains/adfection-intelos.txt) |
| Hosts | OS hosts file; exact hostnames | [hosts/adfection-intelos.txt](https://raw.githubusercontent.com/LeonardSEO/adfection-blocklist/main/lists/hosts/adfection-intelos.txt) |
| RPZ | BIND, PowerDNS, Knot, Technitium | [rpz/adfection-intelos.txt](https://raw.githubusercontent.com/LeonardSEO/adfection-blocklist/main/lists/rpz/adfection-intelos.txt) |
| Unbound | Unbound local-zone configuration | [unbound/adfection-intelos.txt](https://raw.githubusercontent.com/LeonardSEO/adfection-blocklist/main/lists/unbound/adfection-intelos.txt) |

<!-- LISTS:END -->

## What is covered

The source publications are:

1. [Citizen Lab Report 195 — Exposing AdFection](https://citizenlab.ca/research/how-discover-tech-turned-targeted-ads-into-a-pipeline-for-spyware/) (15 October 2026), including Appendix C.
2. [Confiant — ADINT: Weaponized Ad Tech for Zero-Click Spyware and Mass Identity Vacuuming](https://blog.confiant.com/p/adint-weaponized-ad-tech-for-zero-click-spyware-and-mass-identity-vacuuming) (15 October 2026), including its Indicators section.
3. [Recorded Future — Tracking Candiru's DevilsTongue Spyware in Multiple Countries, CTA-2025-0805](https://assets.recordedfuture.com/content/dam/insikt-report-pdfs/2025/cta-2025-0805.pdf) (5 August 2025), for additional historical Candiru indicators.

See [source attribution and coverage](docs/SOURCES.md) for extraction counts, inclusion policy and known gaps. Inclusion follows these publications; it is not an independent attribution of wrongdoing. Historical indicators remain until reviewed; ownership and use may change.

## Formats and subdomains

| Directory | Syntax | Coverage |
| --- | --- | --- |
| `lists/adblock/` | `\|\|example.org^` | Root and subdomains in compatible filter engines |
| `lists/domains/` | `example.org` | All explicitly listed hosts; importer determines matching |
| `lists/hosts/` | `0.0.0.0 example.org` | Exact hostname when used as an OS hosts file |
| `lists/dnsmasq/` | `local=/example.org/` | Local negative answers for root and subdomains |
| `lists/wildcard/*-onlydomains.txt` | `example.org` | Compressed roots; importer **must** also match descendants |
| `lists/wildcard/adfection*.txt` (without `-onlydomains`) | `example.org` and `*.example.org` | Explicit pairs; requires an importer accepting both syntaxes |
| `lists/rpz/` | Root and wildcard `CNAME .` records | NXDOMAIN policy zone; includes SOA and NS records |
| `lists/unbound/` | `local-zone: "example.org." always_nxdomain` | Root and descendants |

Compression removes a hostname only when another entry covers its parent. Domains and Hosts retain explicit subdomains. They cannot enumerate every possible or future subdomain. Asterisk and RPZ files emit two blocking records per compressed domain, so their entry counts differ from their domain counts.

## Repository layout

```text
sources/*.txt                 Published domains with category and source comments
allowlist.txt                 Exact exclusions for shared platform roots and other exceptions
candidates/approved.txt        Frozen legacy reviewed additions
candidates/candidates-*.txt    Historical reports migrated into the register
candidates/candidates-*.json   Discovery status, errors and skipped sources
scripts/build.py              Validation, deduplication, compression and eight output formats
scripts/refresh.py            Independent collector and persistent queue
lists/                        Generated subscription/configuration files; do not edit directly
tests/                        Offline regression and format coverage tests
.github/workflows/            Read-only CI and scheduled build/discovery automation
```

## Development

Python **3.10+**, standard library only. No package installation or API key is required to build or run the offline tests.

```bash
python3 -m unittest discover -s tests -v
python3 scripts/build.py
python3 scripts/build.py --check
```

`--check` compares every generated file and the README download table against a temporary rebuild without changing the working tree. `SOURCE_DATE_EPOCH` can fix the build timestamp for reproducible output. GitHub links are derived from `GITHUB_REPOSITORY` or the `origin` remote; before a remote is configured, links remain local.

## Discovery and updates

```bash
python3 scripts/refresh.py --max-seconds 600  # exit 3 means partial observations, not corruption
python3 scripts/publish.py
python3 scripts/publish.py --check
python3 scripts/build.py
python3 scripts/build.py --check
```

The same independent engine as Pegasus collects CT/SAN, DNS, existing scans and bounded root-only HTTP/TLS evidence. AdFection additionally searches the request hosts serving its configured tracking assets, allowing standalone new roots without blocking publishers. It does not submit new third-party scans. `research/project.json` owns the search and unverified-tier rules; qualified verified detectors live in `research/detectors.json`. No API credentials are required.

The frozen bootstrap preserves all existing category subscriptions and the reviewed additions previously stored in `approved.txt`. Historical discovery reports and open issue leads were migrated with their references and unknown observation dates, then queued for current measurements. Future additions are generated from the register, not by resynchronizing community lists. The legacy `discover.py` command remains available but is no longer the daily pipeline.

See the [architecture](docs/ARCHITECTURE.md) for evidence rules, isolation, direct-main publication and failure handling. CI uses Python 3.10/3.14 and resolver syntax checks. Dependabot and human contribution PRs retain their validated auto-merge path; daily research creates no PRs or review issues.

## Limitations

- Published indicators are only part of the infrastructure. Citizen Lab reports finding 305 Candiru validator domains; this repository does not contain that entire set.
- A DNS list does not remove spyware, patch browser vulnerabilities or stop every ad-based attack. Connections using cached DNS, a different resolver, new domains or direct IPs may escape it.
- Associated sites and historical infrastructure can cause false positives. Use a narrower category or a local exception when appropriate, and report the evidence.
- Shared hosting roots such as `cloudfront.net` are excluded, while specifically reported tenant hostnames can be included. The allowlist is an **exact exclusion**, not a blanket exemption for descendants.

## Contributing and reporting problems

Read [CONTRIBUTING.md](CONTRIBUTING.md). Report false positives or missing indicators through [GitHub issues](https://github.com/LeonardSEO/adfection-blocklist/issues), with the exact hostname and a source or reproduction. Please do not include private browsing logs, personal identifiers or credentials.

## License and attribution

The project's original list compilation and additions are offered under [CC BY-NC-SA 4.0](https://creativecommons.org/licenses/by-nc-sa/4.0/). Scripts, tests and workflow code use the MIT license. Original research remains attributed to its authors and subject to its own terms; this repository does not relicense their reports. See [LICENSE](LICENSE) and [source notes](docs/SOURCES.md).
