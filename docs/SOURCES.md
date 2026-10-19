# Sources and coverage

Reviewed on **19 October 2026**. This document describes the scope of this compilation; it is not a claim that all infrastructure or all domains mentioned anywhere in the reports are blocked.

| Source file | Publication | Unique explicit hosts in file |
| --- | --- | ---: |
| `sources/citizenlab-adfection.txt` | [Citizen Lab Report 195](https://citizenlab.ca/research/how-discover-tech-turned-targeted-ads-into-a-pipeline-for-spyware/), 15 October 2026 | 67 |
| `sources/confiant-adint.txt` | [Confiant ADINT investigation](https://blog.confiant.com/p/adint-weaponized-ad-tech-for-zero-click-spyware-and-mass-identity-vacuuming), 15 October 2026 | 17 |
| `sources/recordedfuture-candiru.txt` | [Recorded Future CTA-2025-0805](https://assets.recordedfuture.com/content/dam/insikt-report-pdfs/2025/cta-2025-0805.pdf), 5 August 2025 | 108 |

Four hosts overlap between the source files. After deduplication, the compilation contains **188 unique hosts**, grouped as Candiru (124), Discover-Tech (56), Bindecy (7), and Intelos (1). Category assignment is for list selection, not an assertion of exclusive ownership.

## Review on 19 October 2026

The Citizen Lab Appendix C list revealed six omissions from the initial compilation:

- `noas.adtimizer.co`
- `noas.impchkdsp.com`
- `noas.trakking.co`
- `checkmyimp.com`
- `ads-impressions.com`
- `nutralove.co`

All six are now explicit source entries. `noas.adtimizer.co` was already covered by the parent in wildcard-aware formats, but was absent from exact-host formats. The first three are described in Appendix C as additional NOAS domains that appear associated with Discover-Tech; the last three as associated ad tracking or targeting domains. This qualified attribution is preserved in the source comments.

The published Confiant Indicators section's domains are represented either explicitly or through their reported wildcard parent. The review is based on the publications; no successful live discovery sweep is claimed by this source review. Consult each discovery JSON report separately.

## Inclusion and exclusion policy

1. Use publicly attributable research evidence and record its URL, date and role in `sources/`, or record the supporting evidence in `candidates/approved.txt` after review.
2. Include specifically reported delivery, C2, profiling, tracking and related platform hosts. Some associated corporate sites are included; users who need narrower coverage should review the category lists.
3. Do not block a publisher merely because it displayed an ad or loaded a tracking pixel. Do not treat IP co-hosting or a matching certificate alone as proof of malicious use.
4. Preserve shared platform roots using exact exclusions in `allowlist.txt`. Specific tenant hosts remain eligible.
5. Do not infer that an entire registrable parent is malicious from one tenant or subdomain. Parent-level blocking needs its own evidence.
6. Record removals and significant coverage changes in `CHANGELOG.md`. Discovery never grants automatic approval.

## Known gaps and historical status

Citizen Lab describes 305 identified Candiru validator domains, including earlier publicly attributed ones. That figure is not the number of domains in this repository, nor a measure of present-day active servers. The repository includes published historical indicators from 2025 and 2026 and does not routinely remove them simply because they stop resolving.

Plain hosts files cannot express the full coverage of reported wildcards. A list build date means that files were generated, not that every hostname was re-investigated on that date. A successful discovery run means only its configured queries completed; result limits and undisclosed infrastructure still prevent exhaustive coverage.

## Attribution and third-party rights

Citizen Lab Report 195 is by Bill Marczak, Wolfie Christl, John Scott-Railton, Astrid Perry, Siena Anstis and Ron Deibert, University of Toronto. The other publications are attributed to Confiant Threat Intelligence and Recorded Future Insikt Group respectively. Follow the linked originals for full methods, qualifications, company responses and publication terms.

The project's CC BY-NC-SA offer concerns its own compilation and additions. It does not imply that Confiant or Recorded Future published their reports under that license or that their rights are transferred. HaGeZi is credited for organizational inspiration; no endorsement or source-list import is claimed.
