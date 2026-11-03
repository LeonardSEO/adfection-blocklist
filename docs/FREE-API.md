# Shared Free API accounts

Adfection and Pegasus share the same urlscan.io and Censys Free accounts. There is one coordinator workflow in **LeonardSEO/adfection-blocklist**: `Shared Free API collection`, scheduled at **05:47 UTC** and manually dispatchable. The ordinary research workflows run at 06:17/06:47 UTC and consume sanitized public snapshots. Neither research runner receives API keys.

Add these **Actions repository secrets only in Adfection**:

- `URLSCAN_API_KEY`: urlscan.io API key, sent only as the API-Key header to urlscan.io.
- `CENSYS_PAT`: current Censys Platform Personal Access Token, sent only to api.platform.censys.io. No organization ID, legacy API ID/secret, or paid API search is used.

The provider job is separate from the write job and never connects to candidate hosts. Provider redirects are rejected rather than forwarding credentials. Only successful public urlscan observations are exported, with query tokens, cookies, arbitrary headers and raw bodies removed. Censys responses export names/asset references only; they never establish malicious ownership or authorize a block by themselves.

## Budgets shared across both repositories

| Operation | Automation ceiling, both projects together | Free account allowance supplied for setup |
| --- | --- | --- |
| urlscan searches | 80/day, max 40/project | 1,000/day |
| urlscan result retrievals | 200/day, max 100/project | 10,000/day |
| New private/unlisted/public scans | 0 | Not used |
| Censys asset lookups | At most 2/day, max 1 new lookup/project; shared assets deduplicated | 100 credits/month; 1 credit/asset |
| Censys monthly budget | Hard cap 100; daily ceilings naturally permit at most 62/month | 100/month |
| Censys concurrent requests | 1 across the single coordinator | 1 |

No history, advanced/regex/similarity search, alerts, feeds, live rescans, collections, Shodan or historical-DNS service is called. Censys Free does **not** provide the general search API: this implementation enriches already known public IPs and TLS certificate fingerprints via the current asset lookup endpoints. It can discover new names reported on these assets, but it cannot run the legacy `cupid-ca` global search using a Free token.

The coordinator calls the urlscan quota endpoint and respects response rate-limit/reset headers and 401/402/403/429 responses. Calls are serial and conservatively paced. A quota/auth failure stops that provider; no automatic purchase, paid fallback or anonymous bypass is attempted. UI/manual activity shares the provider account: leave automation headroom, and inspect the actual quota response/status if external usage exhausts the balance. The documented extra daily Censys free actions are not added to our budget.

`research/providers/state.json` persists reservations **before requests are made**. A provider/project receives at most one reservation per UTC day, including manual runs. Failed/interrupted attempts do not refund uncertain usage. Re-running a collection job with `GITHUB_RUN_ATTEMPT > 1` makes no requests; it cannot replay an already reserved plan. To resume after a failed reservation, wait for the next UTC day. A new month resets the calendar-month Censys counter. Do not delete/reset this ledger to rerun jobs: that would lose account-wide accounting.

API observations are cached for at most seven days, under a 3 MiB snapshot bound. Duplicated Censys assets are reused by both projects. Every candidate retains the actual provider observation timestamp when available; unknown times remain unknown, separate from cache retrieval time. Existing evidence and blocklists survive unavailable providers, stale/missing snapshots and quota exhaustion. The snapshot is not a third-party blocklist: it is our own bounded research output from raw observations.

## Operation and diagnosis

1. Add the two secrets in Adfection.
2. Run `Shared Free API collection` once. Its status file records sanitized HTTP status codes, per-action attempt counts, provider stops and missing/already-reserved providers.
3. Run `Independent research and direct publication` in each repository, or let its daily schedule run. It imports the shared snapshots, measures candidates without secrets and publishes through the existing trusted direct-main validation path.

Snapshots: `research/providers/adfection.json` and `research/providers/pegasus.json` in Adfection; status: `research/providers/status.json`; durable budget: `research/providers/state.json`. Pegasus retrieves only its public snapshot, so it needs no cross-repository access token or duplicate secrets.

Sources: [urlscan rate limits](https://docs.urlscan.io/pages/api-rate-limits), [urlscan quotas](https://docs.urlscan.io/apis/urlscan-openapi/generic/getquotas), [Censys Free API access](https://docs.censys.com/reference/get-started), [Censys credit costs](https://docs.censys.com/docs/platform-credits-free-starter).
