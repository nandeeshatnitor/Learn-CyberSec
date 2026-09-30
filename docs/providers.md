# Data providers (Phase 1)

CVE data is retrieved from public vulnerability databases and normalised into one internal schema
(`backend/app/schemas/cve.py`). The API, cache, database and UI never see a provider-specific
shape, and provider identity is a plain string, so **adding a provider does not change the core
CVE model**.

| Provider | ID | What it supplies | Lookup | Search |
| --- | --- | --- | --- | --- |
| NVD (NIST) | `nvd` | description, CVSS v2/v3/v4, CWEs, affected products and versions (CPE), references, dates, NVD's copy of KEV fields | by ID | keyword, severity and KEV filters, pagination |
| MITRE / CVE Program | `mitre` | CNA description, CNA/ADP CVSS, CWEs, vendor-stated affected versions, references | by ID | not supported by the API |
| CISA KEV | `cisa_kev` | whether a CVE is in the Known Exploited Vulnerabilities catalogue, and CISA's details | in-memory lookup in the cached catalogue | vendor/product/keyword and ID-prefix over the catalogue |

## Request flow

```
GET /api/cves/{id}
   │
   ▼ fan out in parallel (thread pool) to every provider that supports lookup
 ┌─────────────────────────── per provider: ProviderGateway ───────────────────────────┐
 │ cache (Redis: fresh TTL + stale window) ─hit─► return                                │
 │   miss ─► per-key lock ─► circuit breaker ─► outbound rate budget ─► adapter.get_cve │
 │                                                    │ failure                         │
 │                                     stale copy? ───┴─► serve it, flagged stale       │
 └──────────────────────────────────────────────────────────────────────────────────────┘
   │  ProviderCVE (one provider's normalised, partial record) × N
   ▼
 merge_provider_records ─► CVERecord (+ field_sources, sources, meta.providers, warnings)
   │
   ├─► best-effort upsert into PostgreSQL (never replaces fuller data with less)
   └─► response
   if no core provider could contribute: stored copy from PostgreSQL, else 503
```

### Search

| Query | Route |
| --- | --- |
| exact ID (`CVE-2021-44228`) | same aggregate lookup as the detail page, wrapped as a one-item result |
| partial ID (`CVE-2021-4`, `2021-4`) | stored CVEs + KEV catalogue. **NVD and MITRE cannot search by ID prefix**, so this only covers CVEs already retrieved and KEV entries; the response says so |
| keyword / product / vendor / phrase | NVD keyword search (paginated by NVD); each result gets KEV status from the cached catalogue at no extra upstream cost |
| NVD unavailable | fallback: KEV catalogue matches + stored CVEs, de-duplicated and paginated locally; `meta.served_from = "fallback"` with a warning |

NVD's keyword search matches text in CVE descriptions. Product and vendor names therefore work
when the description mentions them (it usually does: "Apache Log4j2 …", "OpenSSL …"), and KEV adds
structured vendor/product matching, but there is no CPE-based product index yet. The `severity`
filter uses NVD's CVSS v3 severity, so CVEs that only have v2/v4 scores are excluded when it is set.
`known_exploited=true` maps to NVD's `hasKev`; `known_exploited=false` is rejected rather than
answered inaccurately.

## Caching

Implemented per provider in `app/integrations/resilience.py`, on Redis (`app/cache/`), or an
in-process LRU when `REDIS_URL` is unset.

* **Fresh TTL** (`CACHE_TTL_SECONDS`, default 6 h): served without contacting the provider.
* **Stale window** (`CACHE_STALE_TTL_SECONDS`, default 7 d): after the fresh TTL an entry is kept
  as a fallback. If the provider fails (timeout, 5xx, 429, malformed response, open circuit, local
  rate limit) the stale copy is served and marked `stale: true` with its **original** retrieval
  time; it is never re-labelled as new.
* **Negative caching** (`CACHE_NEGATIVE_TTL_SECONDS`, default 10 min): "no such CVE" answers, so
  typos do not hammer providers. A stale "not found" is never served as an answer.
* **Search results** are cached by query, page, limit and filters (`CACHE_SEARCH_TTL_SECONDS`), and
  the CVEs inside a live NVD search response seed the per-CVE cache: opening a search result costs
  no further NVD request.
* **CISA KEV** is one file, so the whole catalogue is cached (`KEV_CACHE_TTL_SECONDS`) and looked up
  in memory: checking twenty search results costs one download at most.
* Concurrent requests for the same uncached CVE share one upstream call (per-process lock).
* A Redis outage degrades to "cache miss" (logged once, then skipped for 10 s); it never breaks a
  request. Cached payloads are re-validated on read, so a corrupt entry is only ever a miss.

## Rate limiting and failure isolation

* **Outbound** (protects the providers): a sliding-window budget per provider, shared by all
  workers through a Redis Lua script (in-process fallback if Redis is down: never "unlimited").
  Defaults: NVD 4 requests / 30 s without an API key (NVD allows 5), 45 / 30 s with `NVD_API_KEY`
  (allows 50); MITRE 30 / 60 s; KEV 4 / 60 s. Over budget → the provider is not called; stale data is
  served if it exists.
* **Circuit breaker** per provider: after 3 consecutive failures calls are skipped for 30 s (then
  one probe), so a dead provider costs one timeout, not one per request.
* **Inbound** (protects this API): per client IP, `API_RATE_LIMIT_REQUESTS` per window on the CVE
  endpoints, `429` with `Retry-After`. See "Client IPs" below.
* One provider failing never fails the request while another can answer. Each response carries
  `meta.providers` (status of each provider) and `meta.warnings`, and the UI shows them.

### Client IPs

The web app's server calls the API on behalf of visitors, so without help the API would see one
client (the web server). Set `TRUSTED_PROXIES` to the addresses/CIDRs of your reverse proxy and
web server; from those peers the API takes the client address from `X-Forwarded-For` (the
right-most address that is not itself trusted). The web app forwards the `X-Forwarded-For` it
received. **Put a reverse proxy in front of the web app that sets or overwrites that header**;
otherwise a visitor can spoof it. Without `TRUSTED_PROXIES` (local development), all traffic from
the web app shares one budget.

## Source transparency

Every normalised record carries:

* `sources[]`: each provider that contributed, with its own record URL, `retrieved_at`, `stale`;
* `field_sources`: which provider(s) supplied each field (`description`, `cvss`, `cwes`,
  `affected_products`, `references`, `known_exploited`, …);
* per-item attribution: each CWE, reference and affected-product statement lists its providers;
* `meta.providers`: outcome per provider for this request (`ok`, `stale`, `not_found`,
  `unavailable`, `rate_limited`, `circuit_open`).

The UI shows "Source: NVD" / "Source: CISA KEV" on each section, states that data is *retrieved,
not independently verified*, and links to the original record. Reference URLs are preserved
exactly as published (never rewritten, upgraded to https, or visited).

`known_exploited` is tri-state: `true`, `false` (the catalogue was consulted and does not list the
CVE), or `null` (unknown: the catalogue could not be consulted; NVD's copy can still confirm a
positive). The UI never turns "unknown" into "no".

CVSS: all reported metrics are kept. The headline is NVD's own (`Primary`) analysis when present,
otherwise the CNA/ADP score; within a tier, the newest CVSS version wins. CNA and ADP scores are
never labelled as NVD's analysis.

## Untrusted-data handling

Provider responses are attacker-influenced (anyone can publish a reference or write a CNA
description). See [security.md](security.md). In short: fixed allow-listed hosts, no automatic
redirects, size and time limits, JSON-only parsing, every field re-typed, bounded and sanitised in
the adapter, only `http(s)` URLs kept, and nothing from a response is ever executed, fetched or
rendered as HTML.

## Adding a provider

1. Create `app/integrations/<name>/` with a `normalizer.py` (raw JSON → `ProviderCVE`, defensive,
   using `app/utils/sanitize.py`) and a `provider.py` subclassing `CVEProvider`:
   `get_cve`, `search`, `health_check`, plus `id`, `name`, `publisher`, `source_type`,
   `reliability`, `capabilities`, `priority` (lower wins when providers disagree).
2. Take a `ProviderHTTPClient` in the constructor: it enforces the host allow-list, redirect,
   size and timeout policy. Never build request URLs from anything but validated values.
3. Register it in `app/integrations/registry.py` (base URL setting, rate budget) and add its ID to
   `KNOWN_PROVIDERS` in `app/config/settings.py`.
4. Add fixtures and tests, including a hostile payload. Nothing in the API, cache, merge or UI
   needs to change: the UI labels unknown provider IDs with the raw ID until you add a friendly name
   to `frontend/src/lib/format.ts`.

## Verifying against the real APIs

The automated tests use **hand-written fixtures** based on the documented response formats; they
never touch the network. The adapters were developed without access to the live services, so run
this once on a machine with internet access:

```bash
make verify-providers                                     # fetch CVE-2021-44228 from each provider
make verify-providers ARGS="CVE-2014-0160 --record backend/tests/recorded"   # also save raw responses
```

It prints what each adapter parsed, runs the health checks, and exits non-zero if a real response
could not be handled. `--record` saves the raw JSON so you can promote it to fixtures.

For offline work, `make fake-providers` serves the fixtures as fake NVD/MITRE/KEV APIs on
localhost (data is prefixed `[FAKE UPSTREAM]`; see `scripts/fake_providers.py`).
