# Architecture

```
Browser ──► Next.js (server components) ──► FastAPI ──► PostgreSQL  (stored copies, Phase 0 tables)
                                               │
                                               ├──► Redis         (provider cache, rate limits)
                                               └──► NVD · MITRE/CVE Program · CISA KEV  (public APIs)
```

The browser only ever talks to Next.js. Server components call the API using `BACKEND_URL`
(`frontend/src/lib/api.ts`, guarded by `import "server-only"` so it cannot be bundled into client
code). This keeps backend addresses and all provider credentials out of the browser and removes the
need for cross-origin calls; CORS is nonetheless locked to configured origins, GET-only.

## Backend layers

| Layer | Path | Responsibility |
| --- | --- | --- |
| API | `app/api/` | Parse/validate HTTP input, call one service, shape the response. No business logic. |
| Services | `app/services/` | Lookup/search orchestration (`cve_service.py`), merging provider records (`cve_merge.py`), domain errors. |
| Integrations | `app/integrations/` | One adapter per provider behind the `CVEProvider` interface; the bounded HTTP client; circuit breaker; cache + rate-limit wrapper (`resilience.py`); registry that builds it all from settings. |
| Cache | `app/cache/` | Redis / in-memory cache, fresh + stale envelope, sliding-window rate limiter, per-key locks. |
| Repositories | `app/repositories/` | All SQL. Nothing else touches the session. |
| Models / Schemas | `app/models/`, `app/schemas/` | ORM tables vs. the normalised, provider-independent API contracts. |
| Workers | `app/workers/` | Background jobs on Redis (none needed yet). |
| Config / DB / Utils | `app/config/`, `app/database/`, `app/utils/` | Settings, engine/session, logging, sanitisers and helpers. |

Dependencies point downwards only: API → services → integrations/repositories → models/schemas.
Wiring lives in `app/api/dependencies.py`. Domain errors are mapped to HTTP status codes in one place
(`app/api/errors.py`).

### The provider abstraction

```python
class CVEProvider(ABC):
    id, name, publisher, source_type, reliability, capabilities, priority
    def get_cve(cve_id) -> ProviderCVE | None
    def search(query: SearchQuery) -> ProviderSearchResult
    def health_check() -> ProviderHealth
```

An adapter only translates one external API into the normalised, partial `ProviderCVE`. Caching,
rate limiting, circuit breaking, merging and persistence are separate layers, so a new provider is
one small package (see [providers.md](providers.md#adding-a-provider)) and needs no change to the
core CVE model, the API or the cache.

`ProviderGateway` wraps an adapter with the resilience layer. Adapters that manage their own bulk
cache (CISA KEV downloads a whole catalogue) are marked `self_managed` so budgets and breaker trials
are not double-counted.

## Adding services later

`services/` is reserved for standalone deployable units (for example an ingestion worker or a
sandbox orchestrator). Each gets its own directory and Dockerfile and a service entry in
`docker-compose.yml`, sharing the same Postgres/Redis. They should communicate through the API,
the database or Redis queues, not by importing backend code.

## Frontend

App Router, all data fetching in server components. `/cves` (search: filters, pagination, loading,
empty and error states, provider-status banner) and `/cves/[cveId]` (Overview, Severity, CVSS,
Affected software, Affected versions, Weakness, Known exploitation status, References, Sources).
Sections without data render as visibly "Not available"; sections with data name their source.
`loading.tsx` files provide streaming skeletons. Untrusted text is only ever rendered through React
(escaped), and links only through `SafeLink` (http/https only).

## Observability

Structured logs via structlog (`LOG_JSON=true` for JSON). Every request gets a request ID
(returned as `X-Request-ID`, bound to all log lines, including those from provider worker
threads, and included in error bodies). Provider calls log provider and outcome only: never URLs,
query strings or headers. HTTP client libraries' own request logging is silenced for that reason.
