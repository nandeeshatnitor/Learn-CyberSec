# CVE Learning Explorer

A cybersecurity learning platform. A student searches for a CVE and gets structured, attributed
vulnerability information from public databases, and (in later phases) a lesson: how it works, how to
reproduce it in an authorised local lab, and how to fix it.

> **Educational use only.** Only test systems you own or have explicit written permission to
> test. Everything from external sources is treated as untrusted input.

## Status: Phase 4 (sandboxed labs)

You can open the site, search for a CVE (by ID, part of an ID, keyword, product or vendor), open
it, and see metadata retrieved from **NVD**, **MITRE / CVE Program** and the **CISA KEV
catalogue**: description, CVSS, severity, CWEs, affected software and versions, known-exploitation
status, dates and the original references. Every section says which source it came from, and the
site says that it *retrieved* the data and did *not independently verify* it. If one provider is
down the site keeps working with the others (and with cached or stored copies, labelled as such).

**Learning guides (phase 2).** On a CVE page, **Generate Learning Guide** researches public sources
(vendor and CERT advisories, GitHub advisories, write-ups, Exploit-DB pages) in a background job and
builds a structured guide: what it is, why it happens, affected versions, prerequisites, a local lab
reproduction where the sources support one, what to observe, impact, remediation and references.
Every statement cites its sources and carries an evidence level; where the sources are silent the
guide says so instead of guessing. Retrieved web content is treated strictly as data: nothing is
executed, and a language model (optional) only rewrites evidence that is then re-checked in code. See
[docs/research.md](docs/research.md).

**Interactive learning (phase 3).** Instead of reading the solution, press **Start learning session** and
work through it at `/learn/CVE-…`: objectives and progress on the left, the current task in the middle,
the AI tutor, hints and sources on the right. Tasks: identify the vulnerable component and input, reproduce
the documented behaviour in a lab, explain why it happens, identify the remediation. Answer in your own
words and get feedback that never hands you the answer; ask for up to three progressively more explicit
hints (a small, configurable score cost) or the solution; ask the tutor, whose answers cite their sources
and say so when the sources are silent. See [docs/learning.md](docs/learning.md).

**Sandboxed labs (phase 4).** A lesson can offer a hands-on lab: a disposable, isolated container running an
*intentionally vulnerable toy application*, with a browser terminal, the lab's own web app in a sandboxed
frame, and objectives that are verified against how the lab *behaves* (an exploit that really works, a fix that
really blocks it while the app still does its job). Each student gets their own lab on a private network with no
route out (proven before it starts), hard CPU/memory/process limits, a read-only filesystem, no capabilities and no
host mounts; it can be reset at any time and is deleted when its time runs out. Off by default (`SANDBOX_ENABLED`);
needs a Docker daemon the backend may drive. The demo lab is a path-traversal toy app at `/labs`. See
[docs/sandbox.md](docs/sandbox.md).

**Not implemented yet (later phases):** user accounts (learners are anonymous, identified by a cookie) and labs for
arbitrary CVEs. See [docs/roadmap.md](docs/roadmap.md) and [docs/providers.md](docs/providers.md).

> **Guides work without an API key.** With no `ANTHROPIC_API_KEY` the guide is assembled from
> verbatim excerpts of the sources. Set the key (backend/worker only) for model-written guides.

> **Verify against the real APIs.** The automated tests use hand-written fixtures and never touch
> the network; the adapters were built without access to the live services. Run
> `make verify-providers` once on a machine with internet access (see
> [docs/providers.md](docs/providers.md#verifying-against-the-real-apis)).

## Layout

```
frontend/         Next.js (App Router) + TypeScript + Tailwind + shadcn/ui-style components
backend/          FastAPI, Pydantic, SQLAlchemy, Alembic
  app/api/          HTTP layer only (routes, error handlers, middleware)
  app/services/     business logic (lookup/search orchestration, merging)
  app/integrations/ provider adapters (nvd/, mitre/, cisa_kev/), HTTP client, cache/limit wrapper
  app/cache/        Redis cache, sliding-window rate limiter, in-process fallbacks
  app/repositories/ database access
  app/models/       ORM models       app/schemas/  normalised, provider-independent schemas
  app/learning/     interactive challenge, answer rubric, scoring, AI tutor
  app/research/     research pipeline: discovery, safe fetching, extraction, screening, synthesis, validation
  app/sandbox/      sandboxed labs: templates, Docker runtime, network controller, instance manager, cleanup, verifier, terminal gateway
  app/workers/      RQ queue, research job and worker; the lab cleanup worker
labs/             lab definitions (lab.json + Dockerfile + the intentionally vulnerable toy app) and the isolation-probe image
services/         future standalone services (see services/README.md)
infrastructure/   deployment/infra assets
docs/             architecture, providers, data model, security, roadmap
scripts/          helper scripts (env setup, live provider check, fake providers, fake research web)
tests/            cross-service smoke test
```

## Quick start (Docker)

Requires Docker with Compose v2.

```bash
make setup      # creates .env with freshly generated passwords (never commit it)
make up         # postgres, redis, migrations, backend, research worker, frontend
```

- Web app: http://localhost:3000
- API: http://localhost:8000/api/health (interactive docs at `/api/docs` in development)

Then open http://localhost:3000, search for `CVE-2021-44228` or `log4j`, and select a result.
Verify the stack end to end with `make smoke`.

`make down` stops the stack; `docker compose down -v` also deletes the database volume.

**Optional NVD API key.** Without one NVD allows 5 requests per 30 s; the platform stays inside
that (and caches heavily). To raise it to 50, [request a key](https://nvd.nist.gov/developers/request-an-api-key)
and put it in `.env` as `NVD_API_KEY=...`. It is used only by the backend, only sent to NVD in a
request header, and never exposed to the browser or logs.

## Host-based development

Requires Python 3.11+, Node 20+, PostgreSQL 16 and Redis 7 running locally (or start just those
two with `docker compose up -d db redis`).

```bash
make setup                  # .env (DATABASE_URL / REDIS_URL point at localhost)
make install                # backend venv + frontend node_modules
make migrate                # alembic upgrade head
make backend-dev            # terminal 1: http://localhost:8000
make frontend-dev           # terminal 2: http://localhost:3000
```

Working offline (or want to watch a provider fail)? `make fake-providers` serves fake
NVD/MITRE/KEV APIs on localhost; the values to put in `.env` are in `scripts/fake_providers.py`.
`make seed` loads a few hand-entered sample CVEs that are shown only as a last-resort fallback,
clearly labelled "Development sample record".

Learning guides offline: with the fake providers running, `make fake-research` starts the research
worker on a *fictional* web (the real pipeline, queue and database; only the network is replaced), and
`/cves/CVE-2099-12345` then generates a complete guide. `FAKE_LLM=malicious make fake-research` plays
a model that obeys the hostile pages, to show that none of it reaches the guide. See
[docs/research.md](docs/research.md#running-it).

## Tests and checks

```bash
make test        # backend (pytest) + frontend (vitest)
make lint        # ruff + eslint
make typecheck   # mypy + tsc
make smoke       # against a running stack
make verify-providers   # against the REAL NVD / MITRE / CISA APIs (needs internet)
make test-sandbox-docker # sandbox tests on a REAL Docker daemon (root; builds the lab images; starts containers)
```

Backend tests use in-memory SQLite and mocked HTTP by default. To run them on PostgreSQL, create a
*dedicated* database whose name ends in `_test` and set `TEST_DATABASE_URL` (its tables are
dropped after each test; the suite refuses any other name). Set `REDIS_TEST_URL` to also run the
real-Redis tests (cache expiry, the Lua rate limiter shared across workers):

```bash
TEST_DATABASE_URL=postgresql+psycopg://user:pass@localhost:5432/cvelearn_test \
REDIS_TEST_URL=redis://:pass@localhost:6379/0 make test-backend
```

## API

| Method | Path | Notes |
| --- | --- | --- |
| GET | `/api/health` | Liveness + database/Redis status. 503 if the database is down. |
| GET | `/api/health/providers` | Active probe of NVD / MITRE / KEV (cached 60 s). One failing provider does not make the API unhealthy. |
| GET | `/api/cves/{cve_id}` | Normalised record from all providers, merged, with attribution. 404 unknown, 422 malformed, 503 no provider reachable and no stored copy. |
| GET | `/api/cves/search?q=&page=&limit=&severity=&known_exploited=` | Exact ID, partial ID, keyword, product, vendor. `severity` = LOW/MEDIUM/HIGH/CRITICAL, `known_exploited=true` = CISA KEV only. |
| POST | `/api/cves/{cve_id}/research` | Start (or join, or reuse) learning-guide research. Body `{"refresh": false}`. 202 queued, 200 joined/reused, 404 unknown CVE, 429 per-client or daily limit, 503 disabled or queue down. |
| GET | `/api/cves/{cve_id}/research/status` | `not_started / queued / researching / synthesizing / ready / failed`, counts, versions, error. Poll this. |
| GET | `/api/cves/{cve_id}/research` | The stored guide (every claim with evidence level and citations), sources used, and what happened to every other source. 404 until a guide exists. |
| POST/GET | `/api/learning…` | Learning sessions: create/start/complete, hints (`GET …/hints`, `POST …/hints`), answers, solution, AI tutor. Needs the `X-Learner-Token` header (set by the web app from a cookie). See [docs/learning.md](docs/learning.md#api). |
| `/api/sandbox…` | | Sandboxed labs: catalogue, start/reset/stop, verify, isolation check, terminal ticket, lab progress per learning session; plus the lab's web app and the terminal WebSocket. Off unless `SANDBOX_ENABLED=true`. See [docs/sandbox.md](docs/sandbox.md#api). |
| GET | `/api/sources/{source_id}` | Stored source by UUID. |

Response shape (abridged):

```json
{
  "cve_id": "CVE-2021-44228",
  "description": "…",
  "severity": "CRITICAL",
  "cvss": {"score": 10.0, "vector": "CVSS:3.1/…", "version": "3.1", "source": "nvd", "primary": true},
  "cvss_metrics": [],
  "cwes": [{"id": "CWE-502", "name": null, "sources": ["nvd", "mitre"]}],
  "affected_products": [{"vendor": "apache", "product": "log4j", "source": "nvd", "versions": []}],
  "references": [{"url": "https://…", "title": null, "tags": [], "sources": ["nvd"]}],
  "published_at": "2021-12-10T10:15:09.143Z",
  "modified_at": "2025-05-05T17:15:00Z",
  "known_exploited": true,
  "kev": {"source": "cisa_kev", "date_added": "2021-12-10"},
  "sources": [{"provider": "nvd", "name": "NVD", "url": "https://nvd.nist.gov/…", "retrieved_at": "…", "stale": false}],
  "field_sources": {"description": ["nvd"], "known_exploited": ["cisa_kev"]},
  "meta": {"served_from": "providers", "warnings": [], "providers": [{"provider": "nvd", "status": "ok"}]}
}
```

`known_exploited` is `null` (unknown) when the KEV catalogue could not be consulted, never a
guessed `false`. Errors share one shape: `{"error": {"code", "message", "request_id", "details?"}}`.

## Configuration

All configuration is via environment variables; see [.env.example](.env.example). There are no
hardcoded secrets or API keys, and `DATABASE_URL` has no default. Provider credentials live only
in the backend. The frontend only reads `BACKEND_URL` on the server; nothing backend-related is
exposed to the browser.

## Documentation

- [Architecture](docs/architecture.md)
- [Data providers, caching and rate limiting](docs/providers.md)
- [Data model](docs/data-model.md)
- [Security design](docs/security.md)
- [Sandboxed labs](docs/sandbox.md)
- [Roadmap](docs/roadmap.md)
