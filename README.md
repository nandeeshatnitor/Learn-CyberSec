# CVE Learning Explorer

A cybersecurity learning platform. A student searches for a CVE and gets a structured lesson:
what the vulnerability is, who is affected, how it works, how to reproduce it in an authorised
local lab, what evidence shows success, why it happens, how to fix it, and the original sources
behind every claim.

> **Educational use only.** Only test systems you own or have explicit written permission to
> test. Everything from external sources is treated as untrusted input.

## Status: Phase 0 (foundation)

Implemented: monorepo, FastAPI API, PostgreSQL schema + Alembic migrations, Redis wiring,
Next.js UI with placeholder sections, Docker Compose, tests.

**Not implemented yet (later phases):** retrieval from NVD/MITRE/vendor/CISA/etc., learning-guide
generation, hints, sandbox labs, users/progress. The UI states clearly when information is
*unavailable* rather than inventing it, and the few sample CVEs in the database are flagged as
hand-entered, unverified seed data. See [docs/roadmap.md](docs/roadmap.md).

## Layout

```
frontend/         Next.js (App Router) + TypeScript + Tailwind + shadcn/ui-style components
backend/          FastAPI, Pydantic, SQLAlchemy, Alembic
  app/api/          HTTP layer only (routes, error handlers, middleware)
  app/services/     business logic
  app/repositories/ database access
  app/models/       ORM models       app/schemas/  Pydantic API models
  app/integrations/ external sources (empty until Phase 1)
  app/workers/      background jobs (empty until Phase 1)
services/         future standalone services (see services/README.md)
infrastructure/   deployment/infra assets
docs/             architecture, data model, security, roadmap
scripts/          helper scripts     tests/  cross-service smoke test
```

## Quick start (Docker)

Requires Docker with Compose v2.

```bash
make setup      # creates .env with freshly generated passwords (never commit it)
make up         # postgres, redis, migrations, backend, frontend
```

- Web app: http://localhost:3000
- API: http://localhost:8000/api/health (interactive docs at `/api/docs` in development)

Load the sample records (optional), then verify everything end-to-end:

```bash
docker compose run --rm backend python -m app.database.seed
make smoke
```

`make down` stops the stack; `docker compose down -v` also deletes the database volume.

## Host-based development

Requires Python 3.11+, Node 20+, PostgreSQL 16 and Redis 7 running locally (or start just those
two with `docker compose up -d db redis`).

```bash
make setup                  # .env (DATABASE_URL / REDIS_URL point at localhost)
make install                # backend venv + frontend node_modules
make migrate                # alembic upgrade head
make seed                   # optional sample CVEs
make backend-dev            # terminal 1: http://localhost:8000
make frontend-dev           # terminal 2: http://localhost:3000
```

## Tests and checks

```bash
make test        # backend (pytest) + frontend (vitest)
make lint        # ruff + eslint
make typecheck   # mypy + tsc
make smoke       # against a running stack
```

Backend tests use in-memory SQLite by default. To run them on PostgreSQL, create a *dedicated*
database whose name ends in `_test` and set `TEST_DATABASE_URL` (its tables are dropped after each
test; the suite refuses any other name):

```bash
TEST_DATABASE_URL=postgresql+psycopg://user:pass@localhost:5432/cvelearn_test make test-backend
```

## API (Phase 0)

| Method | Path | Notes |
| --- | --- | --- |
| GET | `/api/health` | Liveness + database/Redis status. 503 if the database is down. |
| GET | `/api/cves/{cve_id}` | 404 if not in the local DB, 422 if the ID is malformed. |
| GET | `/api/cves/search?q=&limit=&offset=` | Literal substring search over stored CVE IDs/descriptions. |
| GET | `/api/sources/{source_id}` | Source by UUID. |

Errors share one shape: `{"error": {"code", "message", "request_id", "details?"}}`.

## Configuration

All configuration is via environment variables; see [.env.example](.env.example). There are no
hardcoded secrets or API keys, and `DATABASE_URL` has no default. The frontend only reads
`BACKEND_URL` on the server; nothing backend-related is exposed to the browser.

## Documentation

- [Architecture](docs/architecture.md)
- [Data model](docs/data-model.md)
- [Security design](docs/security.md)
- [Roadmap](docs/roadmap.md)
