# Architecture

```
Browser ──► Next.js (server components) ──► FastAPI ──► PostgreSQL
                                               └──────► Redis (health now; cache/jobs later)
```

The browser only ever talks to Next.js. Server components call the API using `BACKEND_URL`
(`frontend/src/lib/api.ts`, guarded by `import "server-only"` so it cannot be bundled into client
code). This keeps backend addresses and any future credentials out of the browser and removes the
need for cross-origin calls; CORS is nonetheless locked to configured origins, GET-only.

## Backend layers

| Layer | Path | Responsibility |
| --- | --- | --- |
| API | `app/api/` | Parse/validate HTTP input, call one service, shape the response. No business logic. |
| Services | `app/services/` | Business rules and input normalisation. Raise domain errors (`NotFoundError`, `InvalidInputError`). |
| Repositories | `app/repositories/` | All SQL. Nothing else touches the session. |
| Models / Schemas | `app/models/`, `app/schemas/` | ORM tables vs. API contracts, kept separate. |
| Integrations | `app/integrations/` | External data sources (Phase 1+). |
| Workers | `app/workers/` | Background jobs on Redis (Phase 1+). |
| Config / DB / Utils | `app/config/`, `app/database/`, `app/utils/` | Settings, engine/session, logging and helpers. |

Dependencies point downwards only: API → services → repositories → models. Wiring lives in
`app/api/dependencies.py`. Domain errors are mapped to HTTP status codes in one place
(`app/api/errors.py`).

## Adding services later

`services/` is reserved for standalone deployable units (for example an ingestion worker or a
sandbox orchestrator). Each gets its own directory and Dockerfile and a service entry in
`docker-compose.yml`, sharing the same Postgres/Redis. They should communicate through the API,
the database or Redis queues, not by importing backend code.

## Observability

Structured logs via structlog (`LOG_JSON=true` for JSON). Every request gets a request ID
(returned as `X-Request-ID`, bound to all log lines, and included in error bodies).
