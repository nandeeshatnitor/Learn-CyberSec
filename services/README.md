# services/

Reserved for standalone services added in later phases (for example an ingestion worker). Nothing lives here yet:
the phase 4 sandbox (`backend/app/sandbox/`, run with `make sandbox-worker`) is a backend module and worker, because it
shares the API's database and rate limits; a separately deployed sandbox service is on the roadmap. See [docs/architecture.md](../docs/architecture.md#adding-services-later).
