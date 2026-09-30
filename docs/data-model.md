# Data model

## Normalised record (API / cache contract)

`backend/app/schemas/cve.py` defines the provider-independent `CVERecord`: description, status,
dates, `cvss` (headline) + `cvss_metrics` (all), `cwes`, `affected_products` (with `VersionRange`s),
`references`, `known_exploited` (tri-state) + `kev`, `sources` (attribution with retrieval time),
`field_sources` (which provider supplied each field), `data_origin`. Provider IDs are plain strings,
so new providers need no schema change. Adapters produce partial `ProviderCVE` records which
`services/cve_merge.py` combines.

## Stored in PostgreSQL

Stored copies serve as (a) the last-resort fallback when every provider is unavailable and no cache
entry exists, (b) the corpus for partial-ID and outage-time search, and (c) the anchor for later
phases. Redis, not PostgreSQL, is the primary cache.

**`cves`**: `id` (UUID), `cve_id` (unique), `description`, `published_at`, `modified_at`,
`cvss_score`, `cvss_vector`, `severity`, `cwes` (JSONB list of IDs), `affected_products` (JSONB
summaries, searchable), `data_origin`, `created_at`, `updated_at`; added in migration `0002`:
`vuln_status`, `known_exploited` (NULL = unknown), `retrieved_at`, and `record` (JSONB: the full
normalised `CVERecord`, the source of truth for a stored copy; the columns above are denormalised
for querying).

- `data_origin`: `seed` (hand-entered fixture, not retrieved) or `providers`.
- A stored record is only replaced by data from at least the same set of providers and newer, so
  a request served while NVD was down never overwrites a fuller copy.

**`sources`**: `id`, `source_type` (nvd, mitre, cisa, vendor_advisory, github_advisory,
github_repository, security_blog, research, exploit_database, cert, government, other), `title`,
`url` (unique, http(s) only in API output), `publisher`, `retrieved_at`, `reliability_level`
(official, high, medium, low, unverified); added in migration `0003`: `status` (discovered,
retrieved, extracted, irrelevant, duplicate, blocked, excluded, skipped, failed: how far the source
got the last time it was researched) and `content_hash` (SHA-256 of the normalised extracted text;
the page itself is never stored).
Provider record pages are stored as `official` sources with the real `retrieved_at`; **reference
URLs are stored as `unverified` link-only sources with `retrieved_at IS NULL`** (never fetched).
`source_type` of a reference is inferred from its host/tags (for example github.com advisories,
CERT, Exploit-DB, "Vendor Advisory").

**`cve_references`**: `cve_id` → `cves`, `source_id` → `sources`, `tags`; unique per pair.
Deleting a CVE cascades to its references; a source that is still referenced cannot be deleted.

Enums are stored as `VARCHAR` (not native PG enums) so adding a value is not an `ALTER TYPE`
migration.

**`research_runs`** (migration `0003`): one attempt to build a guide, and the cache for it. `cve_id`,
`status` (queued, researching, synthesizing, ready, failed), `stage_detail`, `started_at`,
`completed_at`, `generation_version`, `model_version`, `synthesis_method` (llm | extractive),
`sources_discovered`, `source_count`, `guide` (JSONB: the validated `LearningGuide`), `stats`,
`error_code`/`error_message` (fixed, safe text only). A partial unique index allows **one active run
per CVE**.

**`research_run_sources`**: what one run did with each source: `sid` ("S3", the ID citations use;
"X…" for sources that are not citable), `kind`, `outcome`/`outcome_detail` (e.g. `blocked` /
`robots_disallowed`), `independent_group`, `relevance`, and `passages` (the short excerpts kept:
never whole pages).

## Placeholders (documented only; no tables yet)

| Entity | Intended purpose | Phase |
| --- | --- | --- |
| `User` | Accounts and roles | with progress tracking |
| `SearchQuery` | Search history / popularity | later |
| `LearningGuide` | *Implemented* as the validated JSON in `research_runs.guide` (schema: `app/research/synthesis/schema.py`); a dedicated table is only needed if guides must be queried by field | phase 2 |
| `Hint` | Progressive hints per guide/lab step | hints |
| `UserProgress` | Per-user completion state | hints/labs |
| `LabDefinition` | Declarative sandbox environments | sandbox |
| `LabAttempt` | A user's run of a lab | sandbox |

## Migrations

```bash
cd backend
alembic revision --autogenerate -m "describe change"   # review the generated file!
alembic upgrade head
alembic check                                          # fails if models and migrations diverge
```

The test suite runs an upgrade/downgrade round trip and `alembic check` on every run.
