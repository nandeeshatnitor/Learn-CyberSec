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

**`sources`**: `id`, `source_type` (nvd, mitre, vendor_advisory, github_advisory, cert, cisa,
exploit_db, research_blog, other), `title`, `url` (unique, http(s) only in API output),
`publisher`, `retrieved_at`, `reliability_level` (official, high, medium, low, unverified).
Provider record pages are stored as `official` sources with the real `retrieved_at`; **reference
URLs are stored as `unverified` link-only sources with `retrieved_at IS NULL`** (never fetched).
`source_type` of a reference is inferred from its host/tags (for example github.com advisories,
CERT, Exploit-DB, "Vendor Advisory").

**`cve_references`**: `cve_id` → `cves`, `source_id` → `sources`, `tags`; unique per pair.
Deleting a CVE cascades to its references; a source that is still referenced cannot be deleted.

Enums are stored as `VARCHAR` (not native PG enums) so adding a value is not an `ALTER TYPE`
migration.

## Placeholders (documented only; no tables yet)

| Entity | Intended purpose | Phase |
| --- | --- | --- |
| `User` | Accounts and roles | with progress tracking |
| `SearchQuery` | Search history / popularity | later |
| `CVEAnalysis` | Structured, source-cited extraction from advisories | analysis |
| `LearningGuide` | Generated lesson sections linked to sources | analysis |
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
