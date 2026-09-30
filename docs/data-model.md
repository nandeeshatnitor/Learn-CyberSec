# Data model

## Implemented in Phase 0 (migration `0001`)

**`cves`**: `id` (UUID), `cve_id` (unique), `description`, `published_at`, `modified_at`,
`cvss_score`, `cvss_vector`, `severity`, `cwes` (JSONB list), `affected_products` (JSONB list),
`data_origin`, `created_at`, `updated_at`.

- `data_origin` is an addition to the requested fields: `seed` (hand-entered fixture, not
  retrieved from an authority) or `nvd` (reserved). It lets the UI and API state provenance
  instead of presenting fixtures as retrieved facts.
- `references` is a relationship (`cve_references`), not a column.

**`sources`**: `id`, `source_type` (nvd, mitre, vendor_advisory, github_advisory, cert, cisa,
exploit_db, research_blog, other), `title`, `url` (unique, http(s) only in API output),
`publisher`, `retrieved_at`, `reliability_level` (official, high, medium, low, unverified).
`retrieved_at IS NULL` means "linked but never fetched".

**`cve_references`**: `cve_id` → `cves`, `source_id` → `sources`, `tags`; unique per pair.
Deleting a CVE cascades to its references; a source that is still referenced cannot be deleted.

Enums are stored as `VARCHAR` (not native PG enums) so adding a value is not an `ALTER TYPE`
migration.

## Placeholders (documented only; no tables yet)

| Entity | Intended purpose | Phase |
| --- | --- | --- |
| `User` | Accounts and roles | with progress tracking |
| `SearchQuery` | Search history / popularity, retrieval triggers | retrieval |
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
