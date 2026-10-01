# Candidate labs and review (phase 5)

Turns documented CVE research into **candidate** lab definitions, tests them automatically, and puts them in front
of a person. Only a reviewer's approval publishes one, as an immutable version.

```
CVE → research guide → affected-version identification → safe objective → candidate specification
    → build (offline) → automated validation (10 checks) → security validation → human approval → publish
```

**The pipeline cannot publish.** Its jobs end in `awaiting_review` (or a failure). The only code path that creates a
published lab is `LabPublisher.approve`, reachable only from an authenticated reviewer's request, and it re-checks every
gate itself. No lab is ever deployed automatically, and nothing is ever deployed to production by this system: a
published lab is a row and a locally tagged image that the sandbox (phase 4) may start for a student.

## How a candidate is made

* **From vetted blueprints, not generated code.** Two blueprints exist (`expression_injection`: a header value is
  evaluated; `path_traversal`). A blueprint is repository code that renders a *minimal, intentionally vulnerable toy
  application*, its lab definition and its validation plan from a handful of parameters. The vendor's code is never
  copied, downloaded or run; documented Docker images and commands are recorded in the specification
  (`documented_artifacts`) and shown to the reviewer, and never used.
* **Parameters come from the guide**, extracted deterministically (`labgen/facts.py`): product, the affected ranges
  ("4.0.0 through 4.2.3", "before 4.2.4", NVD ranges), the fixed version, the request header/endpoint, the probe and its
  result. The *vulnerable version* the lab pins is the highest version the sources state as affected (else a documented
  test-image tag, else the start of the range) and is rejected if it is not below the fixed version. A sentence that
  says a version is *not* affected is never read as affected. If the sources do not document enough, **nothing is
  invented**: the result is a specification-only candidate that says why.
* **Every parameter is re-validated** (`labgen/sanitize.py`) and embedded only as a Python `repr` literal, so text from
  a source cannot become code or a command. Guide text is data, never instructions.
* **An LLM may only polish wording** (the safe objective and summary), when `LABGEN_USE_LLM` and an API key allow it. Its
  output is a two-field schema, length- and content-checked (no markup, commands, URLs, unknown versions); on any
  problem the deterministic wording is used and the reason is recorded. It never writes code, files or the definition.
* **The candidate specification** (`labgen/spec.py`) holds: CVE, affected software, vulnerable version (with the basis
  and evidence), safe lab objective, prerequisites, learning tasks, expected behaviour (vulnerable / after the fix),
  verification method, remediation task and source references, plus the blueprint and parameters, caveats and the
  generation record (method, model, fallback reason, reviewer overrides).

## Automated gates

1. **Static security scan** (`labgen/scan.py`), an allow-list that treats the candidate as hostile: a small fixed file
   set; a Dockerfile with one allow-listed `FROM`, no `ADD`/URLs, only allow-listed `RUN`s and `USER 10001:10001`;
   Python limited to a per-module vocabulary (no `eval`/`exec`/`getattr`/dunders/`.format`, no writes, no URLs,
   `os` only for `path`/`sep`, no reaching a banned module through an allowed one); shell without network tools or
   command substitution; no embedded credentials; a lab definition that is non-root, no-egress, within conservative
   caps (1 CPU, 256 MB, 128 processes, 32 MB scratch, ≤ 60 min) and uses a `cvelearn-candidate/` image.
2. **Offline build** (`labgen/build.py`): the files are written to a private temp directory and built with
   `--network none --pull=false`; the image is tagged `cvelearn-candidate/<family>:<context hash>` and labelled with the
   hash, so what is approved is provably what was scanned.
3. **Validation harness** (`labgen/validate.py`) runs the candidate in the *real* sandbox (isolation proof, container
   audit, cleanup manager) under a throwaway user and records the ten required checks: build succeeds · application
   starts · a student can connect · verification works · expected vulnerable behaviour exists · remediation removes it ·
   no unauthorized network access · resource limits work (memory hog, fork bomb, scratch fill) · cleanup works
   (in-container kill switch and the expiry worker) · reset works. It also inspects the running container (unprivileged
   user, no capabilities, read-only root, no Docker socket, no host paths, no egress).

A candidate that fails any of these stays out of review (`validation_failed`, `build_failed`, …) and shows why.

## Human approval

Admin interface: `/admin/labs` (**Candidate Labs**: CVE, Status, Sources, Build Status, Security Validation, Reviewer;
a generate-candidate form; published versions) and `/admin/labs/{id}` (the full specification, sources, the validation
and security reports, the generated files and build log, review history, and the decision panel). Actions:

* **Approve**: enabled only when every gate passed; two-step; re-checks the stage results, all ten checks, the security
  report, the files' hash against the validated hash, and the image's label and id against the stored values.
* **Reject** / **Request Changes**: a reason is required and recorded. After *Request Changes* a reviewer can generate a
  **new revision** with corrections (product, versions, header, endpoint, parameter, probe), each validated per field.
* Re-run build and tests; release a stalled job; **Stop offering** a published version (with a reason).

Approval is an atomic `awaiting_review → approved` update: of two reviewers, one wins. A revision that is not the latest
of its lab cannot be approved. If preparing the image or saving the version fails, the candidate returns to review.

**Reviewer access.** `X-Admin-Token` (the web app keeps it in an HttpOnly, SameSite=Strict cookie after sign-in and
proxies the API; page script never sees it). Only SHA-256 hashes are configured: `ADMIN_REVIEWERS=alice=<hash>` (make a
token with `make admin-token NAME=alice`). Comparison is constant-time; wrong tokens are rate limited per client; the API
answers 503 unless `LABGEN_ENABLED` is on and at least one reviewer is configured. Admin pages are `noindex`.

## Versioning and immutability

An approved candidate becomes `lab_versions` row `<family>-v<N>` (e.g. `cve-2099-12345-v1`) with the frozen spec, files,
a content hash, and the image retagged `cvelearn-lab/<family>:vN`. **A published version never changes**: the ORM refuses
edits to its content columns, a PostgreSQL trigger refuses them even to direct SQL, and the content hash is re-checked
every time a version is loaded (a tampered row is not served). A change is a *new candidate revision* and, once approved,
the next version; the older one becomes `superseded` (a reviewer can also withdraw one).

Existing learning records keep pointing at the version used: a lab instance and its verified objectives store the exact
`lab_id` (`…-v1`). Only the **offered** version (status `published`) can be started; older versions still resolve, and a
learning session shows them as "an earlier version" with the learner's progress.

## Students

`LayeredCatalog` serves the repository's labs plus the database's *published* versions. Candidates, rejected, changes-
requested and unreviewed labs are not in the catalogue and cannot be started (their image prefix is also not allowed for
students, which a re-check on every load enforces). Students never see images, commands or runtime details.

## Running it

```
LABGEN_ENABLED=true  SANDBOX_ENABLED=true  ADMIN_REVIEWERS=alice=<sha256>
make labgen-worker        # needs Redis and a Docker daemon it may drive (builds and tests candidates)
make sandbox-worker       # cleanup of lab instances, as in phase 4
```

The API process needs no Docker for this phase (it creates candidates, queues jobs and records decisions); the worker
does. Base images must already be present locally (`LABGEN_BASE_IMAGES`, default `python:3.12-alpine`): builds are offline.

## Tests

`backend/tests/labgen/`: facts and version extraction; generation (spec fields, hostile overrides, LLM wording
validation and fallback); the static scan with malicious variants; pipeline states; publication gates, atomic approval,
versioning, withdrawal and immutability (including the PostgreSQL trigger, `TEST_DATABASE_URL`); the student catalogue;
the reviewer API (auth, rate limit, state errors, the job having no way to publish). The pipeline, approval, a student
exploiting the published lab, and v1→v2 run on **real Docker** with `make test-labgen-docker`. Frontend: proxy allow-list,
cookie flags and same-origin checks, sign-in, the candidate table, the review page and every action.

## Known limitations

* Two blueprints only. Anything else produces a specification-only candidate for a person to write by hand.
* Fact extraction is lexical (regex over cited claims): the reviewer sees the evidence behind each fact and can correct
  it, but must read it.
* A candidate is a *toy reproduction* of a documented weakness, not the vendor's software; it teaches the class of bug.
* Approval is a human judgement over generated files: read them. The gates reduce the chance of a mistake; they do not
  replace the reviewer.
* The labgen worker needs Docker with the same host requirements as the sandbox ([sandbox.md](sandbox.md#known-limitations)).
* Reviewer tokens are shared secrets with no expiry; rotate by changing `ADMIN_REVIEWERS`. There is no per-reviewer audit
  beyond the review history.
