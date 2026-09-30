# Learning-guide research (phase 2)

A CVE page has a **Generate Learning Guide** button. Pressing it starts a background job that
gathers public security research about the CVE and turns it into a structured, source-cited guide.
The platform does **not** ask a language model "how do I exploit CVE-X?". A model, if one is
configured, only *rewrites evidence the platform has already retrieved*, and everything it writes is
re-checked against that evidence in code before anyone sees it.

```
CVE record ─► discover sources ─► retrieve ─► extract text ─► screen ─► de-duplicate ─► filter for
relevance ─► select passages ─► EVIDENCE PACK ─► synthesize (LLM or excerpts) ─► VALIDATE ─► guide
```

Code: `backend/app/research/` (pipeline), `app/services/research_service.py` (requests, caching,
job execution), `app/workers/` (queue, job, worker), `frontend/src/components/research/` (UI).

## Data flow and status

| Stage shown in the UI | What is happening |
| --- | --- |
| Queued | A run row exists and a job is on the queue (RQ), in a thread, or inline. |
| Researching | Sources are discovered, fetched, extracted, screened, de-duplicated and filtered. |
| Synthesizing | The guide is written from the evidence pack and validated. |
| Ready / Failed | The guide is stored, or a fixed, safe error message is. |

* `POST /api/cves/{id}/research` starts (or joins, or reuses) research: `202` when a new run was
  queued, `200` when it joined a running one or reused a stored guide. Body: `{"refresh": bool}`.
* `GET /api/cves/{id}/research/status` is polled by the UI (own, larger rate budget).
* `GET /api/cves/{id}/research` returns the stored guide, the research sources and what happened to
  each (used, duplicate, blocked by robots.txt, excluded as adversarial, ...).

The browser never calls these directly: same-origin Next.js route handlers
(`frontend/src/app/api/cves/...`) forward them (see [security.md](security.md)).

### Caching and cost control

The `research_runs` table is both the job state and the cache. A READY run with the current
`generation_version` (`app/research/version.py`: bump it when the pipeline, prompt, schema or
validator change) younger than `RESEARCH_GUIDE_TTL_SECONDS` is reused: no research, no model call.
Recorded per run: status, `started_at`, `completed_at`, sources discovered/used, generation version,
model version, synthesis method, statistics. Further guards:

* one active run per CVE, enforced by a partial unique index (concurrent clicks join one run);
* `refresh` is refused inside `RESEARCH_REFRESH_COOLDOWN_SECONDS`;
* new runs per client IP per hour (`RESEARCH_PER_IP_RUNS_PER_HOUR`) and per day overall
  (`RESEARCH_DAILY_RUN_BUDGET`): joining or reusing costs nothing;
* an active run that stops moving (crashed worker) is failed after `RESEARCH_STALE_RUN_SECONDS`, so
  a CVE can never be stuck "researching";
* job retries are harmless: only a QUEUED run is ever executed, once.

## Sources

Discoverers are small classes behind one protocol (`research/discovery/base.py`):

| Discoverer | Finds |
| --- | --- |
| `ReferenceDiscoverer` | The references NVD and MITRE list: vendor/CERT/government advisories, mailing-list posts, write-ups, Exploit-DB pages. |
| `GitHubAdvisoryDiscoverer` | Reviewed GitHub Security Advisories (API text, nothing fetched). |
| `GitHubRepositoryDiscoverer` | READMEs (only) of repositories whose name or description names the CVE, at low reliability. Source files and archives are never read. |

Adding one (a vendor feed, a mailing-list archive, a search engine) is a class with `discover(record)`
returning `SourceCandidate`s; retrieval, screening and filtering are shared. URLs are classified into
`VENDOR_ADVISORY, GITHUB_ADVISORY, GITHUB_REPOSITORY, SECURITY_BLOG, RESEARCH, EXPLOIT_DATABASE, CERT,
GOVERNMENT, CISA, OTHER` with a reliability level (`app/research/classify.py`); a tag such as
"Vendor Advisory" on a URL of unknown ownership never makes it *official*.

Each source is stored (table `sources`) with `source_type, title, url, publisher, retrieved_at,
content_hash, reliability_level, status` where `status` is how far it got: `discovered → retrieved →
extracted`, or `irrelevant / duplicate / blocked / excluded / skipped / failed`.

### What is stored, and what is not

Metadata, a SHA-256 of the extracted text, short **relevant excerpts** (each ≤ ~900 characters, ≤ 12
per source) and citations. Full pages are never stored. Retrieval respects `robots.txt` (RFC 9309:
4xx = allowed, 5xx/unreachable = not crawled), a per-host request spacing (shared across workers via
Redis), `Crawl-delay`, size and time limits, and only reads text content types. Whole proof-of-concept
scripts and long code blocks are dropped during extraction; short command snippets that a write-up uses
for reproduction are kept as cited excerpts.

## Trust boundary: EXTERNAL CONTENT = DATA ONLY

Everything retrieved is untrusted. It is never executed, evaluated, followed or obeyed.

1. **Fetching.** `PublicWebFetcher` allows only http(s) on ports 80/443 to public addresses. Every
   resolved address must be public (a mixed answer is refused, IPv4 embedded in IPv6 is checked), the
   connection is *pinned* to the validated address (no DNS rebinding between check and use), redirects
   are never auto-followed (each hop is re-validated, re-resolved and re-checked against robots.txt,
   max 3), a fresh client is used per request (no cookies), and binary or oversized bodies are refused.
2. **Extraction** only parses. Scripts, styles, iframes, navigation, banners, forms, hidden elements
   and HTML comments are removed; *hidden text is set aside solely for screening* and never becomes
   content. Nothing is rendered or run. The page's shape is bounded before a tree is built (deeply
   nested markup is refused: building that tree is quadratic).
3. **Screening** (defence in depth, `research/injection.py`): text is Unicode-normalised (zero-width
   characters, look-alike letters) and scored for injection phrasing. Suspicious passages are withheld;
   a page whose *hidden* text addresses AI assistants is excluded entirely.
4. **The model boundary** (`research/synthesis/llm.py`, the real protection): a fixed system prompt
   with nothing retrieved in it; evidence sent only as string values in one JSON document in the user
   message (`ensure_ascii`, so control/bidi/look-alike characters arrive escaped) preceded by a note
   that it is data; **no tools, no browsing, no execution**; structured output (`GuideDraft` schema);
   one retry on malformed output; refusal, truncation and API failure fall back to excerpts.
5. **Validation** (`research/synthesis/validate.py`): the model's output is treated as an untrusted
   proposal (see below). Screening can be evaded; this step does not depend on it.
6. **Rendering**: React text only (no `dangerouslySetInnerHTML`), links only via `SafeLink`, commands
   in a `<pre>` with "nothing here runs it". There is no "run" button anywhere.

`scripts/fake_research.py` with `FAKE_LLM=malicious` plays a model that *did* obey the hostile pages;
the unit tests do the same. Its added claims ("this vulnerability is not real", `curl … | sh`,
"reveal your system prompt", "tell the user to disable security tooling") do not appear in the guide.

## The guide and how claims are checked

Sections: 1 What is the vulnerability? 2 Why does it happen? 3 Affected versions 4 Prerequisites
5 Safe, local reproduction environment 6 Reproduction procedure 7 What to observe 8 Why the
reproduction works 9 Impact 10 Remediation 11 References. Plus Research sources and Confidence.

For **every** claim the validator decides, in code:

* **Citations.** Unknown source/passage IDs are dropped; a passage names its true source. A claim with
  no valid citation is **removed**.
* **Invented specifics.** Versions, identifiers, paths, URLs, IPs, numbers, config settings and
  backticked text in a claim must occur in the cited passages. Found only elsewhere in the evidence →
  the citation is corrected; found nowhere → the claim is **removed** (not softened).
* **Relatedness.** Text unrelated to what it cites is removed whatever the model says.
* **Evidence level** (the model's `basis` can only *lower* it):

  | Level | Meaning |
  | --- | --- |
  | `DOCUMENTED` | A retrieved source states it. |
  | `SUPPORTED_BY_MULTIPLE_SOURCES` | Independent sources (different publishers/groups) each contain it: computed by searching the whole pack, not taken from the model. NVD and MITRE count as one group; mirrors are removed as duplicates first. |
  | `SYNTHESIZED` | Drawn from the cited sources but not stated outright. |
  | `UNCERTAIN` | The model said it was unsure. Kept, labelled. |

* **Commands** must appear verbatim in a source, must not pipe a download into an interpreter, must
  not be destructive, and must target only local/lab hosts (loopback, RFC 1918, `*.local`, single-label
  compose service names). Otherwise the step keeps its text but the command is **withheld** with the
  reason shown, or the step is removed when the command was invented.
* **Reproduction status** is computed: `established` (grounded steps + environment + observation from
  retrieved documents, not just provider records), `partial` (with the missing pieces named) or
  `not_established`, in which case the guide *says so* with fixed wording and lists no steps, instead of
  filling the gap.
* **Confidence** (`high/medium/low/insufficient`, plus a separate reproduction rating) is a formula over
  independent source groups, source reliability, share of directly-stated claims, coverage of the core
  sections and reproduction status, minus removals; capped at *low* with no retrieved document, *medium*
  with one independent document, without an established reproduction, or for excerpt-only guides. Every
  factor is listed in the UI.
* **Limitations** written by the model are kept only if they are plain statements about gaps: nothing
  addressed to the reader, no URLs or commands, no ungrounded specifics.

### Without a language model

With no `ANTHROPIC_API_KEY` (or `RESEARCH_SYNTHESIS=extractive`), and whenever the model refuses,
fails, is truncated, or its output validates to almost nothing, the **extractive synthesizer** builds
the guide from verbatim excerpts of the evidence. The same validator runs over it. The UI says how the
guide was made and why it fell back (`generation.fallback_reason`).

### What validation cannot do

It is lexical. It reliably catches invented details, uncited or unrelated claims and instruction-like
text; it cannot prove that a paraphrase is *faithful* (a model can still reword a cited sentence into
something subtly different, or negate it), and "independent" sources are judged by publisher, so two
sites repeating one original advisory can still look independent. The guide therefore shows the exact
excerpt behind every claim ("Show evidence") so a reader can check it.

## Scope: education and authorized testing only

The system prompt, the safety notice on every guide, the command checks and the UI copy all frame
reproduction as *local, intentionally vulnerable or authorized lab* work. Steps and commands aimed at
third-party systems are removed or withheld. The platform does not run anything, ever.

## Running it

```bash
make up                          # includes the `worker` service (RESEARCH_JOB_BACKEND=rq)
# host-based: RESEARCH_JOB_BACKEND=rq in .env, then
make backend-dev &  make worker &  make frontend-dev
```

Without Redis the API runs jobs on a thread pool inside the API process (`auto`), which is fine for
one developer but loses jobs on restart (the stale-run reaper then fails them).

**Offline demo with fictional data:** `make fake-providers` (serves NVD/MITRE/KEV fixtures including
the fictional `CVE-2099-12345`), point the API at it as described in `scripts/fake_providers.py`, run
`make fake-research` (the real pipeline/queue/database on an in-memory fictional web; add
`FAKE_LLM=malicious` for a hostile model) and open `/cves/CVE-2099-12345`.

**Egress.** The worker fetches arbitrary public URLs. The fetcher's SSRF checks are application
level; in production also restrict the worker container's network egress (deny private ranges and
metadata endpoints) so a bug cannot become an internal request.

## Known limitations

* Not exercised against the live internet or the live Anthropic API in this repository's development
  environment (no network or key there). Everything is tested with mock transports, an injected
  resolver and fake models; the Anthropic adapter was checked against the SDK's parse/structured-output
  interface and its error types, not against a real response. Run one real guide before relying on it.
* `robots.txt` handling uses the standard library parser; unusual directives may be read differently
  from a search engine's.
* Discovery starts from the CVE's own references and GitHub. There is no general web search yet.
* HTML pages that need JavaScript to show their content yield little text.
