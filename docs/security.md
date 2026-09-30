# Security design

This platform retrieves vulnerability information from third parties and displays it to students.
**Everything a provider returns is untrusted**: anyone can publish a reference URL, and CNAs write
their own descriptions. Design rules and how they are met:

| Requirement | How it is handled |
| --- | --- |
| Validate all input | CVE IDs must match `^CVE-[0-9]{4}-[0-9]{4,19}$` (ASCII digits only: a test caught `\d` accepting other Unicode digits). Search queries are trimmed, stripped of control characters, length-capped; `page`, `limit`, `severity`, `known_exploited` are bounded/enumerated; source IDs are UUIDs. The frontend mirrors these rules and re-validates query-string values. |
| No injection into provider requests | Provider URLs are built only from configuration plus validated values. User text goes into a query string via proper encoding, never into the path, host or extra parameters (tested with `&apiKey=…`, `#`, CRLF payloads). MITRE requests use only a regex-validated CVE ID in the path. |
| SQL injection | SQLAlchemy bound parameters only; `LIKE` wildcards in user input are escaped so `%`/`_` match literally. |
| SSRF | Providers are fetched only through `ProviderHTTPClient`: **https only** (plain http solely when `ALLOW_INSECURE_PROVIDER_URLS` is set for local fakes, refused in production), **host allow-list derived from configuration**, no userinfo, no non-standard ports, **redirects never followed automatically** (at most 3 manual hops, each re-checked against the allow-list, so a redirect cannot reach an internal address), no data-driven fetching. URLs found inside responses are data: they are stored and displayed, never fetched. |
| Resource exhaustion | Response size cap enforced while streaming (also bounds decompression bombs), connect/read timeouts, JSON depth errors contained, per-field length limits, item-count limits (references, products, versions, catalogue entries), outbound rate budgets, circuit breakers, inbound per-IP rate limit. |
| Untrusted response data | Adapters re-type and bound every field: control and bidi characters removed, NFC-normalised, scores 0–10 only, CVSS vectors and CWE IDs pattern-checked, dates parsed strictly, only English descriptions used (a translation is never presented as the description), only `http(s)` URLs kept. Malformed items are dropped individually. A hostile fixture (`nvd_hostile.json`) is tested at adapter, service and API level. |
| Don't execute or fetch external content | Nothing from a response is executed, evaluated, shelled out, saved to disk, or downloaded. Only JSON is parsed. Proof-of-concept code is never fetched or run. |
| Sanitise rendered external content | The UI renders all provider text through React (escaped); `dangerouslySetInnerHTML` is banned by ESLint (`react/no-danger`). MITRE's HTML `supportingMedia` is ignored in favour of the plain-text value. KEV free text (`notes`) is shown as text, not links. Links only via `SafeLink` (absolute `http(s)`, `rel="noopener noreferrer nofollow"`); the API also refuses to emit non-http(s) URLs. |
| Credentials never reach the frontend | The NVD key is a backend `SecretStr`, sent only in a request header to the configured NVD host (never to MITRE/CISA, never in a URL), never logged, never in a response. Redirects cannot forward it off-host. The frontend has no credentials and reads `BACKEND_URL` server-side only (`server-only` guard). A test greps every response, header and log line for the key. |
| No hardcoded secrets | `DATABASE_URL` has no default; compose requires credentials from `.env`; `make setup` generates random passwords; `.env` is git-ignored; Redis requires a password. |
| Logging | Structured logs; provider calls log provider and status only. HTTP libraries' request logging (which includes full URLs and thus user search terms) is silenced; a test guards this. |
| Error handling | Uniform error envelope; 500s are generic; provider failures surface as fixed messages, never raw upstream text; validation errors do not echo submitted input; health checks do not leak driver errors. |
| HTTP hardening | API: `nosniff`, `X-Frame-Options: DENY`, `CSP: default-src 'none'`, `no-store`; CORS GET-only for configured origins; docs disabled in production. Frontend: CSP, `X-Frame-Options`, `Referrer-Policy`, `Permissions-Policy`. |
| Containers | Non-root users; ports published on `127.0.0.1` only. |

## Phase 2: retrieving and summarising third-party web content

Full design in [research.md](research.md#trust-boundary-external-content--data-only). Summary of the
controls and where they are tested:

| Requirement | How it is handled |
| --- | --- |
| Treat all retrieved content as untrusted; never execute it | Only text is parsed. Nothing is evaluated, rendered, executed, shelled out or downloaded as a file; proof-of-concept scripts are dropped; the UI has no run button and shows commands as inert text. |
| SSRF from the crawler | `PublicWebFetcher`: http(s) on 80/443 only, no userinfo, IP-literal and internal hostnames refused, every resolved address must be public (IPv4-in-IPv6, mixed answers), the connection is pinned to the validated address, redirects are re-validated hop by hop (max 3), a fresh cookie-less client per request. Tested against loopback, link-local/metadata, RFC 1918, CGNAT, IPv6 forms, credentials, odd ports, redirects to internal hosts and DNS answers that turn private. |
| Respect sites | `robots.txt` per RFC 9309, `Crawl-delay`, per-host spacing shared across workers, size/time limits, text content types only, a declared user agent. |
| Resource exhaustion from hostile pages | Byte cap while streaming, deadlines, page shape bounded *before* building a tree (a 20,000-deep nesting took minutes; it is now refused instantly), tag-count cap, passage and source budgets. |
| Prompt injection in web pages | Hidden text/comments isolated and screened; suspicious passages withheld; pages with hidden AI-addressed instructions excluded; Unicode/look-alike normalisation. **This is defence in depth only.** The boundary is structural: fixed system prompt, evidence as escaped JSON data, no tools, schema-constrained output, and re-verification of every claim (below). |
| A model that obeys an injection | `validate_and_ground` removes claims without a valid citation, with details found in no source, unrelated to their citations, or instruction-like; withholds commands that are not verbatim from a source, pipe into interpreters, are destructive or target non-local hosts; drops model-written limitations that address the reader. Tested with a fake model that follows every hostile page, at unit level and end to end through the real queue, database and UI. |
| Unsupported claims shown as fact | Evidence levels and confidence are computed by the platform, never taken from the model; missing sections and an unestablished reproduction are stated, not filled. |
| Credentials | `ANTHROPIC_API_KEY`/`GITHUB_TOKEN` are backend/worker `SecretStr`s: never in responses, logs, the queue (only a run ID travels) or the frontend; the GitHub token is only sent to `api.github.com`; provider error text is never surfaced. |
| Cost and abuse | Per-IP and daily limits on new runs, one active run per CVE, cache reuse, refresh cooldown, stale-run reaper; status polling has its own budget. |
| Browser → backend | Same-origin Next.js route handlers only: cross-site POSTs refused (`Sec-Fetch-Site`/`Origin`), only a sanitised `X-Forwarded-For` forwarded (no cookies or Authorization), a fixed set of statuses and error fields passed through, everything else becomes a generic 503. |
| Scope of advice | Reproduction is framed and enforced as local / intentionally vulnerable / authorized-lab only; third-party targets are removed or withheld. |

## Phase 3: learning sessions and the AI tutor

Full design in [learning.md](learning.md). Controls and where they are tested:

| Requirement | How it is handled |
| --- | --- |
| Answers must not leak early | Accepted answers, hints and solutions are server-side only; the guide endpoint returns the challenge redacted; the session view carries public task text only; hints 1 and 2 are checked in code not to contain an accepted phrase; feedback never echoes the expected answer. Tests assert no private string appears in any pre-reveal response. |
| Tutor must not invent or spoil | Every claim is re-validated against the session's evidence (invented versions/identifiers/URLs/numbers and uncited claims removed). Evidence that would answer the current task is withheld from the model and matching sentences are removed from replies, including answers embedded in identifiers. Tested with a scripted model that tries to leak, invent and obey hostile text. |
| Tutor must stay in scope | Questions about attacking/scanning/testing systems the student does not own, or naming non-local hosts, get a fixed refusal; replies never contain non-local hosts; lab questions carry a reminder; the system prompt limits reproduction to local or authorized labs. |
| Student input is untrusted | Questions and answers are length-capped and sent to the model only as data in a JSON document (no tools); answers are graded by code. |
| Identity without accounts | Random token in an HttpOnly, SameSite=Lax cookie unreadable by scripts; only its SHA-256 is stored; a session is invisible (404) to any other token; the token is never echoed in a response or page. |
| Browser → backend | Same-origin route handlers only, fixed path/method allow-list (no traversal), cross-site POSTs refused, request bodies re-serialised and size-capped, only a sanitised `X-Forwarded-For` and the learner token forwarded, fixed error fields, unexpected statuses become a generic 503. |
| Cost and abuse | Tutor questions limited per session and per client; sessions per client per hour; learning endpoints have their own read budget. |

## Trust and provenance (integrity of what users are told)

* Data is presented as *retrieved from* a named source, never as verified by this platform.
* CNA/ADP scores are never labelled as NVD's analysis; NVD's own (`Primary`) score is the headline
  only when NVD supplied it.
* `known_exploited` is `null` when it could not be determined; "not listed" is worded so it cannot
  be read as "not exploited"; stale and stored copies are labelled with their original retrieval time.
* Sample records (`make seed`) are flagged `data_origin=seed`, shown only when no provider can
  answer, and carry a prominent "not retrieved from a public source" banner.

## Known limitations

* **Not yet verified against the live APIs.** Adapters were written from the documented formats;
  run `make verify-providers`. Field-level surprises there would be normalisation bugs, not
  security ones: unknown shapes are dropped or rejected, not trusted.
* The frontend CSP allows `'unsafe-inline'` scripts because Next.js emits inline bootstrap scripts;
  move to a nonce-based CSP when hardening for production.
* The inbound rate limit keys on the client IP. Behind the web app that means `TRUSTED_PROXIES` plus a
  reverse proxy that overwrites `X-Forwarded-For` (see [providers.md](providers.md#client-ips));
  without both, users share a budget or can spoof their address. There is no authentication.
* DNS rebinding of an allow-listed provider hostname to an internal address is not blocked at the
  socket level; egress filtering at the network layer is recommended in production.
* Pin container image digests and add dependency/vulnerability scanning in CI before release.
* **The research worker's SSRF defence is application-level.** Also restrict the worker's network
  egress (deny private ranges and cloud metadata endpoints) in production.
* **Claim validation is lexical** (see [research.md](research.md#what-validation-cannot-do)): it cannot
  prove a paraphrase is faithful. Every claim shows the excerpt it rests on.
* **Learner identity is an anonymous cookie**, so possession of the token is the only credential: fine for
  a learning exercise, not for anything sensitive; add real accounts before storing more than progress.
* Answer checking is keyword/concept matching (see [learning.md](learning.md#answer-checking)); it can
  misjudge unusual phrasing in both directions.
* Phase 2 has not been run against the live web or the live Anthropic API in development (no network
  or key); it is tested with mock transports and fake models.
