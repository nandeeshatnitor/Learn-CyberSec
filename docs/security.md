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
