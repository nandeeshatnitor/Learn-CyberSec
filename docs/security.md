# Security design

This platform displays vulnerability information gathered from third parties. Design rules:

| Requirement | How Phase 0 handles it |
| --- | --- |
| Validate all input | CVE IDs must match `^CVE-[0-9]{4}-[0-9]{4,19}$` (ASCII digits only: a test caught `\d` accepting other Unicode digits). Search queries are trimmed, stripped of control characters and length-capped; pagination is bounded. Source IDs must be UUIDs. Frontend mirrors these rules. |
| SQL injection | SQLAlchemy bound parameters only; `LIKE` wildcards in user input are escaped so `%`/`_` match literally. |
| Sanitise rendered external content | The UI renders all CVE text through React (escaped); `dangerouslySetInnerHTML` is banned by ESLint (`react/no-danger`). Links are rendered only for absolute `http(s)` URLs (`SafeLink`, `safeHttpUrl`) with `rel="noopener noreferrer nofollow"`; the API also refuses to emit non-http(s) URLs. |
| Don't execute external commands or PoCs | No code path executes, shells out with, or evaluates anything from a source. `app/integrations/` documents this as a requirement for every future integration. |
| Untrusted external content | Treated as data. Provenance is explicit: each record has `data_origin`, each source has `reliability_level` and `retrieved_at`. |
| SSRF (future URL fetching) | No fetching exists yet. Future integrations must go through one shared client with host allow-listing, blocking of private/loopback/link-local ranges (including after redirects and DNS resolution), and size/time limits. |
| Backend credentials never reach the frontend | Backend URL is read server-side only (`server-only` import guard; no `NEXT_PUBLIC_` variables). No API keys exist yet; future ones live in backend env only. |
| No hardcoded secrets | `DATABASE_URL` has no default; compose requires credentials from `.env`; `make setup` generates random passwords; `.env` is git-ignored; Redis requires a password. |
| Error handling | Uniform error envelope; 500s are generic (details only in logs); validation errors do not echo submitted input; health checks do not leak driver errors. |
| HTTP hardening | API: `nosniff`, `X-Frame-Options: DENY`, `CSP: default-src 'none'`, `no-store`; CORS GET-only for configured origins; docs disabled when `ENVIRONMENT=production`. Frontend: CSP, `X-Frame-Options`, `Referrer-Policy`, `Permissions-Policy`. |
| Containers | Non-root users; ports published on `127.0.0.1` only. |

## Known limitations (deliberate for Phase 0)

- The frontend CSP allows `'unsafe-inline'` scripts because Next.js emits inline bootstrap
  scripts; move to a nonce-based CSP when hardening for production.
- No authentication, authorization or rate limiting: nothing to protect yet (read-only public
  data, no users). Add both before exposing publicly or introducing writes.
- Pin container image digests and add dependency/vulnerability scanning in CI before release.
