# Roadmap

| Phase | Scope | Status |
| --- | --- | --- |
| 0 | Foundation: monorepo, API skeleton, schema/migrations, UI shell, Docker, tests | **done** |
| 1 | Authoritative data: NVD, MITRE/CVE Program and CISA KEV providers behind a `CVEProvider` abstraction; normalised schema; Redis caching with stale fallback; rate limiting; search (ID, partial ID, keyword, product, vendor); attributed UI | **done** (adapters still to be checked against the live APIs: `make verify-providers`) |
| 1b | More sources: GitHub Security Advisories, CERT/CC, vendor advisories, Exploit-DB metadata (adapter-only work, see [providers.md](providers.md#adding-a-provider)); CPE-based product search; background refresh jobs | planned |
| 2 | Learning guides: public-source research pipeline, source-cited structured guides with evidence levels, validation of every claim, background jobs, caching (see [research.md](research.md)) | **done** (not yet exercised against the live web or the live Anthropic API) |
| 2b | More discovery: general web search, vendor feeds, mailing-list archives; nonce-based CSP; worker egress policy | planned |
| 3 | Interactive learning: sessions, progressive hints, answer checking, AI tutor, scoring, `/learn/[cveId]` (see [learning.md](learning.md)) | **done** (anonymous learners; not exercised against the live Anthropic API) |
| 3b | Accounts and cross-device progress (`User`), richer answer grading | planned |
| 4 | Isolated sandbox labs (`LabDefinition`, `LabAttempt`) in `services/` | planned |

Not implemented: user accounts, sandbox labs. Reproduction *guidance* is phase 2; nothing
is ever executed by the platform.
