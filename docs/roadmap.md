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
| 4 | Sandboxed labs: lab templates, Docker runtime, per-lab isolated network with a fail-closed isolation proof, instance lifecycle + reset + cleanup worker, browser terminal gateway, behaviour-based verifier, progress in learning sessions, demo lab (see [sandbox.md](sandbox.md)) | **done** (Docker required; tested on real Docker) |
| 5 | Candidate labs: controlled pipeline from researched CVEs to candidate lab definitions (vetted blueprints, offline build, static + runtime security validation, ten automated checks), reviewer interface, immutable versioned publication (see [labgen.md](labgen.md)) | **done** (Docker required; tested on real Docker and in a real browser) |
| 4b | More labs (real CVE reproductions built by the team), multi-container labs, egress allow-lists, VM/gVisor-backed runtimes, a separately deployed sandbox service | planned |

Not implemented: user accounts, labs for arbitrary CVEs (phase 5 builds candidates for the vulnerability classes it has blueprints for, and a person approves each one). Reproduction *guidance* is phase 2; the platform executes
nothing from retrieved content. The only thing it ever runs is a repository-defined lab, in a sealed container
(phase 4, [sandbox.md](sandbox.md)).
