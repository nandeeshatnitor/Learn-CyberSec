# Roadmap

| Phase | Scope | Status |
| --- | --- | --- |
| 0 | Foundation: monorepo, API skeleton, schema/migrations, UI shell, Docker, tests | **done** |
| 1 | Authoritative data: NVD, MITRE/CVE Program and CISA KEV providers behind a `CVEProvider` abstraction; normalised schema; Redis caching with stale fallback; rate limiting; search (ID, partial ID, keyword, product, vendor); attributed UI | **done** (adapters still to be checked against the live APIs: `make verify-providers`) |
| 1b | More sources: GitHub Security Advisories, CERT/CC, vendor advisories, Exploit-DB metadata (adapter-only work, see [providers.md](providers.md#adding-a-provider)); CPE-based product search; background refresh jobs | planned |
| 2 | Analysis: structured, source-cited CVE analysis and learning guides (`CVEAnalysis`, `LearningGuide`) | planned |
| 3 | Users & progress (`User`, `UserProgress`), hints (`Hint`) | planned |
| 4 | Isolated sandbox labs (`LabDefinition`, `LabAttempt`) in `services/` | planned |

Nothing beyond Phase 1 is implemented: no LLM-generated content, reproduction guides, hints or labs.
