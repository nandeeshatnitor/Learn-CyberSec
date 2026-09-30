# Test fixtures

Hand-written from the **documented response formats** of NVD CVE API 2.0, CVE Services (CVE
Record Format 5) and the CISA KEV JSON feed. They are **not recordings of live responses**
(the development sandbox that produced them could not reach those services), and their values
are illustrative. Run `make verify-providers` on a machine with network access to check the
adapters against the real APIs, and to record fresh fixtures if you want them.

`nvd_hostile.json` is intentionally malicious: script tags, `javascript:` URLs, control and
bidi characters, out-of-range scores, oversized fields. Adapters must neutralise all of it.
