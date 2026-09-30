"""External data-source integrations (NVD, MITRE, GitHub advisories, CISA, ...).

Intentionally empty in Phase 0. Every integration added here must:
  * treat all fetched content as untrusted input,
  * fetch only through a shared SSRF-safe HTTP client (allow-listed hosts, no redirects to
    private/link-local/loopback ranges, size and time limits),
  * never execute, or pass to a shell/interpreter, anything received from a source.
"""
