#!/usr/bin/env python3
"""Check the provider adapters against the REAL NVD, MITRE and CISA KEV services.

The automated tests use hand-written fixtures, so this is the one place the adapters meet the
live APIs. Run it on a machine with internet access:

    make verify-providers                     # checks CVE-2021-44228
    make verify-providers ARGS="CVE-2014-0160 --record tests/recorded"

It makes a handful of requests (NVD's public limit is 5 per 30 seconds without an API key),
prints what each provider returned, and exits non-zero if an adapter could not parse a real
response. With --record DIR the raw JSON responses are saved there, so you can promote them to
test fixtures. Nothing from the responses is executed or opened.
"""

import argparse
import json
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "backend"))
os.environ.setdefault("DATABASE_URL", "sqlite://")  # settings need it; this script never uses the DB

from app.cache import InMemoryCache, InMemorySlidingWindowLimiter, ResultCache  # noqa: E402
from app.config import get_settings  # noqa: E402
from app.integrations import http_client  # noqa: E402
from app.integrations.base import SearchQuery  # noqa: E402
from app.integrations.errors import ProviderError  # noqa: E402
from app.integrations.registry import build_registry  # noqa: E402
from app.services.cve_merge import merge_provider_records  # noqa: E402


def install_recorder(directory: Path) -> None:
    directory.mkdir(parents=True, exist_ok=True)
    original = http_client.ProviderHTTPClient.get_json
    counter: dict[str, int] = {}

    def recording(self, url, *, headers=None):  # type: ignore[no-untyped-def]
        payload = original(self, url, headers=headers)
        counter[self._provider] = counter.get(self._provider, 0) + 1  # noqa: SLF001
        name = f"{self._provider}_{counter[self._provider]}.json"  # noqa: SLF001
        (directory / name).write_text(json.dumps(payload, indent=2))
        print(f"    recorded {directory / name}")
        return payload

    http_client.ProviderHTTPClient.get_json = recording  # type: ignore[method-assign]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawTextHelpFormatter)
    parser.add_argument("cve_id", nargs="?", default="CVE-2021-44228")
    parser.add_argument("--keyword", default="log4j", help="keyword for the NVD search check")
    parser.add_argument("--record", type=Path, help="save raw JSON responses into this directory")
    args = parser.parse_args()

    if args.record:
        install_recorder(args.record)

    settings = get_settings()
    registry = build_registry(
        settings,
        cache=ResultCache(InMemoryCache()),
        limiter=InMemorySlidingWindowLimiter(),
    )
    failures = 0
    parts = []
    print(f"NVD API key configured: {'yes' if settings.nvd_api_key else 'no (public rate limit)'}\n")

    for gateway in registry.gateways:
        print(f"[{gateway.provider.name}] get_cve({args.cve_id})")
        try:
            record, _ = gateway.get_cve(args.cve_id)
        except ProviderError as exc:
            failures += 1
            print(f"    FAILED: {type(exc).__name__}: {exc.detail}")
            continue
        if record is None:
            print("    no record (not found at this provider)")
            continue
        parts.append(record)
        print(f"    description : {(record.description or '-')[:90]}")
        print(f"    cvss metrics: {[(m.version, m.score) for m in record.cvss_metrics]}")
        print(f"    cwes        : {[c.id for c in record.cwes]}")
        print(f"    products    : {len(record.affected_products)}   references: {len(record.references)}")
        print(f"    kev         : {record.kev.date_added if record.kev else '-'}")

    if any(g.id == "nvd" for g in registry.gateways):
        nvd = next(g for g in registry.gateways if g.id == "nvd")
        print(f"\n[NVD] search('{args.keyword}')")
        try:
            result, _ = nvd.search(SearchQuery(text=args.keyword, limit=5))
            print(f"    total={result.total} page={[r.cve_id for r in result.items]}")
        except ProviderError as exc:
            failures += 1
            print(f"    FAILED: {type(exc).__name__}: {exc.detail}")

    print("\nHealth checks")
    for health in registry.health():
        print(f"    {health.name:22} {health.status:12} {health.detail}")
        failures += health.status == "unavailable"

    if parts:
        merged = merge_provider_records(
            parts,
            priority=registry.priorities(),
            exploitation_checked_by=next((p.provider for p in parts if p.kev and p.kev.source == "cisa_kev"), None),
        )
        print(f"\nMerged: severity={merged.severity} cvss={merged.cvss.score if merged.cvss else None} "
              f"known_exploited={merged.known_exploited} sources={[s.provider for s in merged.sources]}")
    registry.close()
    print("\nOK" if not failures else f"\n{failures} problem(s): the adapters may need adjusting to the real API.")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
