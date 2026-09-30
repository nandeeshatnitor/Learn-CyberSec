"""Caching, stale fallback, rate limiting and circuit breaking, through the real adapters."""

import threading

import pytest

from app.integrations.base import SearchQuery
from app.integrations.errors import (
    ProviderBadResponse,
    ProviderCircuitOpen,
    ProviderRateLimited,
    ProviderUnavailable,
)

CVE = "CVE-2021-44228"


def gateway(registry, provider_id: str):
    return next(g for g in registry.gateways if g.id == provider_id)


class TestCaching:
    def test_repeated_lookups_do_not_call_the_provider_again(self, registry, upstream) -> None:
        nvd = gateway(registry, "nvd")
        first, first_fresh = nvd.get_cve(CVE)
        second, second_fresh = nvd.get_cve(CVE)
        assert upstream.count("nvd") == 1
        assert (first_fresh.origin, second_fresh.origin) == ("live", "cache")
        assert first == second

    def test_each_provider_is_cached_independently(self, registry, upstream) -> None:
        for provider in ("nvd", "mitre"):
            gateway(registry, provider).get_cve(CVE)
            gateway(registry, provider).get_cve(CVE)
        assert (upstream.count("nvd"), upstream.count("mitre")) == (1, 1)

    def test_entries_expire_after_the_configured_ttl(self, registry, upstream, clock) -> None:
        nvd = gateway(registry, "nvd")
        nvd.get_cve(CVE)
        clock.advance(3599)
        nvd.get_cve(CVE)
        assert upstream.count("nvd") == 1
        clock.advance(2)
        nvd.get_cve(CVE)
        assert upstream.count("nvd") == 2

    def test_ttl_is_configurable(self, make_registry, upstream, clock) -> None:
        nvd = gateway(make_registry(cache_ttl_seconds=10), "nvd")
        nvd.get_cve(CVE)
        clock.advance(11)
        nvd.get_cve(CVE)
        assert upstream.count("nvd") == 2

    def test_unknown_cves_are_cached_briefly_so_typos_do_not_hammer_the_provider(
        self, registry, upstream, clock
    ) -> None:
        nvd = gateway(registry, "nvd")
        assert nvd.get_cve("CVE-1999-0001")[0] is None
        assert nvd.get_cve("CVE-1999-0001")[0] is None
        assert upstream.count("nvd") == 1
        clock.advance(301)  # negative TTL is 300s in the test settings
        nvd.get_cve("CVE-1999-0001")
        assert upstream.count("nvd") == 2

    def test_a_cached_record_carries_its_original_retrieval_time(self, registry, clock) -> None:
        nvd = gateway(registry, "nvd")
        retrieved = nvd.get_cve(CVE)[0].attribution.retrieved_at
        clock.advance(1800)
        again = nvd.get_cve(CVE)[0].attribution
        assert again.retrieved_at == retrieved  # not "now": readers must see how old the data is
        assert again.stale is False

    def test_corrupt_cached_payload_is_discarded_and_refetched(
        self, registry, upstream, result_cache
    ) -> None:
        nvd = gateway(registry, "nvd")
        nvd.get_cve(CVE)
        result_cache.store(
            f"cve:v1:nvd:{CVE}",
            {"cve_id": CVE, "attribution": "garbage"},
            fresh_ttl=3600,
            stale_ttl=3600,
        )
        record, freshness = nvd.get_cve(CVE)
        assert record.cve_id == CVE and freshness.origin == "live"
        assert upstream.count("nvd") == 2

    def test_concurrent_requests_for_the_same_cve_share_one_upstream_call(
        self, registry, upstream
    ) -> None:
        nvd = gateway(registry, "nvd")
        results: list[object] = []
        barrier = threading.Barrier(8)

        def worker() -> None:
            barrier.wait()
            results.append(nvd.get_cve(CVE)[0])

        threads = [threading.Thread(target=worker) for _ in range(8)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        assert len(results) == 8 and all(r is not None for r in results)
        assert upstream.count("nvd") == 1


class TestStaleFallback:
    def test_expired_copy_is_served_when_the_provider_fails(
        self, registry, upstream, clock
    ) -> None:
        nvd = gateway(registry, "nvd")
        original = nvd.get_cve(CVE)[0].attribution.retrieved_at
        clock.advance(3601)
        upstream.modes["nvd"] = "500"
        record, freshness = nvd.get_cve(CVE)
        assert freshness.origin == "stale"
        assert record.attribution.stale is True
        assert record.attribution.retrieved_at == original
        assert record.description.startswith("Apache Log4j2")

    @pytest.mark.parametrize(
        "mode", ["500", "timeout", "429", "403", "html", "bad_json", "huge", "wrong_shape"]
    )
    def test_every_failure_mode_falls_back_to_stale(self, registry, upstream, clock, mode) -> None:
        nvd = gateway(registry, "nvd")
        nvd.get_cve(CVE)
        clock.advance(3601)
        upstream.modes["nvd"] = mode
        assert nvd.get_cve(CVE)[1].origin == "stale"

    def test_without_a_cached_copy_the_error_propagates(self, registry, upstream) -> None:
        upstream.modes["nvd"] = "500"
        with pytest.raises(ProviderUnavailable):
            gateway(registry, "nvd").get_cve(CVE)

    def test_stale_copies_are_dropped_after_the_stale_window(
        self, registry, upstream, clock
    ) -> None:
        nvd = gateway(registry, "nvd")
        nvd.get_cve(CVE)
        clock.advance(3600 + 86_400 + 1)
        upstream.modes["nvd"] = "500"
        with pytest.raises(ProviderUnavailable):
            nvd.get_cve(CVE)

    def test_recovery_replaces_the_stale_copy(self, registry, upstream, clock) -> None:
        nvd = gateway(registry, "nvd")
        nvd.get_cve(CVE)
        clock.advance(3601)
        upstream.modes["nvd"] = "500"
        assert nvd.get_cve(CVE)[1].origin == "stale"
        clock.advance(31)  # let the breaker's probe window open
        upstream.modes["nvd"] = "ok"
        record, freshness = nvd.get_cve(CVE)
        assert freshness.origin == "live" and record.attribution.stale is False

    def test_a_stale_not_found_is_never_served_as_an_answer(
        self, registry, upstream, clock
    ) -> None:
        nvd = gateway(registry, "nvd")
        assert nvd.get_cve("CVE-1999-0001")[0] is None
        clock.advance(301)
        upstream.modes["nvd"] = "500"
        with pytest.raises(ProviderUnavailable):  # "not found" is unknown now, not still true
            nvd.get_cve("CVE-1999-0001")

    def test_search_results_also_fall_back_to_stale(self, registry, upstream, clock) -> None:
        nvd = gateway(registry, "nvd")
        query = SearchQuery(text="log4j")
        nvd.search(query)
        clock.advance(601)  # search TTL is 600s in the test settings
        upstream.modes["nvd"] = "timeout"
        result, freshness = nvd.search(query)
        assert freshness.origin == "stale" and result.stale is True
        assert all(item.attribution.stale for item in result.items)


class TestOutboundRateLimit:
    def test_provider_is_never_called_beyond_its_budget(self, registry, upstream) -> None:
        nvd = gateway(registry, "nvd")  # default budget without an API key: 4 per 30s
        for n in range(4):
            nvd.get_cve(f"CVE-2020-100{n}")
        assert upstream.count("nvd") == 4
        with pytest.raises(ProviderRateLimited) as exc:
            nvd.get_cve("CVE-2020-1009")
        assert upstream.count("nvd") == 4  # the 5th request was never sent
        assert 0 < exc.value.retry_after <= 30

    def test_budget_replenishes(self, registry, upstream, clock) -> None:
        nvd = gateway(registry, "nvd")
        for n in range(4):
            nvd.get_cve(f"CVE-2020-100{n}")
        clock.advance(31)
        nvd.get_cve("CVE-2020-1009")
        assert upstream.count("nvd") == 5

    def test_cache_hits_do_not_spend_budget(self, registry, upstream) -> None:
        nvd = gateway(registry, "nvd")
        for _ in range(50):
            nvd.get_cve(CVE)
        assert upstream.count("nvd") == 1

    def test_rate_limited_lookup_prefers_a_stale_copy(self, registry, upstream, clock) -> None:
        nvd = gateway(registry, "nvd")
        nvd.get_cve(CVE)
        clock.advance(3601)  # the copy is now stale, and the 30s budget window has reset
        for n in range(4):  # spend the whole budget on other CVEs
            nvd.get_cve(f"CVE-2020-100{n}")
        assert upstream.count("nvd") == 5
        record, freshness = nvd.get_cve(CVE)
        assert freshness.origin == "stale" and record.cve_id == CVE
        assert upstream.count("nvd") == 5  # rate limited: no request was made, stale data served

    def test_configured_budget_and_api_key_default(self, make_registry, upstream) -> None:
        nvd = gateway(make_registry(nvd_rate_limit_requests=2), "nvd")
        nvd.get_cve("CVE-2020-1000")
        nvd.get_cve("CVE-2020-1001")
        with pytest.raises(ProviderRateLimited):
            nvd.get_cve("CVE-2020-1002")

    def test_budgets_are_per_provider(self, registry, upstream) -> None:
        nvd, mitre = gateway(registry, "nvd"), gateway(registry, "mitre")
        for n in range(4):
            nvd.get_cve(f"CVE-2020-100{n}")
        with pytest.raises(ProviderRateLimited):
            nvd.get_cve("CVE-2020-1009")
        assert mitre.get_cve(CVE)[0] is not None  # MITRE is unaffected by NVD's exhaustion


class TestCircuitBreaker:
    def fail_three_times(self, nvd, upstream) -> None:
        upstream.modes["nvd"] = "500"
        for n in range(3):
            with pytest.raises(ProviderUnavailable):
                nvd.get_cve(f"CVE-2020-200{n}")

    def test_repeated_failures_stop_further_upstream_calls(self, registry, upstream) -> None:
        nvd = gateway(registry, "nvd")
        self.fail_three_times(nvd, upstream)
        sent = upstream.count("nvd")
        with pytest.raises(ProviderCircuitOpen):
            nvd.get_cve("CVE-2020-2009")
        assert upstream.count("nvd") == sent  # fast-failed locally

    def test_probe_after_cooldown_can_close_the_circuit(self, registry, upstream, clock) -> None:
        nvd = gateway(registry, "nvd")
        self.fail_three_times(nvd, upstream)
        clock.advance(31)
        upstream.modes["nvd"] = "ok"
        assert nvd.get_cve(CVE)[0] is not None
        assert nvd.get_cve("CVE-2020-2222")[0] is None  # circuit closed: calls flow again

    def test_rate_limiting_and_not_found_do_not_trip_the_breaker(self, registry, upstream) -> None:
        nvd = gateway(registry, "nvd")
        for n in range(4):
            nvd.get_cve(f"CVE-1999-000{n}")  # "not found" answers
        with pytest.raises(ProviderRateLimited):
            nvd.get_cve("CVE-1999-0009")
        assert nvd.circuit_state == "closed"  # neither says the provider is unhealthy

    def test_one_failing_provider_does_not_affect_another(self, registry, upstream) -> None:
        self.fail_three_times(gateway(registry, "nvd"), upstream)
        assert gateway(registry, "mitre").get_cve(CVE)[0] is not None


class TestSearchCachingAndSeeding:
    def test_identical_searches_are_cached(self, registry, upstream) -> None:
        nvd = gateway(registry, "nvd")
        nvd.search(SearchQuery(text="log4j"))
        nvd.search(SearchQuery(text="  LOG4J "))  # same query after normalisation
        assert upstream.count("nvd") == 1

    def test_page_limit_and_filters_are_part_of_the_cache_key(self, registry, upstream) -> None:
        nvd = gateway(registry, "nvd")
        nvd.search(SearchQuery(text="log4j"))
        nvd.search(SearchQuery(text="log4j", page=2))
        nvd.search(SearchQuery(text="log4j", limit=5))
        nvd.search(SearchQuery(text="log4j", severity="HIGH"))
        assert upstream.count("nvd") == 4

    def test_search_results_seed_the_per_cve_cache(self, registry, upstream) -> None:
        nvd = gateway(registry, "nvd")
        nvd.search(SearchQuery(text="log4j"))
        calls_after_search = upstream.count("nvd")
        record, freshness = nvd.get_cve("CVE-2021-45105")  # arrived inside the search response
        assert record.cve_id == "CVE-2021-45105" and freshness.origin == "cache"
        assert upstream.count("nvd") == calls_after_search

    def test_serving_stale_search_results_does_not_refresh_the_per_cve_entries(
        self, registry, upstream, clock
    ) -> None:
        nvd = gateway(registry, "nvd")
        first = nvd.search(SearchQuery(text="log4j"))[0].retrieved_at
        clock.advance(601)
        upstream.modes["nvd"] = "500"
        assert nvd.search(SearchQuery(text="log4j"))[1].origin == "stale"
        clock.advance(3100)  # the entries seeded by the first search are now past their TTL
        record, freshness = nvd.get_cve("CVE-2021-45105")
        assert freshness.origin == "stale"
        # still stamped with the ORIGINAL retrieval time: stale data was not re-labelled as new
        assert record.attribution.retrieved_at == first


class TestKevCatalogue:
    def test_stale_catalogue_is_served_when_cisa_is_down(self, registry, upstream, clock) -> None:
        kev = gateway(registry, "cisa_kev")
        assert kev.get_cve(CVE)[0].attribution.stale is False
        clock.advance(3601 + 31)  # past the KEV TTL and the in-process memo
        upstream.modes["cisa_kev"] = "500"
        record, _ = kev.get_cve(CVE)
        assert record is not None and record.attribution.stale is True

    def test_no_catalogue_at_all_raises(self, registry, upstream) -> None:
        upstream.modes["cisa_kev"] = "500"
        with pytest.raises((ProviderUnavailable, ProviderBadResponse)):
            gateway(registry, "cisa_kev").get_cve(CVE)

    def test_catalogue_download_respects_its_own_budget(
        self, make_registry, upstream, clock
    ) -> None:
        kev = gateway(make_registry(kev_rate_limit_requests=1, kev_cache_ttl_seconds=1), "cisa_kev")
        assert kev.get_cve(CVE)[0].attribution.stale is False
        clock.advance(
            40
        )  # past the 1s TTL and the 30s in-process memo, inside the 60s budget window
        record, _ = kev.get_cve(CVE)
        assert upstream.count("cisa_kev") == 1  # the second download was refused locally...
        assert record.attribution.stale is True  # ...and the last good catalogue was served
