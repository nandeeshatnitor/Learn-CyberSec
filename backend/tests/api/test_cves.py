import json
import logging

import pytest
from pydantic import SecretStr

from app.config import get_settings
from app.main import app
from tests.conftest import load_fixture

CVE_ID = "CVE-2021-44228"


class TestGetCve:
    def test_returns_the_normalised_schema(self, client) -> None:
        response = client.get(f"/api/cves/{CVE_ID}")
        assert response.status_code == 200
        body = response.json()

        # The shape requested for the API, whichever provider supplied the data.
        assert body["cve_id"] == CVE_ID
        assert body["description"].startswith("Apache Log4j2 2.0-beta9 through 2.15.0")
        assert body["severity"] == "CRITICAL"
        assert body["cvss"]["score"] == 10.0
        assert body["cvss"]["vector"] == "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"
        assert body["known_exploited"] is True
        assert body["published_at"] == "2021-12-10T10:15:09.143000Z"
        assert body["modified_at"].startswith("2025-05-05")
        assert {c["id"] for c in body["cwes"]} == {"CWE-20", "CWE-400", "CWE-502", "CWE-917"}
        assert isinstance(body["affected_products"], list) and body["affected_products"]
        assert isinstance(body["references"], list) and body["references"]

    def test_every_datum_is_attributed_to_a_source(self, client) -> None:
        body = client.get(f"/api/cves/{CVE_ID}").json()
        assert [s["provider"] for s in body["sources"]] == ["nvd", "mitre", "cisa_kev"]
        for source in body["sources"]:
            assert (
                source["url"].startswith("https://")
                and source["retrieved_at"]
                and source["stale"] is False
            )
        assert body["field_sources"]["description"] == ["nvd"]
        assert body["field_sources"]["known_exploited"] == ["cisa_kev"]
        assert body["affected_products"][0]["source"] in {"nvd", "mitre"}
        assert all(r["sources"] for r in body["references"])
        assert body["meta"]["served_from"] == "providers"
        assert {p["provider"]: p["status"] for p in body["meta"]["providers"]} == {
            "nvd": "ok",
            "mitre": "ok",
            "cisa_kev": "ok",
        }

    def test_original_urls_are_preserved(self, client) -> None:
        urls = {r["url"] for r in client.get(f"/api/cves/{CVE_ID}").json()["references"]}
        assert (
            "http://www.openwall.com/lists/oss-security/2021/12/10/1" in urls
        )  # http:// not upgraded
        assert "https://www.kb.cert.org/vuls/id/930724" in urls

    def test_kev_details_and_affected_versions(self, client) -> None:
        body = client.get(f"/api/cves/{CVE_ID}").json()
        assert body["kev"]["source"] == "cisa_kev"
        assert body["kev"]["date_added"] == "2021-12-10"
        assert body["kev"]["known_ransomware_campaign_use"] == "Known"
        nvd = next(
            p for p in body["affected_products"] if p["source"] == "nvd" and p["product"] == "log4j"
        )
        assert {"start_including": "2.0.1", "end_excluding": "2.3.1"}.items() <= next(
            v for v in nvd["versions"] if v["start_including"] == "2.0.1"
        ).items()

    def test_lowercase_ids_are_accepted(self, client) -> None:
        assert client.get("/api/cves/cve-2021-44228").json()["cve_id"] == CVE_ID

    def test_unknown_cve_is_404_in_the_error_envelope(self, client) -> None:
        response = client.get("/api/cves/CVE-1999-0001")
        assert response.status_code == 404
        error = response.json()["error"]
        assert error["code"] == "not_found"
        assert error["request_id"] == response.headers["x-request-id"]

    @pytest.mark.parametrize(
        "bad_id", ["nope", "CVE-2021-1", "CVE-2021-44228'--", "%00", "CVE-2021-4422x"]
    )
    def test_malformed_ids_are_422_and_never_reach_a_provider(
        self, client, upstream, bad_id
    ) -> None:
        response = client.get(f"/api/cves/{bad_id}")
        assert response.status_code == 422
        assert upstream.calls == []

    def test_overlong_ids_are_rejected(self, client) -> None:
        assert client.get("/api/cves/" + "A" * 200).status_code == 422


class TestOneProviderUnavailable:
    def test_nvd_outage_still_serves_the_page_from_the_others(self, client, upstream) -> None:
        upstream.modes["nvd"] = "500"
        response = client.get(f"/api/cves/{CVE_ID}")
        assert response.status_code == 200
        body = response.json()
        nvd = body["meta"]["providers"][0]
        assert (nvd["provider"], nvd["status"], nvd["from_cache"]) == ("nvd", "unavailable", False)
        assert nvd["message"] == "The provider is unavailable."  # fixed text, not the upstream's
        assert nvd["retrieved_at"] is None
        assert body["field_sources"]["description"] == ["mitre"]
        assert any(w.startswith("NVD:") for w in body["meta"]["warnings"])

    def test_stale_data_is_flagged_in_the_response(self, client, upstream, clock) -> None:
        client.get(f"/api/cves/{CVE_ID}")
        clock.advance(3601)
        upstream.modes["nvd"] = "timeout"
        body = client.get(f"/api/cves/{CVE_ID}").json()
        nvd = next(s for s in body["sources"] if s["provider"] == "nvd")
        assert nvd["stale"] is True
        assert nvd["retrieved_at"].startswith("2026-09-30T06:00")  # the original retrieval time
        assert body["meta"]["providers"][0]["status"] == "stale"

    def test_all_providers_down_is_503_with_safe_details(self, client, upstream) -> None:
        for provider in upstream.modes:
            upstream.modes[provider] = "500"
        response = client.get(f"/api/cves/{CVE_ID}")
        assert response.status_code == 503
        error = response.json()["error"]
        assert error["code"] == "providers_unavailable"
        assert {d["provider"] for d in error["details"]} == {"nvd", "mitre", "cisa_kev"}
        assert "upstream down" not in response.text  # the provider's own error text is not relayed
        assert "https://" not in response.text

    def test_health_of_providers_endpoint_reports_each_one(self, client, upstream) -> None:
        body = client.get("/api/health/providers").json()
        assert {p["provider"]: p["status"] for p in body["providers"]} == {
            "nvd": "ok",
            "mitre": "ok",
            "cisa_kev": "ok",
        }

    def test_a_down_provider_degrades_only_the_providers_health_not_the_api(
        self, client, upstream, clock
    ) -> None:
        upstream.modes["mitre"] = "500"
        providers = {
            p["provider"]: p["status"]
            for p in client.get("/api/health/providers").json()["providers"]
        }
        assert providers["mitre"] == "unavailable" and providers["nvd"] == "ok"
        assert client.get("/api/health").json()["status"] == "ok"


class TestSearch:
    def test_keyword_search_returns_normalised_records_with_pagination_metadata(
        self, client
    ) -> None:
        body = client.get("/api/cves/search", params={"q": "log4j", "page": 1, "limit": 2}).json()
        assert (body["query"], body["query_type"]) == ("log4j", "keyword")
        assert (body["total"], body["page"], body["limit"], body["pages"]) == (37, 1, 2, 19)
        first = next(i for i in body["items"] if i["cve_id"] == "CVE-2021-44228")
        assert first["known_exploited"] is True and first["severity"] == "CRITICAL"
        assert first["cvss"]["score"] == 10.0 and first["cwes"][0]["id"] == "CWE-502"
        assert first["affected_products"] and first["references"] and first["published_at"]
        assert first["sources"][0]["provider"] == "nvd"

    def test_exact_and_partial_ids(self, client) -> None:
        exact = client.get("/api/cves/search", params={"q": "CVE-2021-44228"}).json()
        assert (exact["query_type"], exact["total"]) == ("cve_id", 1)
        partial = client.get("/api/cves/search", params={"q": "CVE-2021-4"}).json()
        assert partial["query_type"] == "partial_cve_id"
        assert {i["cve_id"] for i in partial["items"]} == {"CVE-2021-44228", "CVE-2021-41773"}
        assert partial["meta"]["warnings"]

    def test_filters_are_echoed_and_forwarded(self, client, upstream) -> None:
        body = client.get(
            "/api/cves/search",
            params={"q": "apache", "severity": "high", "known_exploited": "true"},
        ).json()
        assert body["filters"] == {"severity": "HIGH", "known_exploited": True}
        assert "cvssV3Severity=HIGH" in str(upstream.requests_to("nvd")[-1].url)

    def test_search_survives_an_nvd_outage(self, client, upstream) -> None:
        upstream.modes["nvd"] = "500"
        response = client.get("/api/cves/search", params={"q": "apache"})
        assert response.status_code == 200
        body = response.json()
        assert body["meta"]["served_from"] == "fallback"
        assert body["total"] == 3 and body["meta"]["warnings"]

    @pytest.mark.parametrize(
        "params",
        [
            {},
            {"q": ""},
            {"q": "x" * 201},
            {"q": "ok", "page": 0},
            {"q": "ok", "page": 1001},
            {"q": "ok", "limit": 0},
            {"q": "ok", "limit": 1000},
            {"q": "ok", "limit": "abc"},
            {"q": "ok", "severity": "URGENT"},
            {"q": "ok", "severity": "NONE"},
            {"q": "ok", "known_exploited": "false"},
            {"q": "ok", "known_exploited": "maybe"},
            {"q": "x" * 101},
            {"q": "\x00\x01"},
        ],
    )
    def test_invalid_input_is_422(self, client, upstream, params) -> None:
        response = client.get("/api/cves/search", params=params)
        assert response.status_code == 422
        assert response.json()["error"]["code"] in {"validation_error", "invalid_input"}
        assert upstream.calls == []

    def test_search_route_is_not_shadowed_by_the_id_route(self, client) -> None:
        assert client.get("/api/cves/search", params={"q": "zzzz-nothing"}).status_code == 200

    def test_validation_errors_do_not_echo_input(self, client) -> None:
        response = client.get("/api/cves/search", params={"q": "<script>alert(1)</script>" * 20})
        assert response.status_code == 422
        assert "<script>" not in response.text


class TestInboundRateLimit:
    def test_excess_requests_get_429_with_retry_after(self, client, settings) -> None:
        app.dependency_overrides[get_settings] = lambda: settings.model_copy(
            update={"api_rate_limit_requests": 3}
        )
        statuses = [
            client.get("/api/cves/search", params={"q": "log4j"}).status_code for _ in range(5)
        ]
        assert statuses == [200, 200, 200, 429, 429]
        blocked = client.get("/api/cves/search", params={"q": "log4j"})
        assert blocked.json()["error"]["code"] == "rate_limited"
        assert int(blocked.headers["retry-after"]) >= 1

    def test_health_is_not_rate_limited(self, client, settings) -> None:
        app.dependency_overrides[get_settings] = lambda: settings.model_copy(
            update={"api_rate_limit_requests": 1}
        )
        assert all(client.get("/api/health").status_code == 200 for _ in range(5))

    def test_rate_limited_requests_never_reach_providers(self, client, settings, upstream) -> None:
        app.dependency_overrides[get_settings] = lambda: settings.model_copy(
            update={"api_rate_limit_requests": 1}
        )
        client.get(f"/api/cves/{CVE_ID}")
        before = len(upstream.calls)
        assert client.get("/api/cves/CVE-2020-0001").status_code == 429
        assert len(upstream.calls) == before


class TestHostileUpstreamData:
    """What happens when a provider's data is malicious: it must come out inert."""

    @pytest.fixture
    def hostile(self, upstream):
        wrapper = load_fixture("nvd_hostile.json")["vulnerabilities"][0]
        upstream.nvd_records["CVE-2099-0001"] = wrapper
        return wrapper

    def test_dangerous_urls_never_reach_the_client(self, client, hostile) -> None:
        body = client.get("/api/cves/CVE-2099-0001").json()
        urls = [r["url"] for r in body["references"]]
        assert urls == ["https://example.com/ok?a=1&b=<b>"]
        assert not any(u.lower().startswith(("javascript:", "data:", "file:")) for u in urls)

    def test_markup_is_returned_as_json_text_never_as_a_document(self, client, hostile) -> None:
        response = client.get("/api/cves/CVE-2099-0001")
        assert response.headers["content-type"] == "application/json"
        assert response.headers["x-content-type-options"] == "nosniff"
        assert "default-src 'none'" in response.headers["content-security-policy"]
        assert json.loads(response.text)["description"].startswith(
            "<script>"
        )  # inert data for the UI to escape

    def test_control_and_bidi_characters_are_gone(self, client, hostile) -> None:
        text = client.get("/api/cves/CVE-2099-0001").json()["description"]
        assert not any(ch in text for ch in ("\x00", "\x1b", "‮", "​"))

    def test_invalid_scores_and_cwes_are_dropped(self, client, hostile) -> None:
        body = client.get("/api/cves/CVE-2099-0001").json()
        assert [m["score"] for m in body["cvss_metrics"]] == [9.8]
        assert [c["id"] for c in body["cwes"]] == ["CWE-79"]
        assert body["affected_products"] == []

    def test_nothing_from_upstream_is_ever_fetched_or_executed(
        self, client, hostile, upstream
    ) -> None:
        client.get("/api/cves/CVE-2099-0001")
        hosts = {c.url.host for c in upstream.calls}
        assert hosts <= set(
            upstream.HOSTS.values()
        )  # only the three configured providers were contacted

    def test_oversized_and_wrong_shaped_upstream_bodies_are_contained(
        self, client, upstream
    ) -> None:
        for mode in ("huge", "wrong_shape", "bad_json", "html"):
            upstream.modes["nvd"] = mode
            response = client.get(f"/api/cves/{CVE_ID}")
            assert response.status_code == 200  # MITRE + KEV still answer
            # After three consecutive bad answers the circuit breaker (correctly) opens.
            assert response.json()["meta"]["providers"][0]["status"] in {
                "unavailable",
                "circuit_open",
            }


class TestCredentialsNeverLeak:
    SECRET = "nvd-key-4f9a1c2b-secret"

    def test_api_key_appears_in_no_response_header_body_or_log(
        self, make_registry, db, settings, limiter, upstream, caplog
    ) -> None:
        from fastapi.testclient import TestClient

        from app.api.dependencies import Infrastructure, get_infrastructure
        from app.database import get_db

        caplog.set_level(logging.DEBUG)
        registry = make_registry(nvd_api_key=SecretStr(self.SECRET))
        app.dependency_overrides[get_db] = lambda: db
        app.dependency_overrides[get_infrastructure] = lambda: Infrastructure(registry, limiter)
        app.dependency_overrides[get_settings] = lambda: settings
        try:
            with TestClient(app, raise_server_exceptions=False) as client:
                responses = [
                    client.get(f"/api/cves/{CVE_ID}"),
                    client.get("/api/cves/search", params={"q": "log4j"}),
                    client.get("/api/health/providers"),
                    client.get("/api/openapi.json"),
                ]
                upstream.modes["nvd"] = "500"
                responses.append(client.get("/api/cves/CVE-2020-0001"))
                upstream.modes["nvd"] = "403"
                responses.append(client.get("/api/cves/search", params={"q": "another"}))
        finally:
            app.dependency_overrides.clear()

        assert upstream.count("nvd") > 0
        assert all(
            r.request.headers.get("apikey") is None for r in responses
        )  # not accepted from clients either
        for response in responses:
            assert self.SECRET not in response.text
            assert self.SECRET not in str(dict(response.headers))
        assert self.SECRET not in " ".join(str(r.msg) + str(r.args) for r in caplog.records)
        assert any(
            r.headers.get("apikey") == self.SECRET for r in upstream.requests_to("nvd")
        )  # it WAS used upstream
        assert self.SECRET not in repr(
            settings.model_copy(update={"nvd_api_key": SecretStr(self.SECRET)})
        )


class TestClientIdentityForRateLimiting:
    """The web app calls the API for every visitor, so limits must key on the forwarded address."""

    @pytest.fixture
    def web_app(self, client):
        """A client whose TCP peer is a real (private) address, like the web app in Docker."""
        from fastapi.testclient import TestClient

        with TestClient(app, client=("10.1.2.3", 50000), raise_server_exceptions=False) as peer:
            yield peer

    def limit(self, settings, proxies: list[str]) -> None:
        app.dependency_overrides[get_settings] = lambda: settings.model_copy(
            update={"api_rate_limit_requests": 2, "trusted_proxies": proxies}
        )

    def status(self, http, xff: str) -> int:
        return http.get(
            "/api/cves/search", params={"q": "log4j"}, headers={"X-Forwarded-For": xff}
        ).status_code

    def test_visitors_behind_a_trusted_web_app_get_separate_budgets(
        self, web_app, settings
    ) -> None:
        self.limit(settings, ["10.0.0.0/8"])
        assert [self.status(web_app, "198.51.100.1") for _ in range(3)] == [200, 200, 429]
        assert self.status(web_app, "198.51.100.2") == 200  # a different visitor is unaffected

    def test_without_trusted_proxies_everyone_behind_the_web_app_shares_one_budget(
        self, web_app, settings
    ) -> None:
        self.limit(settings, [])
        assert [self.status(web_app, f"198.51.100.{n}") for n in range(1, 4)] == [200, 200, 429]

    def test_the_header_is_ignored_when_the_peer_is_not_trusted(self, client, settings) -> None:
        self.limit(settings, ["10.0.0.0/8"])  # the default test client's peer is not in this range
        statuses = [self.status(client, f"198.51.100.{n}") for n in range(1, 5)]
        assert statuses == [200, 200, 429, 429]  # rotating the header does not evade the limit

    def test_spoofed_leading_addresses_do_not_evade_the_limit(self, web_app, settings) -> None:
        self.limit(settings, ["10.0.0.0/8"])
        statuses = [self.status(web_app, f"6.6.6.{n}, 198.51.100.9") for n in range(1, 5)]
        assert statuses == [
            200,
            200,
            429,
            429,
        ]  # the right-most untrusted hop identifies the client
