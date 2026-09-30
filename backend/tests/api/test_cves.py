import pytest


def test_get_cve_returns_full_record_with_references(client, make_cve, make_source, link_reference):
    cve = make_cve()
    source = make_source()
    link_reference(cve, source, ["Vendor Advisory"])

    response = client.get("/api/cves/CVE-2021-44228")

    assert response.status_code == 200
    body = response.json()
    assert body["cve_id"] == "CVE-2021-44228"
    assert body["cvss_score"] == 10.0
    assert body["severity"] == "CRITICAL"
    assert body["cwes"] == ["CWE-502"]
    assert body["data_origin"] == "seed"
    assert body["affected_products"] == [{"vendor": "Apache", "product": "Log4j2"}]
    assert body["references"][0]["tags"] == ["Vendor Advisory"]
    assert body["references"][0]["source"]["url"] == source.url
    assert body["references"][0]["source"]["retrieved_at"] is None


def test_get_cve_is_case_insensitive(client, make_cve):
    make_cve()
    assert client.get("/api/cves/cve-2021-44228").json()["cve_id"] == "CVE-2021-44228"


def test_get_cve_not_found_uses_error_envelope(client):
    response = client.get("/api/cves/CVE-1999-0001")
    assert response.status_code == 404
    error = response.json()["error"]
    assert error["code"] == "not_found"
    assert error["request_id"] == response.headers["x-request-id"]


@pytest.mark.parametrize(
    "bad_id", ["nope", "CVE-2021-1", "CVE-2021-44228'--", "%00", "CVE-2021-4422x"]
)
def test_get_cve_rejects_malformed_ids(client, bad_id):
    response = client.get(f"/api/cves/{bad_id}")
    assert response.status_code == 422
    assert response.json()["error"]["code"] == "invalid_input"


def test_get_cve_rejects_overlong_ids(client):
    response = client.get("/api/cves/" + "A" * 200)
    assert response.status_code == 422
    assert response.json()["error"]["code"] == "validation_error"


def test_search_by_keyword(client, make_cve):
    make_cve("CVE-2021-44228", description="Log4j JNDI injection")
    make_cve("CVE-2014-0160", description="OpenSSL heartbeat over-read")
    body = client.get("/api/cves/search", params={"q": "log4j"}).json()
    assert body["total"] == 1
    assert body["items"][0]["cve_id"] == "CVE-2021-44228"
    assert body["query"] == "log4j"
    assert "references" not in body["items"][0]


def test_search_by_id_is_case_insensitive(client, make_cve):
    make_cve("CVE-2014-0160")
    body = client.get("/api/cves/search", params={"q": "cve-2014-0160"}).json()
    assert [item["cve_id"] for item in body["items"]] == ["CVE-2014-0160"]


def test_search_route_is_not_shadowed_by_cve_id_route(client):
    response = client.get("/api/cves/search", params={"q": "anything"})
    assert response.status_code == 200
    assert response.json()["items"] == []


def test_search_pagination(client, make_cve):
    for n in range(1, 6):
        make_cve(f"CVE-2020-000{n}", description="common keyword")
    page = client.get("/api/cves/search", params={"q": "common", "limit": 2, "offset": 2}).json()
    assert (page["total"], len(page["items"]), page["limit"], page["offset"]) == (5, 2, 2, 2)


@pytest.mark.parametrize(
    "params",
    [
        {},  # missing q
        {"q": ""},
        {"q": "   "},
        {"q": "x" * 201},
        {"q": "ok", "limit": 0},
        {"q": "ok", "limit": 1000},
        {"q": "ok", "offset": -1},
        {"q": "ok", "limit": "abc"},
    ],
)
def test_search_validates_input(client, params):
    response = client.get("/api/cves/search", params=params)
    assert response.status_code == 422
    assert "code" in response.json()["error"]


def test_search_wildcards_and_sql_metacharacters_are_literal(client, make_cve):
    make_cve(description="plain description")
    for q in ["%", "_", "' OR '1'='1", "'; DROP TABLE cves;--"]:
        response = client.get("/api/cves/search", params={"q": q})
        assert response.status_code == 200
        assert response.json()["total"] == 0
    assert client.get("/api/cves/CVE-2021-44228").status_code == 200  # table still intact


def test_validation_errors_do_not_echo_input(client):
    secret = "<script>alert(1)</script>" * 20
    response = client.get("/api/cves/search", params={"q": secret})
    assert response.status_code == 422
    assert "<script>" not in response.text
