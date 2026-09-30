"""The lab's web app through the platform: capability URL, defensive headers, faithful paths."""

from typing import Any

import pytest
from fastapi.testclient import TestClient

from app.models import LabStatus
from app.sandbox.app_client import AppResponse, AppUnreachable, HttpxAppTransport
from tests.sandbox.conftest import ALICE_TOKEN, LAB_ID, Sandbox, headers


@pytest.fixture
def lab(api: TestClient) -> dict[str, Any]:
    response = api.post("/api/sandbox/instances", json={"lab_id": LAB_ID}, headers=headers())
    assert response.status_code == 200
    return response.json()


def url(lab: dict[str, Any], rest: str = "") -> str:
    return "/api/sandbox" + lab["app_path"].removeprefix("/lab-app").rjust(0).join(["", ""]) + rest


def app_url(lab: dict[str, Any], rest: str = "") -> str:
    _, _, iid, token, *_ = lab["app_path"].split("/")
    return f"/api/sandbox/app/{iid}/{token}/{rest}"


def test_the_app_is_served_through_the_platform_without_a_learner_header(
    api: TestClient, lab: dict[str, Any]
) -> None:
    response = api.get(app_url(lab, "health"))
    assert response.status_code == 200 and response.text == "ok\n"
    doc = api.get(app_url(lab, "download?name=welcome.txt"))
    assert doc.status_code == 200 and b"Welcome" in doc.content


def test_the_request_reaches_the_lab_exactly_as_sent(
    api: TestClient, lab: dict[str, Any], sandbox: Sandbox
) -> None:
    """Percent-encoding and dot-dot segments are left for the lab to interpret: that is the point of
    the exercise, and the platform must not "helpfully" normalise them away."""
    sandbox.apps.overrides["/download?name=..%2fprivate%2fcanary.txt"] = AppResponse(
        200, {}, b"raw-path-arrived"
    )
    response = api.get(app_url(lab, "download?name=..%2fprivate%2fcanary.txt"))
    assert response.content == b"raw-path-arrived"
    api.get(app_url(lab, "download?name=../private/canary.txt"))
    assert sandbox.apps.sent[-1]["path"] == "/download?name=../private/canary.txt"


def test_students_can_exploit_the_lab_through_the_app_url(
    api: TestClient, lab: dict[str, Any], sandbox: Sandbox
) -> None:
    row = sandbox.repo.live_for(sandbox.repo.get_any(__import__("uuid").UUID(lab["id"])).user_id)  # type: ignore[union-attr]
    response = api.get(app_url(lab, "download?name=../private/canary.txt"))
    assert response.status_code == 200 and row.canary in response.text  # type: ignore[union-attr]


def test_a_wrong_or_missing_token_is_a_404(api: TestClient, lab: dict[str, Any]) -> None:
    _, _, iid, token, *_ = lab["app_path"].split("/")
    for bad in [token[:-1] + ("A" if token[-1] != "A" else "B"), "x" * 24, token.upper()]:
        assert api.get(f"/api/sandbox/app/{iid}/{bad}/health").status_code == 404
    assert api.get(f"/api/sandbox/app/{iid}/short/health").status_code == 422
    assert (
        api.get(f"/api/sandbox/app/00000000-0000-0000-0000-000000000000/{token}/health").status_code
        == 404
    )


def test_the_url_stops_working_when_the_lab_stops_or_expires(
    api: TestClient, lab: dict[str, Any], sandbox: Sandbox
) -> None:
    assert api.get(app_url(lab, "health")).status_code == 200
    sandbox.clock.advance(60 * 60)
    assert api.get(app_url(lab, "health")).status_code == 404


def test_the_url_of_a_reset_lab_is_dead(api: TestClient, lab: dict[str, Any]) -> None:
    old = app_url(lab, "health")
    new = api.post(f"/api/sandbox/instances/{lab['id']}/reset", headers=headers()).json()
    assert api.get(old).status_code == 404
    assert api.get(app_url(new, "health")).status_code == 200


def test_responses_are_locked_down(api: TestClient, lab: dict[str, Any], sandbox: Sandbox) -> None:
    sandbox.apps.overrides["/x"] = AppResponse(
        200,
        {
            "content-type": "text/html",
            "set-cookie": "session=steal",
            "x-powered-by": "evil",
            "server": "evil",
            "access-control-allow-origin": "*",
        },
        b"<script>fetch('/api/learning')</script>",
    )
    response = api.get(app_url(lab, "x"))
    assert "sandbox" in response.headers["content-security-policy"]
    assert "allow-same-origin" not in response.headers["content-security-policy"]
    assert "frame-ancestors 'self'" in response.headers["content-security-policy"]
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["cache-control"] == "no-store"
    assert response.headers["referrer-policy"] == "no-referrer"
    for leaked in ("set-cookie", "x-powered-by", "access-control-allow-origin"):
        assert leaked not in response.headers
    assert response.headers["content-type"].startswith("text/html")


def test_platform_credentials_are_never_forwarded_to_the_lab(
    api: TestClient, lab: dict[str, Any], sandbox: Sandbox
) -> None:
    api.get(
        app_url(lab, "health"),
        headers={
            "Cookie": "cvele_learner=secret",
            "Authorization": "Bearer x",
            "X-Learner-Token": ALICE_TOKEN,
            "Accept": "text/plain",
        },
    )
    sent = sandbox.apps.sent[-1]["headers"]
    assert {k.lower() for k in sent} <= {"accept", "accept-language", "content-type"}
    assert "cookie" not in {k.lower() for k in sent}


def test_relative_redirects_stay_inside_the_lab_and_others_are_dropped(
    api: TestClient, lab: dict[str, Any], sandbox: Sandbox
) -> None:
    sandbox.apps.overrides["/go"] = AppResponse(
        302, {"location": "/download?name=welcome.txt"}, b""
    )
    sandbox.apps.overrides["/out"] = AppResponse(302, {"location": "http://evil.example/"}, b"")
    sandbox.apps.overrides["/proto"] = AppResponse(302, {"location": "//evil.example/"}, b"")
    prefix = f"/lab-app/{lab['id']}/{lab['app_path'].split('/')[3]}"
    ok = api.get(app_url(lab, "go"), headers={"X-Lab-Prefix": prefix}, follow_redirects=False)
    assert ok.status_code == 302
    assert ok.headers["location"] == f"{prefix}/download?name=welcome.txt"
    assert "location" not in api.get(app_url(lab, "out"), follow_redirects=False).headers
    assert "location" not in api.get(app_url(lab, "proto"), follow_redirects=False).headers


def test_absolute_links_in_html_stay_inside_the_lab(
    api: TestClient, lab: dict[str, Any], sandbox: Sandbox
) -> None:
    sandbox.apps.overrides["/page"] = AppResponse(
        200,
        {"content-type": "text/html; charset=utf-8"},
        b"""<a href="/download?name=a">a</a> <img src='/logo.png'> <form action="/go"></form>
        <a href="//evil.example/x">proto-relative</a> <a href="https://evil.example/">abs</a>
        <a href="relative/path">rel</a>""",
    )
    prefix = f"/lab-app/{lab['id']}/{lab['app_path'].split('/')[3]}"
    body = api.get(app_url(lab, "page"), headers={"X-Lab-Prefix": prefix}).text
    assert f'href="{prefix}/download?name=a"' in body
    assert f"src='{prefix}/logo.png'" in body
    assert f'action="{prefix}/go"' in body
    assert 'href="//evil.example/x"' in body and 'href="https://evil.example/"' in body  # untouched
    assert 'href="relative/path"' in body
    # without a valid prefix nothing is rewritten (the prefix header is validated, never trusted)
    for bad in ("/evil", "https://evil.example", "/lab-app/x/y", prefix + "/../x"):
        assert (
            'href="/download?name=a"'
            in api.get(app_url(lab, "page"), headers={"X-Lab-Prefix": bad}).text
        )


def test_non_html_bodies_are_never_rewritten(
    api: TestClient, lab: dict[str, Any], sandbox: Sandbox
) -> None:
    sandbox.apps.overrides["/data.txt"] = AppResponse(
        200, {"content-type": "text/plain"}, b'href="/x"'
    )
    prefix = f"/lab-app/{lab['id']}/{lab['app_path'].split('/')[3]}"
    assert api.get(app_url(lab, "data.txt"), headers={"X-Lab-Prefix": prefix}).text == 'href="/x"'


def test_only_get_head_and_post_are_allowed(api: TestClient, lab: dict[str, Any]) -> None:
    for method in ("put", "delete", "patch"):
        assert getattr(api, method)(app_url(lab, "health")).status_code == 405
    assert api.head(app_url(lab, "health")).status_code == 200
    assert api.head(app_url(lab, "health")).content == b""


def test_post_bodies_are_forwarded_but_capped(
    api: TestClient, lab: dict[str, Any], sandbox: Sandbox
) -> None:
    api.post(
        app_url(lab, "health"),
        content=b"a=1",
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )
    assert sandbox.apps.sent[-1]["method"] == "POST" and sandbox.apps.sent[-1]["body"] == b"a=1"
    big = api.post(app_url(lab, "health"), content=b"x" * 100_000)
    assert big.status_code == 413


def test_a_lab_whose_app_is_down_gives_a_bad_gateway_not_an_error_page(
    api: TestClient, lab: dict[str, Any], sandbox: Sandbox
) -> None:
    sandbox.apps.only().down = True
    response = api.get(app_url(lab, "health"))
    assert response.status_code == 502 and b"not answering" in response.content
    assert "traceback" not in response.text.lower()


# -- the transport itself ------------------------------------------------------------------------
@pytest.mark.parametrize(
    ("address", "port", "method", "path"),
    [
        ("127.0.0.1", 8080, "GET", "/"),  # not in the lab pool
        ("10.0.0.5", 8080, "GET", "/"),  # private, but not the lab pool
        ("169.254.169.254", 80, "GET", "/"),  # cloud metadata
        ("192.168.1.10", 8080, "GET", "/"),
        ("10.200.1.2", 0, "GET", "/"),
        ("10.200.1.2", 70000, "GET", "/"),
        ("10.200.1.2", 8080, "DELETE", "/"),
        ("10.200.1.2", 8080, "GET", "http://evil.example/"),
        ("10.200.1.2", 8080, "GET", "//evil.example/"),
        ("example.com", 80, "GET", "/"),
        ("not-an-ip", 80, "GET", "/"),
    ],
)
def test_the_transport_only_ever_talks_to_lab_addresses(
    address: str, port: int, method: str, path: str
) -> None:
    transport = HttpxAppTransport("10.200.0.0/16")
    with pytest.raises(AppUnreachable):
        transport.request(address, port, method, path, timeout=0.2, max_bytes=100)


def test_the_labs_status_after_the_proxy_is_unaffected(
    api: TestClient, lab: dict[str, Any], sandbox: Sandbox
) -> None:
    api.get(app_url(lab, "health"))
    assert sandbox.repo.get_any(__import__("uuid").UUID(lab["id"])).status is LabStatus.RUNNING  # type: ignore[union-attr]
