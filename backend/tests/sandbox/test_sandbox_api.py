"""HTTP contract of /api/sandbox: identity, ownership, the whole student journey, error mapping."""

from typing import Any

import pytest
from fastapi.testclient import TestClient

from app.config import Settings
from tests.sandbox.conftest import ALICE, ALICE_TOKEN, BOB, BOB_TOKEN, LAB_ID, Sandbox, headers

EXPLOIT = "/download?name=../private/canary.txt"


def start(api: TestClient, token: str = ALICE_TOKEN, **body: Any) -> dict[str, Any]:
    response = api.post(
        "/api/sandbox/instances", json={"lab_id": LAB_ID, **body}, headers=headers(token)
    )
    assert response.status_code == 200, response.text
    return response.json()


# -- catalogue -------------------------------------------------------------------------------
def test_the_catalogue_lists_labs_without_runtime_details(api: TestClient) -> None:
    response = api.get("/api/sandbox/labs", headers=headers())
    assert response.status_code == 200
    [lab] = response.json()
    assert lab["id"] == LAB_ID and lab["cwe_ids"] == ["CWE-22"]
    assert [o["id"] for o in lab["objectives"]] == ["exploit", "remediate"]
    assert lab["resources"] == {
        "cpus": 0.5,
        "memory_mb": 128,
        "processes": 64,
        "scratch_mb": 16,
        "timeout_minutes": 45,
    }
    text = response.text
    for hidden in (
        "image",
        "startup_command",
        "cvelearn-lab",
        "block_paths",
        "keep_working",
    ):
        assert hidden not in text


def test_labs_are_matched_to_a_cve_by_weakness(api: TestClient) -> None:
    assert len(api.get("/api/sandbox/labs?cve_id=CVE-2099-0022", headers=headers()).json()) == 1
    assert api.get("/api/sandbox/labs?cve_id=cve-2099-0022", headers=headers()).status_code == 200
    assert api.get("/api/sandbox/labs?cve_id=CVE-2099-0001", headers=headers()).json() == []
    assert api.get("/api/sandbox/labs?cve_id=nonsense", headers=headers()).status_code == 422


def test_one_lab_and_a_missing_lab(api: TestClient) -> None:
    assert api.get(f"/api/sandbox/labs/{LAB_ID}", headers=headers()).json()["title"]
    assert api.get("/api/sandbox/labs/nope-nope", headers=headers()).status_code == 404
    assert api.get("/api/sandbox/labs/BAD..ID", headers=headers()).status_code == 422


# -- identity and ownership ------------------------------------------------------------------
@pytest.mark.parametrize("token", [None, "", "short", "has spaces in the token 0123456789"])
def test_a_learner_token_is_required(api: TestClient, token: str | None) -> None:
    h = {} if token is None else {"X-Learner-Token": token}
    response = api.post("/api/sandbox/instances", json={"lab_id": LAB_ID}, headers=h)
    assert response.status_code == 401
    assert api.get("/api/sandbox/instances/current", headers=h).status_code == 401


def test_someone_elses_lab_is_not_found_for_every_action(api: TestClient) -> None:
    lab = start(api)
    for method, path, body in [
        ("get", f"/api/sandbox/instances/{lab['id']}", None),
        ("post", f"/api/sandbox/instances/{lab['id']}/reset", None),
        ("post", f"/api/sandbox/instances/{lab['id']}/stop", None),
        (
            "post",
            f"/api/sandbox/instances/{lab['id']}/verify",
            {"check_id": "exploit", "payload": EXPLOIT},
        ),
        ("post", f"/api/sandbox/instances/{lab['id']}/network-check", None),
        ("post", f"/api/sandbox/instances/{lab['id']}/terminal-ticket", None),
    ]:
        response = getattr(api, method)(
            path, headers=headers(BOB_TOKEN), **({"json": body} if body else {})
        )
        assert response.status_code == 404, (path, response.text)
    assert (
        api.get(f"/api/sandbox/instances/{lab['id']}", headers=headers()).json()["status"]
        == "running"
    )


def test_a_malformed_id_is_not_found_not_an_error(api: TestClient) -> None:
    assert api.get("/api/sandbox/instances/not-a-uuid", headers=headers()).status_code == 404


# -- the journey -----------------------------------------------------------------------------
def test_start_returns_a_view_without_secrets_or_runtime_names(
    api: TestClient, sandbox: Sandbox
) -> None:
    lab = start(api)
    assert lab["status"] == "running" and lab["can_use"] is True
    assert lab["seconds_remaining"] > 44 * 60
    assert lab["app_path"].startswith(f"/lab-app/{lab['id']}/") and lab["app_path"].endswith("/")
    assert lab["ports"] == [{"name": "app", "protocol": "http"}]
    assert [o["verified"] for o in lab["objectives"]] == [False, False]
    row = sandbox.repo.live_for(ALICE)
    text = str(lab)
    for hidden in (row.canary, row.container_name, row.network_name, row.address, row.image):  # type: ignore[union-attr]
        assert str(hidden) not in text


def test_the_full_student_journey(api: TestClient, sandbox: Sandbox) -> None:
    lab = start(api)
    iid = lab["id"]
    # 1. a working exploit
    miss = api.post(
        f"/api/sandbox/instances/{iid}/verify",
        json={"check_id": "exploit", "payload": "/download?name=welcome.txt"},
        headers=headers(),
    )
    assert miss.json()["outcome"]["status"] == "failed"
    hit = api.post(
        f"/api/sandbox/instances/{iid}/verify",
        json={"check_id": "exploit", "payload": EXPLOIT},
        headers=headers(),
    )
    body = hit.json()
    assert body["outcome"]["status"] == "passed"
    assert [o["verified"] for o in body["instance"]["objectives"]] == [True, False]
    assert body["instance"]["objectives"][0]["attempts"] == 2
    # 2. an unfixed app fails the remediation check
    assert (
        api.post(
            f"/api/sandbox/instances/{iid}/verify",
            json={"check_id": "remediate"},
            headers=headers(),
        ).json()["outcome"]["status"]
        == "failed"
    )
    # 3. the fix
    sandbox.apps.only().pending_fix = True
    fixed = api.post(
        f"/api/sandbox/instances/{iid}/verify", json={"check_id": "remediate"}, headers=headers()
    ).json()
    assert fixed["outcome"]["status"] == "passed"
    assert [o["verified"] for o in fixed["instance"]["objectives"]] == [True, True]
    # 4. reset gives a fresh, vulnerable lab; progress is kept
    reset = api.post(f"/api/sandbox/instances/{iid}/reset", headers=headers()).json()
    assert reset["id"] != iid and reset["reset_of"] == iid and reset["status"] == "running"
    assert [o["verified"] for o in reset["objectives"]] == [True, True]
    assert api.get(f"/api/sandbox/instances/{iid}", headers=headers()).json()["status"] == "stopped"
    assert sandbox.apps.only().fixed is False
    # 5. stop
    stopped = api.post(f"/api/sandbox/instances/{reset['id']}/stop", headers=headers()).json()
    assert (
        stopped["status"] == "stopped"
        and stopped["can_use"] is False
        and stopped["app_path"] is None
    )
    assert not sandbox.runtime.containers and not sandbox.runtime.networks


def test_the_current_lab(api: TestClient) -> None:
    assert api.get("/api/sandbox/instances/current", headers=headers()).json() == {"instance": None}
    lab = start(api)
    assert (
        api.get("/api/sandbox/instances/current", headers=headers()).json()["instance"]["id"]
        == lab["id"]
    )
    assert api.get("/api/sandbox/instances/current", headers=headers(BOB_TOKEN)).json() == {
        "instance": None
    }


def test_a_second_lab_is_a_conflict(api: TestClient) -> None:
    start(api)
    response = api.post("/api/sandbox/instances", json={"lab_id": LAB_ID}, headers=headers())
    assert response.status_code == 409 and response.json()["error"]["code"] == "conflict"


def test_an_expired_lab_reports_its_state_and_frees_the_learner(
    api: TestClient, sandbox: Sandbox
) -> None:
    lab = start(api)
    sandbox.clock.advance(46 * 60)
    view = api.get(f"/api/sandbox/instances/{lab['id']}", headers=headers()).json()
    assert (
        view["status"] == "stopped"
        and view["stop_reason"] == "expired"
        and view["can_use"] is False
    )
    assert view["seconds_remaining"] == 0 and view["app_path"] is None
    assert start(api)["status"] == "running"


def test_verifying_a_lab_that_is_not_running_is_a_conflict(api: TestClient) -> None:
    lab = start(api)
    api.post(f"/api/sandbox/instances/{lab['id']}/stop", headers=headers())
    response = api.post(
        f"/api/sandbox/instances/{lab['id']}/verify",
        json={"check_id": "exploit", "payload": EXPLOIT},
        headers=headers(),
    )
    assert response.status_code == 409


def test_request_bodies_are_validated(api: TestClient) -> None:
    lab = start(api)
    verify = f"/api/sandbox/instances/{lab['id']}/verify"
    for body in [
        {},
        {"check_id": "BAD ID"},
        {"check_id": "exploit", "payload": "x" * 700},
        {"check_id": "exploit", "extra": 1},
    ]:
        assert api.post(verify, json=body, headers=headers()).status_code == 422
    assert api.post(verify, json={"check_id": "nope_nope"}, headers=headers()).status_code == 404
    assert (
        api.post("/api/sandbox/instances", json={"lab_id": "x"}, headers=headers()).status_code
        == 422
    )
    assert (
        api.post(
            "/api/sandbox/instances", json={"lab_id": LAB_ID, "image": "evil:1"}, headers=headers()
        ).status_code
        == 422
    )


def test_the_start_endpoint_cannot_be_used_to_run_anything_else(
    api: TestClient, sandbox: Sandbox
) -> None:
    for body in [
        {"lab_id": "alpine"},
        {"lab_id": LAB_ID, "cmd": ["sh"]},
        {"lab_id": "../etc/passwd"},
    ]:
        assert api.post("/api/sandbox/instances", json=body, headers=headers()).status_code in (
            404,
            422,
        )
    assert not sandbox.runtime.containers


def test_a_failed_start_maps_to_a_bad_gateway_with_a_fixed_message(
    api: TestClient, sandbox: Sandbox
) -> None:
    sandbox.runtime.reachable = {"169.254.169.254"}
    response = api.post("/api/sandbox/instances", json={"lab_id": LAB_ID}, headers=headers())
    assert response.status_code == 502
    error = response.json()["error"]
    assert error["code"] == "lab_start_failed" and "isolation" in error["message"]
    assert "169.254" not in response.text


def test_capacity_and_rate_limits_map_to_503_and_429(api: TestClient, sandbox: Sandbox) -> None:
    sandbox.instances._config = sandbox.config.__class__(max_active=1, starts_per_hour=1)  # noqa: SLF001
    start(api)
    assert api.post(
        "/api/sandbox/instances", json={"lab_id": LAB_ID}, headers=headers(BOB_TOKEN)
    ).status_code in (429, 503)


def test_the_isolation_check_can_be_run_on_demand(api: TestClient, sandbox: Sandbox) -> None:
    lab = start(api)
    response = api.post(f"/api/sandbox/instances/{lab['id']}/network-check", headers=headers())
    assert response.status_code == 200
    body = response.json()
    assert body["passed"] is True and all(r["blocked"] for r in body["results"])
    assert any("internet" in r["target"].lower() for r in body["results"])
    sandbox.runtime.reachable = {"1.1.1.1"}
    leaked = api.post(f"/api/sandbox/instances/{lab['id']}/network-check", headers=headers()).json()
    assert leaked["passed"] is False and any(not r["blocked"] for r in leaked["results"])


# -- learning-session integration ------------------------------------------------------------
def test_labs_for_a_session_and_progress_in_it(
    api: TestClient, sandbox: Sandbox, make_session: Any
) -> None:
    session = make_session()
    empty = api.get(f"/api/sandbox/sessions/{session.id}/labs", headers=headers()).json()
    [entry] = empty["labs"]
    assert entry["lab"]["id"] == LAB_ID and (entry["verified"], entry["total"]) == (0, 2)
    assert entry["instance_id"] is None and entry["last_instance_id"] is None

    lab = start(api, session_id=str(session.id))
    api.post(
        f"/api/sandbox/instances/{lab['id']}/verify",
        json={"check_id": "exploit", "payload": EXPLOIT},
        headers=headers(),
    )
    after = api.get(f"/api/sandbox/sessions/{session.id}/labs", headers=headers()).json()["labs"][0]
    assert (after["verified"], after["total"]) == (1, 2)
    assert [o["verified"] for o in after["objectives"]] == [True, False]
    assert after["instance_id"] == lab["id"]

    api.post(f"/api/sandbox/instances/{lab['id']}/stop", headers=headers())
    ended = api.get(f"/api/sandbox/sessions/{session.id}/labs", headers=headers()).json()["labs"][0]
    assert (
        ended["verified"] == 1
        and ended["instance_id"] is None
        and ended["last_instance_id"] == lab["id"]
    )


def test_progress_is_only_shown_to_the_sessions_owner(api: TestClient, make_session: Any) -> None:
    session = make_session()
    assert (
        api.get(f"/api/sandbox/sessions/{session.id}/labs", headers=headers(BOB_TOKEN)).status_code
        == 404
    )
    assert api.get("/api/sandbox/sessions/garbage/labs", headers=headers()).status_code == 404


def test_progress_in_one_session_does_not_leak_into_another(
    api: TestClient, make_session: Any
) -> None:
    first, second = make_session(), make_session()
    lab = start(api, session_id=str(first.id))
    api.post(
        f"/api/sandbox/instances/{lab['id']}/verify",
        json={"check_id": "exploit", "payload": EXPLOIT},
        headers=headers(),
    )
    other = api.get(f"/api/sandbox/sessions/{second.id}/labs", headers=headers()).json()["labs"][0]
    assert other["verified"] == 0


def test_a_lab_cannot_be_attached_to_someone_elses_session(
    api: TestClient, make_session: Any
) -> None:
    theirs = make_session(user_id=BOB)
    response = api.post(
        "/api/sandbox/instances",
        json={"lab_id": LAB_ID, "session_id": str(theirs.id)},
        headers=headers(),
    )
    assert response.status_code == 404


# -- disabled --------------------------------------------------------------------------------
def test_everything_answers_503_when_labs_are_disabled(
    api: TestClient, sandbox: Sandbox, settings: Settings
) -> None:
    sandbox.manager._config = sandbox.config.__class__(enabled=False)  # noqa: SLF001
    for method, path in [("get", "/api/sandbox/labs"), ("get", "/api/sandbox/instances/current")]:
        response = getattr(api, method)(path, headers=headers())
        assert (
            response.status_code == 503 and response.json()["error"]["code"] == "sandbox_disabled"
        )


def test_the_sandbox_is_off_by_default() -> None:
    assert Settings(_env_file=None, database_url="sqlite://").sandbox_enabled is False  # type: ignore[call-arg]
