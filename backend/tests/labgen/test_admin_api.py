"""The reviewer API: who may call it, what it refuses, and that only a person's approval publishes."""

import hashlib
from collections.abc import Callable, Iterator
from typing import Any

import pytest
from fastapi.testclient import TestClient

from app.api.dependencies import get_job_queue, get_labgen_pipeline, get_labgen_publisher
from app.config import Settings, get_settings
from app.main import app
from app.models import CandidateStatus
from tests.labgen.conftest import ADMIN, CVE_ID, Labs

ALICE_TOKEN = "alice-reviewer-token-0123456789abcdefghijk"
BOB_TOKEN = "bob-reviewer-token-0123456789abcdefghijklm"
DIGEST = lambda t: hashlib.sha256(t.encode()).hexdigest()  # noqa: E731
BASE = "/api/admin/labs"


class Queue:
    """Records the jobs the API would queue; running one is the test's decision."""

    def __init__(self) -> None:
        self.jobs: list[tuple[str, str]] = []

    def enqueue_labgen(self, candidate_id: str, stage: str = "generate") -> None:
        self.jobs.append((candidate_id, stage))

    def enqueue(self, *_: Any, **__: Any) -> None:  # pragma: no cover - not used here
        raise AssertionError("the admin API must only queue labgen jobs")


@pytest.fixture
def queue_(labs: Labs) -> Queue:
    return Queue()


@pytest.fixture
def api(client: TestClient, labs: Labs, settings: Settings, queue_: Queue) -> Iterator[TestClient]:
    enabled = settings.model_copy(
        update={
            "labgen_enabled": True,
            "admin_reviewers": {"alice": DIGEST(ALICE_TOKEN), "bob": DIGEST(BOB_TOKEN)},
        }
    )
    app.dependency_overrides[get_settings] = lambda: enabled
    app.dependency_overrides[get_labgen_pipeline] = lambda: labs.pipeline
    app.dependency_overrides[get_labgen_publisher] = lambda: labs.publisher
    app.dependency_overrides[get_job_queue] = lambda: queue_
    yield client
    for dep in (get_settings, get_labgen_pipeline, get_labgen_publisher, get_job_queue):
        app.dependency_overrides.pop(dep, None)


def auth(token: str = ALICE_TOKEN) -> dict[str, str]:
    return {"X-Admin-Token": token}


def make_candidate(api: TestClient, labs: Labs, queue_: Queue) -> dict[str, Any]:
    response = api.post(f"{BASE}/candidates", json={"cve_id": CVE_ID}, headers=auth())
    assert response.status_code == 202, response.text
    body = response.json()
    assert queue_.jobs[-1] == (body["id"], "generate")
    import uuid

    labs.pipeline.run(uuid.UUID(body["id"]))
    return api.get(f"{BASE}/candidates/{body['id']}", headers=auth()).json()  # type: ignore[no-any-return]


# -- access --------------------------------------------------------------------------------------
@pytest.mark.parametrize("token", [None, "", "wrong", ALICE_TOKEN + "x", "a" * 190])
def test_a_reviewer_token_is_required(api: TestClient, token: str | None) -> None:
    headers = {} if token is None else {"X-Admin-Token": token}
    for method, path in (
        ("get", "/whoami"),
        ("get", "/candidates"),
        ("post", "/candidates"),
        ("get", "/versions"),
        ("post", "/candidates/00000000-0000-0000-0000-000000000000/approve"),
    ):
        response = getattr(api, method)(BASE + path, headers=headers)
        assert response.status_code == 401, (method, path, response.text)


def test_a_learner_token_does_not_open_the_admin_api(api: TestClient) -> None:
    response = api.get(f"{BASE}/candidates", headers={"X-Learner-Token": "a" * 30})
    assert response.status_code == 401


def test_the_reviewer_is_identified_by_their_token(api: TestClient) -> None:
    assert api.get(f"{BASE}/whoami", headers=auth(BOB_TOKEN)).json()["name"] == "bob"
    assert api.get(f"{BASE}/whoami", headers=auth()).json()["name"] == "alice"


def test_the_interface_is_closed_unless_enabled_and_configured(
    api: TestClient, settings: Settings
) -> None:
    off = settings.model_copy(update={"labgen_enabled": False})
    app.dependency_overrides[get_settings] = lambda: off
    response = api.get(f"{BASE}/candidates", headers=auth())
    assert response.status_code == 503 and response.json()["error"]["code"] == "labgen_disabled"
    nobody = settings.model_copy(update={"labgen_enabled": True, "admin_reviewers": {}})
    app.dependency_overrides[get_settings] = lambda: nobody
    response = api.get(f"{BASE}/candidates", headers=auth())
    assert response.status_code == 503 and response.json()["error"]["code"] == "admin_disabled"


def test_wrong_tokens_are_rate_limited_per_client(api: TestClient) -> None:
    codes = [
        api.get(f"{BASE}/whoami", headers={"X-Admin-Token": f"guess-{i}"}).status_code
        for i in range(14)
    ]
    assert codes[:10] == [401] * 10 and set(codes[10:]) == {429}


# -- the review journey ----------------------------------------------------------------------------
def test_a_candidate_is_requested_reviewed_and_approved(
    api: TestClient, labs: Labs, queue_: Queue
) -> None:
    detail = make_candidate(api, labs, queue_)
    assert detail["status"] == "awaiting_review" and detail["can_approve"] is True
    assert detail["blockers"] == [] and len(detail["checks"]) == 10
    assert detail["requested_by"] == "alice" and detail["reviewer"] is None
    assert detail["source_count"] >= 1 and detail["product"] == "AcmeDocs"
    assert any(n.endswith("Dockerfile") or n == "Dockerfile" for n in detail["files"])
    assert detail["lab_id"] is None

    listing = api.get(f"{BASE}/candidates", headers=auth()).json()["candidates"]
    [row] = listing
    assert row["cve_id"] == CVE_ID and row["status"] == "awaiting_review"
    assert (row["build_status"], row["security_status"]) == ("passed", "passed")

    done = api.post(
        f"{BASE}/candidates/{detail['id']}/approve",
        json={"notes": "Good."},
        headers=auth(BOB_TOKEN),
    )
    assert done.status_code == 200, done.text
    body = done.json()
    assert body["status"] == "approved" and body["reviewer"] == "bob"
    assert body["lab_id"] == "cve-2099-12345-v1" and body["can_approve"] is False
    assert [r["action"] for r in body["reviews"]] == ["approve"]
    versions = api.get(f"{BASE}/versions", headers=auth()).json()["versions"]
    assert [(v["lab_id"], v["status"]) for v in versions] == [("cve-2099-12345-v1", "published")]


def test_a_decision_on_the_same_candidate_twice_is_a_conflict(
    api: TestClient, labs: Labs, queue_: Queue
) -> None:
    detail = make_candidate(api, labs, queue_)
    url = f"{BASE}/candidates/{detail['id']}"
    assert api.post(f"{url}/approve", json={}, headers=auth()).status_code == 200
    assert api.post(f"{url}/approve", json={}, headers=auth(BOB_TOKEN)).status_code == 409
    assert api.post(f"{url}/reject", json={"notes": "late"}, headers=auth()).status_code == 409


def test_reject_and_request_changes_require_notes(
    api: TestClient, labs: Labs, queue_: Queue
) -> None:
    detail = make_candidate(api, labs, queue_)
    url = f"{BASE}/candidates/{detail['id']}"
    for action in ("reject", "request-changes"):
        assert api.post(f"{url}/{action}", json={}, headers=auth()).status_code == 422
        assert api.post(f"{url}/{action}", json={"notes": "  "}, headers=auth()).status_code == 422
    assert api.get(url, headers=auth()).json()["status"] == "awaiting_review"
    done = api.post(f"{url}/request-changes", json={"notes": "Use /render."}, headers=auth())
    assert done.status_code == 200 and done.json()["status"] == "changes_requested"
    assert done.json()["review_notes"] == "Use /render."


def test_a_new_revision_follows_requested_changes_and_becomes_v2(
    api: TestClient, labs: Labs, queue_: Queue
) -> None:
    first = make_candidate(api, labs, queue_)
    url = f"{BASE}/candidates/{first['id']}"
    # Not while it is awaiting review.
    assert api.post(f"{url}/regenerate", json={}, headers=auth()).status_code == 409
    api.post(f"{url}/request-changes", json={"notes": "wrong endpoint"}, headers=auth())
    response = api.post(
        f"{url}/regenerate", json={"overrides": {"endpoint": "/render"}}, headers=auth()
    )
    assert response.status_code == 202, response.text
    second = response.json()
    assert second["revision"] == 2 and queue_.jobs[-1] == (second["id"], "generate")
    # One working revision at a time.
    assert api.post(f"{url}/regenerate", json={}, headers=auth()).status_code == 409
    import uuid

    labs.pipeline.run(uuid.UUID(second["id"]))
    detail = api.get(f"{BASE}/candidates/{second['id']}", headers=auth()).json()
    assert detail["parent_id"] == first["id"]
    assert detail["spec"]["generation"]["overrides"] == {"endpoint": "/render"}
    assert detail["spec"]["generation"]["change_notes"] == "wrong endpoint"
    api.post(f"{BASE}/candidates/{second['id']}/approve", json={}, headers=auth())
    # Revision 2 is the first revision that was approved, so it is published as v1.
    versions = api.get(f"{BASE}/versions", headers=auth()).json()["versions"]
    assert [(v["lab_id"], v["status"]) for v in versions] == [("cve-2099-12345-v1", "published")]


def test_approving_a_later_revision_supersedes_the_earlier_version(
    api: TestClient, labs: Labs, queue_: Queue
) -> None:
    first = make_candidate(api, labs, queue_)
    api.post(f"{BASE}/candidates/{first['id']}/approve", json={}, headers=auth())
    response = api.post(f"{BASE}/candidates/{first['id']}/regenerate", json={}, headers=auth())
    assert response.status_code == 202, response.text
    import uuid

    second_id = response.json()["id"]
    labs.pipeline.run(uuid.UUID(second_id))
    api.post(f"{BASE}/candidates/{second_id}/approve", json={}, headers=auth())
    versions = api.get(f"{BASE}/versions", headers=auth()).json()["versions"]
    assert [(v["lab_id"], v["status"]) for v in versions] == [
        ("cve-2099-12345-v2", "published"),
        ("cve-2099-12345-v1", "superseded"),
    ]
    assert versions[1]["superseded_by"] == "cve-2099-12345-v2"


def test_unknown_override_keys_are_rejected(api: TestClient) -> None:
    for body in (
        {"cve_id": CVE_ID, "overrides": {"image": "evil/x:1"}},
        {"cve_id": CVE_ID, "overrides": {"command": "rm -rf /"}},
        {"cve_id": "nonsense"},
        {"cve_id": CVE_ID, "extra": 1},
    ):
        assert api.post(f"{BASE}/candidates", json=body, headers=auth()).status_code == 422


def test_a_candidate_for_a_cve_without_a_guide_is_refused(api: TestClient) -> None:
    response = api.post(f"{BASE}/candidates", json={"cve_id": "CVE-2099-77777"}, headers=auth())
    assert response.status_code == 422 and "guide" in response.json()["error"]["message"]


def test_a_missing_candidate_is_not_found(api: TestClient) -> None:
    missing = "00000000-0000-0000-0000-000000000000"
    assert api.get(f"{BASE}/candidates/{missing}", headers=auth()).status_code == 404
    assert (
        api.post(f"{BASE}/candidates/{missing}/approve", json={}, headers=auth()).status_code == 404
    )
    assert api.get(f"{BASE}/candidates/not-a-uuid", headers=auth()).status_code == 422


def test_a_candidate_that_failed_validation_cannot_be_approved(
    api: TestClient, labs: Labs, queue_: Queue
) -> None:
    labs.validator.fail = {"reset"}
    detail = make_candidate(api, labs, queue_)
    assert detail["status"] == "validation_failed" and detail["can_approve"] is False
    assert detail["blockers"]
    response = api.post(f"{BASE}/candidates/{detail['id']}/approve", json={}, headers=auth())
    assert response.status_code == 409
    assert api.get(f"{BASE}/versions", headers=auth()).json()["versions"] == []


def test_list_filters(api: TestClient, labs: Labs, queue_: Queue) -> None:
    make_candidate(api, labs, queue_)
    assert (
        len(
            api.get(f"{BASE}/candidates?status=awaiting_review", headers=auth()).json()[
                "candidates"
            ]
        )
        == 1
    )
    assert api.get(f"{BASE}/candidates?status=approved", headers=auth()).json()["candidates"] == []
    assert (
        len(
            api.get(f"{BASE}/candidates?cve_id={CVE_ID.lower()}", headers=auth()).json()[
                "candidates"
            ]
        )
        == 1
    )
    assert api.get(f"{BASE}/candidates?status=bogus", headers=auth()).status_code == 422


def test_rebuild_queues_a_build_and_release_frees_a_stalled_job(
    api: TestClient, labs: Labs, queue_: Queue
) -> None:
    detail = make_candidate(api, labs, queue_)
    response = api.post(f"{BASE}/candidates/{detail['id']}/rebuild", headers=auth())
    assert response.status_code == 202 and queue_.jobs[-1] == (detail["id"], "build")
    assert response.json()["status"] == "building"
    # Just started: not stalled.
    assert api.post(f"{BASE}/candidates/{detail['id']}/release", headers=auth()).status_code == 409


def test_withdrawing_a_version(api: TestClient, labs: Labs, queue_: Queue) -> None:
    detail = make_candidate(api, labs, queue_)
    api.post(f"{BASE}/candidates/{detail['id']}/approve", json={}, headers=auth())
    [version] = api.get(f"{BASE}/versions", headers=auth()).json()["versions"]
    url = f"{BASE}/versions/{version['id']}/withdraw"
    assert api.post(url, json={}, headers=auth()).status_code == 422
    done = api.post(url, json={"notes": "Hints were wrong."}, headers=auth(BOB_TOKEN))
    assert done.status_code == 200
    assert done.json()["status"] == "withdrawn" and done.json()["withdrawn_by"] == "bob"
    assert api.post(url, json={"notes": "again"}, headers=auth()).status_code == 409


# -- what students and queued jobs can reach ---------------------------------------------------------
def test_the_job_has_no_way_to_publish(labs: Labs) -> None:
    """Running the whole pipeline leaves the candidate waiting for a human and publishes nothing."""
    candidate = labs.pipeline.request(CVE_ID, ADMIN)
    labs.pipeline.run(candidate.id)
    labs.pipeline.run(candidate.id, "build")
    assert labs.repo.versions() == []
    done = labs.repo.get(candidate.id)
    assert done is not None and done.status is CandidateStatus.AWAITING_REVIEW


def test_admin_responses_are_not_cacheable_and_carry_no_secrets(api: TestClient) -> None:
    response = api.get(f"{BASE}/candidates", headers=auth())
    assert "set-cookie" not in response.headers
    assert ALICE_TOKEN not in response.text


_unused: Callable[..., None] | None = None
