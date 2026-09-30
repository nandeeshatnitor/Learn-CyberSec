"""HTTP contract of /api/learning: identity, the whole student journey, and error mapping."""

from collections.abc import Callable, Iterator
from typing import Any

import pytest
from fastapi.testclient import TestClient

from app.api.dependencies import get_learning_service
from app.main import app
from app.services import LearningConfig, LearningService
from tests.learning.conftest import ALICE, BOB
from tests.research.support import CVE_ID

ANSWERS = {
    "t1": "The template engine.",
    "t2": "The X-Template-Hint header.",
    "t3": "The response body contained 49.",
    "t4": "The renderer evaluates the template header without sanitizing it.",
    "t5": "Upgrade to 4.2.4.",
}


@pytest.fixture
def api(client: TestClient, make_learning: Callable[..., LearningService]) -> Iterator[TestClient]:
    service = make_learning()
    app.dependency_overrides[get_learning_service] = lambda: service
    yield client
    app.dependency_overrides.pop(get_learning_service, None)


def h(token: str = ALICE) -> dict[str, str]:
    return {"X-Learner-Token": token}


def create(api: TestClient, token: str = ALICE) -> dict[str, Any]:
    response = api.post("/api/learning", json={"cve_id": CVE_ID}, headers=h(token))
    assert response.status_code == 200, response.text
    return response.json()


def started(api: TestClient, token: str = ALICE) -> str:
    sid = create(api, token)["id"]
    assert api.post(f"/api/learning/{sid}/start", headers=h(token)).status_code == 200
    return sid


# -- identity --------------------------------------------------------------------------
@pytest.mark.parametrize(
    "headers",
    [
        {},
        {"X-Learner-Token": ""},
        {"X-Learner-Token": "short"},
        {"X-Learner-Token": "bad token with spaces 0123456789"},
        {"X-Learner-Token": "<script>alert(1)</script>0123456789"},
    ],
)
def test_a_learner_token_is_required(api: TestClient, headers: dict[str, str]) -> None:
    response = api.post("/api/learning", json={"cve_id": CVE_ID}, headers=headers)
    assert response.status_code == 401 and response.json()["error"]["code"] == "unauthorized"
    assert api.get("/api/learning/by-cve/" + CVE_ID, headers=headers).status_code == 401


def test_another_learner_cannot_see_or_touch_a_session(api: TestClient) -> None:
    sid = started(api)
    for method, path, body in (
        ("get", f"/api/learning/{sid}", None),
        ("get", f"/api/learning/{sid}/hints", None),
        ("post", f"/api/learning/{sid}/hints", {"task_id": "t1", "number": 1}),
        ("post", f"/api/learning/{sid}/tasks/t1/answer", {"answer": "some words"}),
        ("post", f"/api/learning/{sid}/tasks/t1/solution", None),
        ("post", f"/api/learning/{sid}/tutor", {"question": "Why does this happen?"}),
        ("get", f"/api/learning/{sid}/tutor", None),
        ("post", f"/api/learning/{sid}/complete", None),
    ):
        response = getattr(api, method)(path, headers=h(BOB), **({"json": body} if body else {}))
        assert response.status_code == 404, (path, response.text)
    assert api.get(f"/api/learning/by-cve/{CVE_ID}", headers=h(BOB)).status_code == 404


# -- the journey -----------------------------------------------------------------------
def test_a_student_can_complete_a_session_end_to_end(api: TestClient) -> None:
    # 1-3: (the guide exists) start a session
    session = create(api)
    assert session["status"] == "not_started" and session["score"] == 100
    sid = session["id"]
    assert api.get(f"/api/learning/by-cve/{CVE_ID}", headers=h()).json()["id"] == sid
    assert api.post(f"/api/learning/{sid}/start", headers=h()).json()["status"] == "in_progress"

    # 5: hints, progressively more explicit, with tracking
    assert api.get(f"/api/learning/{sid}/hints", headers=h()).json() == {
        "hints": [], "next": {"task_id": "t1", "number": 1, "penalty": 5},
    }  # fmt: skip
    texts = []
    for n in (1, 2, 3):
        response = api.post(
            f"/api/learning/{sid}/hints", json={"task_id": "t1", "number": n}, headers=h()
        )
        assert response.status_code == 200
        texts.append(response.json()["hint"]["text"])
    assert "template engine" not in texts[0].lower() and "template engine" in texts[2].lower()
    listed = api.get(f"/api/learning/{sid}/hints", headers=h()).json()
    assert [x["number"] for x in listed["hints"]] == [1, 2, 3] and listed["next"] is None
    assert all(
        {"text", "revealed_at", "evidence", "penalty", "label"} <= set(x) for x in listed["hints"]
    )

    # 6-8: tutor, answers with feedback
    tutor = api.post(
        f"/api/learning/{sid}/tutor",
        json={"question": "Can you explain the vulnerability?"},
        headers=h(),
    ).json()
    assert tutor["outcome"] == "answered" and tutor["parts"] and tutor["parts"][0]["source_ids"]
    wrong = api.post(
        f"/api/learning/{sid}/tasks/t1/answer",
        json={"answer": "The HTTP request parser."},
        headers=h(),
    ).json()
    assert wrong["result"] == "incorrect" and wrong["solution"] is None
    right = api.post(
        f"/api/learning/{sid}/tasks/t1/answer", json={"answer": ANSWERS["t1"]}, headers=h()
    ).json()
    assert right["result"] == "correct" and right["solution"]["parts"]
    assert right["session"]["current_task_id"] == "t2"

    # 9: reveal a solution
    api.post(
        f"/api/learning/{sid}/tasks/t2/answer", json={"answer": "no idea whatsoever"}, headers=h()
    )
    revealed = api.post(f"/api/learning/{sid}/tasks/t2/solution", headers=h()).json()
    assert revealed["penalty"] == 30 and revealed["session"]["solution_revealed"] is True

    # 4, 10-11: finish the rest, complete, see score and progress
    for task in ("t3", "t4", "t5"):
        result = api.post(
            f"/api/learning/{sid}/tasks/{task}/answer", json={"answer": ANSWERS[task]}, headers=h()
        ).json()
        assert result["result"] == "correct", (task, result["feedback"])
    done = api.post(f"/api/learning/{sid}/complete", headers=h()).json()
    assert done["status"] == "completed" and done["completed_at"]
    assert done["score"] == 100 - 5 - 10 - 15 - 30
    assert done["progress"] == {"resolved": 5, "total": 5, "percent": 100}
    assert done["hints_used"] == 3 and done["solution_revealed"] is True

    history = api.get(f"/api/learning/{sid}/tutor", headers=h()).json()["messages"]
    assert [m["role"] for m in history] == ["student", "tutor"]


def test_no_response_before_the_reveal_contains_private_content(api: TestClient) -> None:
    sid = started(api)
    wrong = {"answer": "The HTTP parser."}
    seen = [
        api.get(f"/api/learning/{sid}", headers=h()).text,
        api.get(f"/api/learning/{sid}/hints", headers=h()).text,
        api.post(f"/api/learning/{sid}/tasks/t1/answer", json=wrong, headers=h()).text,
    ]
    for blob in seen:
        for secret in ("template engine", "docker run", "curl -H", "key_points", "phrases"):
            assert secret not in blob.lower()


# -- errors ----------------------------------------------------------------------------
def test_state_conflicts_are_409(api: TestClient) -> None:
    sid = create(api)["id"]
    hint = api.post(f"/api/learning/{sid}/hints", json={"task_id": "t1", "number": 1}, headers=h())
    assert hint.status_code == 409 and hint.json()["error"]["code"] == "conflict"
    api.post(f"/api/learning/{sid}/start", headers=h())
    assert api.post(f"/api/learning/{sid}/complete", headers=h()).status_code == 409
    assert api.post(f"/api/learning/{sid}/tasks/t1/solution", headers=h()).status_code == 409
    skip = api.post(
        f"/api/learning/{sid}/tasks/t2/answer", json={"answer": "words here"}, headers=h()
    )
    assert skip.status_code == 409


def test_validation_errors_are_422_without_echoing_input(api: TestClient) -> None:
    sid = started(api)
    cases = [
        ("post", f"/api/learning/{sid}/hints", {"task_id": "t1", "number": 4}),
        ("post", f"/api/learning/{sid}/hints", {"task_id": "../x", "number": 1}),
        ("post", f"/api/learning/{sid}/hints", {"task_id": "t1", "number": 1, "extra": "x"}),
        ("post", f"/api/learning/{sid}/tasks/t1/answer", {"answer": "hm"}),
        ("post", f"/api/learning/{sid}/tasks/t1/answer", {"answer": "x" * 20_000}),
        ("post", f"/api/learning/{sid}/tasks/%3Cscript%3E/answer", {"answer": "words words"}),
        ("post", f"/api/learning/{sid}/tutor", {"question": " "}),
        ("post", "/api/learning", {"cve_id": "nonsense"}),
        ("post", "/api/learning", {}),
        ("get", "/api/learning/not-a-uuid", None),
    ]
    for method, path, body in cases:
        response = getattr(api, method)(path, headers=h(), **({"json": body} if body else {}))
        assert response.status_code == 422, (path, body, response.status_code)
        assert "<script>" not in response.text and "xxxxxxxx" not in response.text


def test_a_cve_without_a_guide_is_404(api: TestClient) -> None:
    response = api.post("/api/learning", json={"cve_id": "CVE-2099-00001"}, headers=h())
    assert response.status_code == 404 and "Generate the learning guide" in response.text


def test_rate_limits_map_to_429(
    client: TestClient, make_learning: Callable[..., LearningService]
) -> None:
    service = make_learning(LearningConfig(tutor_per_session_per_hour=1))
    app.dependency_overrides[get_learning_service] = lambda: service
    try:
        sid = started(client)
        ok = client.post(
            f"/api/learning/{sid}/tutor",
            json={"question": "Explain the vulnerability"},
            headers=h(),
        )
        assert ok.status_code == 200
        limited = client.post(
            f"/api/learning/{sid}/tutor", json={"question": "Explain it again"}, headers=h()
        )
        assert limited.status_code == 429 and int(limited.headers["Retry-After"]) >= 1
    finally:
        app.dependency_overrides.pop(get_learning_service, None)


def test_disabled_learning_is_503(
    client: TestClient, make_learning: Callable[..., LearningService]
) -> None:
    service = make_learning(LearningConfig(enabled=False))
    app.dependency_overrides[get_learning_service] = lambda: service
    try:
        response = client.post("/api/learning", json={"cve_id": CVE_ID}, headers=h())
        assert (
            response.status_code == 503 and response.json()["error"]["code"] == "learning_disabled"
        )
    finally:
        app.dependency_overrides.pop(get_learning_service, None)


def test_responses_are_not_cacheable(api: TestClient) -> None:
    response = api.get(f"/api/learning/{create(api)['id']}", headers=h())
    assert "no-store" in response.headers["cache-control"]
    assert response.headers["x-content-type-options"] == "nosniff"


def test_the_learner_token_is_never_stored_or_echoed(
    api: TestClient,
    db,  # type: ignore[no-untyped-def]
) -> None:
    from sqlalchemy import text

    sid = started(api)
    response = api.get(f"/api/learning/{sid}", headers=h())
    assert ALICE not in response.text
    rows = db.execute(text("select user_id from learning_sessions")).scalars().all()
    assert rows and all(ALICE not in r and len(r) == 48 for r in rows)
