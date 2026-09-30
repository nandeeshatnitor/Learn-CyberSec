"""Sessions, task flow, hints, answers, solutions, completion, scoring and isolation."""

import uuid
from collections.abc import Callable

import pytest

from app.learning.scoring import ScoringConfig
from app.schemas.learning import SessionView
from app.services import (
    ConflictError,
    InvalidInputError,
    LearningConfig,
    LearningService,
    NotFoundError,
    RateLimitedError,
    ResearchService,
)
from tests.learning.conftest import ALICE, BOB, CLIENT
from tests.research.support import CVE_ID

CORRECT = {
    "t1": "The template engine is responsible.",
    "t2": "The X-Template-Hint header.",
    "t3": "The response body contained 49.",
    "t4": "The renderer evaluates the template header without sanitizing it.",
    "t5": "Upgrade to 4.2.4.",
}


def begin(learning: LearningService, user: str = ALICE) -> SessionView:
    view = learning.create(user, CVE_ID, client_key=CLIENT)
    return learning.start(user, uuid.UUID(view.id))


def sid(view: SessionView) -> uuid.UUID:
    return uuid.UUID(view.id)


# -- sessions --------------------------------------------------------------------------
def test_creating_a_session_needs_a_ready_guide(
    db,
    rclock,
    repo,
    cves,  # type: ignore[no-untyped-def]
) -> None:
    from app.cache import InMemorySlidingWindowLimiter
    from app.repositories import LearningRepository

    bare = LearningService(
        LearningRepository(db), repo, cves, InMemorySlidingWindowLimiter(), LearningConfig()
    )
    with pytest.raises(NotFoundError, match="Generate the learning guide"):
        bare.create(ALICE, CVE_ID, client_key=CLIENT)
    with pytest.raises(InvalidInputError):
        bare.create(ALICE, "nonsense", client_key=CLIENT)


def test_a_new_session_starts_not_started_with_only_the_first_task_open(
    learning: LearningService,
) -> None:
    view = learning.create(ALICE, CVE_ID, client_key=CLIENT)
    assert view.status == "not_started" and view.started_at is None
    assert view.score == 100 and view.hints_used == 0 and view.solution_revealed is False
    assert [t.status for t in view.tasks] == ["open", "locked", "locked", "locked", "locked"]
    assert view.current_task_id == "t1" and not view.can_complete
    assert view.progress.model_dump() == {"resolved": 0, "total": 5, "percent": 0}
    assert view.learning_objectives and view.prerequisites and view.sources
    assert view.cve.cve_id == CVE_ID and view.cve.description
    assert view.tasks[0].next_hint_penalty == 5 and view.tasks[0].solution_penalty == 30


def test_creating_again_resumes_the_active_session(learning: LearningService) -> None:
    first = learning.create(ALICE, CVE_ID, client_key=CLIENT)
    again = learning.create(ALICE, CVE_ID, client_key=CLIENT)
    assert first.id == again.id
    other = learning.create(BOB, CVE_ID, client_key=CLIENT)
    assert other.id != first.id


def test_start_moves_to_in_progress(learning: LearningService) -> None:
    view = learning.create(ALICE, CVE_ID, client_key=CLIENT)
    started = learning.start(ALICE, sid(view))
    assert started.status == "in_progress" and started.started_at is not None
    assert learning.start(ALICE, sid(view)).started_at == started.started_at  # idempotent


def test_nothing_can_be_done_before_the_session_is_started(learning: LearningService) -> None:
    view = learning.create(ALICE, CVE_ID, client_key=CLIENT)
    with pytest.raises(ConflictError, match="Start the learning session"):
        learning.reveal_hint(ALICE, sid(view), "t1", 1)
    with pytest.raises(ConflictError):
        learning.submit_answer(ALICE, sid(view), "t1", "some words here")
    with pytest.raises(ConflictError):
        learning.ask_tutor(ALICE, sid(view), "Why?", None, client_key=CLIENT)


def test_the_public_view_never_contains_answers_hints_or_solutions(
    learning: LearningService,
) -> None:
    view = begin(learning)
    blob = view.model_dump_json()
    for secret in (
        "template engine", "docker run", "curl -H", "Upgrade to AcmeDocs", "4.2.4",
        "prompt_injection", "key_points",
    ):  # fmt: skip
        assert secret.lower() not in blob.lower() or secret in ("4.2.4",)
    assert "docker run" not in blob and "curl -H" not in blob
    assert "hints" not in view.model_dump()["tasks"][0]


# -- hints -----------------------------------------------------------------------------
def test_hints_are_revealed_in_order_and_cost_points(learning: LearningService) -> None:
    view = begin(learning)
    s = sid(view)
    with pytest.raises(ConflictError, match="Hint 1"):
        learning.reveal_hint(ALICE, s, "t1", 2)
    scores = []
    for n in (1, 2, 3):
        response = learning.reveal_hint(ALICE, s, "t1", n)
        scores.append(response.session.score)
        assert response.hint.number == n and response.hint.label == f"Hint {n}"
        assert response.hint.penalty == (5, 10, 15)[n - 1]
    assert scores == [95, 85, 70]
    assert response.session.hints_used == 3
    assert response.session.tasks[0].next_hint_penalty is None
    with pytest.raises(ConflictError, match="All three hints"):
        learning.reveal_hint(ALICE, s, "t1", 3)


def test_hints_get_more_explicit_and_only_the_last_shows_source_excerpts(
    learning: LearningService,
) -> None:
    s = sid(begin(learning))
    h1, h2, h3 = (learning.reveal_hint(ALICE, s, "t1", n).hint for n in (1, 2, 3))
    assert "template engine" not in h1.text.lower() and "template engine" not in h2.text.lower()
    assert "template engine" in h3.text.lower()
    assert all(e.excerpt is None for e in h1.evidence + h2.evidence)
    assert h3.evidence and h3.evidence[0].excerpt
    assert all(e.source_id and e.title for e in h3.evidence)


def test_the_hint_history_records_number_time_content_and_evidence(
    learning: LearningService,
) -> None:
    s = sid(begin(learning))
    assert learning.hints(ALICE, s).hints == []
    assert learning.hints(ALICE, s).next.number == 1  # type: ignore[union-attr]
    learning.reveal_hint(ALICE, s, "t1", 1)
    learning.reveal_hint(ALICE, s, "t1", 2)
    history = learning.hints(ALICE, s)
    assert [h.number for h in history.hints] == [1, 2]
    assert all(h.text and h.revealed_at and h.penalty for h in history.hints)
    assert history.next is not None and history.next.number == 3 and history.next.penalty == 15
    assert learning.hints(ALICE, s, "t2").hints == []


def test_hints_only_work_on_the_current_task(learning: LearningService) -> None:
    s = sid(begin(learning))
    with pytest.raises(ConflictError, match="earlier tasks"):
        learning.reveal_hint(ALICE, s, "t2", 1)
    with pytest.raises(NotFoundError):
        learning.reveal_hint(ALICE, s, "t99", 1)


# -- answers ---------------------------------------------------------------------------
def test_incorrect_and_partial_answers_get_feedback_without_the_answer(
    learning: LearningService,
) -> None:
    s = sid(begin(learning))
    wrong = learning.submit_answer(ALICE, s, "t1", "The HTTP request parser is responsible.")
    assert wrong.result == "incorrect" and wrong.solution is None and wrong.attempts == 1
    assert (
        "template engine" not in wrong.feedback.lower() and "renderer" not in wrong.feedback.lower()
    )
    partial = learning.submit_answer(ALICE, s, "t1", "Something in AcmeDocs is responsible.")
    assert partial.result == "partially_correct" and partial.solution is None
    assert "affected product" in partial.feedback and "specific module" in partial.feedback
    assert partial.session.tasks[0].status == "open" and partial.attempts == 2


def test_a_correct_answer_finishes_the_task_shows_the_solution_and_opens_the_next(
    learning: LearningService,
) -> None:
    s = sid(begin(learning))
    result = learning.submit_answer(ALICE, s, "t1", CORRECT["t1"])
    assert result.result == "correct" and result.feedback.startswith("Correct")
    assert result.solution and result.solution.parts and result.solution.evidence
    assert result.solution.evidence[0].excerpt
    tasks = result.session.tasks
    assert (tasks[0].status, tasks[1].status) == ("correct", "open")
    assert result.session.current_task_id == "t2" and result.session.score == 100
    assert result.session.progress.resolved == 1 and result.session.progress.percent == 20


def test_wrong_attempts_do_not_cost_points(learning: LearningService) -> None:
    s = sid(begin(learning))
    for _ in range(4):
        result = learning.submit_answer(ALICE, s, "t1", "nothing relevant whatsoever")
    assert result.session.score == 100


def test_answers_are_validated(learning: LearningService) -> None:
    s = sid(begin(learning))
    for bad in ("", "  ", "hmm", "a"):
        with pytest.raises(InvalidInputError):
            learning.submit_answer(ALICE, s, "t1", bad)
    with pytest.raises(InvalidInputError, match="under 1000"):
        learning.submit_answer(ALICE, s, "t1", "word " * 400)


def test_tasks_must_be_done_in_order(learning: LearningService) -> None:
    s = sid(begin(learning))
    with pytest.raises(ConflictError, match="earlier tasks"):
        learning.submit_answer(ALICE, s, "t2", CORRECT["t2"])
    learning.submit_answer(ALICE, s, "t1", CORRECT["t1"])
    with pytest.raises(ConflictError, match="already finished"):
        learning.submit_answer(ALICE, s, "t1", CORRECT["t1"])


# -- solutions -------------------------------------------------------------------------
def test_the_solution_needs_an_attempt_first_and_costs_thirty(learning: LearningService) -> None:
    s = sid(begin(learning))
    with pytest.raises(ConflictError, match="Try the task first"):
        learning.reveal_solution(ALICE, s, "t1")
    assert learning.get(ALICE, s).tasks[0].solution_available is False
    learning.submit_answer(ALICE, s, "t1", "no idea really about this")
    assert learning.get(ALICE, s).tasks[0].solution_available is True
    response = learning.reveal_solution(ALICE, s, "t1")
    assert response.penalty == 30 and response.session.score == 70
    assert response.session.solution_revealed is True
    assert (
        response.session.tasks[0].status == "revealed" and response.session.current_task_id == "t2"
    )
    assert response.solution.parts and "template engine" in response.solution.parts[0].text.lower()


def test_the_solution_can_be_allowed_without_an_attempt(
    make_learning: Callable[..., LearningService],
) -> None:
    learning = make_learning(LearningConfig(solution_requires_attempt=False))
    s = sid(begin(learning))
    assert learning.reveal_solution(ALICE, s, "t1").session.score == 70


def test_the_reproduction_solution_carries_the_documented_commands_as_cited_text(
    learning: LearningService,
) -> None:
    s = sid(begin(learning))
    for task in ("t1", "t2"):
        learning.submit_answer(ALICE, s, task, CORRECT[task])
    learning.submit_answer(ALICE, s, "t3", "it printed some unrelated page")
    solution = learning.reveal_solution(ALICE, s, "t3").solution
    commands = [p.command for p in solution.parts if p.command]
    assert any("docker run" in c for c in commands) and any("curl -H" in c for c in commands)
    assert all(p.source_ids for p in solution.parts)


# -- completion and scoring ------------------------------------------------------------
def finish_all(learning: LearningService, s: uuid.UUID) -> SessionView:
    view = learning.get(ALICE, s)
    for task in ("t1", "t2", "t3", "t4", "t5"):
        view = learning.submit_answer(ALICE, s, task, CORRECT[task]).session
    return view


def test_completing_requires_every_task(learning: LearningService) -> None:
    s = sid(begin(learning))
    with pytest.raises(ConflictError, match="Finish every task"):
        learning.complete(ALICE, s)
    learning.submit_answer(ALICE, s, "t1", CORRECT["t1"])
    with pytest.raises(ConflictError):
        learning.complete(ALICE, s)


def test_a_full_run_completes_with_a_perfect_score(learning: LearningService) -> None:
    s = sid(begin(learning))
    view = finish_all(learning, s)
    assert view.can_complete and view.progress.percent == 100 and view.current_task_id is None
    done = learning.complete(ALICE, s)
    assert done.status == "completed" and done.completed_at is not None
    assert done.score == 100 and done.hints_used == 0 and not done.solution_revealed
    with pytest.raises(ConflictError, match="ended"):
        learning.submit_answer(ALICE, s, "t1", "anything at all")
    with pytest.raises(ConflictError):
        learning.start(ALICE, s)


def test_score_reflects_hints_and_solutions(learning: LearningService) -> None:
    s = sid(begin(learning))
    learning.reveal_hint(ALICE, s, "t1", 1)  # -5
    learning.submit_answer(ALICE, s, "t1", CORRECT["t1"])
    learning.reveal_hint(ALICE, s, "t2", 1)  # -5
    learning.reveal_hint(ALICE, s, "t2", 2)  # -10
    learning.submit_answer(ALICE, s, "t2", "wrong wrong wrong")
    learning.reveal_solution(ALICE, s, "t2")  # -30
    view = learning.get(ALICE, s)
    assert view.score == 100 - 5 - 5 - 10 - 30 and view.hints_used == 3 and view.solution_revealed


def test_scoring_is_configurable_and_fixed_per_session(
    make_learning: Callable[..., LearningService],
) -> None:
    custom = make_learning(
        LearningConfig(
            scoring=ScoringConfig(start=50, hint_penalties=(1, 2, 3), solution_penalty=7)
        )
    )
    s = sid(begin(custom))
    assert custom.reveal_hint(ALICE, s, "t1", 1).session.score == 49
    later = make_learning(LearningConfig())  # the server's rules change afterwards
    assert later.get(ALICE, s).max_score == 50
    assert later.reveal_hint(ALICE, s, "t1", 2).session.score == 47  # the session keeps its own


def test_the_score_never_drops_below_zero(
    make_learning: Callable[..., LearningService],
) -> None:
    harsh = make_learning(LearningConfig(scoring=ScoringConfig(start=10, solution_penalty=50)))
    s = sid(begin(harsh))
    harsh.submit_answer(ALICE, s, "t1", "nothing useful in here")
    assert harsh.reveal_solution(ALICE, s, "t1").session.score == 0


def test_abandoning_ends_the_session(learning: LearningService) -> None:
    s = sid(begin(learning))
    view = learning.abandon(ALICE, s)
    assert view.status == "abandoned"
    with pytest.raises(ConflictError):
        learning.reveal_hint(ALICE, s, "t1", 1)
    fresh = learning.create(ALICE, CVE_ID, client_key=CLIENT)  # a new one can be started
    assert fresh.id != view.id and fresh.status == "not_started"
    assert learning.latest_for_cve(ALICE, CVE_ID).id == fresh.id


# -- isolation -------------------------------------------------------------------------
def test_sessions_are_private_to_their_learner(learning: LearningService) -> None:
    s = sid(begin(learning))
    for call in (
        lambda: learning.get(BOB, s),
        lambda: learning.start(BOB, s),
        lambda: learning.hints(BOB, s),
        lambda: learning.reveal_hint(BOB, s, "t1", 1),
        lambda: learning.submit_answer(BOB, s, "t1", "some answer words"),
        lambda: learning.reveal_solution(BOB, s, "t1"),
        lambda: learning.complete(BOB, s),
        lambda: learning.abandon(BOB, s),
        lambda: learning.tutor_history(BOB, s),
        lambda: learning.ask_tutor(BOB, s, "Why does this happen?", None, client_key=CLIENT),
    ):
        with pytest.raises(NotFoundError):
            call()
    with pytest.raises(NotFoundError):
        learning.get(ALICE, uuid.uuid4())
    with pytest.raises(NotFoundError):
        learning.latest_for_cve(BOB, CVE_ID)


def test_a_session_is_a_snapshot_regenerating_the_guide_does_not_change_it(
    learning: LearningService,
    service: ResearchService,
    rclock,  # type: ignore[no-untyped-def]
    queue,  # type: ignore[no-untyped-def]
) -> None:
    s = sid(begin(learning))
    before = learning.get(ALICE, s).model_dump()
    rclock.advance(10_000)
    service.request(CVE_ID, client_key="other", refresh=True)
    queue.drain()
    assert learning.get(ALICE, s).model_dump() == before


# -- limits ----------------------------------------------------------------------------
def test_starting_sessions_is_rate_limited_per_client(
    make_learning: Callable[..., LearningService],
) -> None:
    learning = make_learning(LearningConfig(sessions_per_client_per_hour=2))
    for user in ("u-one-0123456789abcdefghij", "u-two-0123456789abcdefghij"):
        learning.create(user, CVE_ID, client_key="same-client")
    with pytest.raises(RateLimitedError):
        learning.create("u-three-0123456789abcdefghi", CVE_ID, client_key="same-client")
    learning.create(ALICE, CVE_ID, client_key="different-client")


def test_disabled_learning_is_refused(make_learning: Callable[..., LearningService]) -> None:
    from app.services import LearningDisabledError

    learning = make_learning(LearningConfig(enabled=False))
    with pytest.raises(LearningDisabledError):
        learning.create(ALICE, CVE_ID, client_key=CLIENT)
