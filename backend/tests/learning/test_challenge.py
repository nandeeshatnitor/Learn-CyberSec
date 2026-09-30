"""Challenge structure, hint ladder (no leaks), redaction, answer grading and scoring."""

import pytest

from app.learning.challenge import build_challenge
from app.learning.rubric import feedback, grade
from app.learning.scoring import ScoringConfig, compute_score
from app.learning.text import contains_phrase, mask, phrase_in, tokens
from app.research.synthesis.builder import build_guide
from app.research.synthesis.schema import LearningGuide
from tests.research.support import fictional_record, gather_pack


@pytest.fixture(scope="module")
def guide() -> LearningGuide:
    return build_guide(gather_pack(), llm=None, generation_version="2")


@pytest.fixture(scope="module")
def challenge(guide: LearningGuide):  # type: ignore[no-untyped-def]
    assert guide.challenge is not None
    return guide.challenge


def task(challenge, kind: str):  # type: ignore[no-untyped-def]
    return next(t for t in challenge.tasks if t.kind == kind)


# -- structure -------------------------------------------------------------------------
def test_every_guide_carries_a_challenge(guide: LearningGuide) -> None:
    c = guide.challenge
    assert c is not None
    assert c.learning_objectives and c.prerequisites and c.tasks
    assert [t.kind for t in c.tasks] == [
        "identify_component",
        "identify_input",
        "reproduce",
        "explain_cause",
        "identify_remediation",
    ]
    assert [t.id for t in c.tasks] == ["t1", "t2", "t3", "t4", "t5"]
    assert len(c.learning_objectives) == len(c.tasks)


def test_each_task_has_criteria_three_hints_and_a_cited_solution(challenge) -> None:  # type: ignore[no-untyped-def]
    for t in challenge.tasks:
        assert t.verification_criteria and t.key_points and t.solution
        assert [h.number for h in t.hints] == [1, 2, 3]
        assert all(part.source_ids for part in t.solution)
        assert t.hints[2].source_ids


def test_a_lab_prerequisite_accompanies_the_reproduction_task(challenge) -> None:  # type: ignore[no-untyped-def]
    assert any("local or authorized lab" in p.text for p in challenge.prerequisites)


def test_tasks_without_evidence_are_left_out_and_explained(guide: LearningGuide) -> None:
    bare = guide.model_copy(deep=True)
    bare.root_cause = []
    bare.why_it_works = []
    bare.remediation = []
    bare.reproduction.status = "not_established"
    bare.reproduction.steps = []
    result = build_challenge(bare, fictional_record())
    kinds = {t.kind for t in result.tasks}
    assert "reproduce" not in kinds and "explain_cause" not in kinds
    assert "identify_remediation" not in kinds
    assert any("left out" in n for n in result.notes)
    assert [t.id for t in result.tasks] == [f"t{i}" for i in range(1, len(result.tasks) + 1)]


def test_the_challenge_is_redacted_for_browsers(challenge) -> None:  # type: ignore[no-untyped-def]
    public = challenge.redacted()
    blob = public.model_dump_json()
    for t in challenge.tasks:
        for h in t.hints:
            assert h.text not in blob
        for part in t.solution:
            assert part.text not in blob
            if part.command:
                assert part.command not in blob
    assert all(not t.key_points and not t.hints and not t.solution for t in public.tasks)
    assert public.tasks[0].prompt == challenge.tasks[0].prompt
    assert challenge.tasks[0].hints  # the original is untouched


# -- the hint ladder -------------------------------------------------------------------
def test_hints_one_and_two_never_contain_an_accepted_answer(challenge) -> None:  # type: ignore[no-untyped-def]
    for t in challenge.tasks:
        answers = [p for k in t.key_points if k.required for p in k.phrases if len(p) >= 3]
        for hint in t.hints[:2]:
            for phrase in answers:
                assert not contains_phrase(hint.text, phrase), (t.id, hint.number, phrase)


def test_hints_become_progressively_more_explicit(challenge) -> None:  # type: ignore[no-untyped-def]
    for t in challenge.tasks:
        h1, h2, h3 = t.hints
        assert (h1.kind, h3.kind) == ("direction", "explicit")
        assert h2.kind in ("masked", "direction")
        assert h1.text != h2.text != h3.text
        assert "█" not in h1.text and "█" not in h3.text
    component = task(challenge, "identify_component")
    assert "█" in component.hints[1].text  # masked
    assert "template engine" in component.hints[2].text.lower()  # revealed only at hint 3


def test_hint_one_does_not_reveal_the_solution_of_any_task(challenge) -> None:  # type: ignore[no-untyped-def]
    for t in challenge.tasks:
        for part in t.solution:
            assert part.text not in t.hints[0].text
            assert not part.command or part.command not in t.hints[0].text


def test_source_titles_that_would_leak_an_answer_are_replaced_by_ids() -> None:
    guide = build_guide(gather_pack(), llm=None, generation_version="2")
    assert guide.challenge
    for t in guide.challenge.tasks:
        for phrase in [p for k in t.key_points if k.required for p in k.phrases]:
            assert not contains_phrase(t.hints[0].text, phrase)


# -- text helpers ----------------------------------------------------------------------
def test_masking_and_matching_ignore_case_and_separators() -> None:
    assert mask("Send the X-Template-Hint header.", ["x template hint"]) == "Send the █████ header."
    assert contains_phrase("the X_Template.Hint value", "x template hint")
    assert phrase_in("template renderer", tokens("The renderers for templates"))  # stem tolerant
    assert not phrase_in("template renderer", tokens("the template"))


# -- grading ---------------------------------------------------------------------------
@pytest.mark.parametrize(
    ("kind", "answer", "expected"),
    [
        ("identify_component", "The template engine that renders the request.", "correct"),
        ("identify_component", "It is a problem in AcmeDocs.", "partially_correct"),
        ("identify_component", "The HTTP request parser.", "incorrect"),
        ("identify_input", "The X-Template-Hint request header.", "correct"),
        ("identify_input", "Some kind of header in the request", "partially_correct"),
        ("identify_input", "The username field of the login form", "incorrect"),
        ("reproduce", "The response body contained the number 49.", "correct"),
        ("reproduce", "I sent a request and it returned a page.", "incorrect"),
        (
            "explain_cause",
            "The renderer evaluates the template header without sanitizing it.",
            "correct",
        ),
        ("explain_cause", "Bad passwords.", "incorrect"),
        ("identify_remediation", "Upgrade to 4.2.4 or later.", "correct"),
        ("identify_remediation", "Disable the preview feature.", "correct"),
        ("identify_remediation", "Be more careful with servers.", "incorrect"),
    ],
)
def test_grading(challenge, kind: str, answer: str, expected: str) -> None:  # type: ignore[no-untyped-def]
    assert grade(task(challenge, kind), answer).result == expected


def test_feedback_never_reveals_the_expected_answer(challenge) -> None:  # type: ignore[no-untyped-def]
    for t in challenge.tasks:
        secrets = [p for k in t.key_points for p in k.phrases if len(p) >= 4]
        for answer in ("no idea at all here", "banana smoothie recipe", "the product AcmeDocs"):
            result = grade(t, answer)
            text = feedback(t, result, hints_left=3, source_titles=["A source"])
            if result.result != "correct":
                for phrase in secrets:
                    if phrase in tokens(answer) or phrase in ("acmedocs", "acme docs"):
                        continue
                    assert not contains_phrase(text, phrase), (t.id, phrase, text)


def test_partial_feedback_names_what_is_covered_and_what_is_missing(challenge) -> None:  # type: ignore[no-untyped-def]
    t = task(challenge, "identify_component")
    result = grade(t, "It is in AcmeDocs")
    text = feedback(t, result, hints_left=2, source_titles=[])
    assert "the affected product" in text and "specific module" in text


# -- scoring ---------------------------------------------------------------------------
def test_scoring_defaults_and_floor() -> None:
    cfg = ScoringConfig()
    assert compute_score(cfg, hints=[], solutions=0) == 100
    assert compute_score(cfg, hints=[1], solutions=0) == 95
    assert compute_score(cfg, hints=[1, 2, 3], solutions=0) == 70
    assert compute_score(cfg, hints=[1, 2, 3], solutions=1) == 40
    assert compute_score(cfg, hints=[3] * 10, solutions=5) == 0


def test_scoring_is_configurable_and_round_trips() -> None:
    cfg = ScoringConfig(start=50, hint_penalties=(1, 2, 3), solution_penalty=10)
    assert ScoringConfig.from_dict(cfg.as_dict()) == cfg
    assert compute_score(cfg, hints=[2], solutions=1) == 38
    assert ScoringConfig.from_dict({}) == ScoringConfig()
