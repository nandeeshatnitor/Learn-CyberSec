"""Checking a student's text answer against a task's key points.

Deliberately transparent and offline: each key point lists the phrases (or a set of concept words)
that show the student has it. An answer is correct when every required point is present, partially
correct when some point is, and incorrect otherwise. Feedback names what was found and describes
what is missing *by label only*: it never echoes the expected answer.
"""

from dataclasses import dataclass
from typing import Literal

from app.learning.schema import KeyPoint, Task
from app.learning.text import phrase_in, tokens, words_in

Result = Literal["correct", "partially_correct", "incorrect"]


@dataclass(frozen=True)
class Grade:
    result: Result
    matched: list[KeyPoint]
    missing: list[KeyPoint]


def satisfied(point: KeyPoint, answer_tokens: list[str]) -> bool:
    if any(phrase_in(phrase, answer_tokens) for phrase in point.phrases):
        return True
    if point.words:
        return words_in(point.words, answer_tokens) >= min(point.min_words, len(point.words))
    return False


def grade(task: Task, answer: str) -> Grade:
    answer_tokens = tokens(answer)
    matched = [p for p in task.key_points if satisfied(p, answer_tokens)]
    missing = [p for p in task.key_points if p not in matched]
    required = [p for p in task.key_points if p.required]
    if not task.key_points:
        return Grade("incorrect", [], [])
    if all(p in matched for p in required) and matched:
        return Grade("correct", matched, missing)
    if matched:
        return Grade("partially_correct", matched, missing)
    return Grade("incorrect", matched, missing)


def _join(labels: list[str]) -> str:
    if len(labels) <= 1:
        return "".join(labels)
    return ", ".join(labels[:-1]) + " and " + labels[-1]


def feedback(task: Task, result: Grade, *, hints_left: int, source_titles: list[str]) -> str:
    """Educational feedback that never reveals the expected answer."""
    read = f" Re-read {_join(source_titles[:2])}" if source_titles else " Re-read the sources"
    if result.result == "correct":
        got = _join([p.label for p in result.matched])
        return f"Correct. Your answer covers {got}. Compare it with what the sources say below."
    if result.result == "partially_correct":
        got = _join([p.label for p in result.matched])
        need = _join(
            [p.label for p in result.missing if p.required] or [p.label for p in result.missing]
        )
        nudge = " Ask for a hint if you are stuck." if hints_left else ""
        return (
            f"You are partly there: you have covered {got}. Still missing: {need}.{read} "
            f"with that in mind, then refine your answer.{nudge}"
        )
    nudge = " A hint can point you in the right direction." if hints_left else ""
    return (
        "That does not match what the sources describe for this task."
        f"{read} looking for: {task.objective.rstrip('.').lower()}.{nudge}"
    )
