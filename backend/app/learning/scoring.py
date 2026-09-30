"""A simple, configurable score. Not the point of the exercise: it starts at 100, hints and solutions
cost a little, and it never goes below zero. The rules are copied into each session when it starts,
so changing configuration never re-scores a session in progress."""

from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class ScoringConfig:
    start: int = 100
    hint_penalties: tuple[int, int, int] = (5, 10, 15)
    solution_penalty: int = 30

    def hint_penalty(self, number: int) -> int:
        return self.hint_penalties[number - 1]

    def as_dict(self) -> dict[str, Any]:
        return {
            "start": self.start,
            "hint_penalties": list(self.hint_penalties),
            "solution_penalty": self.solution_penalty,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "ScoringConfig":
        raw = data.get("hint_penalties") or [5, 10, 15]
        if not isinstance(raw, list) or len(raw) != 3:
            raw = [5, 10, 15]
        first, second, third = (int(x) for x in raw)
        return cls(
            start=int(data.get("start", 100)),
            hint_penalties=(first, second, third),
            solution_penalty=int(data.get("solution_penalty", 30)),
        )


def compute_score(config: ScoringConfig, *, hints: list[int], solutions: int) -> int:
    """`hints` is the number of every hint revealed (1, 2 or 3); one entry per reveal."""
    penalty = sum(config.hint_penalty(n) for n in hints) + solutions * config.solution_penalty
    return max(0, config.start - penalty)
