"""CVSS qualitative severity helpers (FIRST.org rating scales)."""

from typing import get_args

from app.schemas.cve import Severity

_VALID = frozenset(get_args(Severity))


def normalize_severity(value: object) -> Severity | None:
    if isinstance(value, str) and value.strip().upper() in _VALID:
        return value.strip().upper()  # type: ignore[return-value]
    return None


def severity_from_score(score: float, version: str) -> Severity:
    """Derive the rating band from a base score (v2 has no NONE/CRITICAL bands)."""
    if version.startswith("2"):
        return "LOW" if score < 4.0 else "MEDIUM" if score < 7.0 else "HIGH"
    if score == 0:
        return "NONE"
    if score < 4.0:
        return "LOW"
    if score < 7.0:
        return "MEDIUM"
    return "HIGH" if score < 9.0 else "CRITICAL"
