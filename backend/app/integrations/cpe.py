"""Minimal CPE 2.3 formatted-string parser (used to derive vendor/product/version from NVD)."""

import re
from dataclasses import dataclass

_SPLIT = re.compile(r"(?<!\\):")
_UNESCAPE = re.compile(r"\\(.)")
# CPE 2.3 components: unreserved characters, wildcards, or a backslash-escaped character.
_COMPONENT = re.compile(r"(?:[A-Za-z0-9_.~*?\-]|\\.)*")


@dataclass(frozen=True)
class CPE:
    part: str  # "a" application, "o" operating system, "h" hardware
    vendor: str | None
    product: str | None
    version: str | None  # None means "any" (*) or "not applicable" (-)
    update: str | None


def _field(raw: str) -> str | None:
    if raw in {"*", "-", ""}:
        return None
    return _UNESCAPE.sub(r"\1", raw)


def parse_cpe23(criteria: object) -> CPE | None:
    if not isinstance(criteria, str) or len(criteria) > 400:
        return None
    parts = _SPLIT.split(criteria)
    if (
        len(parts) != 13
        or parts[0] != "cpe"
        or parts[1] != "2.3"
        or parts[2] not in {"a", "o", "h"}
    ):
        return None
    if not all(_COMPONENT.fullmatch(part) for part in parts[3:]):
        return None  # e.g. an unescaped "<" or quote: not a well-formed CPE
    return CPE(
        part=parts[2],
        vendor=_field(parts[3]),
        product=_field(parts[4]),
        version=_field(parts[5]),
        update=_field(parts[6]),
    )
