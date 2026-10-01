"""Strict re-validation of every value that leaves the guide and enters a generated file.

The guide's claims were checked against retrieved sources, but those sources are untrusted web text.
A value only becomes part of generated code after passing one of these patterns; anything else is
dropped (the blueprint then falls back to its default or declines to generate).
"""

import re

_PRODUCT = re.compile(r"^[A-Za-z][A-Za-z0-9 ._+-]{0,38}[A-Za-z0-9]$")
_VERSION = re.compile(r"^[0-9]{1,4}(\.[0-9]{1,4}){1,3}([a-z]{1,3}[0-9]{0,3})?$")
_HEADER = re.compile(r"^X-[A-Za-z][A-Za-z0-9]*(-[A-Za-z0-9]+){0,3}$")
_PATH = re.compile(r"^/[a-z][a-z0-9_-]{0,30}$")
_PARAM = re.compile(r"^[a-z][a-z0-9_]{0,23}$")
_EXPRESSION = re.compile(r"^[0-9]{1,3}( ?[-+*] ?[0-9]{1,3}){1,2}$")
_FAMILY = re.compile(r"^cve-[0-9]{4}-[0-9]{4,19}$")
_NOTE = re.compile(r"^[\x20-\x7e\n]{0,2000}$")


def product(value: str | None) -> str | None:
    if value is None:
        return None
    value = " ".join(value.split())
    return value if _PRODUCT.match(value) else None


def version(value: str | None) -> str | None:
    if value is None:
        return None
    value = value.strip().lower().rstrip(".")
    return value if _VERSION.match(value) else None


def header(value: str | None) -> str | None:
    return value if value and _HEADER.match(value) else None


def endpoint(value: str | None) -> str | None:
    return value if value and _PATH.match(value) else None


def parameter(value: str | None) -> str | None:
    return value if value and _PARAM.match(value) else None


def expression(value: str | None) -> str | None:
    """A tiny integer expression (e.g. 7*7), the only kind a blueprint's evaluator accepts."""
    return value if value and _EXPRESSION.match(value) else None


def family_of(cve_id: str) -> str | None:
    family = cve_id.lower()
    return family if _FAMILY.match(family) else None


def version_key(value: str) -> tuple[int, ...]:
    """Numeric ordering key for dotted versions ('4.2.10' > '4.2.3')."""
    return tuple(int(part) for part in re.findall(r"[0-9]+", value))


def review_note(value: str) -> str | None:
    value = value.strip()
    return value if 3 <= len(value) <= 2000 and _NOTE.match(value) else None
