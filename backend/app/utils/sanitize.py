"""Normalisation helpers for untrusted data received from external providers.

Provider payloads are attacker-influenced (anyone can publish a reference URL or write a CNA
description). Everything that leaves an adapter passes through these helpers: values are typed,
bounded, stripped of control/bidi characters, and URLs are restricted to plain http(s).
"""

import re
import unicodedata
from datetime import UTC, date, datetime
from typing import Any
from urllib.parse import urlsplit

from app.utils.text import strip_control_chars

MAX_URL_LENGTH = 2048

# Bidirectional overrides/isolates and zero-width characters can visually spoof text or URLs.
_INVISIBLE = re.compile("[​-‏‪-‮⁠-⁤⁦-⁩﻿]")
_CWE_RE = re.compile(r"^(?:CWE-[0-9]{1,6}|NVD-CWE-(?:Other|noinfo))$")
_CVSS_VECTOR_RE = re.compile(r"^(?:CVSS:[234]\.[01]/)?[A-Za-z0-9:/._-]{1,200}$")


def clean_text(value: Any, max_length: int = 5000) -> str | None:
    """Return printable, NFC-normalised text truncated to max_length, or None if empty/not text."""
    if not isinstance(value, str):
        return None
    text = unicodedata.normalize("NFC", _INVISIBLE.sub("", strip_control_chars(value))).strip()
    if not text:
        return None
    return text[:max_length]


def clean_url(value: Any) -> str | None:
    """Return the URL unchanged if it is an absolute http(s) URL, else None (never rewritten)."""
    if not isinstance(value, str):
        return None
    url = value.strip()
    if not url or len(url) > MAX_URL_LENGTH:
        return None
    if any(ord(ch) <= 0x20 or ord(ch) == 0x7F or _INVISIBLE.match(ch) for ch in url):
        return None
    try:
        parts = urlsplit(url)
    except ValueError:
        return None
    if parts.scheme.lower() not in {"http", "https"} or not parts.netloc or not parts.hostname:
        return None
    return url


def clean_cwe(value: Any) -> str | None:
    if not isinstance(value, str):
        return None
    candidate = value.strip()
    return candidate if _CWE_RE.fullmatch(candidate) else None


def clean_cvss_vector(value: Any) -> str | None:
    if not isinstance(value, str):
        return None
    candidate = value.strip()
    return candidate if _CVSS_VECTOR_RE.fullmatch(candidate) else None


def clean_score(value: Any) -> float | None:
    """CVSS base scores are 0.0-10.0; anything else (or a bool/string) is rejected."""
    if isinstance(value, bool) or not isinstance(value, int | float):
        return None
    score = float(value)
    return round(score, 1) if 0.0 <= score <= 10.0 else None


def clean_string_list(values: Any, *, max_items: int, max_length: int = 100) -> list[str]:
    if not isinstance(values, list):
        return []
    cleaned: list[str] = []
    for item in values[:max_items]:
        text = clean_text(item, max_length)
        if text and text not in cleaned:
            cleaned.append(text)
    return cleaned


def parse_datetime(value: Any) -> datetime | None:
    """Parse ISO-8601 timestamps; naive values are UTC (NVD and CVE Services omit the zone)."""
    if not isinstance(value, str) or not value.strip():
        return None
    text = value.strip()
    if text.endswith(("Z", "z")):
        text = text[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    return parsed.replace(tzinfo=UTC) if parsed.tzinfo is None else parsed.astimezone(UTC)


def parse_date(value: Any) -> date | None:
    parsed = parse_datetime(value)
    return parsed.date() if parsed else None
