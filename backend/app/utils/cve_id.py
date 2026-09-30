"""CVE identifier validation (format: CVE-YYYY-NNNN, with 4 to 19 sequence digits)."""

import re

CVE_ID_PATTERN = r"^CVE-[0-9]{4}-[0-9]{4,19}$"  # [0-9], not \d: \d matches non-ASCII digits
_CVE_ID_RE = re.compile(CVE_ID_PATTERN)


def normalize_cve_id(value: str) -> str | None:
    """Return the canonical upper-case CVE ID, or None when the value is not a valid one."""
    candidate = value.strip().upper()
    return candidate if _CVE_ID_RE.fullmatch(candidate) else None
