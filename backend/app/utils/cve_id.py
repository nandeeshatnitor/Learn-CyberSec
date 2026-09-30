"""CVE identifier validation (format: CVE-YYYY-NNNN, with 4 to 19 sequence digits)."""

import re

CVE_ID_PATTERN = r"^CVE-[0-9]{4}-[0-9]{4,19}$"  # [0-9], not \d: \d matches non-ASCII digits
_CVE_ID_RE = re.compile(CVE_ID_PATTERN)


def normalize_cve_id(value: str) -> str | None:
    """Return the canonical upper-case CVE ID, or None when the value is not a valid one."""
    candidate = value.strip().upper()
    return candidate if _CVE_ID_RE.fullmatch(candidate) else None


# "CVE", "CVE-", "CVE-2024", "CVE-2024-", "CVE-2024-12", ... (a prefix of a valid ID)
_PARTIAL_RE = re.compile(r"^CVE(?:-(?:[0-9]{1,4}(?:-[0-9]{0,19})?)?)?$")
# "2024-1234" without the CVE- prefix
_BARE_PARTIAL_RE = re.compile(r"^[0-9]{4}-[0-9]{1,19}$")


def normalize_partial_cve_id(value: str) -> str | None:
    """Return the canonical upper-case prefix for a partially typed CVE ID, else None."""
    candidate = value.strip().upper()
    if _BARE_PARTIAL_RE.fullmatch(candidate):
        candidate = f"CVE-{candidate}"
    return candidate if _PARTIAL_RE.fullmatch(candidate) else None
