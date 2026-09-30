"""Helpers for handling untrusted text (user input and, later, external CVE content)."""

import re

# C0/C1 control characters except tab, newline and carriage return.
_CONTROL_CHARS = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f-\x9f]")


def strip_control_chars(value: str) -> str:
    return _CONTROL_CHARS.sub("", value)


def escape_like(value: str, escape: str = "\\") -> str:
    """Escape LIKE/ILIKE wildcards so user input is matched literally."""
    return value.replace(escape, escape * 2).replace("%", escape + "%").replace("_", escape + "_")
