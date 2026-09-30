"""Shared clean-up applied to blocks from every extractor."""

import re

from app.research.domain import Block
from app.utils.sanitize import clean_text

MAX_BLOCK_CHARS = 3000
MAX_CODE_CHARS = 800
MAX_CODE_LINES = 25
MAX_BLOCKS = 4000

_BOILERPLATE = re.compile(
    r"accept (all )?cookies|cookie (policy|settings|preferences)|we use cookies|subscribe to|"
    r"sign up for|newsletter|all rights reserved|copyright ©|©\s*\d{4}|share (this|on)|follow us|"
    r"privacy policy|terms of (use|service)|skip to (main )?content|back to top|"
    r"\b(log ?in|sign in|sign up|register)\b$|^(read more|menu|search|home)$|"
    r"powered by|this (site|website) uses",
    re.IGNORECASE,
)
_BLANKS = re.compile(r"\n{3,}")


def clean_paragraph(text: str) -> str | None:
    cleaned = clean_text(" ".join(text.split()), MAX_BLOCK_CHARS)
    return cleaned


def clean_code(text: str) -> str | None:
    lines = [line.rstrip() for line in text.splitlines()]
    cleaned = clean_text(_BLANKS.sub("\n\n", "\n".join(lines)).strip("\n"), MAX_BLOCK_CHARS)
    return cleaned


def is_boilerplate(text: str) -> bool:
    return len(text) < 160 and bool(_BOILERPLATE.search(text))


def finalize(blocks: list[Block], stats: dict[str, int]) -> list[Block]:
    """Drop boilerplate, oversized code (whole PoC scripts), empties and exact repeats."""
    result: list[Block] = []
    seen: set[tuple[str, str]] = set()
    for block in blocks:
        text = block.text
        if not text:
            continue
        if block.kind == "code":
            if len(text) > MAX_CODE_CHARS or text.count("\n") + 1 > MAX_CODE_LINES:
                stats["code_omitted"] = stats.get("code_omitted", 0) + 1
                continue
        elif is_boilerplate(text):
            stats["dropped_boilerplate"] = stats.get("dropped_boilerplate", 0) + 1
            continue
        key = (block.kind, text)
        if key in seen:
            continue
        seen.add(key)
        result.append(block)
        if len(result) >= MAX_BLOCKS:
            stats["truncated"] = 1
            break
    return result
