"""Exact and near-duplicate detection for documents and passages."""

import hashlib
import re
from collections.abc import Sequence
from dataclasses import dataclass

_NON_WORD = re.compile(r"[^\w]+", re.UNICODE)
SHINGLE_SIZE = 5
NEAR_DUPLICATE_JACCARD = 0.8
CONTAINMENT_THRESHOLD = 0.9


def normalise(text: str) -> str:
    return _NON_WORD.sub(" ", text.lower()).strip()


def text_hash(text: str) -> str:
    return hashlib.sha256(normalise(text).encode()).hexdigest()


def shingles(text: str, size: int = SHINGLE_SIZE) -> frozenset[str]:
    words = normalise(text).split()
    if len(words) < size:
        return frozenset({" ".join(words)}) if words else frozenset()
    return frozenset(" ".join(words[i : i + size]) for i in range(len(words) - size + 1))


def jaccard(a: frozenset[str], b: frozenset[str]) -> float:
    if not a or not b:
        return 0.0
    return len(a & b) / len(a | b)


def containment(small: frozenset[str], large: frozenset[str]) -> float:
    return len(small & large) / len(small) if small else 0.0


@dataclass(frozen=True)
class DocumentFingerprint:
    text: str
    weight: float  # higher = preferred survivor (source reliability)


def find_duplicate_documents(docs: Sequence[DocumentFingerprint]) -> dict[int, int]:
    """Map duplicate index -> index of the document kept instead.

    Mirrors, syndicated copies and re-posts are near-identical, so counting them as separate sources
    would fake independent corroboration. The better (heavier, then longer) copy survives.
    """
    order = sorted(
        range(len(docs)), key=lambda i: (-docs[i].weight, -len(normalise(docs[i].text)), i)
    )
    kept: list[int] = []
    hashes: dict[str, int] = {}
    sets: dict[int, frozenset[str]] = {}
    duplicates: dict[int, int] = {}
    for index in order:
        digest = text_hash(docs[index].text)
        if digest in hashes:
            duplicates[index] = hashes[digest]
            continue
        current = shingles(docs[index].text)
        match = next(
            (
                k
                for k in kept
                if jaccard(current, sets[k]) >= NEAR_DUPLICATE_JACCARD
                or containment(current, sets[k]) >= CONTAINMENT_THRESHOLD
            ),
            None,
        )
        if match is not None:
            duplicates[index] = match
            continue
        kept.append(index)
        hashes[digest] = index
        sets[index] = current
    return duplicates
