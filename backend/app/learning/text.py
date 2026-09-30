"""Small text tools shared by the rubric, hint masking and the tutor's spoiler guard."""

import re
import unicodedata

_NON_WORD = re.compile(r"[^\w]+", re.UNICODE)
_CAMEL = re.compile(r"(?<=[a-z0-9])(?=[A-Z])")
STOPWORDS = frozenset(
    [
        "the",
        "a",
        "an",
        "and",
        "or",
        "of",
        "to",
        "in",
        "on",
        "for",
        "with",
        "from",
        "by",
        "at",
        "as",
        "is",
        "are",
        "was",
        "were",
        "be",
        "been",
        "this",
        "that",
        "these",
        "those",
        "it",
        "its",
        "into",
        "than",
        "then",
        "when",
        "which",
        "who",
        "while",
        "also",
        "can",
        "could",
        "may",
        "might",
        "must",
        "should",
        "will",
        "would",
        "has",
        "have",
        "had",
        "not",
        "only",
        "any",
        "all",
        "some",
        "such",
        "other",
        "more",
        "most",
        "both",
        "each",
        "their",
        "there",
        "they",
        "them",
        "you",
        "your",
        "vulnerability",
        "vulnerable",
        "allows",
        "allow",
        "attacker",
        "attackers",
        "because",
        "application",
        "server",
        "software",
        "version",
        "versions",
        "affected",
        "issue",
        "flaw",
        "bug",
        "does",
        "doing",
        "done",
        "being",
        "via",
        "using",
        "use",
        "used",
        "uses",
    ]
)


def normalise(text: str) -> str:
    text = unicodedata.normalize("NFKC", text).lower()
    return _NON_WORD.sub(" ", text).strip()


def tokens(text: str) -> list[str]:
    return normalise(text).split()


def stem(word: str) -> str:
    """A deliberately blunt stem: enough to match "rendering"/"renderer"/"renders"."""
    return word[:5] if len(word) >= 6 else word


def content_words(text: str, *, min_len: int = 5) -> list[str]:
    seen: dict[str, None] = {}
    for word in tokens(text):
        if len(word) >= min_len and word not in STOPWORDS and not word.isdigit():
            seen.setdefault(word)
    return list(seen)


def split_identifier(identifier: str) -> list[str]:
    """`TemplateRenderer.resolveHint()` -> the whole thing and its parts, as phrases."""
    cleaned = identifier.replace("()", "")
    parts = [p for p in re.split(r"[.\-_/:\s]+", cleaned) if p]
    out = [normalise(cleaned)]
    for part in parts:
        words = _CAMEL.sub(" ", part)
        out.append(normalise(part))
        if " " in words:
            out.append(normalise(words))
    return [p for p in dict.fromkeys(out) if len(p) >= 3]


def phrase_in(phrase: str, answer_tokens: list[str]) -> bool:
    """All words of `phrase` occur in the answer (any order, stem-tolerant)."""
    wanted = tokens(phrase)
    if not wanted:
        return False
    have = {stem(t) for t in answer_tokens}
    return all(stem(w) in have for w in wanted)


def words_in(words: list[str], answer_tokens: list[str]) -> int:
    have = {stem(t) for t in answer_tokens}
    return sum(1 for w in words if stem(normalise(w)) in have)


def _pattern(phrase: str) -> re.Pattern[str]:
    """Whole-word match where a space in the phrase also matches `-`, `_` or `.` in the text, so the
    normalised phrase "x template hint" finds "X-Template-Hint"."""
    body = r"[\s\-_.]+".join(re.escape(word) for word in phrase.split())
    return re.compile(rf"(?<![\w]){body}(?![\w])", re.IGNORECASE)


def mask(text: str, phrases: list[str], placeholder: str = "█████") -> str:
    """Replace every occurrence of a phrase (case-insensitive, whole words) with a placeholder."""
    out = text
    for phrase in sorted({p for p in phrases if len(p) >= 3}, key=len, reverse=True):
        out = _pattern(phrase).sub(placeholder, out)
    return out


def contains_phrase(text: str, phrase: str) -> bool:
    """Whole-word containment of a phrase in free text (used by leak checks)."""
    return bool(phrase.split()) and bool(_pattern(phrase).search(text))
