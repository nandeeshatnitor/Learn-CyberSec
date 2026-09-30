"""Decide which documents and passages are technically about *this* CVE."""

import re
from dataclasses import dataclass, field

from app.research.domain import Block
from app.schemas.cve import CVERecord

_GENERIC = frozenset(
    {
        "software", "foundation", "project", "inc", "corp", "corporation", "ltd", "llc", "system",
        "systems", "server", "application", "app", "library", "framework", "core", "tools", "tool",
        "the", "and", "for", "with", "version", "versions", "windows", "linux", "web", "http",
        "data", "services", "service", "products", "product", "group", "open", "source",
    }
)  # fmt: skip

_CWE_KEYWORDS = {
    "CWE-20": ["input validation"], "CWE-22": ["path traversal", "directory traversal"],
    "CWE-78": ["command injection", "os command"], "CWE-79": ["cross-site scripting", "xss"],
    "CWE-89": ["sql injection"], "CWE-94": ["code injection"], "CWE-119": ["buffer", "memory"],
    "CWE-125": ["out-of-bounds read", "out of bounds"], "CWE-190": ["integer overflow"],
    "CWE-287": ["authentication"], "CWE-352": ["csrf", "cross-site request forgery"],
    "CWE-416": ["use after free", "use-after-free"], "CWE-434": ["file upload"],
    "CWE-502": ["deserialization", "deserialisation"], "CWE-611": ["xxe", "xml external entity"],
    "CWE-787": ["out-of-bounds write", "buffer overflow"], "CWE-862": ["authorization"],
    "CWE-863": ["authorization"], "CWE-918": ["ssrf", "server-side request forgery"],
    "CWE-917": ["expression language", "jndi", "lookup"],
}  # fmt: skip

_TECH_TERMS = re.compile(
    r"\b(?:vulnerab\w*|exploit\w*|payload|attacker|remote|arbitrary|injection|overflow|bypass|"
    r"traversal|deserializ\w*|sanitiz\w*|sanitis\w*|patch\w*|advisory|affected|version\w*|"
    r"proof[- ]of[- ]concept|poc|request|response|parameter|header|crafted|malicious|privilege|"
    r"authenticat\w*|execut\w*|disclos\w*|mitigat\w*|workaround|cve-\d{4}-\d{4,})\b",
    re.IGNORECASE,
)
_ANY_CVE = re.compile(r"\bCVE[-‐-― ]?\d{4}[-‐-― ]?\d{4,}\b", re.IGNORECASE)
_SEPARATORS = r"[-‐‑‒–—― ]?"


def _words(text: str | None) -> list[str]:
    return [w for w in re.split(r"[^a-z0-9]+", (text or "").lower()) if w]


@dataclass
class RelevanceContext:
    cve_id: str
    product_terms: set[str] = field(default_factory=set)  # e.g. {"log4j", "log4j2"}
    topic_terms: set[str] = field(default_factory=set)  # vulnerability-class words
    _cve_rx: re.Pattern[str] = field(init=False, repr=False)

    def __post_init__(self) -> None:
        _, year, number = self.cve_id.split("-")
        self._cve_rx = re.compile(
            rf"\bCVE{_SEPARATORS}{year}{_SEPARATORS}{number}\b", re.IGNORECASE
        )

    @classmethod
    def from_record(cls, record: CVERecord) -> "RelevanceContext":
        products: set[str] = set()
        for item in record.affected_products:
            for word in _words(f"{item.vendor or ''} {item.product or ''}"):
                if len(word) >= 3 and word not in _GENERIC and not word.isdigit():
                    products.add(word)
        topics: set[str] = set()
        for cwe in record.cwes:
            topics.update(_CWE_KEYWORDS.get(cwe.id, []))
            topics.update(w for w in _words(cwe.name) if len(w) >= 6 and w not in _GENERIC)
        if record.kev and record.kev.vulnerability_name:
            topics.update(w for w in _words(record.kev.vulnerability_name) if len(w) >= 6)
        return cls(cve_id=record.cve_id, product_terms=products, topic_terms=topics)

    def mentions_cve(self, text: str) -> bool:
        return bool(self._cve_rx.search(text))

    def product_hits(self, text: str) -> int:
        lowered = text.lower()
        return sum(1 for term in self.product_terms if term in lowered)

    def topic_hits(self, text: str) -> int:
        lowered = text.lower()
        return sum(1 for term in self.topic_terms if term in lowered)


@dataclass(frozen=True)
class DocumentRelevance:
    relevant: bool
    score: float
    reason: str


def score_document(text: str, ctx: RelevanceContext) -> DocumentRelevance:
    mentions = ctx.mentions_cve(text)
    products = ctx.product_hits(text)
    tech = len(_TECH_TERMS.findall(text))
    other_cves = {m.upper() for m in _ANY_CVE.findall(text)}
    score = (5.0 if mentions else 0.0) + 2.0 * min(products, 3) + 0.4 * min(tech, 10)
    if mentions:
        return DocumentRelevance(True, score, "mentions_cve")
    if len(other_cves) >= 3:
        return DocumentRelevance(False, score, "about_other_cves")
    if products and tech >= 3:
        return DocumentRelevance(True, score, "product_and_technical_content")
    return DocumentRelevance(False, score, "no_cve_or_product_match")


def score_passage(block: Block, section: str | None, ctx: RelevanceContext) -> float:
    text = block.text
    score = 0.0
    if ctx.mentions_cve(text):
        score += 3.0
    score += 1.5 * min(ctx.product_hits(text), 2)
    score += 0.8 * min(ctx.topic_hits(text), 2)
    score += 0.35 * min(len(_TECH_TERMS.findall(text)), 6)
    if section and (ctx.mentions_cve(section) or ctx.product_hits(section)):
        score += 0.6
    if block.kind == "code":
        score += 0.5
    if len(text) < 40 and block.kind != "code":
        score -= 1.0
    if block.kind == "quote":
        score -= 0.5
    return score
