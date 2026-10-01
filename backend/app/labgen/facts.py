"""Affected-version identification and other facts, extracted from the guide and the CVE record.

Everything here is *derived from text that came from third parties*, so it is treated as untrusted:
patterns are narrow, results are re-validated by `sanitize`, and every fact keeps the sources and the
excerpt it rests on so a reviewer can check it. Nothing is guessed: when a fact is not documented it
stays `None`, and a blueprint that needs it declines to generate (the candidate becomes spec-only).
"""

import re
from collections import Counter
from dataclasses import dataclass, field
from typing import Any

from app.labgen import sanitize
from app.labgen.spec import DocumentedArtifact, Evidence
from app.research.synthesis.schema import Claim, LearningGuide

_V = r"([0-9]+(?:\.[0-9]+){1,3}[a-z]{0,3}[0-9]{0,3})"
_THROUGH = re.compile(rf"\b{_V}\s+(?:through|thru|up to and including|to|-)\s+{_V}\b", re.I)
_EARLIER = re.compile(rf"\b{_V}\s+(?:and|or)\s+(?:earlier|prior|below|before|older)\b", re.I)
_BEFORE = re.compile(rf"\b(?:before|prior to|earlier than)\s+(?:version\s+)?{_V}\b", re.I)
_RELATION = re.compile(rf"\b{_V}\s*(<=|<)\s*version\s*(<=|<)\s*{_V}\b", re.I)
_FIXED = re.compile(
    rf"\b(?:upgrade to|update to|upgrading to|fixed in|patched in|fix(?:ed)? version is)\s+"
    rf"(?:[A-Za-z][A-Za-z0-9._-]*\s+)?(?:version\s+)?{_V}\b",
    re.I,
)
_NOT_AFFECTED_FROM = re.compile(rf"\bversion\s+{_V}\s+and\s+later\s+are\s+not\s+affected\b", re.I)
_HEADER_NAME = re.compile(r"\bX-[A-Za-z][A-Za-z0-9]*(?:-[A-Za-z0-9]+){0,3}\b")
_URL_PATH = re.compile(r"https?://[^\s/'\"]+(/[A-Za-z0-9_-]+)")
_DOCKER_IMAGE = re.compile(r"\bdocker\s+run\b[^\n]*?\s([a-z0-9._-]+/[a-z0-9._-]+:[A-Za-z0-9._-]+)")
_PROBE_RESULT = re.compile(r"\bnumber\s+([0-9]{1,6})\b", re.I)

_NOT_PRODUCTS = {"version", "versions", "cve", "release", "build", "update", "patch", "upgrade"}
_EXPRESSION_WORDS = (
    "template injection",
    "expression injection",
    "expression language",
    "evaluates expressions",
    "evaluating expressions",
    "template engine",
    "expression evaluation",
)
_TRAVERSAL_WORDS = ("path traversal", "directory traversal", "../", "dot-dot")
EXPRESSION_CWES = {"CWE-94", "CWE-95", "CWE-917", "CWE-1336"}
TRAVERSAL_CWES = {"CWE-22", "CWE-23", "CWE-35", "CWE-36"}


@dataclass(frozen=True)
class VersionRange:
    start: str | None
    start_inclusive: bool
    end: str | None
    end_inclusive: bool
    source_ids: tuple[str, ...] = ()

    def describe(self) -> str:
        if self.start and self.end:
            low = "<=" if self.start_inclusive else "<"
            high = "<=" if self.end_inclusive else "<"
            return f"{self.start} {low} version {high} {self.end}"
        if self.end:
            return f"version {'<=' if self.end_inclusive else '<'} {self.end}"
        return f"version >= {self.start}" if self.start else "unspecified"


@dataclass
class GuideFacts:
    cve_id: str
    description: str
    cwes: list[str]
    vendor: str | None = None
    product: str | None = None
    ranges: list[VersionRange] = field(default_factory=list)
    vulnerable_version: str | None = None
    vulnerable_basis: str = ""
    vulnerable_evidence: list[Evidence] = field(default_factory=list)
    fixed_version: str | None = None
    fixed_evidence: list[Evidence] = field(default_factory=list)
    workaround: str | None = None
    headers: list[str] = field(default_factory=list)
    endpoints: list[str] = field(default_factory=list)
    probe_result: str | None = None
    keywords: set[str] = field(default_factory=set)
    artifacts: list[DocumentedArtifact] = field(default_factory=list)
    product_from_text: bool = False  # not in the stored record; read from the guide's text
    text: str = ""  # lower-cased claim text, for classification


def _claims(guide: LearningGuide) -> list[Claim]:
    out: list[Claim] = [*guide.summary, *guide.affected_versions, *guide.root_cause]
    out += [*guide.prerequisites, *guide.why_it_works, *guide.impact, *guide.remediation]
    if guide.vulnerability_class is not None:
        out.append(guide.vulnerability_class)
    return out


def _excerpt(text: str, match: re.Match[str]) -> str:
    start = max(0, match.start() - 60)
    return " ".join(text[start : match.end() + 60].split())[:400]


_NEGATED = re.compile(
    r"\bnot (?:affected|vulnerable)\b|\bunaffected\b|\bare not\b|\bis not\b", re.I
)
_SENTENCES = re.compile(r"(?<=[.!?])\s+")
_PRODUCT_BEFORE_VERSION = re.compile(
    r"\b([A-Z][A-Za-z0-9]{2,30})\s+(?:versions?\s+)?[0-9]+\.[0-9]+"
)


def parse_ranges(text: str, source_ids: tuple[str, ...] = ()) -> list[tuple[VersionRange, str]]:
    """Version ranges stated as *affected*, each with the excerpt it came from. A sentence that
    says versions are NOT affected ("versions before 4.0.0 ... are not affected") is skipped."""
    found: list[tuple[VersionRange, str]] = []
    for sentence in _SENTENCES.split(text):
        if not _NEGATED.search(sentence):
            found.extend(_parse_sentence(sentence, source_ids))
    return found


def _parse_sentence(text: str, source_ids: tuple[str, ...]) -> list[tuple[VersionRange, str]]:
    found: list[tuple[VersionRange, str]] = []
    for m in _RELATION.finditer(text):
        low, high = sanitize.version(m.group(1)), sanitize.version(m.group(4))
        if low and high:
            found.append(
                (
                    VersionRange(low, m.group(2) == "<=", high, m.group(3) == "<=", source_ids),
                    _excerpt(text, m),
                )
            )
    for m in _THROUGH.finditer(text):
        low, high = sanitize.version(m.group(1)), sanitize.version(m.group(2))
        if low and high and sanitize.version_key(low) <= sanitize.version_key(high):
            found.append((VersionRange(low, True, high, True, source_ids), _excerpt(text, m)))
    for m in _EARLIER.finditer(text):
        high = sanitize.version(m.group(1))
        if high:
            found.append((VersionRange(None, False, high, True, source_ids), _excerpt(text, m)))
    for m in _BEFORE.finditer(text):
        high = sanitize.version(m.group(1))
        if high:
            found.append((VersionRange(None, False, high, False, source_ids), _excerpt(text, m)))
    return found


def _version_in(version: str, r: VersionRange) -> bool:
    key = sanitize.version_key(version)
    if r.start and (
        key < sanitize.version_key(r.start)
        or (key == sanitize.version_key(r.start) and not r.start_inclusive)
    ):
        return False
    if r.end:
        end = sanitize.version_key(r.end)
        return key <= end if r.end_inclusive else key < end
    return True


def extract_facts(guide: LearningGuide, cve_row: Any | None) -> GuideFacts:
    """Facts for a candidate. `cve_row` is the stored CVE record (or None when unavailable)."""
    description = (getattr(cve_row, "description", None) or "")[:2000]
    cwes = [str(c) for c in (getattr(cve_row, "cwes", None) or [])]
    facts = GuideFacts(cve_id=guide.cve_id, description=description, cwes=cwes)

    # -- product, from the stored record (statements are per provider; prefer the first) -----
    for entry in getattr(cve_row, "affected_products", None) or []:
        if not isinstance(entry, dict):
            continue
        name = sanitize.product(entry.get("product"))
        if name:
            facts.product = name
            facts.vendor = sanitize.product(entry.get("vendor"))
            for v in entry.get("versions") or []:
                if not isinstance(v, dict) or v.get("status", "affected") != "affected":
                    continue
                low = v.get("start_including") or v.get("start_excluding")
                high = v.get("end_including") or v.get("end_excluding")
                if low or high:
                    facts.ranges.append(
                        VersionRange(
                            sanitize.version(low),
                            bool(v.get("start_including")),
                            sanitize.version(high),
                            bool(v.get("end_including")),
                        )
                    )
            break

    # -- ranges, fixed version, workaround, from the guide's claims ----------------------------
    texts: list[str] = []
    stated_vulnerable: list[tuple[str, Claim, str]] = []
    for claim in _claims(guide):
        texts.append(claim.text)
        ids = tuple(claim.source_ids)
        for r, excerpt in parse_ranges(claim.text, ids):
            facts.ranges.append(r)
            if r.end and r.end_inclusive:
                stated_vulnerable.append((r.end, claim, excerpt))
    for claim in guide.remediation:
        fixed_match = _FIXED.search(claim.text) or _NOT_AFFECTED_FROM.search(claim.text)
        fixed = sanitize.version(fixed_match.group(1)) if fixed_match else None
        if fixed_match and fixed and facts.fixed_version is None:
            facts.fixed_version = fixed
            facts.fixed_evidence = [
                Evidence(
                    source_ids=list(claim.source_ids), excerpt=_excerpt(claim.text, fixed_match)
                )
            ]
        if "disable" in claim.text.lower() and facts.workaround is None:
            facts.workaround = claim.text[:300]
    if facts.fixed_version is None:
        for claim in guide.affected_versions:
            m = _NOT_AFFECTED_FROM.search(claim.text) or re.search(
                rf"\b{_V}\s+and\s+later\s+are\s+not\s+affected\b", claim.text, re.I
            )
            if m and sanitize.version(m.group(1)):
                facts.fixed_version = sanitize.version(m.group(1))
                facts.fixed_evidence = [
                    Evidence(source_ids=list(claim.source_ids), excerpt=_excerpt(claim.text, m))
                ]

    # -- documented artifacts and the reproduction's concrete details ---------------------------
    commands: list[tuple[str, tuple[str, ...]]] = []
    for step in guide.reproduction.steps:
        if step.command:
            commands.append((step.command, tuple(step.source_ids)))
        texts.append(step.step)
    for obs in guide.reproduction.expected_observation:
        texts.append(obs.text)
        m = _PROBE_RESULT.search(obs.text)
        if m and facts.probe_result is None:
            facts.probe_result = m.group(1)
    for command, ids in commands:
        image = _DOCKER_IMAGE.search(command)
        if image:
            facts.artifacts.append(
                DocumentedArtifact(
                    kind="docker_image",
                    value=image.group(1)[:300],
                    source_ids=list(ids),
                    note="Documented by the sources. Not pulled or run: a third-party image is never "
                    "executed by this platform; the candidate is a minimal educational reproduction.",
                )
            )
        else:
            facts.artifacts.append(
                DocumentedArtifact(
                    kind="command",
                    value=" ".join(command.split())[:300],
                    source_ids=list(ids),
                    note="A command from the sources, kept for the reviewer. Never executed.",
                )
            )

    # -- the representative vulnerable version ---------------------------------------------------
    image_versions = []
    for a in facts.artifacts:
        if a.kind == "docker_image":
            tag = sanitize.version(a.value.rsplit(":", 1)[-1])
            if tag:
                image_versions.append((tag, a))
    candidates: list[tuple[str, Claim, str]] = []
    for raw, claim, excerpt in stated_vulnerable:
        clean = sanitize.version(raw)
        if clean:
            candidates.append((clean, claim, excerpt))
    if candidates:
        v, claim, excerpt = max(candidates, key=lambda t: sanitize.version_key(t[0]))
        facts.vulnerable_version = v
        facts.vulnerable_basis = "the highest version the sources state as affected"
        facts.vulnerable_evidence = [Evidence(source_ids=list(claim.source_ids), excerpt=excerpt)]
    elif image_versions and any(_version_in(v, r) for v, _ in image_versions for r in facts.ranges):
        v, art = image_versions[0]
        facts.vulnerable_version = v
        facts.vulnerable_basis = "the version of the vulnerable test image the sources document"
        facts.vulnerable_evidence = [Evidence(source_ids=art.source_ids, excerpt=art.value)]
    else:
        starts = [r.start for r in facts.ranges if r.start and r.start_inclusive]
        if starts:
            facts.vulnerable_version = min(starts, key=sanitize.version_key)
            facts.vulnerable_basis = "the first version of the documented affected range"
    # A vulnerable version at or after the fix is a contradiction: drop it rather than ship it.
    if (
        facts.vulnerable_version
        and facts.fixed_version
        and sanitize.version_key(facts.vulnerable_version)
        >= sanitize.version_key(facts.fixed_version)
    ):
        facts.vulnerable_version = None
        facts.vulnerable_basis = "conflicts with the documented fixed version"

    if facts.product is None:
        # Not in the stored record: accept a name only when several claims agree on it.
        names = Counter(
            sanitize.product(n)
            for t in texts
            for n in _PRODUCT_BEFORE_VERSION.findall(t)
            if sanitize.product(n) and n.lower() not in _NOT_PRODUCTS
        )
        if names:
            name, count = names.most_common(1)[0]
            if name and count >= 3:
                facts.product = name
                facts.product_from_text = True

    # -- header and endpoint names the reproduction uses ------------------------------------------
    blob = "\n".join(texts + [c for c, _ in commands])
    counted = Counter(h for h in _HEADER_NAME.findall(blob) if sanitize.header(h))
    facts.headers = [h for h, _ in counted.most_common(3)]
    path_counts = Counter(
        p for c, _ in commands for p in _URL_PATH.findall(c) if sanitize.endpoint(p)
    )
    facts.endpoints = [p for p, _ in path_counts.most_common(3)]

    lowered = "\n".join(texts + [description]).lower()
    facts.text = lowered
    if any(w in lowered for w in _EXPRESSION_WORDS) or EXPRESSION_CWES & set(cwes):
        facts.keywords.add("expression_injection")
    if any(w in lowered for w in _TRAVERSAL_WORDS) or TRAVERSAL_CWES & set(cwes):
        facts.keywords.add("path_traversal")
    return facts
