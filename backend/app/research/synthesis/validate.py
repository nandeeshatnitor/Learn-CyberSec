"""Turn a `GuideDraft` into a `LearningGuide` the platform is willing to publish.

The draft is treated as an untrusted proposal, whoever wrote it. For every claim this module
decides, in code:

* which sources really support it (citations are checked, repaired from the evidence, or dropped);
* whether it contains specifics (versions, identifiers, commands, URLs, numbers) that appear in no
  retrieved passage, in which case the claim is removed rather than softened;
* its evidence level. The model's stated `basis` can only *lower* a level, never raise it, and
  "supported by multiple sources" is awarded only when independent sources each contain the claim;
* whether a command may be shown at all (verbatim from a source, not piped into an interpreter, not
  destructive, aimed only at local/lab hosts).

Reproduction status and the confidence rating are computed here too. A claim with no valid citation
never survives: uncertainty is reported by the platform itself (limitations, confidence factors),
not by keeping unsupported model statements around with a label.
"""

import re
from collections import Counter
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime

from app.research.classify import RELIABILITY_WEIGHT
from app.research.domain import Passage
from app.research.evidence import EvidencePack, EvidenceSource
from app.research.injection import screen_text
from app.research.synthesis.grounding import (
    collapse_ws,
    command_problem,
    content_words,
    non_local_hosts,
    normalise,
    overlap,
    present_in,
    specifics,
)
from app.research.synthesis.schema import (
    NOT_ESTABLISHED_STATEMENT,
    Claim,
    Confidence,
    ConfidenceLevel,
    DraftClaim,
    DraftStep,
    EvidenceLevel,
    EvidencePassage,
    GuideDraft,
    GuideGeneration,
    LearningGuide,
    Reproduction,
    ReproductionStatus,
    ReproStep,
    SourceCitation,
    ValidationSummary,
)

MAX_CLAIM_CHARS = 700
MAX_STEP_CHARS = 500
MAX_COMMAND_CHARS = 400
MAX_LIMITATION_CHARS = 300
MAX_EXCERPT_CHARS = 500
MAX_CITED_PASSAGES = 4
SECTION_LIMITS = {"summary": 3, "vulnerability_class": 1, "default": 6, "steps": 15}
STATED_OVERLAP = 0.5  # share of a "stated" claim's content words that must be in its sources
INFERRED_OVERLAP = 0.25
CORROBORATION_OVERLAP = 0.6
STEP_CORROBORATION_OVERLAP = 0.75  # procedures must match closely to count as independent

_CONTROL = {c: None for c in range(32) if c not in (9, 10)} | {0x7F: None}


def _clean(text: str, limit: int) -> str:
    text = text.translate(_CONTROL)
    text = "".join(ch for ch in text if ch not in "‪‫‬‭‮⁦⁧⁨⁩​‌‍⁠﻿")
    return collapse_ws(text)[:limit]


# The order encodes strength; a claim's final level is the *weaker* of what it earned and what the
# model said about itself.
_RANK: dict[EvidenceLevel, int] = {
    "UNCERTAIN": 0,
    "SYNTHESIZED": 1,
    "DOCUMENTED": 2,
    "SUPPORTED_BY_MULTIPLE_SOURCES": 3,
}
_SOLID: frozenset[EvidenceLevel] = frozenset({"DOCUMENTED", "SUPPORTED_BY_MULTIPLE_SOURCES"})


@dataclass
class _Tally:
    kept: int = 0
    removed: int = 0
    downgraded: int = 0
    issues: Counter[str] = field(default_factory=Counter)

    def issue(self, code: str) -> None:
        self.issues[code] += 1


@dataclass
class _Grounded:
    text: str
    level: EvidenceLevel
    source_ids: list[str]
    passage_ids: list[str]
    notes: list[str]


class _Evidence:
    """Lookup structures over the evidence pack."""

    def __init__(self, pack: EvidencePack) -> None:
        self.pack = pack
        self.sources: dict[str, EvidenceSource] = {s.sid: s for s in pack.sources}
        self.passages: dict[str, Passage] = {p.id: p for p in pack.passages()}
        self._norm: dict[str, str] = {pid: normalise(p.text) for pid, p in self.passages.items()}
        self._all_text = " \n ".join(self._norm.values())

    def text_of(self, passage_ids: list[str]) -> str:
        return " \n ".join(self._norm[p] for p in passage_ids if p in self._norm)

    def norm(self, passage_id: str) -> str:
        return self._norm[passage_id]

    def in_pack(self, token: str) -> bool:
        return present_in(token, self._all_text)

    def source_of(self, passage_id: str) -> str:
        return self.passages[passage_id].source_sid

    def group(self, sid: str) -> str:
        return self.sources[sid].independent_group

    def is_document(self, sid: str) -> bool:
        return sid in self.sources and self.sources[sid].kind == "document"


# ------------------------------------------------------------------------------------------------
def _resolve_citations(
    ev: _Evidence, source_ids: list[str], passage_ids: list[str]
) -> tuple[list[str], list[str]]:
    """Keep only citations that exist. Passages win over source IDs: a passage that exists names
    its true source, whatever the draft said."""
    passages = list(dict.fromkeys(p for p in passage_ids if p in ev.passages))
    sources = [ev.source_of(p) for p in passages]
    for sid in source_ids:
        if sid in ev.sources and sid not in sources:
            sources.append(sid)
    return list(dict.fromkeys(sources)), passages


def _cited_text(ev: _Evidence, sources: list[str], passages: list[str]) -> str:
    """Evidence text a claim is judged against: its passages, else every passage of its sources."""
    if passages:
        return ev.text_of(passages)
    ids = [p.id for s in sources for p in ev.sources[s].passages]
    return ev.text_of(ids)


def _supporting_passages(
    ev: _Evidence, text: str, tokens: list[str], threshold: float
) -> list[str]:
    """Every passage in the pack that independently contains the claim."""
    result: list[str] = []
    for pid in ev.passages:
        norm = ev.norm(pid)
        if tokens and not all(present_in(t, norm) for t in tokens):
            continue
        if overlap(text, norm) >= threshold:
            result.append(pid)
    return result


def _ground(
    ev: _Evidence,
    text: str,
    source_ids: list[str],
    passage_ids: list[str],
    basis: str,
    tally: _Tally,
    *,
    limit: int = MAX_CLAIM_CHARS,
    connective: bool = False,
    corroboration: float = CORROBORATION_OVERLAP,
) -> _Grounded | None:
    text = _clean(text, limit)
    if len(text) < 3:
        tally.issue("empty_claim")
        return None
    if screen_text(text).suspicious:
        tally.issue("instruction_like_text")
        return None
    sources, passages = _resolve_citations(ev, source_ids, passage_ids)
    if not sources:
        tally.issue("no_valid_citation")
        return None

    notes: list[str] = []
    tokens = specifics(text)
    cited = _cited_text(ev, sources, passages)
    missing = [t for t in tokens if not present_in(t, cited)]
    invented = [t for t in missing if not ev.in_pack(t)]
    if invented:
        tally.issue("specific_not_in_any_source")
        return None
    if missing:  # real, but cited from the wrong place: point the citation at the right one
        for pid, norm in ((p, ev.norm(p)) for p in ev.passages):
            if any(present_in(t, norm) for t in missing) and pid not in passages:
                passages.append(pid)
        passages = passages[: MAX_CITED_PASSAGES + 2]
        sources = list(dict.fromkeys([*sources, *(ev.source_of(p) for p in passages)]))
        cited = _cited_text(ev, sources, passages)
        if any(not present_in(t, cited) for t in tokens):
            tally.issue("specific_not_in_cited_sources")
            return None
        tally.issue("citation_repaired")
        notes.append("citation corrected to the passage that contains the detail")

    similarity = overlap(text, cited)
    if connective and len(content_words(text)) < 2:
        similarity = 1.0  # "Run this command.": the verified command carries the content
    if similarity < INFERRED_OVERLAP:
        # Whatever the model says, text unrelated to what it cites is not support for it.
        tally.issue("not_supported_by_cited_text")
        return None
    level: EvidenceLevel
    if basis == "unsure":
        level = "UNCERTAIN"
    elif basis == "inferred":
        level = "SYNTHESIZED"
    elif similarity >= STATED_OVERLAP:
        level = "DOCUMENTED"
    else:
        level = "SYNTHESIZED"
        notes.append("wording goes beyond what the cited passages say")
    if level in _SOLID:
        supporters = _supporting_passages(ev, text, tokens, corroboration)
        groups = {ev.group(ev.source_of(p)) for p in supporters}
        groups |= {ev.group(s) for s in sources if any(ev.source_of(p) == s for p in supporters)}
        if len(groups) >= 2:
            level = "SUPPORTED_BY_MULTIPLE_SOURCES"
            for pid in supporters:
                if len(passages) >= MAX_CITED_PASSAGES:
                    break
                if pid not in passages:
                    passages.append(pid)
            sources = list(dict.fromkeys([*sources, *(ev.source_of(p) for p in passages)]))
    return _Grounded(text, level, sources, passages[: MAX_CITED_PASSAGES + 2], notes)


def _claims(ev: _Evidence, drafts: list[DraftClaim], tally: _Tally, limit: int) -> list[Claim]:
    out: list[Claim] = []
    seen: set[str] = set()
    for draft in drafts:
        grounded = _ground(ev, draft.text, draft.source_ids, draft.passage_ids, draft.basis, tally)
        if grounded is None:
            tally.removed += 1
            continue
        key = normalise(grounded.text)
        if key in seen:
            continue
        seen.add(key)
        if grounded.level == "UNCERTAIN" or (
            draft.basis != "stated" and grounded.level != "SYNTHESIZED"
        ):
            tally.downgraded += 1
        out.append(
            Claim(
                text=grounded.text,
                evidence_level=grounded.level,
                source_ids=grounded.source_ids,
                passage_ids=grounded.passage_ids,
                notes=grounded.notes,
            )
        )
        if len(out) >= limit:
            break
    return out


# -- reproduction ---------------------------------------------------------------------------------
def _command_in_evidence(ev: _Evidence, command: str, passage_ids: list[str]) -> list[str] | None:
    """Passages that contain `command` verbatim (whitespace-insensitive), or None."""
    wanted = normalise(collapse_ws(command))
    hits = [
        p for p in ev.passages if wanted and wanted in normalise(collapse_ws(ev.passages[p].text))
    ]
    if not hits:
        return None
    preferred = [p for p in hits if p in passage_ids]
    return preferred or hits[:1]


def _steps(ev: _Evidence, drafts: list[DraftStep], tally: _Tally) -> list[ReproStep]:
    out: list[ReproStep] = []
    for draft in drafts:
        step_text = _clean(draft.step, MAX_STEP_CHARS)
        if non_local_hosts(step_text):
            tally.issue("step_targets_non_local_host")
            tally.removed += 1
            continue
        command = _clean(draft.command, MAX_COMMAND_CHARS) if draft.command else None
        source_ids, passage_ids = list(draft.source_ids), list(draft.passage_ids)
        withheld: str | None = None
        notes: list[str] = []
        if command:
            hits = _command_in_evidence(ev, command, passage_ids)
            if hits is None:
                tally.issue("command_not_in_any_source")
                tally.removed += 1
                continue  # an invented command discredits the whole step
            passage_ids = list(dict.fromkeys([*passage_ids, *hits]))
            problem = command_problem(command)
            if problem:
                withheld, command = problem, None
                tally.issue(f"command_withheld:{problem}")
        grounded = _ground(
            ev,
            step_text,
            source_ids,
            passage_ids,
            draft.basis,
            tally,
            limit=MAX_STEP_CHARS,
            connective=command is not None or withheld is not None,
            corroboration=STEP_CORROBORATION_OVERLAP,
        )
        if grounded is None:
            tally.removed += 1
            continue
        if not any(ev.is_document(s) for s in grounded.source_ids):
            tally.issue("reproduction_without_document_source")
            tally.removed += 1
            continue
        notes.extend(grounded.notes)
        if grounded.level == "UNCERTAIN":
            tally.downgraded += 1
        out.append(
            ReproStep(
                step=grounded.text,
                evidence_level=grounded.level,
                source_ids=grounded.source_ids,
                passage_ids=grounded.passage_ids,
                command=command,
                command_withheld=withheld,
                notes=notes,
            )
        )
        if len(out) >= SECTION_LIMITS["steps"]:
            break
    return out


def _document_claims(ev: _Evidence, claims: list[Claim], tally: _Tally) -> list[Claim]:
    kept = [c for c in claims if any(ev.is_document(s) for s in c.source_ids)]
    tally.removed += len(claims) - len(kept)
    if len(kept) != len(claims):
        tally.issue("reproduction_without_document_source")
    return kept


def _reproduction(
    ev: _Evidence, draft: GuideDraft, tally: _Tally
) -> tuple[Reproduction, list[str]]:
    environment = _document_claims(
        ev, _claims(ev, draft.reproduction.environment, tally, SECTION_LIMITS["default"]), tally
    )
    observation = _document_claims(
        ev,
        _claims(ev, draft.reproduction.expected_observation, tally, SECTION_LIMITS["default"]),
        tally,
    )
    steps = _steps(ev, draft.reproduction.steps, tally)

    solid_steps = [s for s in steps if s.evidence_level in _SOLID]
    solid_env = [c for c in environment if c.evidence_level in _SOLID]
    solid_obs = [c for c in observation if c.evidence_level in _SOLID]
    notes: list[str] = []
    status: ReproductionStatus
    if solid_steps and solid_env and solid_obs:
        status = "established"
    elif steps and (solid_steps or environment or observation):
        status = "partial"
    else:
        status = "not_established"

    if status == "not_established":
        return Reproduction(status=status, statement=NOT_ESTABLISHED_STATEMENT), []

    if not solid_steps:
        notes.append("the steps are inferred from sources rather than stated by them")
    if not solid_env:
        notes.append("no source clearly describes the environment to use")
    if not solid_obs:
        notes.append("no source clearly says what to observe")
    used = list(
        dict.fromkeys(
            s
            for group in (environment, observation, steps)
            for item in group
            for s in item.source_ids
            if ev.is_document(s)
        )
    )
    groups = {ev.group(s) for s in used}
    if status == "established":
        if len(used) == 1:
            statement = (
                f"Based on a single public source ({used[0]}); nothing confirms it independently."
            )
        elif len(groups) == 1:
            statement = (
                f"Based on {len(used)} public sources that are not independent of one another."
            )
        else:
            statement = f"Based on {len(used)} independent public sources."
    else:
        statement = (
            "Only partially established from public sources: "
            + "; ".join(notes)
            + ". Steps not listed here are unknown, not implied."
        )
    return (
        Reproduction(
            status=status,
            statement=statement,
            environment=environment,
            steps=steps,
            expected_observation=observation,
            evidence=used,
        ),
        notes,
    )


# -- confidence ---------------------------------------------------------------------------------
_LEVEL_WEIGHT: dict[EvidenceLevel, float] = {
    "SUPPORTED_BY_MULTIPLE_SOURCES": 1.0,
    "DOCUMENTED": 0.8,
    "SYNTHESIZED": 0.5,
    "UNCERTAIN": 0.1,
}


_BAND_CEILING: dict[str, float] = {"insufficient": 0.34, "low": 0.54, "medium": 0.74, "high": 1.0}


def _band(score: float) -> ConfidenceLevel:
    if score >= 0.75:
        return "high"
    if score >= 0.55:
        return "medium"
    if score >= 0.35:
        return "low"
    return "insufficient"


def _confidence(
    ev: _Evidence,
    sections: dict[str, list[Claim]],
    repro: Reproduction,
    tally: _Tally,
    method: str,
) -> Confidence:
    guide_claims = [c for claims in sections.values() for c in claims]
    all_items: list[Claim | ReproStep] = [
        *guide_claims,
        *repro.environment,
        *repro.steps,
        *repro.expected_observation,
    ]
    cited = {s for c in all_items for s in c.source_ids}
    groups = {ev.group(s) for s in cited}
    doc_groups = {ev.group(s) for s in cited if ev.is_document(s)}
    best = max((RELIABILITY_WEIGHT[ev.sources[s].reliability_level] for s in cited), default=0.0)
    factors: list[str] = []

    source_part = 0.6 * min(len(groups), 3) / 3 + 0.4 * best
    factors.append(
        f"{len(groups)} independent source group(s) cited"
        + (f" ({len(doc_groups)} retrieved document group(s))" if doc_groups else "")
    )
    if best >= 0.85:
        factors.append("an official or high-reliability source is cited")
    elif cited:
        factors.append("no cited source is official or high-reliability")

    counts = Counter(item.evidence_level for item in all_items)
    weights = [_LEVEL_WEIGHT[item.evidence_level] for item in all_items]
    evidence_part = sum(weights) / len(weights) if weights else 0.0
    solid = counts["DOCUMENTED"] + counts["SUPPORTED_BY_MULTIPLE_SOURCES"]
    if all_items:
        factors.append(f"{solid} of {len(all_items)} claims are stated directly by a source")
    if counts["UNCERTAIN"]:
        factors.append(f"{counts['UNCERTAIN']} claim(s) are only weakly supported")

    core = ("summary", "affected_versions", "root_cause", "remediation")
    covered = [name for name in core if sections.get(name)]
    coverage_part = len(covered) / len(core)
    missing = [name.replace("_", " ") for name in core if name not in covered]
    if missing:
        factors.append("no supported statement for: " + ", ".join(missing))

    repro_part = {"established": 1.0, "partial": 0.5, "not_established": 0.0}[repro.status]
    factors.append(f"reproduction: {repro.status.replace('_', ' ')}")

    attempted = tally.kept + tally.removed
    removed_ratio = tally.removed / attempted if attempted else 0.0
    if tally.removed:
        factors.append(f"{tally.removed} unsupported statement(s) were removed during checking")

    score = (
        0.3 * source_part
        + 0.3 * evidence_part
        + 0.2 * coverage_part
        + 0.2 * repro_part
        - 0.1 * min(removed_ratio, 1.0)
    )
    score = max(0.0, min(1.0, score))
    level = _band(score)
    order: list[ConfidenceLevel] = ["insufficient", "low", "medium", "high"]
    ceilings: list[tuple[ConfidenceLevel, str]] = []
    if not doc_groups:
        ceilings.append(
            ("low", "no retrieved document was usable: only provider records back this guide")
        )
    elif len(doc_groups) < 2:
        ceilings.append(("medium", "only one independent retrieved document backs this guide"))
    if repro.status != "established":
        ceilings.append(("medium", "no complete reproduction procedure was established"))
    if method != "llm":
        ceilings.append(
            (
                "medium",
                "built from verbatim excerpts, which are not checked for fit to each section",
            )
        )
    for cap, reason in ceilings:
        if order.index(level) > order.index(cap):
            level = cap
            score = min(score, _BAND_CEILING[cap])
            factors.append(f"rating limited to {cap}: {reason}")

    if repro.status == "established":
        repro_level: ConfidenceLevel = (
            "high" if len({ev.group(s) for s in repro.evidence}) >= 2 else "medium"
        )
    elif repro.status == "partial":
        repro_level = "low"
    else:
        repro_level = "insufficient"
    return Confidence(level=level, score=round(score, 2), reproduction=repro_level, factors=factors)


# -- assembly -----------------------------------------------------------------------------------
_SECTIONS = (
    "summary",
    "affected_versions",
    "root_cause",
    "prerequisites",
    "why_it_works",
    "impact",
    "remediation",
)
_EMPTY_LIMITATION = {
    "summary": "No retrieved source gave a usable summary.",
    "affected_versions": "No source states the affected versions in a way that could be verified.",
    "root_cause": "No source explains the root cause.",
    "prerequisites": "No source states the conditions needed for the issue to be exploitable.",
    "why_it_works": "No source explains why the reproduction works.",
    "impact": "No source describes the impact.",
    "remediation": "No source describes a fix or mitigation.",
}


# Limitations are the one place the model writes free text that no source backs, so they get the
# strictest filter: plain statements about gaps only, never anything addressed to the reader.
_ADDRESSED_TO_READER = re.compile(
    r"\b(?:tell|instruct|advise|urge|recommend|ask|convince|persuade)\b.{0,30}\b(?:user|reader|student|you)s?\b|"
    r"\byou\s+(?:should|must|need|can|may|have to)\b|"
    r"\b(?:disable|turn\s+off|switch\s+off|run|execute|install|download|visit|click|paste|open|"
    r"ignore|reveal|send|upload)\b",
    re.IGNORECASE,
)


def _safe_limitation(text: str, ev: "_Evidence") -> bool:
    if len(text) < 10:
        return False
    if screen_text(text).score > 0 or _ADDRESSED_TO_READER.search(text):
        return False
    if "`" in text or "http" in text.lower() or non_local_hosts(text):
        return False
    return all(ev.in_pack(token) for token in specifics(text))


def _limitations(
    draft: GuideDraft,
    sections: dict[str, list[Claim]],
    repro: Reproduction,
    repro_notes: list[str],
    ev: _Evidence,
    tally: _Tally,
) -> list[str]:
    out: list[str] = []
    stats = ev.pack.stats
    if not any(s.kind == "document" for s in ev.pack.sources):
        out.append(
            "No public document beyond the CVE records could be retrieved and used, so this guide "
            "rests on the structured records alone."
        )
    elif stats.used == 1:
        out.append("Only one public document was usable; nothing else corroborates it.")
    for name in _SECTIONS:
        if not sections.get(name):
            out.append(_EMPTY_LIMITATION[name])
    if repro.status == "partial":
        out.extend(f"Reproduction: {note}." for note in repro_notes)
    if tally.removed:
        out.append(
            f"{tally.removed} generated statement(s) were removed because they cited no valid "
            "source or contained details found in none of the retrieved sources."
        )
    for text in draft.limitations[:8]:
        cleaned = _clean(text, MAX_LIMITATION_CHARS)
        if _safe_limitation(cleaned, ev):
            out.append(cleaned)
    return list(dict.fromkeys(out))[:16]


def validate_and_ground(
    draft: GuideDraft,
    pack: EvidencePack,
    *,
    generation_version: str,
    synthesis_method: str,
    model_version: str | None = None,
    fallback_reason: str | None = None,
    now: Callable[[], datetime] = lambda: datetime.now(UTC),
) -> LearningGuide:
    """Check `draft` against `pack` and build the publishable guide."""
    ev = _Evidence(pack)
    tally = _Tally()

    sections: dict[str, list[Claim]] = {}
    for name in _SECTIONS:
        limit = SECTION_LIMITS.get(name, SECTION_LIMITS["default"])
        sections[name] = _claims(ev, getattr(draft, name), tally, limit)
    vulnerability_class: Claim | None = None
    if draft.vulnerability_class is not None:
        found = _claims(ev, [draft.vulnerability_class], tally, 1)
        vulnerability_class = found[0] if found else None
    reproduction, repro_notes = _reproduction(ev, draft, tally)

    everything: list[Claim | ReproStep] = [
        *(c for claims in sections.values() for c in claims),
        *([vulnerability_class] if vulnerability_class else []),
        *reproduction.environment,
        *reproduction.steps,
        *reproduction.expected_observation,
    ]
    tally.kept = len(everything)
    by_level = Counter(item.evidence_level for item in everything)

    scored = dict(sections)
    if vulnerability_class:
        scored["vulnerability_class"] = [vulnerability_class]
    confidence = _confidence(ev, scored, reproduction, tally, synthesis_method)
    limitations = _limitations(draft, sections, reproduction, repro_notes, ev, tally)

    cited_by: Counter[str] = Counter()
    cited_passages: dict[str, None] = {}
    for item in everything:
        cited_by.update(set(item.source_ids))
        cited_passages.update(dict.fromkeys(item.passage_ids))
    sources = [
        SourceCitation(
            id=s.sid,
            kind=s.kind,
            title=_clean(s.title, 300),
            url=s.url,
            publisher=s.publisher,
            source_type=s.source_type,
            reliability_level=s.reliability_level,
            retrieved_at=s.retrieved_at,
            content_hash=s.content_hash,
            independent_group=s.independent_group,
            cited_by=cited_by.get(s.sid, 0),
        )
        for s in pack.sources
    ]
    evidence = [
        EvidencePassage(
            id=pid,
            source_id=ev.passages[pid].source_sid,
            kind=ev.passages[pid].kind,
            text=ev.passages[pid].text[:MAX_EXCERPT_CHARS],
        )
        for pid in cited_passages
        if pid in ev.passages
    ]
    summary = ValidationSummary(
        claims_kept=tally.kept,
        claims_removed=tally.removed,
        claims_downgraded=tally.downgraded,
        by_level=dict(by_level),
        issues=sorted(tally.issues),
    )
    return LearningGuide(
        cve_id=pack.cve.cve_id,
        summary=sections["summary"],
        vulnerability_class=vulnerability_class,
        affected_versions=sections["affected_versions"],
        root_cause=sections["root_cause"],
        prerequisites=sections["prerequisites"],
        reproduction=reproduction,
        why_it_works=sections["why_it_works"],
        impact=sections["impact"],
        remediation=sections["remediation"],
        confidence=confidence,
        limitations=limitations,
        sources=sources,
        evidence=evidence,
        generation=GuideGeneration(
            generation_version=generation_version,
            synthesis_method="llm" if synthesis_method == "llm" else "extractive",
            model_version=model_version,
            generated_at=now(),
            fallback_reason=fallback_reason,
        ),
        validation=summary,
    )
