"""Deterministic synthesis: quote the evidence, invent nothing.

Used when no LLM is configured, when it is unavailable or refuses, and when its output does not
survive validation. Every claim is a verbatim excerpt of a retrieved passage, so it is grounded by
construction; the guide is plainer than an LLM's but never worse than its sources. The validator
still runs over the result, because the same rules apply to every synthesizer.
"""

from collections import defaultdict

from app.research.classify import RELIABILITY_WEIGHT
from app.research.domain import Passage
from app.research.evidence import EvidencePack, EvidenceSource
from app.research.synthesis.schema import (
    DraftClaim,
    DraftReproduction,
    DraftStep,
    GuideDraft,
)

_EXCERPT_CHARS = 420
_PER_SOURCE = 2
_ADJACENT = 2  # a code block this close after a step's text is that step's command

# Most specific facets first: a passage is used by the first section that claims it.
_SECTION_FACETS = {
    "remediation": "remediation",
    "affected_versions": "affected_versions",
    "prerequisites": "prerequisites",
    "root_cause": "root_cause",
    "impact": "impact",
}
_LIMITS = {"summary": 2, "affected_versions": 3, "root_cause": 3, "prerequisites": 3, "impact": 3}


def _excerpt(text: str) -> str:
    """A verbatim prefix ending at a sentence or word boundary."""
    if len(text) <= _EXCERPT_CHARS:
        return text
    cut = text[:_EXCERPT_CHARS]
    for mark in (". ", "; ", ", ", " "):
        index = cut.rfind(mark)
        if index >= _EXCERPT_CHARS // 2:
            return cut[: index + (1 if mark == ". " else 0)].rstrip()
    return cut


def _claim(source: EvidenceSource, passage: Passage) -> DraftClaim:
    return DraftClaim(
        text=_excerpt(passage.text),
        source_ids=[source.sid],
        passage_ids=[passage.id],
        basis="stated",
    )


def _ranked(
    pack: EvidencePack, facet: str, kinds: tuple[str, ...]
) -> list[tuple[EvidenceSource, Passage]]:
    candidates = [
        (s, p)
        for s in pack.sources
        for p in s.passages
        if facet in p.facets and p.kind in kinds and "injection_suspect" not in p.flags
    ]
    candidates.sort(key=lambda sp: (-RELIABILITY_WEIGHT[sp[0].reliability_level], -sp[1].score))
    return candidates


def _pick(
    pack: EvidencePack, facet: str, limit: int, kinds: tuple[str, ...], used: set[str]
) -> list[DraftClaim]:
    """Best passages for a facet. `used` keeps one passage from appearing in several sections."""
    per_source: dict[str, int] = defaultdict(int)
    out: list[DraftClaim] = []
    for source, passage in _ranked(pack, facet, kinds):
        if per_source[source.sid] >= _PER_SOURCE or passage.id in used:
            continue
        per_source[source.sid] += 1
        used.add(passage.id)
        out.append(_claim(source, passage))
        if len(out) >= limit:
            break
    return out


def _reproduction_source(pack: EvidencePack) -> EvidenceSource | None:
    """The one document whose procedure is followed (mixing write-ups would invent a procedure)."""
    best: tuple[float, EvidenceSource] | None = None
    for source in pack.sources:
        if source.kind != "document":
            continue
        relevant = [p for p in source.passages if {"reproduction", "environment"} & set(p.facets)]
        steps = [p for p in relevant if "reproduction" in p.facets]
        if not steps:
            continue
        score = len(relevant) + 0.5 * RELIABILITY_WEIGHT[source.reliability_level]
        if best is None or score > best[0]:
            best = (score, source)
    return best[1] if best else None


def _reproduction(pack: EvidencePack) -> DraftReproduction:
    source = _reproduction_source(pack)
    if source is None:
        return DraftReproduction(
            feasible="no",
            explanation="No retrieved source describes how to reproduce the issue.",
            environment=[],
            steps=[],
            expected_observation=[],
        )
    environment: list[DraftClaim] = []
    steps: list[DraftStep] = []
    last_text_step: tuple[int, int] | None = None  # (index in steps, passage position)
    for passage in sorted(source.passages, key=lambda p: p.position):
        facets = set(passage.facets)
        if passage.kind == "code":
            if not facets & {"environment", "reproduction"}:
                continue
            if (
                last_text_step is not None
                and steps[last_text_step[0]].command is None
                and passage.position - last_text_step[1] <= _ADJACENT
            ):
                previous = steps[last_text_step[0]]
                previous.command = passage.text
                previous.passage_ids.append(passage.id)
            else:
                steps.append(
                    DraftStep(
                        step="Run this command.",
                        command=passage.text,
                        source_ids=[source.sid],
                        passage_ids=[passage.id],
                        basis="stated",
                    )
                )
                last_text_step = None
            continue
        if "environment" in facets:
            environment.append(_claim(source, passage))
        elif "reproduction" in facets:
            steps.append(
                DraftStep(
                    step=_excerpt(passage.text),
                    command=None,
                    source_ids=[source.sid],
                    passage_ids=[passage.id],
                    basis="stated",
                )
            )
            last_text_step = (len(steps) - 1, passage.position)
    observation = [
        _claim(s, p)
        for s, p in _ranked(pack, "observation", ("paragraph", "list_item"))
        if s.kind == "document"
    ][:2]
    return DraftReproduction(
        feasible="yes" if steps else "no",
        explanation=f"Followed the procedure published in source {source.sid}.",
        environment=environment[:4],
        steps=steps[:15],
        expected_observation=observation,
    )


class ExtractiveSynthesizer:
    method = "extractive"

    def draft(self, pack: EvidencePack) -> GuideDraft:
        used: set[str] = set()
        summary: list[DraftClaim] = []
        provider = next((s for s in pack.sources if s.kind == "provider_record"), None)
        if provider and provider.passages:  # the CVE record's own description leads
            summary = [_claim(provider, provider.passages[0])]
            used.add(provider.passages[0].id)
        sections = {
            name: _pick(pack, facet, _LIMITS.get(name, 3), ("paragraph", "list_item"), used)
            for name, facet in _SECTION_FACETS.items()
        }
        if not summary:
            summary = _pick(pack, "summary", 2, ("paragraph", "list_item"), used)
        sections["summary"] = summary
        reproduction = _reproduction(pack)
        repro_source = _reproduction_source(pack)
        why: list[DraftClaim] = []
        if repro_source is not None:
            why = [
                _claim(repro_source, p)
                for p in repro_source.passages
                if "root_cause" in p.facets and p.kind in ("paragraph", "list_item")
            ][:2]
        return GuideDraft(
            summary=sections["summary"],
            vulnerability_class=None,
            affected_versions=sections["affected_versions"],
            root_cause=sections["root_cause"],
            prerequisites=sections["prerequisites"],
            reproduction=reproduction,
            why_it_works=why,
            impact=sections["impact"],
            remediation=sections["remediation"],
            limitations=[],
        )
