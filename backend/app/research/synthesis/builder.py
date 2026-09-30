"""Guide construction: pick a synthesizer, validate its draft, fall back when it does not hold."""

from app.learning.challenge import build_challenge
from app.research.evidence import EvidencePack
from app.research.synthesis.extractive import ExtractiveSynthesizer
from app.research.synthesis.llm import LLMError, StructuredLLM, build_messages
from app.research.synthesis.schema import LearningGuide
from app.research.synthesis.validate import validate_and_ground
from app.utils.logging import get_logger

log = get_logger(__name__)

# A guide from which validation removed (nearly) everything cannot be trusted to have been written
# from the sources at all, so the deterministic guide is used instead.
MIN_KEPT_CLAIMS = 3


def _with_challenge(guide: LearningGuide, pack: EvidencePack) -> LearningGuide:
    guide.challenge = build_challenge(guide, pack.cve)
    return guide


def build_guide(
    pack: EvidencePack,
    *,
    llm: StructuredLLM | None,
    generation_version: str,
) -> LearningGuide:
    extractive = ExtractiveSynthesizer()
    reason: str | None = "llm_not_configured"
    if llm is not None and pack.passages():
        system, user = build_messages(pack)
        try:
            result = llm.generate(system=system, user=user)
        except LLMError as exc:
            log.warning("llm_synthesis_failed", code=exc.code)
            reason = exc.code
        else:
            guide = validate_and_ground(
                result.draft,
                pack,
                generation_version=generation_version,
                synthesis_method="llm",
                model_version=result.model,
            )
            if guide.validation.claims_kept >= MIN_KEPT_CLAIMS:
                return _with_challenge(guide, pack)
            log.warning("llm_draft_rejected", kept=guide.validation.claims_kept)
            reason = "llm_output_unsupported"
    elif llm is not None:
        reason = "no_evidence"
    return _with_challenge(
        validate_and_ground(
            extractive.draft(pack),
            pack,
            generation_version=generation_version,
            synthesis_method="extractive",
            fallback_reason=reason,
        ),
        pack,
    )
