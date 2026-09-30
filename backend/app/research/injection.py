"""Heuristic screening of retrieved text for prompt-injection attempts.

IMPORTANT: this is a *defence in depth* layer, not the security boundary. Pattern matching cannot
catch every phrasing, and attackers can rephrase. The real protections are structural (see
`synthesis/llm.py`): retrieved text is passed to the model only as JSON data in a separate message,
the model has no tools and cannot browse or execute anything, its output must fit a schema, and every
claim it makes is re-verified in code against the cited passages. Screening reduces exposure and gives
visibility; it never replaces those.
"""

import re
import unicodedata
from dataclasses import dataclass

# Characters used to hide or disguise text.
_INVISIBLE = re.compile("[​-‏‪-‮⁠-⁤⁦-⁩﻿­]")
_CONFUSABLES = str.maketrans(
    {"а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "у": "y", "х": "x", "і": "i", "ѕ": "s"}
)  # fmt: skip

SUSPICIOUS_SCORE = 3  # a passage at or above this is withheld from synthesis
HIDDEN_TEXT_SCORE = 2  # hidden text this suspicious marks the whole document adversarial

_AI = r"(?:ai|a\.i\.|llm|assistant|language model|chatbot|chatgpt|gpt-?\d*|claude|copilot|gemini|agent|model|bot)s?"

_PATTERNS: tuple[tuple[str, re.Pattern[str], int], ...] = tuple(
    (name, re.compile(rx, re.IGNORECASE | re.DOTALL), weight)
    for name, rx, weight in (
        (
            "override_instructions",
            r"\b(?:ignore|disregard|forget|override|bypass|discard|skip)\b.{0,40}\b(?:all|any|the|your|previous|prior|above|earlier|preceding|system|these)\b.{0,40}\b(?:instruction|prompt|rule|direction|guideline|message|context|constraint)s?\b",
            3,
        ),
        ("new_instructions", r"\b(?:new|updated|revised|real|actual|hidden)\s+(?:instruction|prompt|task|directive)s?\s*[:\-]", 3),
        ("addressed_to_ai", rf"\b(?:attention|note|message|instructions?|notice)\s*(?:to|for)\s*(?:the\s+)?{_AI}\b", 3),
        ("if_you_are_ai", rf"\b(?:if|when|since)\s+you\s+are\s+(?:an?\s+)?{_AI}\b", 3),
        ("ai_reading_this", rf"\b{_AI}\s+(?:reading|processing|summari[sz]ing|analy[sz]ing|scraping)\s+(?:this|the)\b", 3),
        ("ai_must", rf"\b{_AI}\b.{{0,40}}\b(?:must|shall|need to|have to|are required to|are instructed to|should always)\b", 2),
        ("exfiltrate_prompt", r"\b(?:reveal|print|show|repeat|output|leak|disclose|display)\b.{0,30}\b(?:system|initial|hidden|original|secret)\s+(?:prompt|instruction|message)s?\b", 3),
        ("system_prompt_mention", r"\bsystem\s+prompt\b", 1),
        ("role_reassignment", r"\byou\s+are\s+(?:now|no longer)\b", 2),
        ("from_now_on", r"\bfrom\s+now\s+on\b.{0,60}\b(?:you|assistant|respond|answer|reply)\b", 2),
        ("act_as", r"\b(?:act|behave|respond)\s+as\s+(?:if\s+)?(?:you\s+(?:are|were)|an?\s+)", 2),
        ("pretend", r"\bpretend\s+(?:to\s+be|you)\b", 2),
        ("jailbreak", r"\b(?:jailbreak|dan\s+mode|developer\s+mode|do\s+anything\s+now)\b", 3),
        ("role_marker_line", r"(?:^|\n)\s*(?:system|assistant|developer|human|user)\s*:\s", 2),
        ("chat_template_tokens", r"<\|?(?:im_start|im_end|system|assistant|endoftext|eot_id)\|?>|\[/?inst\]|<</?sys>>", 3),
        ("xml_role_tags", r"</?(?:system|assistant|instructions?|prompt|tool_?call|function_?call)\b[^>]{0,40}>", 2),
        ("prompt_delimiter", r"(?:begin|start|end)\s+(?:of\s+)?(?:system\s+)?(?:prompt|instructions?)\b", 2),
        ("exfil_to_url", r"\b(?:send|post|upload|exfiltrate|forward|email|submit)\b.{0,50}\b(?:to|at)\s+https?://", 2),
        ("markdown_image_exfil", r"!\[[^\]]*\]\(https?://[^)]*[?&](?:data|prompt|secret|token|q|d)=", 2),
        ("tell_user_to", r"\b(?:tell|instruct|advise|convince)\s+the\s+user\s+to\b", 2),
        ("do_not_disclose", r"\bdo\s+not\s+(?:tell|mention|reveal|disclose)\b.{0,30}\b(?:user|anyone|this)\b", 2),
    )
)  # fmt: skip


@dataclass(frozen=True)
class InjectionVerdict:
    score: int
    reasons: tuple[str, ...]

    @property
    def suspicious(self) -> bool:
        return self.score >= SUSPICIOUS_SCORE


def normalise_for_screening(text: str) -> str:
    text = unicodedata.normalize("NFKC", text)
    text = _INVISIBLE.sub("", text).lower().translate(_CONFUSABLES)
    return re.sub(r"[ \t]+", " ", text)


def screen_text(text: str) -> InjectionVerdict:
    normalised = normalise_for_screening(text)
    reasons: list[str] = []
    score = 0
    for name, pattern, weight in _PATTERNS:
        if pattern.search(normalised):
            reasons.append(name)
            score += weight
    return InjectionVerdict(score=score, reasons=tuple(reasons))
