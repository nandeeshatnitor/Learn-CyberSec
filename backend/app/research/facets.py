"""Tag passages with the learning-guide facets they could support (rule-based, no LLM).

A facet says "this passage may be evidence for X"; it is a routing hint for synthesis, never a claim.
"""

import re

from app.research.domain import Block

_RX = {
    "affected_versions": re.compile(
        r"\b(?:affected|vulnerable|impacted)\b.{0,60}\b(?:versions?|releases?|builds?|through|before|prior to)\b|"
        r"\b(?:versions?|releases?)\s+(?:before|prior to|up to|through|from|<=?|>=?)\s*v?\d|"
        r"\b(?:before|prior to|through|<=?|up to)\s+v?\d+\.\d+|\bfixed\s+in\b|\bv?\d+\.\d+(?:\.\d+)?\s*(?:-|to|through)\s*v?\d+\.\d+",
        re.IGNORECASE,
    ),
    "root_cause": re.compile(
        r"\b(?:caused\s+by|due\s+to|because|root\s+cause|the\s+(?:flaw|bug|issue|problem|vulnerability)\s+(?:is|lies|exists|stems)|"
        r"improper(?:ly)?|does\s+not\s+(?:properly\s+)?(?:validate|sanitize|sanitise|check|verify|escape|neutrali[sz]e)|"
        r"fails?\s+to\s+(?:validate|sanitize|check|verify|escape)|un(?:sanitized|validated|checked|escaped)|lack\s+of|missing\s+(?:check|validation|authentication|authorization)|"
        r"use[- ]after[- ]free|buffer\s+overflow|out[- ]of[- ]bounds|integer\s+overflow|deserializ|injection|path\s+traversal|"
        r"insecure\s+default|hard-?coded)\b",
        re.IGNORECASE,
    ),
    "prerequisites": re.compile(
        r"\b(?:requires?|required|must\s+(?:be|have)|needs?\s+to|prerequisites?|preconditions?|only\s+(?:when|if)|"
        r"unauthenticated|authenticated|without\s+authentication|network\s+access|default\s+configuration|"
        r"(?:if|when)\s+.{0,40}\b(?:enabled|configured|exposed|reachable)|attacker\s+(?:must|needs|can\s+only))\b",
        re.IGNORECASE,
    ),
    "environment": re.compile(
        r"\b(?:docker|docker-?compose|container|vulhub|virtual\s+machine|vagrant|lab|test\s*bed|sandbox|"
        r"install(?:ed|ing)?|set\s*up|pip\s+install|apt(?:-get)?\s+install|npm\s+install|"
        r"vulnerable\s+(?:image|container|application|app|instance|environment)|intentionally\s+vulnerable)\b",
        re.IGNORECASE,
    ),
    "reproduction": re.compile(
        r"\b(?:steps?\s+to\s+reproduce|to\s+reproduce|reproduc(?:e|tion|ing)|proof[- ]of[- ]concept|poc|"
        r"send\s+(?:a|the)\s+(?:request|payload|header|packet|message)|payload|curl\s|wget\s|"
        r"trigger(?:s|ed|ing)?\s+the|demonstrat(?:e|es|ed|ion))\b",
        re.IGNORECASE,
    ),
    "observation": re.compile(
        r"\b(?:you\s+(?:will|should|can)\s+(?:see|observe|notice)|observe[sd]?|expected\s+(?:output|result|behaviou?r)|"
        r"(?:response|output|log|logs)\s+(?:contains?|shows?|will\s+show)|callback|connection\s+(?:is\s+)?received|"
        r"confirm(?:s|ing)\s+(?:that\s+)?(?:the|it|this|exploit\w*|code)|indicat(?:es|ed|ing)\s+(?:that\s+)?the|results?\s+in|returns?\s+(?:a|an|the))\b",
        re.IGNORECASE,
    ),
    "impact": re.compile(
        r"\b(?:remote\s+code\s+execution|rce|arbitrary\s+code|denial[- ]of[- ]service|dos|information\s+disclosure|"
        r"privilege\s+escalation|authentication\s+bypass|data\s+(?:leak|exfiltration|loss)|allows?\s+(?:remote\s+)?(?:attackers?|users?)|"
        r"attackers?\s+(?:can|could|may|to)|impact|takeover|compromise)\b",
        re.IGNORECASE,
    ),
    "remediation": re.compile(
        r"\b(?:upgrade\s+to|update\s+to|patch(?:ed|es)?|fixed\s+in|mitigat(?:e|ion|ions)|work-?around|"
        r"disable[sd]?|remediat(?:e|ion)|recommend(?:ed|s)?|apply\s+the\s+(?:fix|patch|update)|security\s+update|"
        r"remove\s+the|set\s+.{0,30}\s+to\s+(?:true|false))\b",
        re.IGNORECASE,
    ),
}
_CODE_HINTS = re.compile(
    r"\b(?:curl|wget|nc|ncat|python\d?|docker|pip|nmap|http)\b|://|^\s*[$#>]\s",
    re.IGNORECASE | re.MULTILINE,
)


def tag_facets(block: Block, *, neighbour_text: str = "") -> list[str]:
    """Facets a block could evidence. `neighbour_text` is the preceding block, so a bare code
    block after "Steps to reproduce:" is recognised as reproduction material."""
    text = block.text
    facets = [name for name, rx in _RX.items() if rx.search(text)]
    if block.kind == "code":
        context = neighbour_text
        if "reproduction" not in facets and (
            _RX["reproduction"].search(context) or _CODE_HINTS.search(text)
        ):
            facets.append("reproduction")
        if "environment" not in facets and _RX["environment"].search(context + " " + text):
            facets.append("environment")
    if block.kind == "heading":
        return facets
    if not facets and block.kind == "paragraph" and len(text) > 80:
        facets.append("summary")
    return facets
