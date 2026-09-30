"""Turn a validated learning guide into an interactive challenge, deterministically.

Every key point, hint and solution part is taken from claims the research validator has already
grounded in retrieved sources, so nothing here can be invented. Hints escalate on a fixed ladder:

    1  a direction only, generic, naming no answer term
    2  one source sentence with the answer terms masked
    3  that sentence in full, cited
    solution  every supporting claim (and for reproduction, the documented steps), cited

Hints 1 and 2 are checked in code never to contain an accepted answer phrase; if the wording would
leak, a more generic hint is used instead.
"""

import re

from app.learning.schema import (
    Challenge,
    Hint,
    KeyPoint,
    Prerequisite,
    SolutionPart,
    Task,
)
from app.learning.text import (
    STOPWORDS,
    contains_phrase,
    content_words,
    mask,
    normalise,
    split_identifier,
)
from app.research.relevance import RelevanceContext
from app.research.synthesis.grounding import specifics
from app.research.synthesis.schema import Claim, LearningGuide
from app.schemas.cve import CVERecord

STUDY_PREREQUISITES = (
    "Comfort reading a CVE record or vendor advisory: affected versions, causes and fixes.",
    "Basic familiarity with how software receives input, for example an HTTP request.",
)
LAB_PREREQUISITE = (
    "A local or authorized lab environment that you control. Never test a system you do not own "
    "or have explicit permission to test."
)

_HEADS = (
    "renderer|parser|engine|evaluator|interpreter|deserializer|decoder|servlet|handler|resolver|"
    "compiler|library|framework|module|component|function|endpoint"
)
_SPECIFIC_HEADS = frozenset(
    [
        "renderer",
        "parser",
        "engine",
        "evaluator",
        "interpreter",
        "deserializer",
        "decoder",
        "servlet",
        "compiler",
    ]
)
_COMPONENT_RX = re.compile(rf"\b((?:[a-z][a-z-]+\s+){{0,2}}(?:{_HEADS}))\b", re.IGNORECASE)
_LEADING = frozenset(
    [
        "the",
        "a",
        "an",
        "its",
        "of",
        "in",
        "by",
        "that",
        "which",
        "this",
        "these",
        "our",
        "their",
        "and",
        "or",
        "to",
        "for",
        "with",
        "from",
    ]
)
_IDENT_RX = re.compile(
    r"\b[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)+(?:\(\))?|\b[a-z]+[A-Z]\w*|\b[A-Z][a-z0-9]+[A-Z]\w*"
)
_VERSION_RX = re.compile(r"^v?\d+(\.\d+){1,3}")
_HEADER_RX = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)+$")
_KNOWN_HEADERS = frozenset(
    [
        "content-type",
        "user-agent",
        "host",
        "cookie",
        "referer",
        "accept",
        "authorization",
        "origin",
        "content-length",
        "transfer-encoding",
        "accept-language",
        "x-forwarded-for",
        "x-forwarded-host",
    ]
)
_PARAM_RX = re.compile(
    r"\b(?:parameter|param|field|argument|variable|property|cookie|attribute)\s+[`'\"]?([A-Za-z_][\w.-]{1,40})",
    re.IGNORECASE,
)
_CATEGORIES = {
    "header": ["header", "http header", "request header"],
    "parameter": ["parameter", "query parameter", "argument"],
    "cookie": ["cookie"],
    "body": ["request body", "post body", "payload"],
    "field": ["form field", "field", "input field"],
    "url": ["url", "path", "uri"],
    "file": ["filename", "file name", "uploaded file", "file upload"],
}
_ACTIONS = {
    "upgrade": ["upgrade", "update", "patch", "newer version", "latest version", "fixed version"],
    "update": ["upgrade", "update", "patch", "newer version", "latest version"],
    "patch": ["upgrade", "update", "patch"],
    "disable": ["disable", "turn off", "switch off", "deactivate"],
    "remove": ["remove", "uninstall", "delete"],
    "restrict": ["restrict", "limit", "allow list", "allowlist", "whitelist"],
    "sanitize": ["sanitize", "sanitise", "validate", "escape", "filter"],
    "sanitise": ["sanitize", "sanitise", "validate", "escape", "filter"],
    "validate": ["validate", "sanitize", "check", "filter"],
    "configure": ["configure", "set", "setting"],
    "block": ["block", "filter", "deny"],
}
_FEATURE_RX = re.compile(r"\b(?:disable|turn off|remove)\s+(?:the\s+)?([a-z][\w-]+)", re.IGNORECASE)
_MAX_TEXT = 420


_CVE_TOKEN = re.compile(r"^cve-\d{4}-\d+$")
_CAUSAL = re.compile(
    r"\b(because|caused by|due to|does not|fails? to|without|unsanitized|not sanitiz|no check|"
    r"lack of|missing|improper)\b",
    re.IGNORECASE,
)


def _variants(token: str) -> list[str]:
    """Accepted spellings of a name: whole for hyphenated names (headers), parts for code names."""
    if _CVE_TOKEN.match(token):
        return []
    if "-" in token and "." not in token and "(" not in token:
        return [normalise(token)]
    return split_identifier(token)


_GENERIC_WORDS = frozenset(
    "through earlier later exists exist value before after walk other thing which their about "
    "affects affected including".split()
)


def _causal_sentence(text: str) -> str:
    """The sentence that states the cause, when there is one (else the whole claim)."""
    sentences = re.split(r"(?<=[.!?])\s+", text)
    return next((s for s in sentences if _CAUSAL.search(s)), text)


def _clip(text: str) -> str:
    return text if len(text) <= _MAX_TEXT else text[:_MAX_TEXT].rsplit(" ", 1)[0] + " …"


def _refs(claims: list[Claim]) -> tuple[list[str], list[str]]:
    sources = list(dict.fromkeys(s for c in claims for s in c.source_ids))
    passages = list(dict.fromkeys(p for c in claims for p in c.passage_ids))
    return sources, passages


def _parts(claims: list[Claim]) -> list[SolutionPart]:
    return [
        SolutionPart(
            text=c.text,
            source_ids=c.source_ids,
            passage_ids=c.passage_ids,
            evidence_level=c.evidence_level,
        )
        for c in claims
    ]


def _unique(items: list[str]) -> list[str]:
    return [i for i in dict.fromkeys(i for i in items if i)]


class _Ctx:
    def __init__(self, guide: LearningGuide, cve: CVERecord) -> None:
        self.guide = guide
        self.product_terms = RelevanceContext.from_record(cve).product_terms
        self.products = [p.product for p in cve.affected_products if p.product]
        titles = {s.id: s.title for s in guide.sources}
        self.titles = titles

    def source_titles(self, ids: list[str]) -> list[str]:
        return [f"“{self.titles[i]}” [{i}]" for i in ids if i in self.titles][:2]

    def is_product(self, phrase: str) -> bool:
        words = phrase.lower().split()
        return bool(words) and all(w in self.product_terms for w in words)


# -- key-point extraction ---------------------------------------------------------------------------
def _identifiers(ctx: _Ctx, text: str) -> list[str]:
    found = []
    for match in _IDENT_RX.findall(text):
        parts = split_identifier(match)
        if parts and not ctx.is_product(parts[0]):
            found.append(match)
    return found


def _component(ctx: _Ctx) -> Task | None:
    g = ctx.guide
    pool = [*g.root_cause, *g.why_it_works, *g.summary, *g.prerequisites, *g.impact]
    phrases: list[str] = []
    hits: list[Claim] = []
    for claim in pool:
        local: list[str] = []
        for ident in _identifiers(ctx, claim.text):
            local += split_identifier(ident)
        for match in _COMPONENT_RX.findall(claim.text):
            words = [
                w
                for w in match.lower().split()
                if w not in _LEADING and w not in STOPWORDS and w not in ctx.product_terms
            ]
            while words and words[0] in _LEADING:
                words.pop(0)
            if not words:
                continue
            phrase = " ".join(words)
            head = words[-1]
            if not ctx.is_product(phrase):
                local.append(phrase)
                if head in _SPECIFIC_HEADS:
                    local.append(head)
        if local:
            phrases += local
            hits.append(claim)
    phrases = [p for p in _unique(phrases) if not ctx.is_product(p)]
    product_phrases = _unique(
        [x for name in ctx.products for x in split_identifier(name)] + sorted(ctx.product_terms)
    )
    points: list[KeyPoint] = []
    src, psg = _refs(hits[:2] or pool[:1])
    if phrases:
        points.append(
            KeyPoint(
                id="component",
                label="the specific module, function or feature responsible",
                phrases=phrases,
                statement=(hits[0].text if hits else ""),
                source_ids=src,
                passage_ids=psg,
            )
        )
    if product_phrases:
        points.append(
            KeyPoint(
                id="product",
                label="the affected product",
                phrases=product_phrases,
                required=not phrases,
                statement="",
                source_ids=src,
                passage_ids=psg,
            )
        )
    if not points:
        return None
    return Task(
        id="",
        order=0,
        kind="identify_component",
        title="Identify the vulnerable component",
        prompt="Which component (module, function or feature) is responsible for the vulnerability? "
        "Name the part of the software, not just the product.",
        objective="Identify the vulnerable component.",
        verification_criteria=[
            "Names the specific module, function or feature responsible, not only the product",
            "Agrees with what the cited sources describe",
        ],
        context_source_ids=src,
        key_points=points,
        solution=_parts(hits[:2] or pool[:1]),
    )


def _input(ctx: _Ctx) -> Task | None:
    g = ctx.guide
    repro_text = [s.step + " " + (s.command or "") for s in g.reproduction.steps]
    pool = [*g.root_cause, *g.summary, *g.prerequisites, *g.why_it_works]
    texts = [c.text for c in pool] + repro_text
    names: list[str] = []
    hit_claims: list[Claim] = []
    for claim in pool:
        local = _input_names(ctx, claim.text)
        if local:
            names += local
            hit_claims.append(claim)
    for text in repro_text:
        names += _input_names(ctx, text)
    names = _unique(names)
    joined = " ".join(texts).lower()
    categories = [
        c for c, words in _CATEGORIES.items() if any(contains_phrase(joined, w) for w in words)
    ]
    if not names and not categories:
        return None
    src, psg = _refs(hit_claims[:2] or pool[:1])
    points: list[KeyPoint] = []
    if names:
        phrases = [x for n in names for x in _variants(n)]
        points.append(
            KeyPoint(
                id="input",
                label="the specific input (header, parameter or field) the attacker controls",
                phrases=phrases,
                statement=(hit_claims[0].text if hit_claims else ""),
                source_ids=src,
                passage_ids=psg,
            )
        )
    if categories:
        points.append(
            KeyPoint(
                id="input_kind",
                label="the kind of input (for example a header, parameter or file)",
                phrases=_unique([w for c in categories for w in _CATEGORIES[c]]),
                required=not names,
                source_ids=src,
                passage_ids=psg,
            )
        )
    solution = _parts(hit_claims[:2] or pool[:1])
    return Task(
        id="",
        order=0,
        kind="identify_input",
        title="Identify the vulnerable input",
        prompt="Which input can an attacker control to trigger the flaw? Be as specific as the sources are.",
        objective="Identify the vulnerable input.",
        verification_criteria=[
            "Names the specific input (not just 'user input')",
            "Agrees with what the cited sources describe",
        ],
        context_source_ids=src,
        key_points=points,
        solution=solution,
    )


def _input_names(ctx: _Ctx, text: str) -> list[str]:
    names: list[str] = []
    lowered = text.lower()
    for token in specifics(text):
        is_header = _HEADER_RX.match(token) and not any(
            t in ctx.product_terms for t in token.split("-")
        )
        if is_header and (token.startswith("x-") or token in _KNOWN_HEADERS or "header" in lowered):
            names.append(token)
    names += [m for m in _PARAM_RX.findall(text) if not ctx.is_product(m.lower())]
    return names


def _reproduce(ctx: _Ctx) -> Task | None:
    repro = ctx.guide.reproduction
    if repro.status == "not_established" or not repro.steps:
        return None
    observed = repro.expected_observation
    obs_text = " ".join(c.text for c in observed) or " ".join(s.step for s in repro.steps)
    tokens_ = [t for t in specifics(obs_text) if not t.startswith("http") and "/" not in t]
    phrases = _unique(
        [x for t in tokens_ for x in _variants(t) if not _CVE_TOKEN.match(t)] + tokens_
    )
    # Concept words are only a fallback: with a concrete token (a number, a string) require that.
    words = [] if phrases else content_words(obs_text)[:8]
    if not phrases and not words:
        return None
    claims = [*repro.environment[:1], *observed[:1]]
    src, psg = _refs([*claims] or [])
    src = src or list(repro.evidence)
    points = [
        KeyPoint(
            id="observation",
            label="the observable result that confirms the behavior",
            phrases=phrases,
            words=words,
            min_words=2 if len(words) >= 3 else 1,
            statement=observed[0].text if observed else "",
            source_ids=src,
            passage_ids=psg,
        )
    ]
    solution = [
        *_parts(repro.environment),
        *[
            SolutionPart(
                text=s.step,
                command=s.command,
                source_ids=s.source_ids,
                passage_ids=s.passage_ids,
                evidence_level=s.evidence_level,
            )
            for s in repro.steps
        ],
        *_parts(observed),
    ]
    return Task(
        id="",
        order=0,
        kind="reproduce",
        title="Reproduce the documented behavior safely",
        prompt="In a local or authorized lab that you control, reproduce the behavior the sources "
        "document. Then describe what you observed that confirms it. Do not test systems you do not own.",
        objective="Reproduce the documented behavior in a safe environment.",
        verification_criteria=[
            "Describes an observation, not just the steps taken",
            "The observation matches what the cited sources document",
            "Was obtained only in a local or authorized environment",
        ],
        context_source_ids=src or list(repro.evidence),
        key_points=points,
        solution=solution,
    )


def _cause(ctx: _Ctx) -> Task | None:
    g = ctx.guide
    ranked = sorted(
        g.root_cause or g.why_it_works, key=lambda c: 0 if _CAUSAL.search(c.text) else 1
    )
    claims = ranked[:2]
    if not claims:
        return None
    points: list[KeyPoint] = []
    for index, claim in enumerate(claims):
        sentence = _causal_sentence(claim.text)
        words = [
            w
            for w in content_words(sentence)
            if w not in ctx.product_terms and w not in _GENERIC_WORDS
        ][:8]
        # Code identifiers are accepted as an answer; product names, headers and IDs are not the cause.
        phrases = [x for ident in _identifiers(ctx, claim.text) for x in split_identifier(ident)]
        if not words and not phrases:
            continue
        points.append(
            KeyPoint(
                id=f"cause{index + 1}",
                label="the underlying cause the sources give",
                phrases=_unique(phrases),
                words=words,
                min_words=2 if len(words) >= 4 else 1,
                required=index == 0,
                statement=claim.text,
                source_ids=claim.source_ids,
                passage_ids=claim.passage_ids,
            )
        )
    if not points:
        return None
    src, _ = _refs(claims)
    return Task(
        id="",
        order=0,
        kind="explain_cause",
        title="Explain why the behavior occurs",
        prompt="In your own words, explain why the vulnerable behavior occurs. What does the software "
        "do (or fail to do) that makes it possible?",
        objective="Explain why the behavior occurs.",
        verification_criteria=[
            "States the underlying cause, not just the symptom",
            "Uses the mechanism the cited sources describe",
        ],
        context_source_ids=src,
        key_points=points,
        solution=_parts(claims),
    )


def _remediation(ctx: _Ctx) -> Task | None:
    claims = ctx.guide.remediation[:2]
    if not claims:
        return None
    text = " ".join(c.text for c in claims)
    lowered = text.lower()
    action_phrases: list[str] = []
    for verb, synonyms in _ACTIONS.items():
        if contains_phrase(lowered, verb):
            action_phrases += synonyms
    for feature in _FEATURE_RX.findall(text):
        action_phrases.append(feature.lower())
    settings = [t for t in specifics(text) if "=" in t]
    for setting in settings:
        action_phrases += split_identifier(setting.split("=")[0])
    versions = [t for t in specifics(text) if _VERSION_RX.match(t)]
    action_phrases = _unique(action_phrases)
    if not action_phrases and not versions:
        return None
    src, psg = _refs(claims)
    points: list[KeyPoint] = []
    if action_phrases:
        points.append(
            KeyPoint(
                id="action",
                label="the corrective action (what to change)",
                phrases=action_phrases,
                statement=claims[0].text,
                source_ids=src,
                passage_ids=psg,
            )
        )
    if versions:
        points.append(
            KeyPoint(
                id="fixed_version",
                label="the fixed version or setting",
                phrases=_unique(versions + settings),
                required=not action_phrases,
                source_ids=src,
                passage_ids=psg,
            )
        )
    return Task(
        id="",
        order=0,
        kind="identify_remediation",
        title="Identify the remediation",
        prompt="How should this vulnerability be fixed or mitigated? Include a specific version or "
        "setting if the sources give one.",
        objective="Identify the remediation.",
        verification_criteria=[
            "Describes a concrete fix or mitigation, not general advice",
            "Names the fixed version or setting when the sources give one",
        ],
        context_source_ids=src,
        key_points=points,
        solution=_parts(claims),
    )


# -- hints -----------------------------------------------------------------------------------------
_L1 = {
    "identify_component": "Start from the advisory's description of what goes wrong. Which stage of "
    "processing does the untrusted data reach, and which part of the software performs it?",
    "identify_input": "Follow the data. What does an attacker send to the software, and which piece "
    "of that request is used in an unsafe way?",
    "reproduce": "Use only a lab you control. Check whether the sources mention an intentionally "
    "vulnerable setup you can start locally, and what result they say to expect.",
    "explain_cause": "Think about what the software should do with the attacker's input before "
    "using it, and what it actually does instead.",
    "identify_remediation": "Look for the vendor's or advisory's own words on the fix: a version to "
    "move to, or a setting to change as a workaround.",
}
_L2_FALLBACK = {
    "identify_component": "The answer is a specific module, function or feature named in the sources.",
    "identify_input": "The answer is one specific request element named in the sources.",
    "reproduce": "The sources describe one concrete, checkable result of the documented request.",
    "explain_cause": "The sources give a single missing check or unsafe operation as the cause.",
    "identify_remediation": "The sources give one specific action, and possibly a version or setting.",
}


def _leaks(text: str, task: Task) -> bool:
    return any(
        contains_phrase(text, phrase)
        for kp in task.key_points
        if kp.required
        for phrase in kp.phrases
        if len(phrase) >= 3
    )


def _hints(ctx: _Ctx, task: Task) -> list[Hint]:
    primary = task.solution[0] if task.solution else None
    src = task.context_source_ids
    titles = ctx.source_titles(src)
    read = f" Sources to read: {', '.join(titles)}." if titles else ""
    if _leaks(read, task):  # a source title can contain an answer term: point by ID only
        read = f" Sources to read: {', '.join(f'[{i}]' for i in src[:3])}." if src else ""
    l1 = _L1[task.kind] + read
    if _leaks(l1, task):  # the templates are generic; guard anyway
        l1 = "Re-read the sources with this task's question in mind." + read

    all_phrases = [p for kp in task.key_points for p in kp.phrases]
    all_words = [w for kp in task.key_points for w in kp.words]
    if task.kind == "reproduce":
        basis = [s for s in task.solution if s.command is None][:2]
        explicit = "; ".join(s.text for s in basis)
        steps = [s.text for s in task.solution if s.command is not None]
        if steps:
            explicit += (
                (" Steps: " + " ".join(steps[:3])) if explicit else "Steps: " + " ".join(steps[:3])
            )
        p_src = list(dict.fromkeys(i for s in task.solution for i in s.source_ids))
        p_psg = list(dict.fromkeys(i for s in task.solution for i in s.passage_ids))
    else:
        explicit = primary.text if primary else ""
        p_src = primary.source_ids if primary else src
        p_psg = primary.passage_ids if primary else []
    explicit = _clip(explicit)
    masked = mask(explicit, all_phrases)
    if masked == explicit or _leaks(masked, task):
        masked = mask(masked, all_words) if masked != explicit else masked
    if not explicit or masked == explicit or _leaks(masked, task):
        l2 = _L2_FALLBACK[task.kind] + read
        l2_kind = "direction"
    else:
        l2 = f"A source puts it like this, with the key terms hidden: “{masked}”"
        l2_kind = "masked"
    l3 = (
        f"The sources state: “{explicit}”"
        if explicit
        else "The sources give no more detail on this task."
    )
    return [
        Hint(number=1, text=l1, kind="direction", source_ids=src),
        Hint(number=2, text=l2, kind=l2_kind, source_ids=p_src, passage_ids=[]),
        Hint(number=3, text=l3, kind="explicit", source_ids=p_src, passage_ids=p_psg),
    ]


# -- assembly ----------------------------------------------------------------------------------------
def build_challenge(guide: LearningGuide, cve: CVERecord) -> Challenge:
    ctx = _Ctx(guide, cve)
    builders = [
        ("component", _component),
        ("input", _input),
        ("reproduction", _reproduce),
        ("cause", _cause),
        ("remediation", _remediation),
    ]
    tasks: list[Task] = []
    notes: list[str] = []
    for name, build in builders:
        task = build(ctx)
        if task is None:
            notes.append(
                f"The '{name}' task was left out: the retrieved sources do not give enough "
                "specific detail to check an answer against."
            )
            continue
        task.order = len(tasks) + 1
        task.id = f"t{task.order}"
        task.hints = _hints(ctx, task)
        tasks.append(task)
    # What the student should bring, not what the sources found: the guide's own "prerequisites"
    # claims are conditions of the vulnerability and would give away the answers to the tasks.
    prerequisites = [Prerequisite(text=text) for text in STUDY_PREREQUISITES]
    if any(t.kind == "reproduce" for t in tasks):
        prerequisites.append(Prerequisite(text=LAB_PREREQUISITE))
    return Challenge(
        learning_objectives=[t.objective for t in tasks],
        prerequisites=prerequisites,
        tasks=tasks,
        notes=notes,
    )
