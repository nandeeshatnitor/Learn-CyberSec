"""Lexical grounding checks: is what a claim says actually present in the evidence?

These checks are deliberately conservative and mechanical. They cannot prove that a paraphrase is
faithful, but they reliably catch the failures that matter most for a reproduction guide: invented
versions, identifiers, commands, paths, URLs and numbers. A claim containing a specific that appears
nowhere in the retrieved evidence is removed, not softened.
"""

import ipaddress
import re
import unicodedata
from urllib.parse import urlsplit

_INVISIBLE = re.compile("[​-‏‪-‮⁠-⁤⁦-⁩﻿­]")
_WS = re.compile(r"\s+")

# Specifics a claim must not invent. Each pattern picks out the *token* to look up in evidence.
_SPECIFIC_PATTERNS = (
    re.compile(r"`([^`\n]{2,120})`"),  # anything the writer marked as code
    re.compile(r"\bhttps?://[^\s<>\"')\]]+", re.IGNORECASE),  # URLs
    re.compile(r"\bCVE-\d{4}-\d{4,19}\b", re.IGNORECASE),
    re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}(?::\d{1,5})?\b"),  # IPv4 (and IPv4:port)
    re.compile(r"\bv?\d+(?:\.\d+){1,3}(?:[-+][0-9A-Za-z.]+)?\b"),  # versions such as 4.2.3
    re.compile(r"\b[A-Za-z][A-Za-z0-9]*(?:-[A-Za-z0-9]+){2,}\b"),  # X-Template-Hint, log4j-core-2
    re.compile(r"\b[A-Za-z_][\w]*\.[A-Za-z_][\w.]*\(\)?"),  # TemplateRenderer.resolveHint()
    re.compile(r"\b[a-z]+_[a-z0-9_]+\b"),  # snake_case identifiers
    re.compile(r"\b[a-z]+[A-Z][A-Za-z0-9]*\b"),  # camelCase identifiers
    re.compile(r"\b[A-Z][a-z0-9]+[A-Z][A-Za-z0-9]*\b"),  # PascalCase identifiers (AcmeDocs)
    re.compile(r"(?<![\w/])/(?:[\w.-]+/)*[\w.-]+"),  # absolute paths
    re.compile(
        r"\b[\w-]+\.(?:conf|cfg|ini|ya?ml|json|xml|properties|toml|jar|war|py|sh|php|jsp)\b"
    ),
    re.compile(r"\b[\w.-]+\.[\w.-]+=[\w.-]+\b"),  # config settings: preview.enabled=false
    re.compile(r"(?<![\w.])\d{2,}(?!\w|\.\d)"),  # bare numbers with 2+ digits (ports, results)
)
_TRAILING = ".,;:!?)]}'\""
_STOP = frozenset(
    (
        "the", "a", "an", "and", "or", "of", "to", "in", "on", "for", "with", "from", "by", "at",
        "as", "is", "are", "was", "were", "be", "been", "this", "that", "these", "those", "it",
        "its", "into", "than", "then", "when", "which", "who", "whom", "while", "also", "can",
        "could", "may", "might", "must", "should", "will", "would", "has", "have", "had", "not",
        "only", "any", "all", "some", "such", "other", "more", "most", "both", "each", "their",
        "there", "they", "them", "you", "your", "one", "two", "via", "per", "using", "use", "used",
        "uses", "because", "before", "after", "through", "under", "over", "between", "within",
        "without", "does", "did", "done", "being",
    )
)  # fmt: skip


def normalise(text: str) -> str:
    text = unicodedata.normalize("NFKC", text)
    text = _INVISIBLE.sub("", text).lower()
    return _WS.sub(" ", text).strip()


def specifics(text: str) -> list[str]:
    """Distinct specifics in `text` (normalised), longest first. Substrings of a longer specific
    are dropped so `4.2.3` inside `acmedocs-4.2.3` is not looked up twice."""
    found: dict[str, None] = {}
    for pattern in _SPECIFIC_PATTERNS:
        for match in pattern.finditer(text):
            raw = match.group(1) if pattern.groups else match.group(0)
            token = normalise(raw)
            if token.endswith("()"):
                token = token[:-2]
            token = token.rstrip(_TRAILING).lstrip("(")
            if len(token) >= 2:
                found[token] = None
    ordered = sorted(found, key=len, reverse=True)
    kept: list[str] = []
    for token in ordered:
        if not any(token in longer for longer in kept):
            kept.append(token)
    return kept


def present_in(token: str, haystack: str) -> bool:
    """`token` occurs in the normalised `haystack` as a whole token (not inside another)."""
    start = 0
    while True:
        index = haystack.find(token, start)
        if index < 0:
            return False
        before = haystack[index - 1] if index > 0 else " "
        end = index + len(token)
        after = haystack[end] if end < len(haystack) else " "
        after_two = haystack[end : end + 2]
        joined_before = before.isalnum() and token[0].isalnum()
        joined_after = after.isalnum() and token[-1].isalnum()
        version_continues = (
            token[-1].isdigit() and after == "." and len(after_two) == 2 and after_two[1].isdigit()
        )
        if not (joined_before or joined_after or version_continues):
            return True
        start = index + 1


def content_words(text: str) -> set[str]:
    words = re.findall(r"[a-z0-9][a-z0-9_.-]*[a-z0-9]|[a-z0-9]", normalise(text))
    return {w for w in words if len(w) >= 4 and w not in _STOP}


def overlap(claim: str, evidence: str) -> float:
    """Share of the claim's content words that also occur in the evidence text."""
    words = content_words(claim)
    if not words:
        return 1.0
    available = content_words(evidence)
    return len(words & available) / len(words)


# -- command and target safety ------------------------------------------------------------------
_PIPE_TO_INTERPRETER = re.compile(
    r"\|\s*(?:sudo\s+(?:-\w+\s+)?)?(?:ba|z|da|k|c|tc)?sh\b|\|\s*(?:python\d?|perl|ruby|node|php)\b",
    re.IGNORECASE,
)
_DESTRUCTIVE = re.compile(
    r"\brm\s+-[a-z]*r[a-z]*f?[a-z]*\s+(?:--no-preserve-root\s+)?(?:/|~|\*)|\bmkfs\b|"
    r"\bdd\s+[^|;]*\bof=/dev/|:\(\)\s*\{|\bchmod\s+-R\s+[0-7]{3,4}\s+/(?:\s|$)|>\s*/dev/sd|"
    r"\bshutdown\b|\bhalt\b|\breboot\b",
    re.IGNORECASE,
)
_URL_IN_COMMAND = re.compile(r"[a-z][a-z0-9+.-]*://[^\s'\"<>|;&)]+", re.IGNORECASE)
_USER_AT_HOST = re.compile(r"\b[\w.-]+@([A-Za-z0-9][A-Za-z0-9.-]*\.[A-Za-z]{2,})\b")
_IP_LITERAL = re.compile(r"(?<![\w.])(\d{1,3}(?:\.\d{1,3}){3})(?![\w.])")
_IMAGE_REGISTRY = re.compile(
    r"\bdocker\s+(?:run|pull|create)\b[^|;&]*?\s([a-z0-9.-]+\.[a-z]{2,}(?::\d+)?)/[\w./:@-]+",
    re.IGNORECASE,
)
_KNOWN_REGISTRIES = frozenset(
    {"docker.io", "ghcr.io", "quay.io", "mcr.microsoft.com", "gcr.io", "public.ecr.aws"}
)
_LAB_NETWORKS = tuple(
    ipaddress.ip_network(n)
    for n in ("127.0.0.0/8", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "169.254.0.0/16")
)
_LOCAL_SUFFIXES = (".localhost", ".local", ".test", ".internal", ".lan", ".home.arpa", ".invalid")
_LOCAL_NAMES = frozenset({"localhost", "host.docker.internal", "0.0.0.0"})  # noqa: S104 - a lab target, not a bind address


def is_local_host(host: str) -> bool:
    host = host.strip("[]").lower().rstrip(".")
    if host in _LOCAL_NAMES or host.endswith(_LOCAL_SUFFIXES):
        return True
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        return "." not in host  # a bare name such as a docker-compose service ("acmedocs")
    return _is_lab_ip(address)


def _is_lab_ip(address: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    """Loopback and RFC 1918 space only: documentation ranges are *not* lab addresses."""
    if isinstance(address, ipaddress.IPv6Address):
        return (
            address.is_loopback
            or address.is_link_local
            or address in ipaddress.ip_network("fc00::/7")
        )
    return any(address in network for network in _LAB_NETWORKS)


def non_local_hosts(text: str) -> list[str]:
    """Hosts in `text` that are not obviously a local or lab machine."""
    hosts: list[str] = []
    for url in _URL_IN_COMMAND.findall(text):
        try:
            host = urlsplit(url).hostname or ""
        except ValueError:
            host = "?"
        if not host or not is_local_host(host):
            hosts.append(host or "?")
    for match in _IP_LITERAL.finditer(text):
        try:
            address = ipaddress.ip_address(match.group(1))
        except ValueError:
            continue
        if not _is_lab_ip(address):
            hosts.append(str(address))
    hosts.extend(h for h in _USER_AT_HOST.findall(text) if not is_local_host(h))
    for registry in _IMAGE_REGISTRY.findall(text):
        name = registry.split(":")[0].lower()
        if name not in _KNOWN_REGISTRIES and not is_local_host(name):
            hosts.append(name)
    return list(dict.fromkeys(hosts))


def command_problem(command: str) -> str | None:
    """A fixed reason code when a command must not be shown as runnable, else None."""
    if _PIPE_TO_INTERPRETER.search(command):
        return "pipes_download_to_interpreter"
    if _DESTRUCTIVE.search(command):
        return "destructive_command"
    if non_local_hosts(command):
        return "targets_non_local_host"
    return None


def collapse_ws(text: str) -> str:
    return _WS.sub(" ", unicodedata.normalize("NFKC", text)).strip()
