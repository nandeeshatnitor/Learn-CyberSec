"""Data carried through the research pipeline."""

from dataclasses import dataclass, field
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

BlockKind = Literal["heading", "paragraph", "list_item", "code", "quote", "table_row"]

FACETS = (
    "summary",
    "affected_versions",
    "root_cause",
    "prerequisites",
    "environment",
    "reproduction",
    "observation",
    "impact",
    "remediation",
)


@dataclass(frozen=True)
class Block:
    kind: BlockKind
    text: str
    level: int | None = None  # heading level


@dataclass
class ExtractedDocument:
    title: str | None
    blocks: list[Block]
    # Text that human readers cannot see (hidden elements, HTML comments, <noscript>). It is NEVER
    # used as content: it is kept only so hidden prompt-injection attempts can be detected.
    hidden_text: str = ""
    stats: dict[str, int] = field(default_factory=dict)

    @property
    def text(self) -> str:
        return "\n".join(b.text for b in self.blocks)


class Passage(BaseModel):
    """A short, relevant excerpt of a source: the unit of evidence that claims cite."""

    model_config = ConfigDict(extra="ignore")

    id: str  # "S2-P05"
    source_sid: str  # "S2"
    text: str
    kind: BlockKind = "paragraph"
    facets: list[str] = Field(default_factory=list)
    score: float = 0.0
    position: int = 0  # order within the source
    section: str | None = None  # nearest preceding heading, for context
    flags: list[str] = Field(default_factory=list)  # e.g. "injection_suspect"


@dataclass(frozen=True)
class SourceCandidate:
    """A URL that might hold useful information about the CVE, before anything is fetched."""

    url: str
    title: str | None = None
    tags: tuple[str, ...] = ()
    discoverer: str = "unknown"
    # provider ids that listed it (nvd, mitre) or "github", so the UI can show how it was found
    found_by: tuple[str, ...] = ()
    # Pre-fetched text (e.g. a GitHub advisory delivered by API): no HTTP fetch needed.
    inline_text: str | None = None
    inline_format: Literal["markdown", "text"] = "markdown"
