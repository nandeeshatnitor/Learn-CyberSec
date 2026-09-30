"""HTML -> readable blocks, without executing anything.

The page is only parsed (never rendered or scripted). Navigation, banners and other page furniture
are removed; text hidden from human readers is set aside for injection screening and discarded.
"""

import re
from collections.abc import Iterator

from bs4 import BeautifulSoup
from bs4.element import Comment, NavigableString, Tag

from app.research.domain import Block, ExtractedDocument
from app.research.extract.blocks import (
    clean_code,
    clean_paragraph,
    finalize,
)
from app.utils.sanitize import clean_text

_DROP_TAGS = frozenset(
    {
        "script", "style", "noscript", "template", "svg", "canvas", "iframe", "object", "embed",
        "form", "button", "input", "select", "textarea", "nav", "footer", "aside", "dialog",
        "audio", "video", "picture", "map", "head", "meta", "link", "title",
    }
)  # fmt: skip
_HIDDEN_ONLY_TAGS = frozenset({"noscript", "template", "iframe", "object", "embed"})
_BOILERPLATE_CLASS = re.compile(
    r"(^|[-_ ])(cookie|cookies|consent|gdpr|banner|newsletter|subscribe|signup|sidebar|share|"
    r"sharing|social|comments?|related|breadcrumbs?|menu|navbar|nav|footer|adverts?|ads?|promo|"
    r"popup|modal|toc|pagination|skip|masthead|toolbar)([-_ ]|$)",
    re.IGNORECASE,
)
_BOILERPLATE_ROLES = frozenset(
    {"navigation", "banner", "complementary", "contentinfo", "search", "dialog", "alertdialog"}
)
_HIDDEN_STYLE = re.compile(
    r"display\s*:\s*none|visibility\s*:\s*hidden|font-size\s*:\s*0(?![.\d])|opacity\s*:\s*0(?:\.0+)?(?![.\d])|"
    r"(?:left|top|text-indent|margin-left)\s*:\s*-\d{3,}|(?:height|width|max-height)\s*:\s*0(?:px)?(?![.\d])|"
    r"clip\s*:\s*rect\(\s*0|transform\s*:\s*scale\(\s*0\s*\)|color\s*:\s*transparent",
    re.IGNORECASE,
)
_CONTENT_SELECTOR = (
    "article, main, [role=main], #content, #main, .post-content, .entry-content, .article-body, "
    ".markdown-body, .post, .content, #readme"
)
_BLOCK_TAGS = frozenset(
    {
        "p", "div", "section", "article", "main", "li", "ul", "ol", "dl", "dt", "dd", "tr", "table",
        "thead", "tbody", "blockquote", "pre", "h1", "h2", "h3", "h4", "h5", "h6", "figure",
        "figcaption", "details", "summary", "address", "hr", "br",
    }
)  # fmt: skip
_HEADINGS = {f"h{i}": i for i in range(1, 7)}
MAX_DEPTH = 120
MAX_HIDDEN_CHARS = 8000


def _is_hidden(tag: Tag) -> bool:
    attrs = tag.attrs or {}
    if "hidden" in attrs or str(attrs.get("aria-hidden", "")).lower() == "true":
        return True
    style = attrs.get("style")
    return isinstance(style, str) and bool(_HIDDEN_STYLE.search(style))


def _is_boilerplate(tag: Tag) -> bool:
    attrs = tag.attrs or {}
    if str(attrs.get("role", "")).lower() in _BOILERPLATE_ROLES:
        return True
    tokens = " ".join(attrs.get("class", []) if isinstance(attrs.get("class"), list) else [])
    identifier = str(attrs.get("id", ""))
    return bool(_BOILERPLATE_CLASS.search(tokens) or _BOILERPLATE_CLASS.search(identifier))


def _inside(tag: Tag, names: frozenset[str]) -> bool:
    return any(getattr(parent, "name", None) in names for parent in tag.parents)


def _strip_page_furniture(soup: BeautifulSoup, stats: dict[str, int]) -> list[str]:
    """Remove non-content nodes; return the text of hidden ones (for screening only)."""
    hidden: list[str] = []
    for comment in soup.find_all(string=lambda node: isinstance(node, Comment)):
        hidden.append(str(comment))
        comment.extract()
    for tag in list(soup.find_all(True)):
        if tag.decomposed:
            continue
        if tag.name in _DROP_TAGS:
            if tag.name in _HIDDEN_ONLY_TAGS:
                hidden.append(tag.get_text(" ", strip=True))
            tag.decompose()
            continue
        if _is_hidden(tag):
            hidden.append(tag.get_text(" ", strip=True))
            stats["hidden_elements"] = stats.get("hidden_elements", 0) + 1
            tag.decompose()
            continue
        if _is_boilerplate(tag):
            stats["dropped_boilerplate"] = stats.get("dropped_boilerplate", 0) + 1
            tag.decompose()
            continue
        if tag.name == "header" and not _inside(tag, frozenset({"article", "main"})):
            tag.decompose()
    return [h for h in hidden if h]


def _content_root(soup: BeautifulSoup) -> Tag:
    candidates = [c for c in soup.select(_CONTENT_SELECTOR) if isinstance(c, Tag)]
    if candidates:
        return max(candidates, key=lambda c: len(c.get_text(" ", strip=True)))
    return soup.body if isinstance(soup.body, Tag) else soup


class _Collector:
    def __init__(self) -> None:
        self.blocks: list[Block] = []
        self._buffer: list[str] = []
        self._link_chars = 0
        self._total_chars = 0

    def text(self, value: str, *, in_link: bool) -> None:
        self._buffer.append(value)
        stripped = len(value.strip())
        self._total_chars += stripped
        if in_link:
            self._link_chars += stripped

    def flush(self, kind: str, level: int | None = None) -> None:
        raw = "".join(self._buffer)
        link_chars, total_chars = self._link_chars, self._total_chars
        self._buffer, self._link_chars, self._total_chars = [], 0, 0
        text = clean_code(raw) if kind == "code" else clean_paragraph(raw)
        if not text:
            return
        # Link-dense short blocks are navigation, not prose.
        if kind != "code" and total_chars and link_chars / total_chars >= 0.7 and len(text) < 250:
            return
        self.blocks.append(Block(kind=kind, text=text, level=level))  # type: ignore[arg-type]


def _walk(node: Tag, out: _Collector, ctx: str, depth: int, in_link: bool) -> None:
    for child in list(node.children):
        if isinstance(child, NavigableString):
            if not isinstance(child, Comment):
                out.text(str(child), in_link=in_link)
            continue
        if not isinstance(child, Tag):
            continue
        name = child.name
        if depth > MAX_DEPTH:
            out.text(child.get_text(" ", strip=True) + " ", in_link=in_link)
            continue
        if name == "pre":
            out.flush(ctx)
            out.text(child.get_text(), in_link=False)  # preserve newlines
            out.flush("code")
        elif name in _HEADINGS:
            out.flush(ctx)
            _walk(child, out, "heading", depth + 1, in_link)
            out.flush("heading", _HEADINGS[name])
        elif name in ("li", "dt", "dd"):
            out.flush(ctx)
            _walk(child, out, "list_item", depth + 1, in_link)
            out.flush("list_item")
        elif name == "tr":
            out.flush(ctx)
            for cell in child.find_all(["td", "th"], recursive=False):
                _walk(cell, out, "table_row", depth + 1, in_link)
                out.text(" | ", in_link=False)
            out.flush("table_row")
        elif name == "blockquote":
            out.flush(ctx)
            _walk(child, out, "quote", depth + 1, in_link)
            out.flush("quote")
        elif name == "br":
            out.text(" ", in_link=False)
        elif name in _BLOCK_TAGS:
            out.flush(ctx)
            _walk(child, out, "paragraph" if ctx == "list_item" else ctx, depth + 1, in_link)
            out.flush(ctx if ctx in ("list_item", "quote") else "paragraph")
        else:
            _walk(child, out, ctx, depth + 1, in_link or name == "a")


def _iter_hidden(parts: list[str]) -> Iterator[str]:
    total = 0
    for part in parts:
        if total >= MAX_HIDDEN_CHARS:
            break
        yield part[: MAX_HIDDEN_CHARS - total]
        total += len(part)


def extract_html(body: bytes, charset: str | None = None) -> ExtractedDocument:
    soup = BeautifulSoup(body, "html.parser", from_encoding=charset)
    # The <title> lives in <head>, which is dropped as furniture below: read it first.
    title_tag = soup.find("title")
    raw_title = title_tag.get_text(" ", strip=True) if isinstance(title_tag, Tag) else None
    stats: dict[str, int] = {}
    hidden = _strip_page_furniture(soup, stats)
    root = _content_root(soup)
    collector = _Collector()
    _walk(root, collector, "paragraph", 0, False)
    collector.flush("paragraph")
    blocks = finalize(collector.blocks, stats)
    title = clean_text(re.split(r"\s+[|–—-]\s+", raw_title)[0], 300) if raw_title else None
    if title is None:
        heading = next((b.text for b in blocks if b.kind == "heading"), None)
        title = clean_text(heading, 300) if heading else None
    return ExtractedDocument(
        title=title, blocks=blocks, hidden_text="\n".join(_iter_hidden(hidden)), stats=stats
    )
