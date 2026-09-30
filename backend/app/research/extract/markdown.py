"""Markdown / plain text -> blocks. No rendering; HTML embedded in Markdown is reduced to text."""

import re

from app.research.domain import Block, ExtractedDocument
from app.research.extract.blocks import clean_code, clean_paragraph, finalize

_COMMENT = re.compile(r"<!--.*?-->", re.DOTALL)
_TAG = re.compile(r"</?[A-Za-z][^>]{0,300}>")
_IMAGE = re.compile(r"!\[[^\]]*\]\([^)]*\)")
_LINK = re.compile(r"\[([^\]]+)\]\([^)]*\)")
_REF_LINK_DEF = re.compile(r"^\s*\[[^\]]+\]:\s+\S+.*$")
_FENCE = re.compile(r"^\s{0,3}(```|~~~)")
_HEADING = re.compile(r"^\s{0,3}(#{1,6})\s+(.*?)\s*#*\s*$")
_LIST = re.compile(r"^\s*(?:[-*+]|\d{1,3}[.)])\s+(.*)$")
_TABLE_SEP = re.compile(r"^\s*\|?\s*:?-{2,}:?\s*(\|\s*:?-{2,}:?\s*)*\|?\s*$")


def _inline(text: str) -> str:
    text = _IMAGE.sub("", text)
    text = _LINK.sub(r"\1", text)
    text = _TAG.sub(" ", text)
    return text.replace("**", "").replace("__", "")


def extract_markdown(source: str) -> ExtractedDocument:
    stats: dict[str, int] = {}
    hidden = "\n".join(_COMMENT.findall(source))
    source = _COMMENT.sub("", source)

    blocks: list[Block] = []
    paragraph: list[str] = []
    code: list[str] | None = None
    fence_marker = ""

    def flush_paragraph() -> None:
        if paragraph:
            text = clean_paragraph(_inline(" ".join(paragraph)))
            if text:
                blocks.append(Block("paragraph", text))
            paragraph.clear()

    for line in source.splitlines():
        fence = _FENCE.match(line)
        if code is not None:
            if fence and fence.group(1) == fence_marker:
                text = clean_code("\n".join(code))
                if text:
                    blocks.append(Block("code", text))
                code = None
            else:
                code.append(line)
            continue
        if fence:
            flush_paragraph()
            code, fence_marker = [], fence.group(1)
            continue
        if not line.strip() or _REF_LINK_DEF.match(line):
            flush_paragraph()
            continue
        if line.startswith(("    ", "\t")) and not paragraph:
            # indented code block
            text = clean_code(line.lstrip("\t").removeprefix("    "))
            if text:
                blocks.append(Block("code", text))
            continue
        heading = _HEADING.match(line)
        if heading:
            flush_paragraph()
            text = clean_paragraph(_inline(heading.group(2)))
            if text:
                blocks.append(Block("heading", text, level=len(heading.group(1))))
            continue
        if line.lstrip().startswith("|"):
            flush_paragraph()
            if not _TABLE_SEP.match(line):
                cells = [c.strip() for c in line.strip().strip("|").split("|")]
                text = clean_paragraph(_inline(" | ".join(c for c in cells if c)))
                if text:
                    blocks.append(Block("table_row", text))
            continue
        if line.lstrip().startswith(">"):
            flush_paragraph()
            text = clean_paragraph(_inline(line.lstrip().lstrip(">")))
            if text:
                blocks.append(Block("quote", text))
            continue
        item = _LIST.match(line)
        if item:
            flush_paragraph()
            text = clean_paragraph(_inline(item.group(1)))
            if text:
                blocks.append(Block("list_item", text))
            continue
        paragraph.append(line.strip())
    flush_paragraph()
    if code:  # unterminated fence
        text = clean_code("\n".join(code))
        if text:
            blocks.append(Block("code", text))

    title = next((b.text for b in blocks if b.kind == "heading"), None)
    return ExtractedDocument(
        title=title, blocks=finalize(blocks, stats), hidden_text=hidden[:8000], stats=stats
    )


def extract_plain_text(source: str) -> ExtractedDocument:
    """Advisories and mailing-list posts: blank-line paragraphs; indented runs are code; quoted
    replies ('> ...') are not the author's own words and are kept only as 'quote'."""
    stats: dict[str, int] = {}
    blocks: list[Block] = []
    for chunk in re.split(r"\n\s*\n", source):
        lines = chunk.splitlines()
        if not lines:
            continue
        if all(line.startswith((">", "|")) for line in lines if line.strip()):
            text = clean_paragraph(" ".join(line.lstrip("> |") for line in lines))
            if text:
                blocks.append(Block("quote", text))
        elif all(line.startswith(("    ", "\t")) for line in lines if line.strip()):
            text = clean_code("\n".join(line.removeprefix("    ").lstrip("\t") for line in lines))
            if text:
                blocks.append(Block("code", text))
        else:
            text = clean_paragraph(" ".join(lines))
            if text:
                blocks.append(Block("paragraph", text))
    title = next((b.text for b in blocks if b.kind == "paragraph" and len(b.text) < 160), None)
    return ExtractedDocument(title=title, blocks=finalize(blocks, stats), stats=stats)
