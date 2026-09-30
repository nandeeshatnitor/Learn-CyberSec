from app.research.domain import ExtractedDocument
from app.research.extract.html import extract_html
from app.research.extract.markdown import extract_markdown, extract_plain_text

_HTML_TYPES = frozenset({"text/html", "application/xhtml+xml"})
_MARKDOWN_TYPES = frozenset({"text/markdown", "text/x-markdown"})


class ExtractionError(Exception):
    """The document could not be turned into text safely (for example pathological markup)."""


def _decode(body: bytes, charset: str | None) -> str:
    return body.decode(charset or "utf-8", errors="replace")


def extract_document(
    body: bytes, content_type: str, charset: str | None = None, *, url: str = ""
) -> ExtractedDocument:
    try:
        if content_type in _HTML_TYPES:
            return extract_html(body, charset)
        if content_type in _MARKDOWN_TYPES or url.lower().endswith((".md", ".markdown")):
            return extract_markdown(_decode(body, charset))
        return extract_plain_text(_decode(body, charset))
    except RecursionError as exc:
        raise ExtractionError("document nesting too deep") from exc
    except (ValueError, TypeError) as exc:
        raise ExtractionError("document could not be parsed") from exc
