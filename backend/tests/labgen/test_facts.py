"""Affected-version identification and fact extraction from a guide and a CVE record."""

import pytest

from app.labgen import sanitize
from app.labgen.facts import extract_facts, parse_ranges
from app.research.synthesis.schema import LearningGuide
from tests.labgen.conftest import CVE_ID


def test_the_fictional_guide_yields_the_documented_facts(
    guide: LearningGuide, acme_cve: object
) -> None:
    facts = extract_facts(guide, acme_cve)
    assert facts.product == "AcmeDocs" and facts.vendor == "acme"
    assert facts.vulnerable_version == "4.2.3"  # stated as "4.0.0 through 4.2.3"
    assert "highest version the sources state" in facts.vulnerable_basis
    assert facts.fixed_version == "4.2.4"
    assert facts.headers[0] == "X-Template-Hint"
    assert facts.endpoints[0] == "/preview"
    assert facts.probe_result == "49"
    assert "expression_injection" in facts.keywords
    assert facts.fixed_evidence and facts.fixed_evidence[0].source_ids
    assert facts.vulnerable_evidence and "4.2.3" in facts.vulnerable_evidence[0].excerpt


def test_versions_before_the_range_are_not_read_as_affected(
    guide: LearningGuide, acme_cve: object
) -> None:
    """'Versions before 4.0.0 ... are not affected' must not become an affected range."""
    facts = extract_facts(guide, acme_cve)
    assert all(r.end != "4.0.0" for r in facts.ranges)


def test_a_vendor_test_image_is_recorded_but_never_used(
    guide: LearningGuide, acme_cve: object
) -> None:
    facts = extract_facts(guide, acme_cve)
    images = [a for a in facts.artifacts if a.kind == "docker_image"]
    assert images and images[0].value == "acmedocs/vulnerable:4.2.3"
    assert "never executed" in images[0].note or "Not pulled or run" in images[0].note


def test_without_a_stored_record_the_product_is_read_from_the_guide_text_only_when_claims_agree(
    guide: LearningGuide,
) -> None:
    facts = extract_facts(guide, None)
    assert facts.product == "AcmeDocs" and facts.product_from_text


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("Versions 4.0.0 through 4.2.3 are affected.", [("4.0.0", True, "4.2.3", True)]),
        ("AcmeDocs 4.2.3 and earlier is vulnerable.", [(None, False, "4.2.3", True)]),
        ("Affected: 1.0 <= version < 1.4.2", [("1.0", True, "1.4.2", False)]),
        ("All releases before 2.5.1 are vulnerable.", [(None, False, "2.5.1", False)]),
        ("Versions before 4.0.0 and version 4.2.4 and later are not affected.", []),
        (
            "Version 4.2.4 is not vulnerable, 4.2.3 and earlier is.",
            [],
        ),  # negated sentence is skipped
        ("Nothing about versions here.", []),
        ("Versions 5.0.0 through 4.0.0", []),  # a reversed range is rejected
    ],
)
def test_range_parsing(text: str, expected: list[tuple[str | None, bool, str, bool]]) -> None:
    found = [(r.start, r.start_inclusive, r.end, r.end_inclusive) for r, _ in parse_ranges(text)]
    assert found == expected


@pytest.mark.parametrize("value", ["4.2.3", "10.0", "1.2.3.4", "2.0b1"])
def test_sane_versions_pass(value: str) -> None:
    assert sanitize.version(value) == value


@pytest.mark.parametrize(
    "value",
    ["", "4", "4.2.3; rm -rf /", "v4.2.3", "../../etc", "4.2.3-$(id)", "x" * 40, "4..3"],
)
def test_hostile_versions_are_refused(value: str) -> None:
    assert sanitize.version(value) is None


@pytest.mark.parametrize(
    ("func", "good", "bad"),
    [
        (
            sanitize.product,
            "AcmeDocs",
            ["", "a", "Acme'; import os", "x" * 60, "Acme$(id)", "<b>Acme</b>"],
        ),
        (
            sanitize.header,
            "X-Template-Hint",
            [
                "Host",
                "X-",
                "X-Bad Header",
                "X-A\r\nB: c",
                "Authorization",
                "X-" + "a" * 50 + "-b-c-d-e",
            ],
        ),
        (
            sanitize.endpoint,
            "/preview",
            ["preview", "/../etc", "/a/b", "/Preview", "//x", "/a b", "/" + "a" * 40],
        ),
        (sanitize.parameter, "name", ["Name", "1a", "a-b", "a b", "x" * 40]),
        (
            sanitize.expression,
            "7*7",
            ["__import__('os')", "7**7**7", "a+b", "7*7*7*7", "1234*5", "7 // 7", "(7*7)"],
        ),
    ],
)
def test_every_value_that_enters_generated_code_is_strictly_validated(
    func, good: str, bad: list[str]
) -> None:  # type: ignore[no-untyped-def]
    assert func(good) == good
    for item in bad:
        assert func(item) is None, item


def test_the_family_name_comes_only_from_a_valid_cve_id() -> None:
    assert sanitize.family_of(CVE_ID) == "cve-2099-12345"
    for bad in ("CVE-1-2", "cve-2099-12345; x", "../x", ""):
        assert sanitize.family_of(bad) is None


def test_review_notes_are_plain_text() -> None:
    assert sanitize.review_note("Looks fine to me.") == "Looks fine to me."
    for bad in ("", "no", "x" * 3000, "bell\x07", "<script>é</script>"):
        assert sanitize.review_note(bad) is None


def test_version_ordering_is_numeric() -> None:
    assert sanitize.version_key("4.2.10") > sanitize.version_key("4.2.3")
    assert sanitize.version_key("4.10") > sanitize.version_key("4.9")
