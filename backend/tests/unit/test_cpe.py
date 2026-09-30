import pytest

from app.integrations.cpe import parse_cpe23


def test_parses_versionless_application() -> None:
    cpe = parse_cpe23("cpe:2.3:a:apache:log4j:*:*:*:*:*:*:*:*")
    assert (cpe.part, cpe.vendor, cpe.product, cpe.version, cpe.update) == (
        "a",
        "apache",
        "log4j",
        None,
        None,
    )


def test_parses_version_and_update() -> None:
    cpe = parse_cpe23("cpe:2.3:a:apache:log4j:2.0:beta9:*:*:*:*:*:*")
    assert (cpe.version, cpe.update) == ("2.0", "beta9")


def test_not_applicable_dash_means_no_value() -> None:
    assert parse_cpe23("cpe:2.3:a:netapp:snapcenter:-:*:*:*:*:*:*:*").version is None


def test_escaped_colons_are_not_separators() -> None:
    cpe = parse_cpe23(r"cpe:2.3:a:vendor\:inc:prod\:uct:1.0:*:*:*:*:*:*:*")
    assert (cpe.vendor, cpe.product) == ("vendor:inc", "prod:uct")


@pytest.mark.parametrize(
    "value",
    [
        "not-a-cpe",
        "cpe:2.3:a:x",
        "cpe:2.2:a:x:y:*:*:*:*:*:*:*:*",
        "cpe:2.3:z:x:y:*:*:*:*:*:*:*:*",
        "cpe:/a:x:y",
        None,
        5,
        "cpe:2.3:a:" + "x:" * 300,
    ],
)
def test_rejects_malformed(value: object) -> None:
    assert parse_cpe23(value) is None
