"""Lab definitions: strict validation, platform ceilings, and the catalogue."""

import copy
import json
from pathlib import Path
from typing import Any

import pytest
from pydantic import ValidationError

from app.sandbox.template import (
    LabCatalog,
    LabTemplate,
    PlatformLimits,
    TemplateError,
    check_limits,
    safe_request_path,
)
from tests.sandbox.conftest import LABS_DIR


@pytest.fixture
def raw() -> dict[str, Any]:
    return json.loads((LABS_DIR / "path-traversal-101" / "lab.json").read_text())


def make(raw: dict[str, Any], **changes: Any) -> LabTemplate:
    data = copy.deepcopy(raw)
    data.update(changes)
    return LabTemplate.model_validate(data)


def test_the_demo_lab_definition_is_valid(raw: dict[str, Any]) -> None:
    lab = make(raw)
    assert lab.user == "10001:10001"
    assert lab.network.egress == "none"
    assert [c.id for c in lab.verification.checks] == ["exploit", "remediate"]


@pytest.mark.parametrize(
    "changes",
    [
        {"user": "0:0"},
        {"user": "root"},
        {"user": "10001:0"},
        {"user": "0:10001"},
        {
            "image": "python:3.12"
        },  # no repository prefix is fine for the schema but see limits below
        {"image": "cvelearn-lab/x@sha256:" + "a" * 64},
        {"image": "cvelearn-lab/x"},
        {"startup_command": []},
        {"startup_command": ["ok", "bad\nline"]},
        {"shell": []},
        {"writable_paths": ["/"]},
        {"writable_paths": ["/etc"]},
        {"writable_paths": ["/proc"]},
        {"writable_paths": ["relative"]},
        {"writable_paths": ["/lab/../etc"]},
        {"writable_paths": ["/lab", "/lab"]},
        {"writable_paths": ["/lab space"]},
        {"environment": {"PATH": "/bin"}},
        {"environment": {"LD_PRELOAD": "/x"}},
        {"environment": {"lowercase": "x"}},
        {"environment": {"LAB_CANARY": "x"}},  # the platform sets the secret
        {"ports": [{"name": "app", "container_port": 80}]},  # privileged port
        {
            "ports": [
                {"name": "app", "container_port": 8080},
                {"name": "app", "container_port": 8081},
            ]
        },
        {"network": {"egress": "internet"}},
        {"network": {"egress": "none", "allow": ["1.1.1.1"]}},
        {"resources": {"cpus": 0}},
        {"resources": {"pids": 1}},
        {"timeout_minutes": 0},
        {"id": "Bad_ID"},
        {"cve_id": "CVE-XXXX"},
        {"cwe_ids": ["22"]},
        {"privileged": True},  # unknown fields are refused
        {"volumes": ["/:/host"]},
        {"cap_add": ["SYS_ADMIN"]},
        {"mounts": ["/var/run/docker.sock"]},
    ],
)
def test_an_unsafe_or_unknown_definition_is_rejected(
    raw: dict[str, Any], changes: dict[str, Any]
) -> None:
    if changes == {"image": "python:3.12"}:
        # Schema-valid (the allow-list is a platform limit, tested below).
        make(raw, **changes)
        with pytest.raises(TemplateError):
            check_limits(make(raw, **changes), PlatformLimits())
        return
    with pytest.raises(ValidationError):
        make(raw, **changes)


def test_checks_must_refer_to_declared_ports_and_earlier_checks(raw: dict[str, Any]) -> None:
    data = copy.deepcopy(raw)
    data["verification"]["checks"][0]["port"] = "nope"
    with pytest.raises(ValidationError):
        LabTemplate.model_validate(data)
    data = copy.deepcopy(raw)
    data["verification"]["checks"][0]["requires"] = ["remediate"]  # a later check
    with pytest.raises(ValidationError):
        LabTemplate.model_validate(data)
    data = copy.deepcopy(raw)
    data["verification"]["checks"][1]["id"] = "exploit"  # duplicate ids
    with pytest.raises(ValidationError):
        LabTemplate.model_validate(data)


def test_a_check_that_restarts_needs_a_restart_command(raw: dict[str, Any]) -> None:
    data = copy.deepcopy(raw)
    data["verification"]["restart_command"] = None
    with pytest.raises(ValidationError):
        LabTemplate.model_validate(data)


@pytest.mark.parametrize(
    "path",
    [
        "http://evil.example/x",
        "//evil.example/x",
        "download",
        "/a b",
        "/a\r\nHost: x",
        "/" + "a" * 600,
        "/x#frag",
        "/\x00",
    ],
)
def test_request_paths_can_only_be_plain_paths(path: str) -> None:
    with pytest.raises(ValueError):
        safe_request_path(path)


@pytest.mark.parametrize(
    "path", ["/", "/download?name=../private/canary.txt", "/a/b?x=%2e%2e%2f&y=1"]
)
def test_plain_paths_are_accepted(path: str) -> None:
    assert safe_request_path(path) == path


def test_platform_ceilings_are_enforced(raw: dict[str, Any]) -> None:
    lab = make(raw)
    check_limits(lab, PlatformLimits())
    for limits in (
        PlatformLimits(max_cpus=0.25),
        PlatformLimits(max_memory_mb=64),
        PlatformLimits(max_pids=32),
        PlatformLimits(max_tmpfs_mb=8),
        PlatformLimits(max_timeout_minutes=30),
        PlatformLimits(allowed_image_prefixes=("other/",)),
    ):
        with pytest.raises(TemplateError):
            check_limits(lab, limits)


def test_the_catalogue_skips_a_broken_definition_instead_of_failing(
    tmp_path: Path, raw: dict[str, Any]
) -> None:
    good = tmp_path / "path-traversal-101"
    good.mkdir()
    (good / "lab.json").write_text(json.dumps(raw))
    bad = tmp_path / "broken-lab"
    bad.mkdir()
    (bad / "lab.json").write_text(json.dumps({**raw, "id": "broken-lab", "user": "0:0"}))
    mismatch = tmp_path / "other-name"
    mismatch.mkdir()
    (mismatch / "lab.json").write_text(json.dumps(raw))  # id does not match the directory
    garbage = tmp_path / "garbage-lab"
    garbage.mkdir()
    (garbage / "lab.json").write_text("{not json")
    catalog = LabCatalog.load(tmp_path, PlatformLimits())
    assert list(catalog.labs) == ["path-traversal-101"]
    assert set(catalog.errors) == {"broken-lab", "other-name", "garbage-lab"}


def test_a_definition_over_the_platform_limits_is_not_loaded(
    tmp_path: Path, raw: dict[str, Any]
) -> None:
    folder = tmp_path / "path-traversal-101"
    folder.mkdir()
    (folder / "lab.json").write_text(json.dumps(raw))
    assert not LabCatalog.load(tmp_path, PlatformLimits(max_memory_mb=64)).labs


def test_labs_are_matched_by_cve_then_by_weakness(raw: dict[str, Any]) -> None:
    generic = make(raw)
    specific = make(raw, id="cve-lab-2099", cve_id="CVE-2099-1111", cwe_ids=[])
    other = make(raw, id="other-lab-xyz", cwe_ids=["CWE-89"])
    catalog = LabCatalog(labs={t.id: t for t in (generic, specific, other)})
    assert [t.id for t in catalog.matching("CVE-2099-1111", ["CWE-22"])] == [
        "cve-lab-2099",
        "path-traversal-101",
    ]
    assert [t.id for t in catalog.matching("CVE-2000-0001", ["CWE-89"])] == ["other-lab-xyz"]
    assert catalog.matching("CVE-2000-0001", []) == []
    assert catalog.matching(None, []) == []
