"""The candidate pipeline against a REAL Docker daemon (opt-in; see tests/sandbox/test_docker_integration.py).

SANDBOX_TEST_DOCKER=1 pytest tests/labgen/test_pipeline_docker.py
"""

import os
import subprocess

import pytest
from sqlalchemy.orm import Session

from app.labgen.build import CandidateBuilder
from app.labgen.generate import CandidateGenerator
from app.labgen.pipeline import CandidatePipeline, PipelineConfig
from app.labgen.scan import CANDIDATE_IMAGE_PREFIX
from app.labgen.validate import CandidateValidator
from app.models import CandidateStatus, StageStatus
from app.repositories import CVERepository, LabgenRepository, ResearchRepository, SandboxRepository
from app.sandbox.app_client import HttpxAppTransport
from app.sandbox.config import SandboxConfig
from app.sandbox.docker_runtime import DockerRuntime, SubprocessRunner
from app.sandbox.firewall import HostFirewall
from app.sandbox.template import PlatformLimits
from tests.labgen.conftest import ADMIN, CVE_ID

IMAGES = ("cvelearn-lab/net-probe:1", "python:3.12-alpine")


def _docker(*args: str) -> str:
    done = subprocess.run(
        ["docker", *args], capture_output=True, text=True, timeout=120, check=False
    )
    return done.stdout.strip()


def _available() -> bool:
    if os.environ.get("SANDBOX_TEST_DOCKER") != "1" or os.geteuid() != 0:
        return False
    try:
        return all(_docker("image", "inspect", "--format", "{{.Id}}", i) for i in IMAGES)
    except (OSError, subprocess.SubprocessError):
        return False


pytestmark = pytest.mark.skipif(
    not _available(), reason="set SANDBOX_TEST_DOCKER=1 (root, Docker) to run"
)


def purge() -> None:
    for kind, fmt in (("ps", "{{.ID}}"),):
        for cid in _docker(
            kind, "--all", "--quiet", "--filter", "label=cvelearn.managed=true"
        ).split():
            _docker("rm", "--force", cid)
    for name in _docker(
        "network", "ls", "--filter", "label=cvelearn.managed=true", "--format", "{{.Name}}"
    ).split():
        _docker("network", "rm", name)
    for tag in _docker("images", "--format", "{{.Repository}}:{{.Tag}}").split():
        if tag.startswith(("cvelearn-candidate/", "cvelearn-lab/cve-")):
            _docker("rmi", "--force", tag)


@pytest.fixture
def real(db: Session, repo: ResearchRepository, ready_guide: None, acme_cve: object):  # type: ignore[no-untyped-def]
    purge()
    runner = SubprocessRunner()
    runtime = DockerRuntime(runner, firewall=HostFirewall(runner))
    config = SandboxConfig(grace_seconds=30, start_timeout_seconds=60)
    validator = CandidateValidator(
        runtime, SandboxRepository(db), HttpxAppTransport(config.subnet_pool), config
    )
    labgen = LabgenRepository(db)
    pipeline = CandidatePipeline(
        labgen,
        repo,
        CVERepository(db),
        CandidateGenerator(),
        CandidateBuilder(runner),
        validator,
        PipelineConfig(
            ["python:3.12-alpine"], PlatformLimits(allowed_image_prefixes=(CANDIDATE_IMAGE_PREFIX,))
        ),
    )
    yield pipeline, labgen
    purge()


def test_a_candidate_is_generated_built_and_validated_on_real_docker(real) -> None:  # type: ignore[no-untyped-def]
    pipeline, labgen = real
    candidate = pipeline.request(CVE_ID, ADMIN)
    pipeline.run(candidate.id)
    done = labgen.get(candidate.id)
    assert done is not None
    report = done.validation_report or {}
    print(
        "\n".join(f"{c['id']:14} {c['status']:8} {c['detail']}" for c in report.get("checks", []))
    )
    print(
        "\n".join(
            f"{c['id']:14} {c['status']:8} {c['detail']}"
            for c in (done.security_report or {}).get("runtime", [])
        )
    )
    print(done.build_log[-600:] if done.build_log else "", done.error_code, done.stage_detail)
    assert done.status is CandidateStatus.AWAITING_REVIEW, done.status
    assert (done.build_status, done.validation_status, done.security_status) == (
        StageStatus.PASSED,
    ) * 3


def test_an_approved_candidate_becomes_a_lab_a_student_can_run_and_v1_stays_immutable(real) -> None:  # type: ignore[no-untyped-def]
    """Approve the validated candidate with the real Docker builder, then start the published
    version the way a student would (through the layered catalog) and exploit it."""
    from app.cache import InMemorySlidingWindowLimiter
    from app.labgen.catalog import LayeredCatalog, PublishedLabs
    from app.labgen.publish import STUDENT_IMAGE_PREFIX, LabPublisher
    from app.models import VersionStatus
    from app.sandbox.instances import InstanceManager
    from app.sandbox.network import NetworkController
    from app.sandbox.template import LabCatalog
    from app.sandbox.verifier import Verifier

    pipeline, labgen = real
    candidate = pipeline.request(CVE_ID, ADMIN)
    pipeline.run(candidate.id)
    done = labgen.get(candidate.id)
    assert done is not None and done.status is CandidateStatus.AWAITING_REVIEW

    db = labgen._session  # the same session the pipeline used  # noqa: SLF001
    runner = SubprocessRunner()
    limits = PlatformLimits(allowed_image_prefixes=(STUDENT_IMAGE_PREFIX,))
    publisher = LabPublisher(labgen, CandidateBuilder(runner), limits)
    version = publisher.approve(candidate.id, "alice", "Reviewed the files.")
    assert version.lab_id == "cve-2099-12345-v1" and version.status is VersionStatus.PUBLISHED
    assert _docker("image", "inspect", "--format", "{{.Id}}", version.image_tag) == done.image_id

    config = SandboxConfig(grace_seconds=30, start_timeout_seconds=60)
    runtime = DockerRuntime(runner, firewall=HostFirewall(runner))
    transport = HttpxAppTransport(config.subnet_pool)
    repo = SandboxRepository(db)
    catalog = LayeredCatalog(LabCatalog(labs={}), PublishedLabs(labgen, limits))
    networks = NetworkController(
        runtime, subnet_pool=config.subnet_pool, probe_image=config.probe_image, gate_enabled=True
    )
    instances = InstanceManager(
        repo, runtime, networks, catalog, transport, config, InMemorySlidingWindowLimiter()
    )
    student = "student-" + "0" * 32
    row = instances.start(student, version.lab_id)
    try:
        assert row.address is not None
        template = catalog.get(version.lab_id)
        assert template is not None
        verifier = Verifier(repo, runtime, transport, request_timeout=config.verify_timeout_seconds)
        check = template.verification.checks[0]
        outcome = verifier.verify(row, template, check.id, "${secret}")
        assert outcome.status == "passed", outcome
        wrong = verifier.verify(row, template, check.id, "${7*7}")
        assert wrong.status != "passed"
    finally:
        instances.stop(student, row.id)

    # A later change is a new version; v1 keeps its exact content.
    before = version.content_hash
    labgen.update_fields(candidate.id, status=CandidateStatus.APPROVED)
    nxt = pipeline.request(CVE_ID, ADMIN, parent=labgen.get(candidate.id))
    pipeline.run(nxt.id)
    second = publisher.approve(nxt.id, "alice", None)
    assert second.lab_id == "cve-2099-12345-v2"
    db.expire_all()
    old = labgen.get_version("cve-2099-12345-v1")
    assert old is not None and old.status is VersionStatus.SUPERSEDED and old.content_hash == before
    assert catalog.is_offered("cve-2099-12345-v2") and not catalog.is_offered("cve-2099-12345-v1")
    assert catalog.get("cve-2099-12345-v1") is not None
