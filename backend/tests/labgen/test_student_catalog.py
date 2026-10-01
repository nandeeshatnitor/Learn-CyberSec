"""What students can reach: only approved, currently offered labs; old versions keep resolving."""

import pytest

from app.labgen.catalog import LayeredCatalog, PublishedLabs
from app.models import CandidateStatus, LabInstance
from app.sandbox.template import LabCatalog, PlatformLimits
from app.services.errors import NotFoundError
from tests.conftest import FakeClock
from tests.labgen.conftest import ADMIN, CVE_ID, Labs
from tests.sandbox.conftest import (  # noqa: F401
    ALICE,
    LABS_DIR,
    Sandbox,
    build_sandbox,
    make_session,
)

STUDENT = PlatformLimits(allowed_image_prefixes=("cvelearn-lab/",))
V1, V2 = "cve-2099-12345-v1", "cve-2099-12345-v2"


@pytest.fixture
def static() -> LabCatalog:
    return LabCatalog.load(LABS_DIR, PlatformLimits())


@pytest.fixture
def student(labs: Labs, static: LabCatalog, clock: FakeClock) -> Sandbox:
    layered = LayeredCatalog(static, PublishedLabs(labs.repo, STUDENT))
    built = build_sandbox(labs.db, clock, layered)  # type: ignore[arg-type]
    # The images the publisher tags are "installed" in the fake runtime.
    built.runtime.images |= {"cvelearn-lab/cve-2099-12345:v1", "cvelearn-lab/cve-2099-12345:v2"}
    return built


def candidate(labs: Labs, **kwargs: object):  # type: ignore[no-untyped-def]
    c = labs.pipeline.request(CVE_ID, ADMIN, **kwargs)  # type: ignore[arg-type]
    labs.pipeline.run(c.id)
    done = labs.repo.get(c.id)
    assert done is not None and done.status is CandidateStatus.AWAITING_REVIEW
    return done


def ids(student: Sandbox, cve: str | None = None) -> list[str]:
    return [lab.id for lab in student.manager.labs(cve)]


def test_a_candidate_is_invisible_and_unstartable_for_students(
    labs: Labs, student: Sandbox
) -> None:
    c = candidate(labs)
    assert ids(student) == ["path-traversal-101"]
    for lab_id in (V1, f"cand-{str(c.id)[:8]}", c.family):
        with pytest.raises(NotFoundError):
            student.manager.lab(lab_id)
        with pytest.raises(NotFoundError):
            student.manager.start(ALICE, lab_id, None)


def test_a_rejected_or_changes_requested_candidate_stays_invisible(
    labs: Labs, student: Sandbox
) -> None:
    c = candidate(labs)
    labs.publisher.request_changes(c.id, "alice", "not yet")
    assert V1 not in ids(student)
    with pytest.raises(NotFoundError):
        student.manager.start(ALICE, V1, None)


def test_an_approved_lab_is_offered_and_startable(labs: Labs, student: Sandbox) -> None:
    labs.publisher.approve(candidate(labs).id, "alice", None)
    assert ids(student) == ["path-traversal-101", V1]
    assert ids(student, CVE_ID) == [V1] or V1 in ids(student, CVE_ID)
    lab = student.manager.lab(V1)
    assert lab.cve_id == CVE_ID and lab.title and lab.objectives
    view = student.manager.start(ALICE, V1, None)
    assert view.lab.id == V1 and view.status in ("running", "starting")
    row = student.repo.live_for(ALICE)
    assert isinstance(row, LabInstance) and row.lab_id == V1


def test_the_student_view_never_shows_the_image_or_internals(labs: Labs, student: Sandbox) -> None:
    labs.publisher.approve(candidate(labs).id, "alice", None)
    text = student.manager.lab(V1).model_dump_json()
    for hidden in ("cvelearn-lab", "cvelearn-candidate", "startup_command", "Dockerfile", "image"):
        assert hidden not in text


def test_v2_replaces_v1_for_new_starts_but_v1_records_keep_resolving(
    labs: Labs, student: Sandbox
) -> None:
    labs.publisher.approve(candidate(labs).id, "alice", None)
    started = student.manager.start(ALICE, V1, None)
    student.manager.stop(ALICE, started.id)

    first = labs.repo.search()[0]
    second = labs.pipeline.request(CVE_ID, ADMIN, parent=first)
    labs.pipeline.run(second.id)
    labs.publisher.approve(second.id, "alice", None)

    assert V2 in ids(student) and V1 not in ids(student)
    with pytest.raises(NotFoundError):
        student.manager.start(ALICE, V1, None)  # no longer offered
    # The learner's earlier instance still shows the version they actually used.
    old = student.manager.get(ALICE, started.id)
    assert old.lab.id == V1
    assert student.manager.lab(V1).id == V1  # direct lookups still resolve
    again = student.manager.start(ALICE, V2, None)
    assert again.lab.id == V2


def test_a_withdrawn_version_is_not_offered_but_still_resolves(
    labs: Labs, student: Sandbox
) -> None:
    version = labs.publisher.approve(candidate(labs).id, "alice", None)
    started = student.manager.start(ALICE, V1, None)
    student.manager.stop(ALICE, started.id)
    labs.publisher.withdraw(version.id, "alice", "problem found")
    assert V1 not in ids(student)
    with pytest.raises(NotFoundError):
        student.manager.start(ALICE, V1, None)
    assert student.manager.get(ALICE, started.id).lab.id == V1


def test_a_learning_session_shows_retired_versions_the_learner_used(
    labs: Labs,
    student: Sandbox,
    make_session,  # type: ignore[no-untyped-def]  # noqa: F811
) -> None:
    session = make_session(ALICE, CVE_ID)
    labs.publisher.approve(candidate(labs).id, "alice", None)
    started = student.manager.start(ALICE, V1, str(session.id))
    student.manager.stop(ALICE, started.id)
    progress = student.manager.session_labs(ALICE, str(session.id))
    assert [(p.lab.id, p.retired) for p in progress.labs] == [(V1, False)]

    first = labs.repo.search()[0]
    second = labs.pipeline.request(CVE_ID, ADMIN, parent=first)
    labs.pipeline.run(second.id)
    labs.publisher.approve(second.id, "alice", None)

    progress = student.manager.session_labs(ALICE, str(session.id))
    assert [(p.lab.id, p.retired) for p in progress.labs] == [(V2, False), (V1, True)]


def test_labs_are_not_offered_when_the_feature_is_off(
    labs: Labs, static: LabCatalog, clock: FakeClock
) -> None:
    labs.publisher.approve(candidate(labs).id, "alice", None)
    plain = build_sandbox(labs.db, clock, static)
    assert [lab.id for lab in plain.manager.labs()] == ["path-traversal-101"]
