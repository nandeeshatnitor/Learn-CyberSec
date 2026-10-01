"""Human decisions, publication, versioning and immutability."""

import copy

import pytest
from sqlalchemy import text
from sqlalchemy.orm import Session

from app.labgen.catalog import PublishedLabs, template_of, version_hash
from app.models import (
    CandidateStatus,
    ImmutableVersionError,
    LabCandidate,
    LabVersion,
    StageStatus,
    VersionStatus,
)
from app.sandbox.template import PlatformLimits
from app.services.errors import ConflictError, InvalidInputError, NotFoundError
from tests.labgen.conftest import ADMIN, CVE_ID, Labs

STUDENT = PlatformLimits(allowed_image_prefixes=("cvelearn-lab/",))


def reviewable(labs: Labs, **kwargs: object) -> LabCandidate:
    candidate = labs.pipeline.request(CVE_ID, ADMIN, **kwargs)  # type: ignore[arg-type]
    labs.pipeline.run(candidate.id)
    done = labs.repo.get(candidate.id)
    assert done is not None and done.status is CandidateStatus.AWAITING_REVIEW
    return done


def test_approval_publishes_the_first_immutable_version(labs: Labs) -> None:
    candidate = reviewable(labs)
    version = labs.publisher.approve(candidate.id, "alice", "Looks right.")
    assert version.lab_id == "cve-2099-12345-v1" and version.version == 1
    assert version.status is VersionStatus.PUBLISHED and version.published_by == "alice"
    assert version.image_tag == "cvelearn-lab/cve-2099-12345:v1"
    assert version.image_tag in labs.builder.images
    assert version.spec["image"] == version.image_tag and version.spec["id"] == version.lab_id
    assert version.content_hash == version_hash(version.spec, version.files)
    done = labs.repo.get(candidate.id)
    assert done is not None
    assert done.status is CandidateStatus.APPROVED and done.reviewer == "alice"
    assert done.version_id == version.id
    [review] = labs.repo.reviews(candidate.id)
    assert (review.action, review.reviewer, review.notes) == ("approve", "alice", "Looks right.")


def test_a_published_version_loads_as_a_valid_lab(labs: Labs) -> None:
    version = labs.publisher.approve(reviewable(labs).id, "alice", None)
    template = template_of(version, STUDENT)
    assert template is not None and template.id == "cve-2099-12345-v1"
    assert template.cve_id == CVE_ID and template.verification.checks


@pytest.mark.parametrize(
    "status",
    [
        CandidateStatus.GENERATING,
        CandidateStatus.BUILDING,
        CandidateStatus.VALIDATING,
        CandidateStatus.VALIDATION_FAILED,
        CandidateStatus.BUILD_FAILED,
        CandidateStatus.SPEC_ONLY,
        CandidateStatus.CHANGES_REQUESTED,
        CandidateStatus.REJECTED,
        CandidateStatus.APPROVED,
    ],
)
def test_only_a_candidate_awaiting_review_can_be_approved(
    labs: Labs, status: CandidateStatus
) -> None:
    candidate = reviewable(labs)
    labs.repo.update_fields(candidate.id, status=status)
    with pytest.raises(ConflictError):
        labs.publisher.approve(candidate.id, "alice", None)
    assert labs.repo.versions() == []


def test_approval_rechecks_every_gate_not_just_the_status(labs: Labs) -> None:
    """A row forced into 'awaiting review' with failing results is still refused."""
    for field, value in (
        ("validation_status", StageStatus.FAILED),
        ("security_status", StageStatus.FAILED),
        ("build_status", StageStatus.SKIPPED),
    ):
        candidate = reviewable(labs)
        labs.repo.update_fields(candidate.id, **{field: value})
        with pytest.raises(ConflictError, match="Cannot approve"):
            labs.publisher.approve(candidate.id, "alice", None)
        labs.publisher.reject(candidate.id, "alice", "reset for the next case")
    assert labs.repo.versions() == []


def test_a_failed_check_in_the_report_blocks_approval(labs: Labs) -> None:
    candidate = reviewable(labs)
    report = copy.deepcopy(candidate.validation_report)
    assert report is not None
    report["checks"][4]["status"] = "failed"
    labs.repo.update_fields(candidate.id, validation_report=report)
    with pytest.raises(ConflictError, match="ten automated"):
        labs.publisher.approve(candidate.id, "alice", None)


def test_missing_security_results_block_approval(labs: Labs) -> None:
    candidate = reviewable(labs)
    labs.repo.update_fields(candidate.id, security_report={"static": [], "runtime": []})
    with pytest.raises(ConflictError, match="security"):
        labs.publisher.approve(candidate.id, "alice", None)


def test_files_changed_after_validation_block_approval(labs: Labs) -> None:
    candidate = reviewable(labs)
    files = dict(candidate.files)
    files["app/extra.py"] = "print('hi')\n"
    labs.repo.update_fields(candidate.id, files=files)
    with pytest.raises(ConflictError, match="changed since"):
        labs.publisher.approve(candidate.id, "alice", None)


def test_an_image_that_no_longer_matches_blocks_approval(labs: Labs) -> None:
    candidate = reviewable(labs)
    assert candidate.image_tag
    labs.builder.images[candidate.image_tag]["id"] = "sha256:swapped"
    with pytest.raises(ConflictError, match="image changed"):
        labs.publisher.approve(candidate.id, "alice", None)
    labs.builder.images.pop(candidate.image_tag)
    with pytest.raises(ConflictError, match="does not match"):
        labs.publisher.approve(candidate.id, "alice", None)


def test_two_reviewers_cannot_both_approve(labs: Labs) -> None:
    candidate = reviewable(labs)
    labs.publisher.approve(candidate.id, "alice", None)
    with pytest.raises(ConflictError):
        labs.publisher.approve(candidate.id, "bob", None)
    assert len(labs.repo.versions()) == 1


def test_a_failed_retag_leaves_the_candidate_awaiting_review(labs: Labs) -> None:
    candidate = reviewable(labs)
    labs.builder.fail_retag = True
    with pytest.raises(ConflictError, match="prepared"):
        labs.publisher.approve(candidate.id, "alice", None)
    again = labs.repo.get(candidate.id)
    assert again is not None and again.status is CandidateStatus.AWAITING_REVIEW
    assert again.reviewer is None and labs.repo.versions() == []
    labs.builder.fail_retag = False
    assert labs.publisher.approve(candidate.id, "alice", None).version == 1


def test_a_database_failure_while_publishing_rolls_back(
    labs: Labs, monkeypatch: pytest.MonkeyPatch
) -> None:
    candidate = reviewable(labs)

    def boom(_row: LabVersion) -> LabVersion:
        raise RuntimeError("db down")

    monkeypatch.setattr(labs.repo, "create_version", boom)
    with pytest.raises(RuntimeError):
        labs.publisher.approve(candidate.id, "alice", None)
    again = labs.repo.get(candidate.id)
    assert again is not None and again.status is CandidateStatus.AWAITING_REVIEW
    assert "cvelearn-lab/cve-2099-12345:v1" not in labs.builder.images


def test_reject_and_request_changes_need_a_reason(labs: Labs) -> None:
    candidate = reviewable(labs)
    for call in (labs.publisher.reject, labs.publisher.request_changes):
        for bad in ("", "  ", "x", "a" * 3000, "bad \x00 text"):
            with pytest.raises(InvalidInputError):
                call(candidate.id, "alice", bad)
    assert labs.repo.get(candidate.id).status is CandidateStatus.AWAITING_REVIEW  # type: ignore[union-attr]


def test_reject_and_request_changes_record_who_and_why(labs: Labs) -> None:
    candidate = reviewable(labs)
    changed = labs.publisher.request_changes(candidate.id, "alice", "Use the documented header.")
    assert changed.status is CandidateStatus.CHANGES_REQUESTED and changed.reviewer == "alice"
    assert changed.review_notes == "Use the documented header."
    with pytest.raises(ConflictError):  # already decided
        labs.publisher.reject(candidate.id, "bob", "nope")
    with pytest.raises(ConflictError):
        labs.publisher.approve(candidate.id, "bob", None)
    actions = [(r.action, r.to_status) for r in labs.repo.reviews(candidate.id)]
    assert actions == [("request_changes", "changes_requested")]


def test_an_approved_lab_cannot_be_rejected(labs: Labs) -> None:
    candidate = reviewable(labs)
    labs.publisher.approve(candidate.id, "alice", None)
    with pytest.raises(ConflictError):
        labs.publisher.reject(candidate.id, "bob", "changed my mind")


def test_a_change_publishes_v2_and_keeps_v1_intact(labs: Labs) -> None:
    first = reviewable(labs)
    v1 = labs.publisher.approve(first.id, "alice", None)
    hash_before = v1.content_hash
    second = reviewable(labs, parent=first, change_notes="clearer hints")
    assert second.revision == 2
    v2 = labs.publisher.approve(second.id, "alice", None)
    assert (v2.lab_id, v2.version) == ("cve-2099-12345-v2", 2)
    assert v2.image_tag == "cvelearn-lab/cve-2099-12345:v2"
    labs.db.expire_all()
    old = labs.repo.get_version("cve-2099-12345-v1")
    assert old is not None
    assert old.status is VersionStatus.SUPERSEDED and old.superseded_by == "cve-2099-12345-v2"
    assert old.content_hash == hash_before and old.image_tag in labs.builder.images
    assert [v.lab_id for v in labs.repo.offered_versions()] == ["cve-2099-12345-v2"]
    published = PublishedLabs(labs.repo, STUDENT)
    assert published.get("cve-2099-12345-v1") is not None  # existing records keep resolving
    assert not published.is_offered("cve-2099-12345-v1")
    assert published.is_offered("cve-2099-12345-v2")
    assert [t.id for t in published.offered()] == ["cve-2099-12345-v2"]


def test_an_older_revision_cannot_be_approved_after_a_newer_one_exists(labs: Labs) -> None:
    first = reviewable(labs)
    labs.publisher.request_changes(first.id, "alice", "redo it")
    second = labs.pipeline.request(CVE_ID, ADMIN, parent=first)
    labs.pipeline.run(second.id)
    labs.repo.update_fields(first.id, status=CandidateStatus.AWAITING_REVIEW)  # forced
    with pytest.raises(ConflictError, match="newer revision"):
        labs.publisher.approve(first.id, "alice", None)


def test_withdrawing_stops_offering_a_version_but_keeps_it_resolvable(labs: Labs) -> None:
    version = labs.publisher.approve(reviewable(labs).id, "alice", None)
    with pytest.raises(InvalidInputError):
        labs.publisher.withdraw(version.id, "alice", " ")
    done = labs.publisher.withdraw(version.id, "alice", "Found a problem in the hints.")
    assert done.status is VersionStatus.WITHDRAWN and done.withdrawn_by == "alice"
    assert labs.repo.offered_versions() == []
    published = PublishedLabs(labs.repo, STUDENT)
    assert published.get(version.lab_id) is not None and not published.is_offered(version.lab_id)
    with pytest.raises(ConflictError):
        labs.publisher.withdraw(version.id, "alice", "again")
    import uuid

    with pytest.raises(NotFoundError):
        labs.publisher.withdraw(uuid.uuid4(), "alice", "no such version")


# -- immutability ------------------------------------------------------------------------------
@pytest.mark.parametrize(
    ("column", "value"),
    [
        ("spec", {"id": "x"}),
        ("files", {"a": "b"}),
        ("content_hash", "0" * 64),
        ("image_tag", "cvelearn-lab/other:v1"),
        ("lab_id", "other-v1"),
        ("published_by", "mallory"),
        ("version", 9),
    ],
)
def test_a_published_version_cannot_be_edited(labs: Labs, column: str, value: object) -> None:
    version = labs.publisher.approve(reviewable(labs).id, "alice", None)
    setattr(version, column, value)
    with pytest.raises(ImmutableVersionError):
        labs.db.commit()
    labs.db.rollback()


def test_only_the_offered_state_of_a_version_can_change(labs: Labs) -> None:
    version = labs.publisher.approve(reviewable(labs).id, "alice", None)
    version.status = VersionStatus.WITHDRAWN
    labs.db.commit()
    assert labs.repo.get_version(version.lab_id).status is VersionStatus.WITHDRAWN  # type: ignore[union-attr]


def test_a_row_altered_behind_the_orm_is_refused_on_load(labs: Labs) -> None:
    """A direct UPDATE (a bypass of the ORM guard) breaks the content hash, so the lab is not served."""
    version = labs.publisher.approve(reviewable(labs).id, "alice", None)
    labs.db.execute(
        text("UPDATE lab_versions SET files = :f WHERE id = :i"),
        {"f": '{"Dockerfile": "FROM scratch"}', "i": version.id.hex},
    )
    labs.db.commit()
    labs.db.expire_all()
    fresh = labs.repo.get_version(version.lab_id)
    assert fresh is not None
    assert template_of(fresh, STUDENT) is None
    assert PublishedLabs(labs.repo, STUDENT).get(version.lab_id) is None
    assert PublishedLabs(labs.repo, STUDENT).offered() == []


def test_a_version_pointing_at_a_non_student_image_is_refused(labs: Labs) -> None:
    version = labs.publisher.approve(reviewable(labs).id, "alice", None)
    limits = PlatformLimits(allowed_image_prefixes=("something-else/",))
    assert template_of(version, limits) is None


def test_session_type_is_a_session(labs: Labs) -> None:
    assert isinstance(labs.db, Session)
