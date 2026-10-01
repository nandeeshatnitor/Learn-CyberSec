from dataclasses import dataclass

import pytest
from sqlalchemy.orm import Session

from app.labgen.generate import CandidateGenerator
from app.labgen.pipeline import CandidatePipeline, PipelineConfig
from app.labgen.publish import STUDENT_IMAGE_PREFIX, LabPublisher
from app.labgen.scan import CANDIDATE_IMAGE_PREFIX
from app.models import CVE
from app.repositories import CVERepository, LabgenRepository, ResearchRepository
from app.research.synthesis.schema import LearningGuide
from app.sandbox.template import PlatformLimits
from tests.labgen.fakes import FakeBuilder, FakeValidator
from tests.learning.conftest import (  # noqa: F401 - fixtures used by the tests below
    FakeCVELookup,
    RealtimeClock,
    RecordingQueue,
    cves,
    make_runner,
    make_service,
    policy,
    queue,
    rclock,
    ready_guide,
    repo,
    service,
    web,
)
from tests.research.support import CVE_ID

ADMIN = "reviewer-alice"


@pytest.fixture
def acme_cve(make_cve) -> CVE:  # type: ignore[no-untyped-def]
    """The stored CVE record for the fictional AcmeDocs vulnerability (NVD-style affected data)."""
    return make_cve(
        cve_id=CVE_ID,
        description="AcmeDocs 4.0.0 through 4.2.3 evaluates expressions from the X-Template-Hint request header.",
        cwes=["CWE-94"],
        affected_products=[
            {
                "vendor": "acme",
                "product": "AcmeDocs",
                "source": "nvd",
                "versions": [
                    {"status": "affected", "start_including": "4.0.0", "end_excluding": "4.2.4"}
                ],
            }
        ],
    )


@pytest.fixture
def guide(ready_guide: None, repo: ResearchRepository) -> LearningGuide:  # noqa: F811
    run = repo.latest(CVE_ID, ready_only=True)
    assert run is not None and run.guide is not None
    return LearningGuide.model_validate(run.guide)


@dataclass
class Labs:
    """The candidate pipeline and publisher wired to fakes for Docker (build and validation)."""

    pipeline: CandidatePipeline
    publisher: LabPublisher
    repo: LabgenRepository
    builder: FakeBuilder
    validator: FakeValidator
    db: Session


@pytest.fixture
def labs(db: Session, repo: ResearchRepository, guide: LearningGuide, acme_cve: CVE) -> Labs:  # noqa: F811
    builder, validator = FakeBuilder(), FakeValidator()
    store = LabgenRepository(db)
    pipeline = CandidatePipeline(
        store,
        repo,
        CVERepository(db),
        CandidateGenerator(),
        builder,  # type: ignore[arg-type]
        validator,  # type: ignore[arg-type]
        PipelineConfig(
            ["python:3.12-alpine"],
            PlatformLimits(allowed_image_prefixes=(CANDIDATE_IMAGE_PREFIX,)),
        ),
    )
    publisher = LabPublisher(
        store,
        builder,
        PlatformLimits(allowed_image_prefixes=(STUDENT_IMAGE_PREFIX,)),  # type: ignore[arg-type]
    )
    return Labs(pipeline, publisher, store, builder, validator, db)


__all__ = ["ADMIN", "CVE_ID", "Labs", "Session", "acme_cve", "guide", "labs"]
