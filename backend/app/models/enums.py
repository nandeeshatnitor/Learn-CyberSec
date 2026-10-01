import enum


class SourceType(enum.StrEnum):
    # Structured CVE data providers (Phase 1)
    NVD = "nvd"
    MITRE = "mitre"
    CISA = "cisa"
    # Documents discovered by the research pipeline (Phase 2)
    VENDOR_ADVISORY = "vendor_advisory"
    GITHUB_ADVISORY = "github_advisory"
    GITHUB_REPOSITORY = "github_repository"
    SECURITY_BLOG = "security_blog"
    RESEARCH = "research"  # technical write-ups, mailing-list posts, ZDI-style advisories
    EXPLOIT_DATABASE = "exploit_database"
    CERT = "cert"
    GOVERNMENT = "government"
    OTHER = "other"


class ReliabilityLevel(enum.StrEnum):
    """How much the platform trusts a source. Everything external is still untrusted input."""

    OFFICIAL = "official"  # CNA / NVD / vendor / government authority
    HIGH = "high"  # established security research or coordination body
    MEDIUM = "medium"  # reputable but unofficial
    LOW = "low"  # community / unvetted
    UNVERIFIED = "unverified"  # not yet assessed


class SourceStatus(enum.StrEnum):
    """How far a source got through the research pipeline."""

    DISCOVERED = "discovered"  # known to exist (a link); nothing fetched
    RETRIEVED = "retrieved"  # fetched successfully
    EXTRACTED = "extracted"  # readable text extracted and relevant passages kept
    IRRELEVANT = "irrelevant"  # fetched, but not technically relevant to the CVE
    DUPLICATE = "duplicate"  # same content as a better source
    BLOCKED = "blocked"  # robots.txt or the fetch policy forbids retrieval
    EXCLUDED = "excluded"  # dropped as adversarial (prompt-injection content)
    SKIPPED = "skipped"  # not fetched (unsupported type, over the source budget, ...)
    FAILED = "failed"  # fetch or extraction error


class ResearchStatus(enum.StrEnum):
    QUEUED = "queued"
    RESEARCHING = "researching"
    SYNTHESIZING = "synthesizing"
    READY = "ready"
    FAILED = "failed"


ACTIVE_RESEARCH_STATUSES = (
    ResearchStatus.QUEUED,
    ResearchStatus.RESEARCHING,
    ResearchStatus.SYNTHESIZING,
)


class DataOrigin(enum.StrEnum):
    """Where a CVE record came from, so the UI never presents guesses as retrieved facts."""

    SEED = "seed"  # hand-entered development fixture, NOT retrieved from an authority
    PROVIDERS = "providers"  # retrieved from external providers (NVD, MITRE, CISA KEV, ...)


class LearningStatus(enum.StrEnum):
    NOT_STARTED = "not_started"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    ABANDONED = "abandoned"


ACTIVE_LEARNING_STATUSES = (LearningStatus.NOT_STARTED, LearningStatus.IN_PROGRESS)


class LabStatus(enum.StrEnum):
    """Lifecycle of one lab instance (a disposable container plus its private network)."""

    STARTING = "starting"
    RUNNING = "running"
    EXPIRED = "expired"  # the lease ran out; the resources are still to be removed
    STOPPING = "stopping"
    STOPPED = "stopped"  # terminal: the resources are gone
    FAILED = "failed"  # terminal: it never became usable (the resources are removed as well)


# Instances that still hold (or are about to release) runtime resources. A learner may have one.
LIVE_LAB_STATUSES = (
    LabStatus.STARTING,
    LabStatus.RUNNING,
    LabStatus.EXPIRED,
    LabStatus.STOPPING,
)

# Allowed lifecycle moves; anything else is a bug and is refused by the repository.
LAB_TRANSITIONS: dict[LabStatus, frozenset[LabStatus]] = {
    LabStatus.STARTING: frozenset({LabStatus.RUNNING, LabStatus.FAILED, LabStatus.STOPPING}),
    LabStatus.RUNNING: frozenset({LabStatus.EXPIRED, LabStatus.STOPPING, LabStatus.FAILED}),
    LabStatus.EXPIRED: frozenset({LabStatus.STOPPING}),
    LabStatus.STOPPING: frozenset({LabStatus.STOPPED, LabStatus.FAILED}),
    LabStatus.STOPPED: frozenset(),
    LabStatus.FAILED: frozenset(),
}


class CandidateStatus(enum.StrEnum):
    """Where a candidate lab is in the pipeline. Only a human can move it to APPROVED."""

    GENERATING = "generating"
    GENERATION_FAILED = "generation_failed"
    SPEC_ONLY = "spec_only"  # a specification, but no safe automated lab could be generated
    BUILDING = "building"
    BUILD_FAILED = "build_failed"
    VALIDATING = "validating"
    VALIDATION_FAILED = "validation_failed"  # automated or security validation failed
    AWAITING_REVIEW = "awaiting_review"  # every automated gate passed; a human must decide
    CHANGES_REQUESTED = "changes_requested"
    REJECTED = "rejected"
    APPROVED = "approved"  # published as an immutable lab version


class StageStatus(enum.StrEnum):
    PENDING = "pending"
    RUNNING = "running"
    PASSED = "passed"
    FAILED = "failed"
    SKIPPED = "skipped"


class VersionStatus(enum.StrEnum):
    PUBLISHED = "published"  # offered to students
    SUPERSEDED = "superseded"  # a newer version is offered; still resolves for existing records
    WITHDRAWN = "withdrawn"  # taken down by an admin; still resolves for existing records


# Candidates the pipeline is still working on (the job owns them).
WORKING_CANDIDATE_STATUSES = (
    CandidateStatus.GENERATING,
    CandidateStatus.BUILDING,
    CandidateStatus.VALIDATING,
)
# A reviewer may act only on these.
REVIEWABLE_CANDIDATE_STATUSES = (CandidateStatus.AWAITING_REVIEW,)
