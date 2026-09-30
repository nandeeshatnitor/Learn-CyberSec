import enum


class SourceType(enum.StrEnum):
    NVD = "nvd"
    MITRE = "mitre"
    VENDOR_ADVISORY = "vendor_advisory"
    GITHUB_ADVISORY = "github_advisory"
    CERT = "cert"
    CISA = "cisa"
    EXPLOIT_DB = "exploit_db"
    RESEARCH_BLOG = "research_blog"
    OTHER = "other"


class ReliabilityLevel(enum.StrEnum):
    """How much the platform trusts a source. Everything external is still untrusted input."""

    OFFICIAL = "official"  # CNA / NVD / vendor / government authority
    HIGH = "high"  # established security research or coordination body
    MEDIUM = "medium"  # reputable but unofficial
    LOW = "low"  # community / unvetted
    UNVERIFIED = "unverified"  # not yet assessed


class DataOrigin(enum.StrEnum):
    """Where a CVE record came from, so the UI never presents guesses as retrieved facts."""

    SEED = "seed"  # hand-entered development fixture, NOT retrieved from an authority
    NVD = "nvd"  # reserved for the retrieval phase
