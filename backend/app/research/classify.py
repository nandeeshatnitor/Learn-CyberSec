"""Classify a URL into a source type and a reliability level, and group sources by owner.

Heuristic and deliberately conservative: reliability says how much weight the platform gives a
source when comparing claims, not that the content is correct. Everything fetched is still
untrusted input.
"""

from collections.abc import Iterable
from urllib.parse import urlsplit

from app.models.enums import ReliabilityLevel, SourceType

# Hosts whose subdomains belong to different owners: the registrable domain must include the label.
_SHARED_SUFFIXES = frozenset(
    {
        "github.io", "gitlab.io", "blogspot.com", "wordpress.com", "medium.com", "substack.com",
        "netlify.app", "vercel.app", "pages.dev", "herokuapp.com", "readthedocs.io",
        "co.uk", "org.uk", "gov.uk", "ac.uk", "com.au", "gov.au", "co.jp", "co.nz", "com.br",
        "co.in", "com.cn", "co.za", "com.tw", "com.mx",
    }
)  # fmt: skip

_CVE_RECORD_HOSTS = frozenset(
    {"nvd.nist.gov", "cve.org", "www.cve.org", "cve.mitre.org", "cveawg.mitre.org"}
)

_VENDOR_HOSTS = (
    "apache.org", "microsoft.com", "redhat.com", "access.redhat.com", "ubuntu.com", "debian.org",
    "suse.com", "oracle.com", "cisco.com", "vmware.com", "broadcom.com", "adobe.com", "apple.com",
    "support.apple.com", "android.com", "mozilla.org", "openssl.org", "kernel.org", "php.net",
    "python.org", "nodejs.org", "golang.org", "spring.io", "netapp.com", "fortinet.com",
    "paloaltonetworks.com", "ivanti.com", "citrix.com", "sap.com", "ibm.com", "dell.com",
    "hp.com", "juniper.net", "f5.com", "atlassian.com", "gitlab.com", "jenkins.io", "wordpress.org",
    "drupal.org", "joomla.org", "nginx.org", "postgresql.org", "mysql.com", "samba.org",
)  # fmt: skip

_RESEARCH_HOSTS = (
    "zerodayinitiative.com", "googleprojectzero.blogspot.com", "projectzero.google", "seclists.org",
    "openwall.com", "packetstormsecurity.com", "talosintelligence.com", "qualys.com",
    "rapid7.com", "tenable.com", "portswigger.net", "sec.cloudapps.cisco.com", "vulncheck.com",
    "watchtowr.com", "assetnote.io", "unit42.paloaltonetworks.com", "trendmicro.com",
    "crowdstrike.com", "mandiant.com", "cloud.google.com", "snyk.io", "jfrog.com", "sonarsource.com",
    "veracode.com", "checkmarx.com", "cloudflare.com", "akamai.com", "huntress.com", "sysdig.com",
    "wiz.io", "orca.security", "greynoise.io", "lunasec.io", "securitylab.github.com", "exodusintel.com",
    "horizon3.ai", "attackerkb.com", "fastly.com", "imperva.com", "socradar.io",
)  # fmt: skip

_MAILING_LIST_HOSTS = ("lists.apache.org", "seclists.org", "openwall.com", "lists.debian.org")
_CERT_HOSTS = ("kb.cert.org", "cert.org", "us-cert.cisa.gov", "cert.europa.eu", "cert.ssi.gouv.fr")
_GOV_SUFFIXES = (".gov", ".gov.uk", ".gov.au", ".gc.ca", ".gouv.fr", ".mil", ".gov.in")


def host_of(url: str) -> str:
    try:
        return (urlsplit(url).hostname or "").lower().rstrip(".")
    except ValueError:
        return ""


def _endswith_domain(host: str, domains: Iterable[str]) -> bool:
    return any(host == d or host.endswith("." + d) for d in domains)


def registrable_domain(host: str) -> str:
    """Approximate eTLD+1 without a public-suffix list (which would need a network download)."""
    labels = [label for label in host.lower().split(".") if label]
    if len(labels) <= 2:
        return ".".join(labels)
    if ".".join(labels[-2:]) in _SHARED_SUFFIXES:  # alice.github.io, example.co.uk
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


def is_cve_record_host(url: str) -> bool:
    """NVD / CVE.org pages: already covered by the structured providers, so never fetched."""
    return host_of(url) in _CVE_RECORD_HOSTS


def classify_url(url: str, tags: Iterable[str] = ()) -> tuple[SourceType, ReliabilityLevel]:
    parts = urlsplit(url)
    host = host_of(url)
    path = parts.path.lower()
    normalized_tags = {t.lower().replace("-", " ").strip() for t in tags}

    if host in _CVE_RECORD_HOSTS:
        official_type = SourceType.NVD if host == "nvd.nist.gov" else SourceType.MITRE
        return official_type, ReliabilityLevel.OFFICIAL
    if host == "github.com" or host == "www.github.com":
        if "/advisories/ghsa-" in path or "/security/advisories/ghsa-" in path:
            return SourceType.GITHUB_ADVISORY, ReliabilityLevel.HIGH
        return SourceType.GITHUB_REPOSITORY, ReliabilityLevel.LOW
    if host == "api.github.com" and "/advisories" in path:
        return SourceType.GITHUB_ADVISORY, ReliabilityLevel.HIGH
    if _endswith_domain(host, ("exploit-db.com",)):
        return SourceType.EXPLOIT_DATABASE, ReliabilityLevel.MEDIUM
    if host == "cisa.gov" or host.endswith(".cisa.gov"):
        return SourceType.CISA, ReliabilityLevel.OFFICIAL
    if _endswith_domain(host, _CERT_HOSTS) or host.startswith("cert."):
        return SourceType.CERT, ReliabilityLevel.HIGH
    if host.endswith(_GOV_SUFFIXES) or _endswith_domain(host, ("ncsc.gov.uk", "jpcert.or.jp")):
        return SourceType.GOVERNMENT, ReliabilityLevel.HIGH
    if "vendor advisory" in normalized_tags or _endswith_domain(host, _VENDOR_HOSTS):
        # A vendor's own security page is authoritative about its product.
        level = (
            ReliabilityLevel.HIGH
            if _endswith_domain(host, _VENDOR_HOSTS)
            else ReliabilityLevel.MEDIUM
        )
        return SourceType.VENDOR_ADVISORY, level
    if _endswith_domain(host, _MAILING_LIST_HOSTS):
        return SourceType.RESEARCH, ReliabilityLevel.MEDIUM
    if _endswith_domain(host, _RESEARCH_HOSTS) or "technical description" in normalized_tags:
        blog = host.startswith("blog.") or "/blog" in path
        return (SourceType.SECURITY_BLOG if blog else SourceType.RESEARCH), ReliabilityLevel.MEDIUM
    if (
        host.startswith("blog.")
        or "/blog/" in path
        or host.endswith(("medium.com", "substack.com"))
    ):
        return SourceType.SECURITY_BLOG, ReliabilityLevel.LOW
    return SourceType.OTHER, ReliabilityLevel.LOW


RELIABILITY_WEIGHT = {
    ReliabilityLevel.OFFICIAL: 1.0,
    ReliabilityLevel.HIGH: 0.85,
    ReliabilityLevel.MEDIUM: 0.6,
    ReliabilityLevel.LOW: 0.3,
    ReliabilityLevel.UNVERIFIED: 0.2,
}


def independence_group(url: str, source_type: SourceType) -> str:
    """Sources in the same group are not independent evidence of each other.

    NVD, MITRE/CVE.org describe the same underlying CVE record, so they share one group; other
    sources are grouped by registrable domain (two pages from one site are one voice).
    """
    if source_type in (SourceType.NVD, SourceType.MITRE):
        return "cve-record"
    return registrable_domain(host_of(url)) or "unknown"
