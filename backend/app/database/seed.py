"""Development seed data: `python -m app.database.seed`.

These records are hand-entered fixtures so the UI has something to render before the retrieval
phase exists. They are stored with data_origin="seed" and the API/UI surface that flag: they are
NOT retrieved from NVD or any other authority and must be verified against the linked sources.
Source rows created here are links only (retrieved_at is NULL): nothing was fetched from them.
"""

from datetime import UTC, datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.database import get_session_factory
from app.models import CVE, CVEReference, DataOrigin, ReliabilityLevel, Source, SourceType
from app.utils.logging import configure_logging, get_logger

log = get_logger(__name__)

_SEED_CVES: list[dict[str, Any]] = [
    {
        "cve_id": "CVE-2021-44228",
        "description": (
            "Apache Log4j2 JNDI features do not protect against attacker-controlled LDAP and "
            "other JNDI-related endpoints, allowing remote code execution when an attacker can "
            "control log messages or log message parameters. Widely known as Log4Shell."
        ),
        "published_at": datetime(2021, 12, 10, tzinfo=UTC),
        "cvss_score": 10.0,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
        "severity": "CRITICAL",
        "cwes": ["CWE-20", "CWE-400", "CWE-502", "CWE-917"],
        "affected_products": [
            {"vendor": "Apache", "product": "Log4j2", "versions": "2.0-beta9 through 2.15.0"}
        ],
    },
    {
        "cve_id": "CVE-2014-0160",
        "description": (
            "The TLS/DTLS heartbeat extension in OpenSSL does not properly bounds-check a "
            "request, allowing a remote attacker to read process memory. Known as Heartbleed."
        ),
        "published_at": datetime(2014, 4, 7, tzinfo=UTC),
        "cvss_score": 7.5,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
        "severity": "HIGH",
        "cwes": ["CWE-125"],
        "affected_products": [
            {"vendor": "OpenSSL", "product": "OpenSSL", "versions": "1.0.1 through 1.0.1f"}
        ],
    },
    {
        "cve_id": "CVE-2014-6271",
        "description": (
            "GNU Bash processes trailing strings after function definitions in environment "
            "variable values, allowing remote attackers to execute arbitrary commands in "
            "contexts such as CGI scripts. Known as Shellshock."
        ),
        "published_at": datetime(2014, 9, 24, tzinfo=UTC),
        "cvss_score": 9.8,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "severity": "CRITICAL",
        "cwes": ["CWE-78"],
        "affected_products": [{"vendor": "GNU", "product": "Bash", "versions": "through 4.3"}],
    },
    {
        "cve_id": "CVE-2017-0144",
        "description": (
            "The Microsoft Server Message Block 1.0 (SMBv1) server allows remote attackers to "
            "execute arbitrary code via crafted packets. Known as EternalBlue."
        ),
        "published_at": datetime(2017, 3, 16, tzinfo=UTC),
        "cvss_score": 8.1,
        "cvss_vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "severity": "HIGH",
        "cwes": ["CWE-20"],
        "affected_products": [
            {"vendor": "Microsoft", "product": "Windows (SMBv1)", "versions": "multiple"}
        ],
    },
    {
        "cve_id": "CVE-2022-22965",
        "description": (
            "Spring Framework on JDK 9+ is vulnerable to remote code execution through data "
            "binding when running as a WAR on Tomcat. Known as Spring4Shell."
        ),
        "published_at": datetime(2022, 4, 1, tzinfo=UTC),
        "cvss_score": 9.8,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "severity": "CRITICAL",
        "cwes": ["CWE-94"],
        "affected_products": [
            {
                "vendor": "VMware",
                "product": "Spring Framework",
                "versions": "5.3.0-5.3.17, 5.2.0-5.2.19",
            }
        ],
    },
]


def _get_or_create_source(session: Session, **fields: Any) -> Source:
    source = session.execute(select(Source).where(Source.url == fields["url"])).scalar_one_or_none()
    if source is None:
        source = Source(**fields)
        session.add(source)
        session.flush()
    return source


def seed(session: Session) -> int:
    created = 0
    for data in _SEED_CVES:
        cve_id = data["cve_id"]
        if session.execute(select(CVE).where(CVE.cve_id == cve_id)).scalar_one_or_none():
            continue
        cve = CVE(**data, data_origin=DataOrigin.SEED)
        session.add(cve)
        links = [
            (SourceType.NVD, "NVD", f"https://nvd.nist.gov/vuln/detail/{cve_id}"),
            (SourceType.MITRE, "CVE Program", f"https://www.cve.org/CVERecord?id={cve_id}"),
        ]
        for source_type, publisher, url in links:
            source = _get_or_create_source(
                session,
                source_type=source_type,
                title=f"{publisher} record for {cve_id}",
                url=url,
                publisher=publisher,
                retrieved_at=None,
                reliability_level=ReliabilityLevel.OFFICIAL,
            )
            cve.references.append(CVEReference(source=source, tags=["Record link"]))
        created += 1
    session.commit()
    return created


def main() -> None:
    configure_logging()
    with get_session_factory()() as session:
        created = seed(session)
    log.info("seed_complete", created=created, total=len(_SEED_CVES))


if __name__ == "__main__":
    main()
