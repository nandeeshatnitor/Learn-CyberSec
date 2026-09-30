"""Lab definitions: what a lab is, validated strictly before anything can run.

A definition is trusted repository content (like code), but it is still validated the same way
untrusted input would be, so a typo or a careless edit cannot weaken a lab's isolation: there is no
field that can add a mount, a capability, a published port, a privileged flag or an image outside
the allow-list. Everything that becomes part of a `docker run` command line comes from a typed,
range-checked field here or from the platform itself.
"""

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator, model_validator

from app.utils.logging import get_logger

log = get_logger(__name__)

LAB_ID = re.compile(r"^[a-z0-9][a-z0-9-]{2,62}$")
_IMAGE = re.compile(r"^[a-z0-9][a-z0-9._/-]{1,120}:[A-Za-z0-9][A-Za-z0-9._-]{0,60}$")
_NAME = re.compile(r"^[a-z][a-z0-9-]{0,23}$")
_ENV_NAME = re.compile(r"^[A-Z][A-Z0-9_]{0,39}$")
_USER = re.compile(r"^([1-9][0-9]{0,8}):([1-9][0-9]{0,8})$")
# A request target: a path plus an optional query. No scheme, host or fragment, so a request
# built from it can only ever go to the lab it belongs to.
_REQUEST_PATH = re.compile(r"^/[A-Za-z0-9._~!$&'()*+,;=:@%/?\[\]-]*$")
_FORBIDDEN_WRITABLE = frozenset(
    {"/", "/proc", "/sys", "/dev", "/etc", "/bin", "/sbin", "/usr", "/lib"}
)
# Names the platform sets itself; a definition may not override them.
_RESERVED_ENV = frozenset(
    {"PATH", "HOME", "USER", "TERM", "HOSTNAME", "LD_PRELOAD", "LD_LIBRARY_PATH"}
)
MAX_PATH_CHARS = 512


class TemplateError(ValueError):
    """A lab definition is invalid (or asks for more than the platform allows)."""


def safe_request_path(value: str) -> str:
    """Validate a request path/query that will be sent to a lab. Raises ValueError."""
    if len(value) > MAX_PATH_CHARS:
        raise ValueError(f"must be at most {MAX_PATH_CHARS} characters")
    if not _REQUEST_PATH.match(value) or value.startswith("//"):
        raise ValueError("must be a plain path such as /page?x=1 (no host, scheme or spaces)")
    return value


RequestPath = Annotated[str, Field(min_length=1, max_length=MAX_PATH_CHARS)]


class _Model(BaseModel):
    model_config = ConfigDict(extra="forbid")


class PortSpec(_Model):
    name: str = Field(pattern=_NAME.pattern)
    # Non-privileged ports only: a lab container has no capabilities, so it cannot bind below 1024.
    container_port: int = Field(ge=1024, le=65535)
    protocol: Literal["http", "tcp"] = "http"


class Resources(_Model):
    cpus: float = Field(default=0.5, ge=0.1, le=16)
    memory_mb: int = Field(default=128, ge=16, le=16384)
    pids: int = Field(default=64, ge=8, le=8192)
    tmpfs_mb: int = Field(default=16, ge=1, le=1024)  # size of each writable scratch mount


class NetworkPolicy(_Model):
    # The only supported policy: the lab has no route out. It can be reached by the platform on
    # its declared ports and by nothing else; it can reach nothing.
    egress: Literal["none"] = "none"


class Ready(_Model):
    port: str = Field(pattern=_NAME.pattern)
    path: RequestPath = "/"
    status: int = Field(default=200, ge=100, le=599)
    timeout_seconds: int = Field(default=30, ge=1, le=120)

    @field_validator("path")
    @classmethod
    def _path(cls, value: str) -> str:
        return safe_request_path(value)


class Expectation(_Model):
    """A request the verifier sends to the running lab and what a healthy answer looks like."""

    path: RequestPath
    status_in: list[int] = Field(default_factory=lambda: [200], min_length=1, max_length=8)
    body_contains: str | None = Field(default=None, max_length=200)

    @field_validator("path")
    @classmethod
    def _path(cls, value: str) -> str:
        return safe_request_path(value)


class _Check(_Model):
    id: str = Field(pattern=r"^[a-z][a-z0-9_]{1,31}$")
    title: str = Field(min_length=3, max_length=120)
    description: str = Field(min_length=3, max_length=600)
    port: str = Field(pattern=_NAME.pattern)
    requires: list[str] = Field(default_factory=list, max_length=8)


class PayloadReplayCheck(_Check):
    """The student supplies a request; it passes if the running lab answers it with this
    instance's secret. The proof is what the lab *does*, not what the student typed."""

    kind: Literal["payload_replay"]
    input_label: str = Field(default="Request path", max_length=60)
    input_hint: str = Field(default="/page?name=...", max_length=120)


class RegressionCheck(_Check):
    """After a fix: the attacks (the template's and the student's own working one) must no longer
    return the secret, and the legitimate behaviour must still work."""

    kind: Literal["regression"]
    restart: bool = True
    block_paths: list[RequestPath] = Field(default_factory=list, max_length=40)
    replay_from: list[str] = Field(default_factory=list, max_length=4)
    keep_working: list[Expectation] = Field(min_length=1, max_length=20)

    @field_validator("block_paths")
    @classmethod
    def _paths(cls, value: list[str]) -> list[str]:
        for item in value:
            safe_request_path(item)
        return value


Check = Annotated[PayloadReplayCheck | RegressionCheck, Field(discriminator="kind")]


class Verification(_Model):
    ready: Ready
    # Run inside the lab before a regression check, so a fix takes effect. Fixed argv, no shell.
    restart_command: list[str] | None = Field(default=None, min_length=1, max_length=8)
    checks: list[Check] = Field(min_length=1, max_length=12)

    @model_validator(mode="after")
    def _consistent(self) -> "Verification":
        ids = [c.id for c in self.checks]
        if len(set(ids)) != len(ids):
            raise ValueError("check ids must be unique")
        for index, check in enumerate(self.checks):
            for other in (*check.requires, *getattr(check, "replay_from", [])):
                if other not in ids[:index]:
                    raise ValueError(
                        f"check {check.id!r} refers to {other!r}, which must come first"
                    )
        return self


class LabTemplate(_Model):
    id: str = Field(pattern=LAB_ID.pattern)
    version: str = Field(default="1", pattern=r"^[0-9]{1,4}$")
    title: str = Field(min_length=3, max_length=120)
    summary: str = Field(min_length=3, max_length=600)
    # A lab may teach one specific CVE, or a weakness class that many CVEs share (CWE ids). It is
    # offered next to a learning session when either matches.
    cve_id: str | None = Field(default=None, pattern=r"^CVE-[0-9]{4}-[0-9]{4,}$")
    cwe_ids: list[str] = Field(default_factory=list, max_length=8)
    difficulty: Literal["beginner", "intermediate", "advanced"] = "beginner"
    image: str = Field(max_length=200)
    ports: list[PortSpec] = Field(default_factory=list, max_length=4)
    startup_command: list[str] = Field(min_length=1, max_length=12)
    shell: list[str] = Field(default_factory=lambda: ["/bin/sh"], min_length=1, max_length=4)
    user: str = "10001:10001"
    timeout_minutes: int = Field(ge=1, le=1440)
    resources: Resources = Field(default_factory=Resources)
    writable_paths: list[str] = Field(default_factory=lambda: ["/tmp"], max_length=4)  # noqa: S108
    environment: dict[str, str] = Field(default_factory=dict, max_length=16)
    # Which environment variable carries the per-instance secret into the lab at start-up.
    canary_env: str = Field(default="LAB_CANARY", pattern=_ENV_NAME.pattern)
    network: NetworkPolicy = Field(default_factory=NetworkPolicy)
    instructions: list[str] = Field(default_factory=list, max_length=20)
    safety_notes: list[str] = Field(default_factory=list, max_length=10)
    verification: Verification

    @field_validator("cwe_ids")
    @classmethod
    def _cwes(cls, value: list[str]) -> list[str]:
        for item in value:
            if not re.fullmatch(r"CWE-[0-9]{1,5}", item):
                raise ValueError(f"invalid CWE id {item!r}")
        return value

    @field_validator("image")
    @classmethod
    def _image(cls, value: str) -> str:
        if not _IMAGE.match(value) or "@" in value:
            raise ValueError("image must look like repository/name:tag")
        return value

    @field_validator("user")
    @classmethod
    def _user(cls, value: str) -> str:
        # Never root, never a root group. A lab that truly needs root must be a reviewed change
        # to this rule, not a value in a definition.
        if not _USER.match(value):
            raise ValueError("user must be a non-zero uid:gid such as 10001:10001")
        return value

    @field_validator("startup_command", "shell")
    @classmethod
    def _argv(cls, value: list[str]) -> list[str]:
        for part in value:
            if not part or len(part) > 400 or "\x00" in part or "\n" in part:
                raise ValueError("commands are argv lists of short single-line strings")
        return value

    @field_validator("writable_paths")
    @classmethod
    def _writable(cls, value: list[str]) -> list[str]:
        for path in value:
            parts = path.split("/")
            if (
                not path.startswith("/")
                or path in _FORBIDDEN_WRITABLE
                or ".." in parts
                or "" in parts[1:]
                or len(path) > 100
                or not re.fullmatch(r"[A-Za-z0-9_/.-]+", path)
            ):
                raise ValueError(f"unsafe writable path {path!r}")
        if len(set(value)) != len(value):
            raise ValueError("writable paths must be unique")
        return value

    @field_validator("environment")
    @classmethod
    def _env(cls, value: dict[str, str]) -> dict[str, str]:
        for name, item in value.items():
            if not _ENV_NAME.match(name) or name in _RESERVED_ENV:
                raise ValueError(f"environment variable {name!r} is not allowed")
            if len(item) > 200 or "\x00" in item or "\n" in item:
                raise ValueError(f"environment value for {name} is invalid")
        return value

    @model_validator(mode="after")
    def _consistent(self) -> "LabTemplate":
        names = [p.name for p in self.ports]
        if len(set(names)) != len(names):
            raise ValueError("port names must be unique")
        if self.canary_env in self.environment:
            raise ValueError("the canary variable is set by the platform, not the definition")
        for check in self.verification.checks:
            if check.port not in names:
                raise ValueError(f"check {check.id!r} uses unknown port {check.port!r}")
        if self.verification.ready.port not in names:
            raise ValueError("the readiness check uses an unknown port")
        if (
            any(getattr(check, "restart", False) for check in self.verification.checks)
            and not self.verification.restart_command
        ):
            raise ValueError("a check restarts the lab but no restart_command is defined")
        return self

    def port(self, name: str) -> PortSpec:
        for candidate in self.ports:
            if candidate.name == name:
                return candidate
        raise KeyError(name)

    def check(self, check_id: str) -> PayloadReplayCheck | RegressionCheck | None:
        for candidate in self.verification.checks:
            if candidate.id == check_id:
                return candidate
        return None

    @property
    def uid(self) -> int:
        return int(self.user.split(":")[0])

    @property
    def gid(self) -> int:
        return int(self.user.split(":")[1])


@dataclass(frozen=True)
class PlatformLimits:
    """The most a lab may ask for, and where its image may come from."""

    max_cpus: float = 2.0
    max_memory_mb: int = 1024
    max_pids: int = 512
    max_tmpfs_mb: int = 64
    max_timeout_minutes: int = 240
    allowed_image_prefixes: tuple[str, ...] = ("cvelearn-lab/",)


def check_limits(template: LabTemplate, limits: PlatformLimits) -> None:
    """Refuse a definition that exceeds the platform's ceilings. Raises TemplateError."""
    problems: list[str] = []
    r = template.resources
    if r.cpus > limits.max_cpus:
        problems.append(f"cpus {r.cpus} exceeds {limits.max_cpus}")
    if r.memory_mb > limits.max_memory_mb:
        problems.append(f"memory_mb {r.memory_mb} exceeds {limits.max_memory_mb}")
    if r.pids > limits.max_pids:
        problems.append(f"pids {r.pids} exceeds {limits.max_pids}")
    if r.tmpfs_mb > limits.max_tmpfs_mb:
        problems.append(f"tmpfs_mb {r.tmpfs_mb} exceeds {limits.max_tmpfs_mb}")
    if template.timeout_minutes > limits.max_timeout_minutes:
        problems.append(
            f"timeout_minutes {template.timeout_minutes} exceeds {limits.max_timeout_minutes}"
        )
    if not template.image.startswith(limits.allowed_image_prefixes):
        problems.append(f"image {template.image!r} is not from an allowed repository")
    if problems:
        raise TemplateError("; ".join(problems))


@dataclass
class LabCatalog:
    """The validated set of labs. A broken definition is reported and skipped, never started."""

    labs: dict[str, LabTemplate] = field(default_factory=dict)
    errors: dict[str, str] = field(default_factory=dict)

    @classmethod
    def load(cls, directory: Path, limits: PlatformLimits) -> "LabCatalog":
        catalog = cls()
        if not directory.is_dir():
            return catalog
        for path in sorted(directory.glob("*/lab.json")):
            label = path.parent.name
            try:
                template = LabTemplate.model_validate(json.loads(path.read_text(encoding="utf-8")))
                if template.id != label:
                    raise TemplateError(
                        f"id {template.id!r} must match its directory name {label!r}"
                    )
                check_limits(template, limits)
                if template.id in catalog.labs:
                    raise TemplateError("duplicate lab id")
            except (OSError, ValueError, ValidationError) as exc:
                catalog.errors[label] = _short(exc)
                log.error("lab_definition_invalid", lab=label, error=catalog.errors[label])
                continue
            catalog.labs[template.id] = template
        return catalog

    def get(self, lab_id: str) -> LabTemplate | None:
        return self.labs.get(lab_id)

    def matching(self, cve_id: str | None, cwe_ids: list[str]) -> list[LabTemplate]:
        """Labs for a CVE: those written for it, then those for a weakness class it has."""
        wanted = set(cwe_ids)
        exact = [t for t in self.labs.values() if cve_id is not None and t.cve_id == cve_id]
        related = [t for t in self.labs.values() if t not in exact and (wanted & set(t.cwe_ids))]
        return [*exact, *related]


def _short(exc: Exception) -> str:
    text = str(exc).replace("\n", " ")
    return text[:300]
