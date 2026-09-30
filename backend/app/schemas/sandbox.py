"""API shapes for labs. Nothing here ever carries the per-instance secret, an image name or any
runtime detail (container names, addresses, networks)."""

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

LAB_SAFETY_NOTICE = (
    "This lab runs an intentionally vulnerable toy application in a sealed, disposable container "
    "with no network access. Only practise these techniques on systems you own or are explicitly "
    "authorised to test."
)
InstanceStatus = Literal["starting", "running", "expired", "stopping", "stopped", "failed"]
OutcomeStatus = Literal["passed", "failed", "blocked", "error"]


class _Model(BaseModel):
    model_config = ConfigDict(extra="forbid")


class ObjectiveView(_Model):
    id: str
    title: str
    description: str
    kind: Literal["payload_replay", "regression"]
    input_label: str | None = None
    input_hint: str | None = None
    requires: list[str] = Field(default_factory=list)
    verified: bool = False
    attempts: int = 0
    last_detail: str | None = None


class ResourceView(_Model):
    cpus: float
    memory_mb: int
    processes: int
    scratch_mb: int
    timeout_minutes: int


class LabView(_Model):
    id: str
    title: str
    summary: str
    cve_id: str | None
    cwe_ids: list[str]
    difficulty: str
    instructions: list[str]
    safety_notes: list[str]
    objectives: list[ObjectiveView]
    resources: ResourceView
    network: str = (
        "No network access: the lab cannot reach the internet, other labs or the platform."
    )


class PortView(_Model):
    name: str
    protocol: str


class InstanceView(_Model):
    id: str
    lab: LabView
    status: InstanceStatus
    session_id: str | None
    created_at: datetime
    started_at: datetime | None
    expires_at: datetime
    seconds_remaining: int
    stop_reason: str | None
    failure_message: str | None
    reset_of: str | None
    ports: list[PortView]
    objectives: list[ObjectiveView]
    can_use: bool  # running and inside its lease: terminal and app are available
    app_path: str | None  # the web app's URL path on this site, only while it can be used
    safety_notice: str = LAB_SAFETY_NOTICE


class CurrentInstance(_Model):
    instance: InstanceView | None


class StartLabRequest(_Model):
    lab_id: str = Field(max_length=64, pattern=r"^[a-z0-9][a-z0-9-]{2,62}$")
    session_id: str | None = Field(default=None, max_length=40)


class VerifyRequest(_Model):
    check_id: str = Field(max_length=48, pattern=r"^[a-z][a-z0-9_]{1,31}$")
    payload: str | None = Field(default=None, max_length=600)


class OutcomeView(_Model):
    check_id: str
    status: OutcomeStatus
    detail: str


class VerifyResponse(_Model):
    outcome: OutcomeView
    instance: InstanceView


class IsolationResult(_Model):
    target: str
    blocked: bool


class IsolationView(_Model):
    passed: bool
    results: list[IsolationResult]
    checked_at: datetime


class TicketView(_Model):
    ticket: str
    expires_in: int
    path: str = "/api/sandbox/terminal/ws"
    url: str | None = None  # absolute base (ws/wss) when the gateway has its own public address


class LabProgressView(_Model):
    lab: LabView
    objectives: list[ObjectiveView]
    verified: int
    total: int
    instance_id: str | None  # the learner's live lab for this session, if any
    last_instance_id: str | None


class SessionLabs(_Model):
    session_id: str
    labs: list[LabProgressView]
