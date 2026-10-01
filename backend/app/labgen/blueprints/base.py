"""Blueprints: vetted, minimal, intentionally vulnerable reference apps that a candidate is built from.

A blueprint is code that was written and reviewed *in this repository*. It never contains or copies
code from the sources. What varies between candidates is a handful of validated parameters (a product
name, a version label, a header or endpoint name) which are embedded only as Python string literals
(`repr`), never spliced into code.
"""

from dataclasses import dataclass, field
from typing import Any, Protocol

from app.labgen.facts import GuideFacts


@dataclass(frozen=True)
class Probe:
    """A request the validator sends to the running lab."""

    path: str
    header: str | None = None
    value: str | None = None


@dataclass(frozen=True)
class ValidationPlan:
    """How the validator proves the lab behaves as specified (all fixed, from the blueprint)."""

    exploit: Probe  # reveals the instance's secret while the lab is vulnerable
    benign: Probe  # must NOT pass the exploit check
    vulnerable_probe: Probe  # the documented, harmless demonstration of the behaviour
    vulnerable_expect: str  # what it returns while vulnerable (e.g. "49")
    reference_fix: tuple[str, ...]  # argv run inside the lab to apply the reference remediation
    legit: tuple[tuple[Probe, str], ...]  # (request, text the answer must contain) after the fix
    patched_must_not_contain: tuple[str, ...]  # absent after the fix (e.g. "49")
    restart: tuple[str, ...] = ("sh", "/opt/lab/restart.sh")

    def as_dict(self) -> dict[str, Any]:
        def probe(p: Probe) -> dict[str, str | None]:
            return {"path": p.path, "header": p.header, "value": p.value}

        return {
            "exploit": probe(self.exploit),
            "benign": probe(self.benign),
            "vulnerable_probe": probe(self.vulnerable_probe),
            "vulnerable_expect": self.vulnerable_expect,
            "reference_fix": list(self.reference_fix),
            "legit": [{"probe": probe(p), "contains": text} for p, text in self.legit],
            "patched_must_not_contain": list(self.patched_must_not_contain),
            "restart": list(self.restart),
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "ValidationPlan":
        def probe(d: dict[str, Any]) -> Probe:
            return Probe(d["path"], d.get("header"), d.get("value"))

        return cls(
            exploit=probe(data["exploit"]),
            benign=probe(data["benign"]),
            vulnerable_probe=probe(data["vulnerable_probe"]),
            vulnerable_expect=data["vulnerable_expect"],
            reference_fix=tuple(data["reference_fix"]),
            legit=tuple((probe(i["probe"]), i["contains"]) for i in data["legit"]),
            patched_must_not_contain=tuple(data["patched_must_not_contain"]),
            restart=tuple(data["restart"]),
        )


@dataclass
class Rendered:
    files: dict[str, str]
    lab_template: dict[str, Any]  # a sandbox LabTemplate (id/image are set by the pipeline)
    plan: ValidationPlan
    objective: str
    prerequisites: list[str]
    tasks: list[tuple[str, str, str]]  # (id, title, description)
    expected_vulnerable: str
    expected_fixed: str
    remediation: str
    params: dict[str, str] = field(default_factory=dict)
    defaulted: list[str] = field(default_factory=list)  # parameters the sources did not document


class Blueprint(Protocol):
    id: str
    version: str

    def match(self, facts: GuideFacts) -> str | None:
        """A short reason when the blueprint fits the documented weakness, else None."""
        ...

    def parameters(self, facts: GuideFacts, overrides: dict[str, str]) -> dict[str, str] | None:
        """Validated parameters, or None when the guide does not document enough to build a lab."""
        ...

    def render(self, facts: GuideFacts, params: dict[str, str]) -> Rendered: ...


def common_files(app_name: str = "server.py") -> dict[str, str]:
    """Files every blueprint shares: the supervisor, the restart helper and the Dockerfile."""
    return {
        "start.sh": START_SH,
        "restart.sh": RESTART_SH,
        "Dockerfile": DOCKERFILE.replace("{app}", app_name),
    }


START_SH = """#!/bin/sh
# Start the lab app as the unprivileged lab user on a read-only root filesystem: everything
# writable lives in /lab (a small in-memory scratch area).
set -eu
mkdir -p /lab/app /lab/docs /lab/private
cp /opt/lab/app/server.py /lab/app/server.py
if [ -d /opt/lab/docs ]; then cp -R /opt/lab/docs/. /lab/docs/; fi
# The platform gives every lab instance its own random secret. It is planted where the app is
# never supposed to reveal it; only the documented weakness exposes it.
printf '%s\\n' "${LAB_CANARY:-not-set}" > /lab/private/secret.txt
chmod 600 /lab/private/secret.txt
unset LAB_CANARY
# Supervisor: restart the app if it exits (for example after the student's fix is applied).
while :; do
  python /lab/app/server.py || true
  sleep 0.3
done
"""

RESTART_SH = """#!/bin/sh
# Restart the app so that a change to /lab/app/server.py takes effect; the supervisor loop in
# start.sh brings it straight back up. (The [.] keeps this script from matching itself.)
pkill -f 'python /lab/app/server[.]py' || true
"""

DOCKERFILE = """# Generated candidate lab. Built with no network from this directory only.
FROM python:3.12-alpine
COPY app/{app} /opt/lab/app/{app}
COPY docs/ /opt/lab/docs/
COPY start.sh restart.sh /opt/lab/
RUN chmod 0755 /opt/lab/start.sh /opt/lab/restart.sh
RUN addgroup -g 10001 lab && adduser -D -u 10001 -G lab -h /lab lab
USER 10001:10001
WORKDIR /lab
"""


def base_template(
    *,
    title: str,
    summary: str,
    cve_id: str,
    cwe_ids: list[str],
    instructions: list[str],
    checks: list[dict[str, Any]],
    ready_path: str = "/health",
) -> dict[str, Any]:
    """The sandbox lab definition shared by blueprints: unprivileged, no network, small limits."""
    return {
        "id": "candidate-lab",
        "version": "0",
        "title": title[:120],
        "summary": summary[:600],
        "cve_id": cve_id,
        "cwe_ids": cwe_ids,
        "difficulty": "beginner",
        "image": "cvelearn-candidate/candidate-lab:0",
        "ports": [{"name": "app", "container_port": 8080, "protocol": "http"}],
        "startup_command": ["/opt/lab/start.sh"],
        "shell": ["/bin/sh"],
        "user": "10001:10001",
        "timeout_minutes": 45,
        "resources": {"cpus": 0.5, "memory_mb": 128, "pids": 64, "tmpfs_mb": 16},
        "writable_paths": ["/tmp", "/lab"],  # noqa: S108
        "network": {"egress": "none"},
        "instructions": instructions,
        "safety_notes": [
            "This lab is an intentionally vulnerable toy application running in a sealed container with no network access.",
            "Do not use these techniques against systems you do not own or have written permission to test.",
        ],
        "verification": {
            "ready": {"port": "app", "path": ready_path, "status": 200, "timeout_seconds": 30},
            "restart_command": ["sh", "/opt/lab/restart.sh"],
            "checks": checks,
        },
    }
