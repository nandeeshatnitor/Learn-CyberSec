"""Docker-free stand-ins for the build and validation stages (the real ones run in
test_pipeline_docker.py). They let the pipeline, publisher and admin API be tested for logic."""

from typing import Any

from app.labgen.build import BuildResult, candidate_image_tag, context_hash
from app.labgen.validate import CHECKS, CheckResult, ValidationReport

RUNTIME_CHECKS = (
    "audit",
    "egress",
    "user",
    "capabilities",
    "rootfs",
    "docker_socket",
    "host_files",
)


class FakeBuilder:
    """Builds nothing; remembers which images exist and what they were built from."""

    def __init__(self) -> None:
        self.fail_build = False
        self.fail_retag = False
        self.images: dict[str, dict[str, str]] = {}
        self.builds = 0

    def build(self, candidate_id: str, family: str, files: dict[str, str]) -> BuildResult:
        self.builds += 1
        digest = context_hash(files)
        tag = candidate_image_tag(family, digest)
        if self.fail_build:
            return BuildResult(False, tag, None, "step 3/4 failed: boom")
        image_id = "sha256:" + digest
        self.images[tag] = {"id": image_id, "context": digest}
        return BuildResult(True, tag, image_id, "Successfully built")

    def image_id(self, tag: str) -> str | None:
        found = self.images.get(tag)
        return found["id"] if found else None

    def image_label(self, tag: str, label: str) -> str | None:
        found = self.images.get(tag)
        return found["context"] if found and label == "cvelearn.context-hash" else None

    def retag(self, source: str, target: str) -> bool:
        if self.fail_retag or source not in self.images:
            return False
        self.images[target] = dict(self.images[source])
        return True

    def remove_tag(self, tag: str) -> None:
        self.images.pop(tag, None)

    def image_exists(self, tag: str) -> bool:
        return tag in self.images


class FakeValidator:
    """Reports every check as passed, or fails the ones it is told to."""

    def __init__(self) -> None:
        self.fail: set[str] = set()
        self.fail_security: set[str] = set()
        self.calls = 0

    def run(self, **_: Any) -> ValidationReport:
        self.calls += 1
        checks = [
            CheckResult(i, t, "failed" if i in self.fail else "passed", "ok") for i, t in CHECKS
        ]
        runtime = [
            CheckResult(i, i, "failed" if i in self.fail_security else "passed", "ok")
            for i in RUNTIME_CHECKS
        ]
        return ValidationReport(checks, runtime)
