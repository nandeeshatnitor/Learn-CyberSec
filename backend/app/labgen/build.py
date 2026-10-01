"""Build stage: turn a candidate's files into a local image, offline.

The build context is written to a private temporary directory from the stored files (never from the
network or any path the candidate names), the Dockerfile is the blueprint's (and was statically
scanned), and the build runs with **no network**, so nothing can be downloaded or phoned home. The
resulting image is tagged `cvelearn-candidate/…`, a repository students can never start from.
"""

import hashlib
import os
import shutil
import tempfile
from dataclasses import dataclass
from pathlib import Path

from app.sandbox.firewall import CommandRunner

MAX_LOG_CHARS = 20_000


def context_hash(files: dict[str, str]) -> str:
    """A stable hash of the build context (paths and contents)."""
    digest = hashlib.sha256()
    for path in sorted(files):
        digest.update(path.encode())
        digest.update(b"\0")
        digest.update(hashlib.sha256(files[path].encode()).digest())
    return digest.hexdigest()


def candidate_image_tag(family: str, hash_: str) -> str:
    return f"cvelearn-candidate/{family}:{hash_[:12]}"


@dataclass
class BuildResult:
    ok: bool
    image_tag: str
    image_id: str | None
    log: str


class CandidateBuilder:
    def __init__(
        self, runner: CommandRunner, *, docker: str = "docker", timeout: float = 300.0
    ) -> None:
        self._runner = runner
        self._docker = docker
        self._timeout = timeout

    def build(self, candidate_id: str, family: str, files: dict[str, str]) -> BuildResult:
        hash_ = context_hash(files)
        tag = candidate_image_tag(family, hash_)
        workdir = Path(tempfile.mkdtemp(prefix="labgen-"))
        try:
            os.chmod(workdir, 0o700)
            for path, content in files.items():
                target = workdir / path
                # The static scan already refused unsafe paths; this is the belt to its braces.
                if not str(target.resolve()).startswith(str(workdir.resolve()) + os.sep):
                    return BuildResult(
                        False, tag, None, "refused: a file path leaves the build context"
                    )
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_text(content, encoding="utf-8")
                target.chmod(0o755 if path.endswith(".sh") else 0o644)
            result = self._runner.run(
                [
                    self._docker,
                    "build",
                    "--network",
                    "none",
                    "--pull=false",
                    "--progress",
                    "plain",
                    "--label",
                    f"cvelearn.candidate={candidate_id}",
                    "--label",
                    f"cvelearn.context-hash={hash_}",
                    "--tag",
                    tag,
                    str(workdir),
                ],  # fmt: skip
                timeout=self._timeout,
            )
            log = (result.stdout + "\n" + result.stderr).strip()[-MAX_LOG_CHARS:]
            if result.exit_code != 0:
                return BuildResult(False, tag, None, log or "build failed")
            return BuildResult(True, tag, self.image_id(tag), log)
        finally:
            shutil.rmtree(workdir, ignore_errors=True)

    def image_id(self, tag: str) -> str | None:
        result = self._runner.run(
            [self._docker, "image", "inspect", "--format", "{{.Id}}", tag], timeout=20
        )
        return result.stdout.strip() or None if result.exit_code == 0 else None

    def image_label(self, tag: str, label: str) -> str | None:
        fmt = '{{index .Config.Labels "' + label + '"}}'
        result = self._runner.run(
            [self._docker, "image", "inspect", "--format", fmt, tag], timeout=20
        )
        return result.stdout.strip() or None if result.exit_code == 0 else None

    def retag(self, source: str, target: str) -> bool:
        return self._runner.run([self._docker, "tag", source, target], timeout=30).exit_code == 0

    def remove_tag(self, tag: str) -> None:
        self._runner.run([self._docker, "rmi", "--no-prune", tag], timeout=30)

    def image_exists(self, tag: str) -> bool:
        return self.image_id(tag) is not None
