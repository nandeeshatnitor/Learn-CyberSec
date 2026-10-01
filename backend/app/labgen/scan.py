"""Static security validation of a generated build context, before anything is built or run.

The candidate is treated as hostile. This is a conservative allow-list scan: it accepts only the
small vocabulary the vetted blueprints use and fails everything else, so a mistake in a blueprint, a
bad override or a future code generator cannot smuggle in network access, process execution, a root
user, a download, a secret or an oversized payload. It is a *gate*, not the only defence: the build has
no network, the lab runs in the sandbox, and a human reads the files before approving.
"""

import ast
import re
from dataclasses import asdict, dataclass
from typing import Any

from pydantic import ValidationError

from app.sandbox.template import LabTemplate, PlatformLimits, TemplateError, check_limits

CANDIDATE_IMAGE_PREFIX = "cvelearn-candidate/"
MAX_FILES = 24
MAX_FILE_BYTES = 65_536
MAX_TOTAL_BYTES = 262_144

_PATH = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9_./-]{0,80}$")
_TOP_LEVEL = {"Dockerfile", "start.sh", "restart.sh"}
_TOP_DIRS = {"app", "docs"}
_CONTROL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")

_DOCKER_INSTRUCTIONS = {
    "FROM",
    "COPY",
    "RUN",
    "USER",
    "WORKDIR",
    "ENV",
    "LABEL",
    "CMD",
    "ENTRYPOINT",
}
_RUN_ALLOWED = (
    re.compile(r"^chmod 0?[0-7]{3} (/[A-Za-z0-9_./-]+ ?)+$"),
    re.compile(r"^addgroup -g 10001 lab && adduser -D -u 10001 -G lab -h /lab lab$"),
    re.compile(r"^mkdir -p (/[A-Za-z0-9_./-]+ ?)+$"),
)
_ENV_SECRETISH = re.compile(r"SECRET|TOKEN|KEY|PASSWORD|PASSWD|CREDENTIAL", re.I)

# Plain `import x` is allowed only for these (and only their listed attributes can be used);
# `from x import y` only for the listed names. Everything else, including reaching a banned module
# through an allowed one (`os.path.os.system`, `http.server.os`), is refused.
_PY_PLAIN_IMPORTS = {"ast", "html", "re", "os"}
_PY_MODULE_ATTRS: dict[str, set[str]] = {
    "ast": {"parse", "literal_eval"},  # plus the capitalised node classes, see _is_ast_class
    "html": {"escape"},
    "re": {"compile", "sub", "match", "search", "fullmatch", "findall", "escape", "IGNORECASE"},
    "os": {"path", "sep"},
    "os.path": {
        "join", "normpath", "abspath", "realpath", "basename", "dirname", "exists", "isfile",
        "isdir", "commonpath", "splitext", "sep",
    },
}  # fmt: skip
_PY_FROM_IMPORTS: dict[str, set[str]] = {
    "http.server": {"BaseHTTPRequestHandler", "ThreadingHTTPServer", "HTTPServer"},
    "urllib.parse": {"urlparse", "urlsplit", "parse_qs", "unquote", "quote"},
    "os": {"path", "sep"},
    "html": {"escape"},
    "re": {"compile", "sub", "match", "search", "fullmatch", "findall", "escape"},
}
_PY_FORBIDDEN_CALLS = {
    "eval",
    "exec",
    "compile",
    "__import__",
    "input",
    "breakpoint",
    "globals",
    "locals",
    "vars",
    "getattr",
    "setattr",
    "delattr",
    "type",
    "super",
    "memoryview",
}
_PY_FORBIDDEN_ATTRS = {"format", "format_map", "mro", "system", "popen"}

_SH_FORBIDDEN = re.compile(
    r"\b(curl|wget|nc|ncat|netcat|ssh|scp|sudo|su|docker|mount|umount|chroot|nsenter|iptables|"
    r"apk|apt|apt-get|pip|pip3|npm|git|telnet|ftp|tftp|bash|eval|exec|python3?\s+-c)\b|/dev/(tcp|udp)|`|\$\("
)
_SECRET_PATTERNS = (
    re.compile(r"AKIA[0-9A-Z]{16}"),
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
    re.compile(r"gh[pousr]_[A-Za-z0-9]{30,}"),
    re.compile(r"sk-[A-Za-z0-9_-]{20,}"),
    re.compile(r"xox[baprs]-[A-Za-z0-9-]{10,}"),
)
_URL = re.compile(r"https?://", re.I)


@dataclass
class Finding:
    id: str
    title: str
    passed: bool
    detail: str = ""

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


def _fail(findings: list[Finding], fid: str, title: str, detail: str) -> None:
    findings.append(Finding(fid, title, False, detail[:300]))


def _ok(findings: list[Finding], fid: str, title: str, detail: str = "") -> None:
    findings.append(Finding(fid, title, True, detail))


def scan_files(files: dict[str, str]) -> list[Finding]:
    findings: list[Finding] = []
    title = "The build context is a small set of plain text files"
    problems: list[str] = []
    if not files:
        problems.append("no files")
    if len(files) > MAX_FILES:
        problems.append(f"more than {MAX_FILES} files")
    total = 0
    for path, content in files.items():
        size = len(content.encode("utf-8", errors="replace"))
        total += size
        parts = path.split("/")
        if (
            not _PATH.match(path)
            or ".." in parts
            or "" in parts
            or any(p.startswith(".") for p in parts)
        ):
            problems.append(f"unsafe path {path[:60]!r}")
        elif len(parts) == 1 and path not in _TOP_LEVEL:
            problems.append(f"unexpected top-level file {path!r}")
        elif len(parts) > 1 and parts[0] not in _TOP_DIRS:
            problems.append(f"unexpected directory {parts[0]!r}")
        if size > MAX_FILE_BYTES:
            problems.append(f"{path} is larger than {MAX_FILE_BYTES} bytes")
        if _CONTROL.search(content):
            problems.append(f"{path} contains binary or control characters")
    if total > MAX_TOTAL_BYTES:
        problems.append("the context is too large")
    for required in ("Dockerfile", "start.sh", "restart.sh"):
        if required not in files:
            problems.append(f"{required} is missing")
    if problems:
        _fail(findings, "file_set", title, "; ".join(problems))
    else:
        _ok(findings, "file_set", title, f"{len(files)} files, {total} bytes")
    return findings


def scan_dockerfile(text: str, base_images: list[str]) -> Finding:
    title = "The Dockerfile is minimal, offline and builds an unprivileged image"
    problems: list[str] = []
    logical: list[str] = []
    buffer = ""
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.endswith("\\"):
            buffer += line[:-1] + " "
            continue
        logical.append((buffer + line).strip())
        buffer = ""
    froms = 0
    last_user: str | None = None
    for line in logical:
        instruction, _, rest = line.partition(" ")
        instruction = instruction.upper()
        rest = rest.strip()
        if instruction not in _DOCKER_INSTRUCTIONS:
            problems.append(f"instruction {instruction} is not allowed")
        elif instruction == "FROM":
            froms += 1
            if rest not in base_images:
                problems.append(f"base image {rest[:60]!r} is not in the allow-list")
        elif instruction == "COPY":
            if rest.startswith("--") or _URL.search(rest):
                problems.append("COPY options and URLs are not allowed")
            for token in rest.split():
                if token.startswith("/") and not token.startswith("/opt/lab/"):
                    problems.append("COPY destinations must be under /opt/lab")
                if ".." in token.split("/"):
                    problems.append("COPY paths must stay inside the context")
        elif instruction == "RUN":
            if not any(p.match(rest) for p in _RUN_ALLOWED):
                problems.append(f"RUN {rest[:60]!r} is not an allowed build step")
        elif instruction == "USER":
            last_user = rest
        elif instruction == "ENV" and _ENV_SECRETISH.search(rest):
            problems.append("ENV must not carry secrets")
        elif instruction in {"CMD", "ENTRYPOINT"} and _URL.search(rest):
            problems.append("no URLs in commands")
    if froms != 1:
        problems.append("exactly one FROM is required")
    if last_user != "10001:10001":
        problems.append("the image must end with USER 10001:10001")
    return (
        Finding("dockerfile", title, False, "; ".join(problems)[:300])
        if problems
        else Finding("dockerfile", title, True)
    )


def _is_ast_class(name: str) -> bool:
    return name[:1].isupper() and name.isidentifier()


class _PyScanner(ast.NodeVisitor):
    def __init__(self) -> None:
        self.problems: list[str] = []
        self.modules: dict[str, str] = {}  # a name in the file -> the module it stands for

    def visit_Import(self, node: ast.Import) -> None:  # noqa: N802
        for alias in node.names:
            if alias.name not in _PY_PLAIN_IMPORTS or (alias.asname and alias.asname != alias.name):
                self.problems.append(f"import {alias.name} is not allowed")
            else:
                self.modules[alias.name] = alias.name

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:  # noqa: N802
        module = node.module or ""
        allowed = _PY_FROM_IMPORTS.get(module)
        if node.level or allowed is None:
            self.problems.append(f"import from {module} is not allowed")
            return
        for alias in node.names:
            if alias.name not in allowed or alias.asname:
                self.problems.append(f"from {module} import {alias.name} is not allowed")
            elif f"{module}.{alias.name}" in _PY_MODULE_ATTRS:
                self.modules[alias.name] = f"{module}.{alias.name}"

    def visit_Name(self, node: ast.Name) -> None:  # noqa: N802
        if node.id.startswith("__") and node.id not in {"__name__"}:
            self.problems.append(f"{node.id} is not allowed")

    def visit_Call(self, node: ast.Call) -> None:  # noqa: N802
        func = node.func
        if isinstance(func, ast.Name):
            if func.id in _PY_FORBIDDEN_CALLS:
                self.problems.append(f"call to {func.id}() is not allowed")
            if func.id == "open":
                mode = node.args[1] if len(node.args) > 1 else None
                kwmode = next((k.value for k in node.keywords if k.arg == "mode"), None)
                chosen = mode or kwmode
                if chosen is not None and not (
                    isinstance(chosen, ast.Constant) and chosen.value in {"r", "rb"}
                ):
                    self.problems.append("open() may only read")
        self.generic_visit(node)

    def visit_Attribute(self, node: ast.Attribute) -> None:  # noqa: N802
        chain: list[str] = [node.attr]
        root: ast.expr = node.value
        while isinstance(root, ast.Attribute):
            chain.append(root.attr)
            root = root.value
        if isinstance(root, ast.Name) and root.id in self.modules:
            self._check_module_chain(self.modules[root.id], list(reversed(chain)))
        if node.attr.startswith("__") or node.attr in _PY_FORBIDDEN_ATTRS:
            self.problems.append(f".{node.attr} is not allowed")
        self.generic_visit(node)

    def _check_module_chain(self, module: str, chain: list[str]) -> None:
        """`chain` is what follows the module name: `os.path.join` -> ["path", "join"]."""
        attr = chain[0]
        allowed = _PY_MODULE_ATTRS.get(module, set())
        if not (attr in allowed or (module == "ast" and _is_ast_class(attr))):
            self.problems.append(f"{module}.{attr} is not allowed")
        elif f"{module}.{attr}" in _PY_MODULE_ATTRS and len(chain) > 1:
            self._check_module_chain(f"{module}.{attr}", chain[1:])

    def visit_Constant(self, node: ast.Constant) -> None:  # noqa: N802
        if isinstance(node.value, str) and _URL.search(node.value):
            self.problems.append("URLs are not allowed in code")


def scan_python(path: str, source: str) -> Finding:
    title = f"{path} uses only the allowed standard-library vocabulary"
    try:
        tree = ast.parse(source)
    except SyntaxError as exc:
        return Finding(f"py:{path}", title, False, f"does not parse: {exc.msg}")
    scanner = _PyScanner()
    scanner.visit(tree)
    if scanner.problems:
        return Finding(f"py:{path}", title, False, "; ".join(dict.fromkeys(scanner.problems))[:300])
    return Finding(f"py:{path}", title, True)


def scan_shell(path: str, source: str) -> Finding:
    title = f"{path} runs no network tools, installers or privileged commands"
    match = _SH_FORBIDDEN.search(source)
    if match:
        return Finding(f"sh:{path}", title, False, f"found {match.group(0)!r}")
    return Finding(f"sh:{path}", title, True)


def scan_secrets(files: dict[str, str]) -> Finding:
    title = "No credentials or private keys are embedded"
    for path, content in files.items():
        for pattern in _SECRET_PATTERNS:
            if pattern.search(content):
                return Finding("secrets", title, False, f"a secret-like value is in {path}")
    return Finding("secrets", title, True)


def scan_lab_definition(template: dict[str, Any], limits: PlatformLimits) -> Finding:
    title = "The lab definition is unprivileged, offline and within conservative limits"
    problems: list[str] = []
    try:
        lab = LabTemplate.model_validate(template)
        check_limits(lab, limits)
    except (ValidationError, TemplateError, ValueError) as exc:
        return Finding("lab_definition", title, False, str(exc).replace("\n", " ")[:300])
    r = lab.resources
    if lab.uid == 0 or lab.gid == 0:
        problems.append("runs as root")
    if lab.network.egress != "none":
        problems.append("network egress is not denied")
    if r.cpus > 1 or r.memory_mb > 256 or r.pids > 128 or r.tmpfs_mb > 32:
        problems.append(
            "resource limits exceed the candidate caps (1 CPU, 256 MB, 128 pids, 32 MB)"
        )
    if lab.timeout_minutes > 60:
        problems.append("lease is longer than 60 minutes")
    if not lab.image.startswith(CANDIDATE_IMAGE_PREFIX):
        problems.append("a candidate must use a candidate image")
    if set(lab.writable_paths) - {"/tmp", "/lab"}:  # noqa: S108
        problems.append("unexpected writable paths")
    if lab.environment:
        problems.append("a generated lab may not set environment variables")
    if lab.startup_command != ["/opt/lab/start.sh"] or lab.shell != ["/bin/sh"]:
        problems.append("unexpected start command or shell")
    if lab.verification.restart_command not in (None, ["sh", "/opt/lab/restart.sh"]):
        problems.append("unexpected restart command")
    if any(p.protocol != "http" or p.container_port != 8080 for p in lab.ports):
        problems.append("unexpected ports")
    if problems:
        return Finding("lab_definition", title, False, "; ".join(problems))
    return Finding("lab_definition", title, True)


def static_scan(
    files: dict[str, str],
    template: dict[str, Any],
    *,
    base_images: list[str],
    limits: PlatformLimits,
) -> list[Finding]:
    """Every static finding for a candidate. The candidate passes only if all of them do."""
    findings = scan_files(files)
    if not findings[0].passed:
        return findings  # do not parse a malformed context any further
    if "Dockerfile" in files:
        findings.append(scan_dockerfile(files["Dockerfile"], base_images))
    for path in sorted(files):
        if path.endswith(".py"):
            findings.append(scan_python(path, files[path]))
        elif path.endswith(".sh"):
            findings.append(scan_shell(path, files[path]))
    findings.append(scan_secrets(files))
    findings.append(scan_lab_definition(template, limits))
    return findings
