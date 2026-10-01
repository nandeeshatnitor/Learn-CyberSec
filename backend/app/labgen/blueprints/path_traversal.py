"""Blueprint: path traversal in a document-serving endpoint (CWE-22).

A tiny document portal that joins a user-supplied name to its documents folder without a check.
The weakness is the documented behaviour; the portal itself is written here, not copied from the
affected product.
"""

from typing import Any

from app.labgen import sanitize
from app.labgen.blueprints.base import Probe, Rendered, ValidationPlan, base_template, common_files
from app.labgen.facts import TRAVERSAL_CWES, GuideFacts

ID = "path_traversal"
VERSION = "1"

_APP_BODY = '''
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

DOCS_DIR = "/lab/docs"
PORT = 8080


def read_document(name):
    """Return the bytes of a document from DOCS_DIR."""
    path = os.path.join(DOCS_DIR, name)
    with open(path, "rb") as handle:
        return handle.read()


class Handler(BaseHTTPRequestHandler):
    server_version = "LabApp/1.0"

    def _send(self, status, body, content_type="text/plain; charset=utf-8"):
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):  # noqa: N802
        url = urlparse(self.path)
        if url.path == "/health":
            self._send(200, b"ok\\n")
        elif url.path == "/version":
            self._send(200, (PRODUCT + " " + VERSION + "\\n").encode())
        elif url.path == ENDPOINT:
            name = parse_qs(url.query).get(PARAM, [""])[0]
            try:
                self._send(200, read_document(name))
            except (FileNotFoundError, IsADirectoryError, PermissionError):
                self._send(404, b"Document not found\\n")
        else:
            self._send(404, b"Not found\\n")

    def log_message(self, format, *args):  # noqa: A002
        print(self.address_string(), format % args, flush=True)


if __name__ == "__main__":
    ThreadingHTTPServer(("0.0.0.0", PORT), Handler).serve_forever()
'''

_FIX_SCRIPT = (
    "p='/lab/app/server.py'; s=open(p).read(); "
    "s=s.replace('    path = os.path.join(DOCS_DIR, name)\\n',"
    "'    path = os.path.realpath(os.path.join(DOCS_DIR, name))\\n"
    "    if not path.startswith(DOCS_DIR + os.sep):\\n        raise PermissionError(name)\\n'); "
    "open(p,'w').write(s)"
)


class PathTraversal:
    id = ID
    version = VERSION

    def match(self, facts: GuideFacts) -> str | None:
        if "path_traversal" not in facts.keywords:
            return None
        cwe = sorted(TRAVERSAL_CWES & set(facts.cwes))
        return f"CWE {cwe[0]}" if cwe else "the sources describe path/directory traversal"

    def parameters(self, facts: GuideFacts, overrides: dict[str, str]) -> dict[str, str] | None:
        product = sanitize.product(overrides.get("product")) or facts.product
        vuln = sanitize.version(overrides.get("vulnerable_version")) or facts.vulnerable_version
        if not (product and vuln):
            return None
        return {
            "product": product,
            "vulnerable_version": vuln,
            "fixed_version": sanitize.version(overrides.get("fixed_version"))
            or facts.fixed_version
            or "",
            # Not documented by the guide: the blueprint's own defaults (the spec says so).
            "endpoint": sanitize.endpoint(overrides.get("endpoint")) or "/download",
            "param": sanitize.parameter(overrides.get("param")) or "name",
        }

    def render(self, facts: GuideFacts, params: dict[str, str]) -> Rendered:
        product, version = params["product"], params["vulnerable_version"]
        endpoint, param, fixed = params["endpoint"], params["param"], params["fixed_version"]
        literals = f"PRODUCT = {product!r}\nVERSION = {version!r}\nENDPOINT = {endpoint!r}\nPARAM = {param!r}\n"
        app = (
            '"""Generated candidate lab: a minimal, intentionally vulnerable reproduction. NOT the vendor\'s software."""\n'
            + literals
            + _APP_BODY
        )
        files = {
            **common_files(),
            "app/server.py": app,
            "docs/welcome.txt": f"Welcome to {product} {version}.\n",
            "docs/guides/setup.txt": "Setup guide\nStep 1: open the portal. Step 2: choose a document.\n",
        }
        q = f"{endpoint}?{param}="
        checks: list[dict[str, Any]] = [
            {
                "id": "exploit",
                "kind": "payload_replay",
                "title": "Read a file outside the documents folder",
                "description": "Submit a request path that makes the portal return this lab's private secret.",
                "port": "app",
                "input_label": "Request path",
                "input_hint": f"{q}...",
            },
            {
                "id": "remediate",
                "kind": "regression",
                "title": "Fix the vulnerability",
                "description": "After your fix, the portal must refuse the attack (yours and the usual variants) and still serve real documents.",
                "port": "app",
                "requires": ["exploit"],
                "restart": True,
                "replay_from": ["exploit"],
                "block_paths": [
                    q + "../private/secret.txt",
                    q + "guides/../../private/secret.txt",
                    q + "%2e%2e/private/secret.txt",
                    q + "..%2fprivate%2fsecret.txt",
                    q + "/lab/private/secret.txt",
                    q + "....//private/secret.txt",
                ],
                "keep_working": [
                    {"path": "/health", "status_in": [200], "body_contains": "ok"},
                    {"path": "/version", "status_in": [200], "body_contains": version},
                    {"path": q + "welcome.txt", "status_in": [200], "body_contains": "Welcome"},
                    {
                        "path": q + "guides/setup.txt",
                        "status_in": [200],
                        "body_contains": "Setup guide",
                    },
                    {"path": q + "does-not-exist.txt", "status_in": [400, 403, 404]},
                ],
            },
        ]
        instructions = [
            f"Open the portal (the Lab app tab, or `wget -qO- 'http://localhost:8080{q}welcome.txt'` in the terminal) and look at how documents are requested.",
            "The portal's code is in /lab/app/server.py. Read `read_document` and ask what happens to the name you send.",
            f"The sources document a path-traversal weakness in {product} {version}. This lab hides a per-lab secret in a file outside the documents folder: find a request that makes the portal return it, then submit that request path for verification.",
            "Now fix the code in /lab/app/server.py, keeping legitimate documents (including ones in sub-folders) working. Restart the portal with `sh /opt/lab/restart.sh`, then verify the fix."
            + (
                f" The vendor's documented remediation is to upgrade to {fixed}; here you apply the equivalent change yourself."
                if fixed
                else ""
            ),
            "Everything here is disposable: use Reset lab for a fresh copy of the vulnerable portal at any time.",
        ]
        template = base_template(
            title=f"{product} {version}: path traversal ({facts.cve_id})",
            summary=f"A minimal educational reproduction of the documented weakness behind {facts.cve_id}: a portal that serves files from one folder. Show that it can be tricked into serving a file from outside it, then fix it.",
            cve_id=facts.cve_id,
            cwe_ids=sorted(TRAVERSAL_CWES & set(facts.cwes)) or ["CWE-22"],
            instructions=instructions,
            checks=checks,
        )
        exploit_path = q + "../private/secret.txt"
        plan = ValidationPlan(
            exploit=Probe(exploit_path),
            benign=Probe(q + "welcome.txt"),
            vulnerable_probe=Probe(exploit_path),
            vulnerable_expect="CVL-",
            reference_fix=("python", "-c", _FIX_SCRIPT),
            legit=(
                (Probe("/health"), "ok"),
                (Probe("/version"), version),
                (Probe(q + "welcome.txt"), "Welcome"),
                (Probe(q + "guides/setup.txt"), "Setup guide"),
            ),
            patched_must_not_contain=("CVL-",),
        )
        return Rendered(
            files=files,
            lab_template=template,
            plan=plan,
            objective=f"Reproduce, in an isolated lab, the documented path-traversal behaviour of {product} {version}: read a file outside the documents folder, then fix the code without breaking the portal.",
            prerequisites=[
                "How file paths and '..' work on Linux",
                "Reading a small Python web app",
                "A sandboxed lab only: never test systems you do not own or have permission to test",
            ],
            tasks=[
                ("explore", "Explore the portal", "Find how documents are requested and read."),
                (
                    "exploit",
                    "Read a file outside the folder",
                    "Make the portal return its per-lab secret; verified by replaying your request.",
                ),
                (
                    "remediate",
                    "Remove the behaviour",
                    "Fix the path handling; the verifier checks the attacks are blocked and the portal still serves real documents.",
                ),
            ],
            expected_vulnerable="A request with `../` in the document name returns this lab's private secret.",
            expected_fixed="The same requests are refused, legitimate documents (including sub-folders) still load.",
            remediation=(
                f"Upgrade to {product} {fixed} or later (documented by the sources). "
                if fixed
                else ""
            )
            + "In the lab: resolve the requested path and refuse anything outside the documents folder.",
            params=dict(params),
            defaulted=["endpoint", "param"],
        )


def blueprint() -> PathTraversal:
    return PathTraversal()
