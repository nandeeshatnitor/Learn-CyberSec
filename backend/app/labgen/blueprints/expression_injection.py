"""Blueprint: expression injection through a request header (template-injection class).

A tiny app that renders text from a request header and, *by design*, evaluates `${...}` expressions
found in it, using a restricted evaluator (integers and one named secret; no code execution, no
imports, no attribute access). It reproduces the documented *behaviour* (the expression is evaluated)
safely, without the vendor's code or a remote-code-execution primitive.
"""

import ast
from typing import Any

from app.labgen import sanitize
from app.labgen.blueprints.base import Probe, Rendered, ValidationPlan, base_template, common_files
from app.labgen.facts import EXPRESSION_CWES, GuideFacts

ID = "expression_injection"
VERSION = "1"

_APP_BODY = '''
import ast
import html
import re
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse

PORT = 8080
SECRET_FILE = "/lab/private/secret.txt"


def read_secret():
    try:
        with open(SECRET_FILE) as handle:
            return handle.read().strip()
    except OSError:
        return "unavailable"


CONTEXT = {"secret": read_secret(), "product": PRODUCT, "version": VERSION}
EXPRESSION = re.compile(r"\\$\\{([^}]{1,60})\\}")


def evaluate(node):
    """A deliberately small evaluator: integers, strings from CONTEXT, + - * // %."""
    if isinstance(node, ast.Constant) and isinstance(node.value, int) and not isinstance(node.value, bool):
        return node.value
    if isinstance(node, ast.Name) and node.id in CONTEXT:
        return CONTEXT[node.id]
    if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.USub):
        return -evaluate(node.operand)
    if isinstance(node, ast.BinOp):
        left, right = evaluate(node.left), evaluate(node.right)
        if isinstance(node.op, ast.Add):
            return left + right
        if isinstance(left, int) and isinstance(right, int):
            if isinstance(node.op, ast.Sub):
                return left - right
            if isinstance(node.op, ast.Mult) and abs(left) < 10**6 and abs(right) < 10**6:
                return left * right
            if isinstance(node.op, ast.FloorDiv) and right != 0:
                return left // right
            if isinstance(node.op, ast.Mod) and right != 0:
                return left % right
    raise ValueError("unsupported expression")


def evaluate_expression(text):
    return str(evaluate(ast.parse(text.strip(), mode="eval").body))


def render_template(value):
    """VULNERABLE: expressions in attacker-controlled text are evaluated."""
    def replace(match):
        try:
            return evaluate_expression(match.group(1))
        except (ValueError, SyntaxError, RecursionError):
            return match.group(0)
    return EXPRESSION.sub(replace, value)


class Handler(BaseHTTPRequestHandler):
    server_version = "LabApp/1.0"

    def _send(self, status, body, content_type="text/plain; charset=utf-8"):
        data = body.encode()
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):  # noqa: N802
        path = urlparse(self.path).path
        if path == "/health":
            self._send(200, "ok\\n")
        elif path == "/":
            self._send(200, PRODUCT + " " + VERSION + " preview service. Try " + ENDPOINT + "\\n")
        elif path == "/version":
            self._send(200, PRODUCT + " " + VERSION + "\\n")
        elif path == ENDPOINT:
            hint = self.headers.get(HEADER, "Hello")
            text = render_template(hint)
            self._send(200, "Preview: " + text + "\\n")
        else:
            self._send(404, "Not found\\n")

    def log_message(self, format, *args):  # noqa: A002
        print(self.address_string(), format % args, flush=True)


if __name__ == "__main__":
    ThreadingHTTPServer(("0.0.0.0", PORT), Handler).serve_forever()
'''

_FIX_SCRIPT = (
    "p='/lab/app/server.py'; s=open(p).read(); "
    "s=s.replace('text = render_template(hint)','text = html.escape(hint)'); "
    "open(p,'w').write(s)"
)


class ExpressionInjection:
    id = ID
    version = VERSION

    def match(self, facts: GuideFacts) -> str | None:
        if "expression_injection" not in facts.keywords:
            return None
        cwe = sorted(EXPRESSION_CWES & set(facts.cwes))
        return f"CWE {cwe[0]}" if cwe else "the sources describe expression/template injection"

    def parameters(self, facts: GuideFacts, overrides: dict[str, str]) -> dict[str, str] | None:
        product = sanitize.product(overrides.get("product")) or facts.product
        vuln = sanitize.version(overrides.get("vulnerable_version")) or facts.vulnerable_version
        header = sanitize.header(overrides.get("header")) or (
            facts.headers[0] if facts.headers else None
        )
        endpoint = sanitize.endpoint(overrides.get("endpoint")) or (
            facts.endpoints[0] if facts.endpoints else None
        )
        if not (product and vuln and header and endpoint):
            return None  # the sources do not document enough: no lab is invented
        probe = sanitize.expression(overrides.get("probe_expression")) or "7*7"
        return {
            "product": product,
            "vulnerable_version": vuln,
            "fixed_version": sanitize.version(overrides.get("fixed_version"))
            or facts.fixed_version
            or "",
            "header": header,
            "endpoint": endpoint,
            "probe_expression": probe,
        }

    def render(self, facts: GuideFacts, params: dict[str, str]) -> Rendered:
        product, version = params["product"], params["vulnerable_version"]
        header, endpoint, probe = params["header"], params["endpoint"], params["probe_expression"]
        result = str(eval_probe(probe))
        fixed = params["fixed_version"]
        literals = f"PRODUCT = {product!r}\nVERSION = {version!r}\nHEADER = {header!r}\nENDPOINT = {endpoint!r}\n"
        app = (
            '"""Generated candidate lab: a minimal, intentionally vulnerable reproduction. NOT the vendor\'s software."""\n'
            + literals
            + _APP_BODY
        )
        files = {
            **common_files(),
            "app/server.py": app,
            "docs/README.txt": f"{product} {version} (educational reproduction)\n",
        }
        payload = "${secret}"
        checks: list[dict[str, Any]] = [
            {
                "id": "exploit",
                "kind": "payload_replay",
                "title": f"Make the {header} header reveal the lab's secret",
                "description": f"Submit a {header} value that makes the lab's preview return its private secret.",
                "port": "app",
                "input_label": f"{header} value",
                "input_hint": "${...}",
                "header": header,
                "path": endpoint,
            },
            {
                "id": "remediate",
                "kind": "regression",
                "title": "Fix the vulnerability",
                "description": "After your fix, header text must only ever be treated as data (yours and the usual variants), and the preview must still work.",
                "port": "app",
                "requires": ["exploit"],
                "restart": True,
                "replay_from": ["exploit"],
                "block_headers": [
                    {"path": endpoint, "header": header, "value": "${secret}"},
                    {"path": endpoint, "header": header, "value": "${ secret }"},
                    {"path": endpoint, "header": header, "value": "x${secret}y"},
                ],
                "keep_working": [
                    {"path": "/health", "status_in": [200], "body_contains": "ok"},
                    {"path": "/version", "status_in": [200], "body_contains": version},
                    {
                        "path": endpoint,
                        "headers": {header: "Hello"},
                        "status_in": [200],
                        "body_contains": "Hello",
                    },
                    {
                        "path": endpoint,
                        "headers": {header: "${" + probe + "}"},
                        "status_in": [200],
                        "body_contains": "${" + probe + "}",
                        "body_not_contains": result,
                    },
                ],
            },
        ]
        instructions = [
            f"Open the lab (the Lab app tab, or `wget -qO- http://localhost:8080{endpoint}` in the terminal). Read /lab/app/server.py to see how the {header} header is handled.",
            f"The sources document that {product} {version} evaluates expressions found in the {header} header. Probe it with a harmless arithmetic expression such as ${{{probe}}}, for example: wget --header='{header}: ${{{probe}}}' -qO- http://localhost:8080{endpoint}",
            "This lab keeps a per-lab secret in a file the server can read but never serves. Craft a header value that makes the server reveal it, then submit that header value for verification: the check replays it against the running lab and looks for this lab's secret.",
            f"Now fix the code in /lab/app/server.py so that {header} text is only ever treated as data. Restart the app with `sh /opt/lab/restart.sh`, then verify the fix."
            + (
                f" The vendor's documented remediation is to upgrade to {fixed}; here you apply the equivalent change yourself."
                if fixed
                else ""
            ),
            "Everything here is disposable: use Reset lab for a fresh copy of the vulnerable app at any time.",
        ]
        template = base_template(
            title=f"{product} {version}: expression injection ({facts.cve_id})",
            summary=f"A minimal educational reproduction of the documented behaviour behind {facts.cve_id}: a service that evaluates expressions found in a request header. Show that it can be made to reveal a secret, then fix it.",
            cve_id=facts.cve_id,
            cwe_ids=sorted(EXPRESSION_CWES & set(facts.cwes)) or ["CWE-94"],
            instructions=instructions,
            checks=checks,
        )
        plan = ValidationPlan(
            exploit=Probe(endpoint, header, payload),
            benign=Probe(endpoint, header, "Hello"),
            vulnerable_probe=Probe(endpoint, header, "${" + probe + "}"),
            vulnerable_expect=result,
            reference_fix=("python", "-c", _FIX_SCRIPT),
            legit=(
                (Probe("/health"), "ok"),
                (Probe("/version"), version),
                (Probe(endpoint, header, "Hello"), "Hello"),
                (Probe(endpoint, header, "${" + probe + "}"), "${" + probe + "}"),
            ),
            patched_must_not_contain=(result,),
        )
        return Rendered(
            files=files,
            lab_template=template,
            plan=plan,
            objective=f"Reproduce, in an isolated lab, the documented behaviour that {product} {version} evaluates expressions found in the {header} request header, show its effect safely, then remove it.",
            prerequisites=[
                "Reading source code in a small Python web app",
                "Sending HTTP requests with custom headers (wget or curl)",
                "A sandboxed lab only: never test systems you do not own or have permission to test",
            ],
            tasks=[
                (
                    "explore",
                    "Explore the service",
                    f"Find how the {endpoint} endpoint uses the {header} header.",
                ),
                (
                    "probe",
                    "Observe the documented behaviour",
                    f"Send a harmless expression in {header} and observe that it is evaluated (`${{{probe}}}` becomes {result}).",
                ),
                (
                    "exploit",
                    "Reveal the lab's secret",
                    "Use the same behaviour to make the service return its per-lab secret; verified by replaying your header.",
                ),
                (
                    "remediate",
                    "Remove the behaviour",
                    f"Change the code so {header} text is only treated as data; the verifier checks the attacks are blocked and the app still works.",
                ),
            ],
            expected_vulnerable=f"A {header} value of ${{{probe}}} yields {result} in the response, and ${{secret}} reveals the lab's secret.",
            expected_fixed=f"The same header is echoed back as plain text (${{{probe}}} stays as written), no expression is evaluated and the secret is never revealed.",
            remediation=(
                f"Upgrade to {product} {fixed} or later (documented by the sources). "
                if fixed
                else ""
            )
            + "In the lab: treat header text strictly as data (escape it instead of evaluating it).",
            params=dict(params),
        )


def eval_probe(expression: str) -> int:
    """The result of a validated arithmetic probe like '7*7', computed without eval()."""

    def walk(node: ast.AST) -> int:
        if isinstance(node, ast.Constant) and isinstance(node.value, int):
            return node.value
        if isinstance(node, ast.BinOp):
            left, right = walk(node.left), walk(node.right)
            if isinstance(node.op, ast.Add):
                return left + right
            if isinstance(node.op, ast.Sub):
                return left - right
            if isinstance(node.op, ast.Mult):
                return left * right
        raise ValueError("unsupported probe")

    return walk(ast.parse(expression, mode="eval").body)


def blueprint() -> ExpressionInjection:
    return ExpressionInjection()


__all__ = ["ExpressionInjection", "blueprint", "eval_probe"]
_unused: Any = None
