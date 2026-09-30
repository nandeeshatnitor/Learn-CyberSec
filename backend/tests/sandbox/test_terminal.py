"""Terminal Gateway: ticketed WebSocket to a lab shell, never to the container runtime."""

import json
import time
from collections.abc import Iterator
from contextlib import contextmanager
from typing import Any

import pytest
from fastapi.testclient import TestClient
from starlette.websockets import WebSocketDisconnect

from app.api.dependencies import get_terminal_gateway
from app.main import app
from app.sandbox.terminal import (
    CLOSE_BUSY,
    CLOSE_FORBIDDEN_ORIGIN,
    CLOSE_IDLE,
    CLOSE_LAB_ENDED,
    CLOSE_UNAUTHORIZED,
    TerminalGateway,
)
from tests.sandbox.conftest import BOB_TOKEN, LAB_ID, Sandbox, headers

ORIGIN = {"origin": "http://localhost:3000"}
WS = "/api/sandbox/terminal/ws"


@pytest.fixture
def lab(api: TestClient) -> dict[str, Any]:
    return api.post("/api/sandbox/instances", json={"lab_id": LAB_ID}, headers=headers()).json()


def ticket(api: TestClient, lab: dict[str, Any], token: str | None = None) -> str:
    response = api.post(
        f"/api/sandbox/instances/{lab['id']}/terminal-ticket",
        headers=headers(token or "alice-token-0123456789abcdef"),
    )
    assert response.status_code == 200, response.text
    return response.json()["ticket"]


@contextmanager
def connect(api: TestClient, url: str, **kw: Any) -> Iterator[Any]:
    """Open a terminal socket, and on leaving wait for the gateway to finish its own clean-up.

    Starlette's test client cancels the app task the moment the `with` block ends, which would cut
    a handler that is still closing its shell short and raise CancelledError in the *test*. A real
    server (uvicorn) lets the handler finish, so the helper does the same.
    """
    with api.websocket_connect(url, **kw) as ws:
        yield ws
        ws.close(1000)
        gateway = app.dependency_overrides[get_terminal_gateway]()
        deadline = time.monotonic() + 3
        while gateway._active and time.monotonic() < deadline:  # noqa: SLF001
            time.sleep(0.01)
        time.sleep(0.05)


def refused(api: TestClient, url: str, **kw: Any) -> int:
    """Connect and return the close code the server ends with (the socket is accepted first, so the
    browser can read a reason; only a foreign origin is refused during the handshake)."""
    try:
        with api.websocket_connect(url, **kw) as ws:
            message = json.loads(ws.receive_text())
            assert message["type"] == "closed"
            ws.receive_bytes()
    except WebSocketDisconnect as exc:
        return exc.code
    raise AssertionError("the server did not close the socket")


def text(ws: Any) -> dict[str, Any]:
    return json.loads(ws.receive_text())


# -- tickets ---------------------------------------------------------------------------------
def test_a_ticket_is_short_lived_random_and_stored_only_as_a_hash(
    api: TestClient, lab: dict[str, Any], sandbox: Sandbox
) -> None:
    response = api.post(f"/api/sandbox/instances/{lab['id']}/terminal-ticket", headers=headers())
    body = response.json()
    assert (
        body["expires_in"] == 30
        and body["path"] == "/api/sandbox/terminal/ws"
        and len(body["ticket"]) >= 40
    )
    assert body["url"] is None
    from sqlalchemy import select

    from app.models import TerminalTicket

    rows = list(sandbox.repo._session.execute(select(TerminalTicket)).scalars())  # noqa: SLF001
    assert len(rows) == 1 and body["ticket"] not in (rows[0].token_hash, str(rows[0].id))
    assert len(rows[0].token_hash) == 64


def test_the_public_gateway_url_is_returned_when_configured(
    api: TestClient, lab: dict[str, Any], sandbox: Sandbox
) -> None:
    sandbox.manager._config = sandbox.config.__class__(
        terminal_public_url="wss://labs.example.com/"
    )  # noqa: SLF001
    body = api.post(f"/api/sandbox/instances/{lab['id']}/terminal-ticket", headers=headers()).json()
    assert body["url"] == "wss://labs.example.com"


def test_tickets_cannot_be_requested_for_a_stopped_lab(
    api: TestClient, lab: dict[str, Any]
) -> None:
    api.post(f"/api/sandbox/instances/{lab['id']}/stop", headers=headers())
    assert (
        api.post(
            f"/api/sandbox/instances/{lab['id']}/terminal-ticket", headers=headers()
        ).status_code
        == 409
    )


def test_someone_elses_lab_cannot_get_a_ticket(api: TestClient, lab: dict[str, Any]) -> None:
    assert (
        api.post(
            f"/api/sandbox/instances/{lab['id']}/terminal-ticket", headers=headers(BOB_TOKEN)
        ).status_code
        == 404
    )


# -- connecting ------------------------------------------------------------------------------
def test_a_valid_ticket_opens_a_shell_in_the_labs_container(
    api: TestClient, lab: dict[str, Any], sandbox: Sandbox
) -> None:
    with connect(api, f"{WS}?ticket={ticket(api, lab)}", headers=ORIGIN) as ws:
        assert ws.receive_bytes() == b"$ "
        ws.send_text(json.dumps({"type": "input", "data": "ls\n"}))
        assert ws.receive_bytes() == b"echo:ls\n"
    [(name, args)] = [c for c in sandbox.runtime.calls if c[0] == "open_shell"]
    container, argv, user, cols, rows = args
    row = sandbox.repo.live_for(sandbox.repo.get_any(__import__("uuid").UUID(lab["id"])).user_id)  # type: ignore[union-attr]
    assert container == row.container_name  # type: ignore[union-attr]
    assert argv == ("/bin/sh",) and user == "10001:10001" and (cols, rows) == (80, 24)


def test_the_browser_cannot_choose_the_container_or_the_command(
    api: TestClient, lab: dict[str, Any], sandbox: Sandbox
) -> None:
    url = f"{WS}?ticket={ticket(api, lab)}&container=postgres&cmd=sh&user=root&instance=other"
    with connect(api, url, headers=ORIGIN) as ws:
        ws.receive_bytes()
        ws.send_text(
            json.dumps({"type": "input", "data": "x", "container": "postgres", "command": ["rm"]})
        )
        ws.receive_bytes()
    _, args = next(c for c in sandbox.runtime.calls if c[0] == "open_shell")
    assert args[0].startswith("cvl-lab-") and args[1] == ("/bin/sh",) and args[2] == "10001:10001"


def test_a_ticket_works_once(api: TestClient, lab: dict[str, Any]) -> None:
    t = ticket(api, lab)
    with connect(api, f"{WS}?ticket={t}", headers=ORIGIN) as ws:
        ws.receive_bytes()
    assert refused(api, f"{WS}?ticket={t}", headers=ORIGIN) == CLOSE_UNAUTHORIZED


def test_an_expired_ticket_is_refused(
    api: TestClient, lab: dict[str, Any], sandbox: Sandbox
) -> None:
    t = ticket(api, lab)
    sandbox.clock.advance(31)
    assert refused(api, f"{WS}?ticket={t}", headers=ORIGIN) == CLOSE_UNAUTHORIZED


@pytest.mark.parametrize("bad", ["", "short", "x" * 30, "x" * 200, "../../etc/passwd"])
def test_a_missing_or_invented_ticket_is_refused(api: TestClient, bad: str) -> None:
    assert refused(api, f"{WS}?ticket={bad}", headers=ORIGIN) == CLOSE_UNAUTHORIZED
    assert refused(api, WS, headers=ORIGIN) == CLOSE_UNAUTHORIZED


def test_a_foreign_origin_is_refused_even_with_a_valid_ticket(
    api: TestClient, lab: dict[str, Any]
) -> None:
    t = ticket(api, lab)
    with (
        pytest.raises(WebSocketDisconnect) as info,
        api.websocket_connect(f"{WS}?ticket={t}", headers={"origin": "https://evil.example"}),
    ):
        pass
    assert info.value.code == CLOSE_FORBIDDEN_ORIGIN  # refused during the handshake
    # the refused attempt did not burn the ticket for the right origin
    with connect(api, f"{WS}?ticket={t}", headers=ORIGIN) as ws:
        ws.receive_bytes()


def test_a_ticket_dies_when_the_lab_is_stopped_or_reset(
    api: TestClient, lab: dict[str, Any]
) -> None:
    t = ticket(api, lab)
    api.post(f"/api/sandbox/instances/{lab['id']}/reset", headers=headers())
    assert refused(api, f"{WS}?ticket={t}", headers=ORIGIN) == CLOSE_UNAUTHORIZED


def test_a_ticket_for_an_expired_lab_is_refused(
    api: TestClient, lab: dict[str, Any], sandbox: Sandbox
) -> None:
    t = ticket(api, lab)
    sandbox.clock.advance(60 * 60)
    assert refused(api, f"{WS}?ticket={t}", headers=ORIGIN) == CLOSE_UNAUTHORIZED


def test_labs_disabled_means_no_terminal(
    api: TestClient, lab: dict[str, Any], sandbox: Sandbox
) -> None:
    t = ticket(api, lab)
    sandbox.manager._config = sandbox.config.__class__(enabled=False)  # noqa: SLF001
    assert refused(api, f"{WS}?ticket={t}", headers=ORIGIN) == CLOSE_UNAUTHORIZED


# -- the session -----------------------------------------------------------------------------
def test_resize_and_input_frames_are_clamped(
    api: TestClient, lab: dict[str, Any], sandbox: Sandbox
) -> None:
    with connect(api, f"{WS}?ticket={ticket(api, lab)}", headers=ORIGIN) as ws:
        ws.receive_bytes()
        ws.send_text(json.dumps({"type": "resize", "cols": 9999, "rows": 1}))
        ws.send_text(json.dumps({"type": "resize", "cols": "wide", "rows": 10}))  # ignored
        ws.send_text(json.dumps({"type": "input", "data": "A" * 5_000}))
        echoed = ws.receive_bytes()
        ws.send_bytes(b"B" * 10_000)
        echoed_raw = ws.receive_bytes()
    shell = sandbox.runtime.shells[0]
    assert shell.sizes == [(300, 5)]
    assert len(echoed) == 5 + 4096 and len(echoed_raw) == 5 + 4096


@pytest.mark.parametrize(
    "junk",
    [
        "not json",
        "[1,2]",
        '"text"',
        "null",
        '{"type":"unknown"}',
        '{"type":"input","data":5}',
        "x" * 20_000,
    ],
)
def test_malformed_control_frames_are_ignored(
    api: TestClient, lab: dict[str, Any], sandbox: Sandbox, junk: str
) -> None:
    with connect(api, f"{WS}?ticket={ticket(api, lab)}", headers=ORIGIN) as ws:
        ws.receive_bytes()
        ws.send_text(junk)
        ws.send_text(json.dumps({"type": "input", "data": "ok"}))
        assert ws.receive_bytes() == b"echo:ok"
    assert sandbox.runtime.shells[0].received == [b"ok"]


def test_when_the_shell_exits_the_socket_is_closed(
    api: TestClient, lab: dict[str, Any], sandbox: Sandbox
) -> None:
    with connect(api, f"{WS}?ticket={ticket(api, lab)}", headers=ORIGIN) as ws:
        ws.receive_bytes()
        sandbox.runtime.shells[0].exit()
        assert text(ws) == {"type": "closed", "reason": "shell_exited"}
        with pytest.raises(WebSocketDisconnect) as info:
            ws.receive_bytes()
        assert info.value.code == 1000


def test_the_shell_is_closed_when_the_browser_leaves(
    api: TestClient, lab: dict[str, Any], sandbox: Sandbox
) -> None:
    with connect(api, f"{WS}?ticket={ticket(api, lab)}", headers=ORIGIN) as ws:
        ws.receive_bytes()
    for _ in range(50):
        if sandbox.runtime.shells[0].closed:
            break
        time.sleep(0.05)
    assert sandbox.runtime.shells[0].closed


@pytest.fixture
def quick_gateway(sandbox: Sandbox):  # type: ignore[no-untyped-def]
    def make(**kw: Any) -> TerminalGateway:
        gateway = TerminalGateway(
            sandbox.runtime,
            **{"idle_seconds": 600, "max_per_instance": 2, "watch_interval": 0.05, **kw},
        )
        app.dependency_overrides[get_terminal_gateway] = lambda: gateway
        return gateway

    return make


def test_the_terminal_ends_when_the_lab_expires(
    api: TestClient, lab: dict[str, Any], sandbox: Sandbox, quick_gateway: Any
) -> None:
    quick_gateway()
    with connect(api, f"{WS}?ticket={ticket(api, lab)}", headers=ORIGIN) as ws:
        ws.receive_bytes()
        sandbox.clock.advance(60 * 60)
        assert text(ws) == {"type": "closed", "reason": "lab_ended"}
        with pytest.raises(WebSocketDisconnect) as info:
            ws.receive_bytes()
        assert info.value.code == CLOSE_LAB_ENDED
    assert sandbox.runtime.shells[0].closed


def test_the_terminal_ends_when_the_lab_is_reset(
    api: TestClient, lab: dict[str, Any], sandbox: Sandbox, quick_gateway: Any
) -> None:
    quick_gateway()
    with connect(api, f"{WS}?ticket={ticket(api, lab)}", headers=ORIGIN) as ws:
        ws.receive_bytes()
        api.post(f"/api/sandbox/instances/{lab['id']}/reset", headers=headers())
        assert text(ws)["reason"] == "lab_ended"


def test_an_idle_terminal_is_closed(
    api: TestClient, lab: dict[str, Any], quick_gateway: Any
) -> None:
    quick_gateway(idle_seconds=0.15)
    with connect(api, f"{WS}?ticket={ticket(api, lab)}", headers=ORIGIN) as ws:
        ws.receive_bytes()
        assert text(ws) == {"type": "closed", "reason": "idle"}
        with pytest.raises(WebSocketDisconnect) as info:
            ws.receive_bytes()
        assert info.value.code == CLOSE_IDLE


def test_only_a_few_terminals_per_lab(
    api: TestClient, lab: dict[str, Any], sandbox: Sandbox
) -> None:
    with (
        connect(api, f"{WS}?ticket={ticket(api, lab)}", headers=ORIGIN) as one,
        connect(api, f"{WS}?ticket={ticket(api, lab)}", headers=ORIGIN) as two,
    ):
        one.receive_bytes()
        two.receive_bytes()
        assert refused(api, f"{WS}?ticket={ticket(api, lab)}", headers=ORIGIN) == CLOSE_BUSY
    assert sandbox.gateway.active(__import__("uuid").UUID(lab["id"])) == 0


def test_an_unavailable_runtime_closes_the_socket_with_a_fixed_reason(
    api: TestClient, lab: dict[str, Any], sandbox: Sandbox
) -> None:
    from app.sandbox.runtime import SandboxError

    sandbox.runtime.fail["open_shell"] = SandboxError(
        "terminal_unavailable", "docker: secret detail"
    )
    with connect(api, f"{WS}?ticket={ticket(api, lab)}", headers=ORIGIN) as ws:
        message = text(ws)
        assert message == {"type": "closed", "reason": "unavailable"}
        assert "secret" not in json.dumps(message)
