"""Terminal Gateway: the browser's only path to a lab's shell.

    Browser --WebSocket--> Terminal Gateway (this backend) --docker exec + pty--> lab

* The browser never talks to the container runtime, and never learns a container name or address.
* It presents a single-use ticket (issued to the authenticated learner for one lab, valid for
  seconds). The WebSocket cannot carry the learner cookie to a different origin, hence the ticket.
* The command that runs is fixed by the lab definition. The browser controls only the bytes it types
  and the window size, both clamped.
* The session ends when the lab stops, expires or is reset, after an idle period, or when either
  side hangs up. At most a few terminals per lab.
"""

import asyncio
import json
import time
import uuid
from collections.abc import Awaitable, Callable
from dataclasses import dataclass

from starlette.websockets import WebSocket, WebSocketDisconnect

from app.sandbox.runtime import ContainerRuntime, SandboxError, ShellSession
from app.utils.logging import get_logger

log = get_logger(__name__)

MAX_INPUT_BYTES = 4096
MAX_CONTROL_BYTES = 8192

# WebSocket close codes (4000-4999 are application-defined).
CLOSE_LAB_ENDED = 4001
CLOSE_UNAUTHORIZED = 4401
CLOSE_FORBIDDEN_ORIGIN = 4403
CLOSE_IDLE = 4408
CLOSE_BUSY = 4429


@dataclass(frozen=True)
class TerminalTarget:
    instance_id: uuid.UUID
    container_name: str
    shell: tuple[str, ...]
    user: str


class TerminalGateway:
    def __init__(
        self,
        runtime: ContainerRuntime,
        *,
        idle_seconds: float,
        max_per_instance: int,
        watch_interval: float = 2.0,
    ) -> None:
        self._runtime = runtime
        self._idle = idle_seconds
        self._max = max_per_instance
        self._watch = watch_interval
        self._active: dict[uuid.UUID, int] = {}

    def active(self, instance_id: uuid.UUID) -> int:
        return self._active.get(instance_id, 0)

    async def serve(
        self,
        websocket: WebSocket,
        target: TerminalTarget,
        still_running: Callable[[], Awaitable[bool]],
    ) -> str:
        """Run one terminal session to its end and return why it ended."""
        if self._active.get(target.instance_id, 0) >= self._max:
            await self.reject(websocket, "busy", CLOSE_BUSY)
            return "busy"
        self._active[target.instance_id] = self._active.get(target.instance_id, 0) + 1
        shell = None
        reason = "error"
        try:
            await websocket.accept()
            try:
                shell = await self._runtime.open_shell(
                    target.container_name, target.shell, user=target.user, cols=80, rows=24
                )
            except SandboxError as exc:
                log.warning("terminal_open_failed", instance=str(target.instance_id), code=exc.code)
                await self._finish(websocket, "unavailable", 1011)
                return "unavailable"
            reason = await self._pump(websocket, shell, still_running)
        except WebSocketDisconnect:
            reason = "client_left"
        finally:
            self._active[target.instance_id] -= 1
            if self._active[target.instance_id] <= 0:
                self._active.pop(target.instance_id, None)
            if shell is not None:
                await shell.close()
        if reason != "client_left":
            code = {"lab_ended": CLOSE_LAB_ENDED, "idle": CLOSE_IDLE}.get(reason, 1000)
            await self._finish(websocket, reason, code)
        return reason

    async def _pump(
        self,
        websocket: WebSocket,
        shell: ShellSession,
        still_running: Callable[[], Awaitable[bool]],
    ) -> str:
        last_input = time.monotonic()

        async def output() -> str:
            while True:
                chunk = await shell.read()
                if not chunk:
                    return "shell_exited"
                await websocket.send_bytes(chunk)

        async def keyboard() -> str:
            nonlocal last_input
            while True:
                message = await websocket.receive()
                if message["type"] == "websocket.disconnect":
                    return "client_left"
                last_input = time.monotonic()
                raw = message.get("bytes")
                text = message.get("text")
                if raw is not None:
                    shell.write(raw[:MAX_INPUT_BYTES])
                elif text is not None:
                    self._control(shell, text)

        async def watchdog() -> str:
            while True:
                await asyncio.sleep(self._watch)
                if not await still_running():
                    return "lab_ended"
                if time.monotonic() - last_input > self._idle:
                    return "idle"

        tasks = [asyncio.ensure_future(fn()) for fn in (output, keyboard, watchdog)]
        try:
            done, _ = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
            return next(iter(done)).result()
        finally:
            for task in tasks:
                task.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)

    @staticmethod
    def _control(shell: ShellSession, text: str) -> None:
        """A JSON control frame: {"type":"input","data":"ls\\n"} or {"type":"resize",...}."""
        if len(text) > MAX_CONTROL_BYTES:
            return
        try:
            message = json.loads(text)
        except ValueError:
            return
        if not isinstance(message, dict):
            return
        kind = message.get("type")
        if kind == "input" and isinstance(message.get("data"), str):
            shell.write(message["data"].encode("utf-8", errors="ignore")[:MAX_INPUT_BYTES])
        elif kind == "resize":
            cols, rows = message.get("cols"), message.get("rows")
            if isinstance(cols, int) and isinstance(rows, int):
                shell.resize(max(20, min(cols, 300)), max(5, min(rows, 100)))

    @classmethod
    async def reject(cls, websocket: WebSocket, reason: str, code: int) -> None:
        """Refuse a connection *after* accepting it, so the browser can read why: a close during
        the handshake reaches JavaScript only as a bare failure with no code."""
        await websocket.accept()
        await cls._finish(websocket, reason, code)

    @staticmethod
    async def _finish(websocket: WebSocket, reason: str, code: int) -> None:
        try:
            await websocket.send_text(json.dumps({"type": "closed", "reason": reason}))
            await websocket.close(code=code)
        except (RuntimeError, WebSocketDisconnect):
            pass  # the client is already gone
