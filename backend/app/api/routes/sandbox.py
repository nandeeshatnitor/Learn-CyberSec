"""Sandboxed-lab endpoints (phase 4).

    GET  /api/sandbox/labs[?cve_id=]                     the labs (all, or those that fit a CVE)
    GET  /api/sandbox/labs/{lab_id}
    POST /api/sandbox/instances                          start a lab (optionally inside a session)
    GET  /api/sandbox/instances/current                  the caller's live lab, if any
    GET  /api/sandbox/instances/{id}                     status, lease, objectives
    POST /api/sandbox/instances/{id}/reset | stop
    POST /api/sandbox/instances/{id}/verify              check an objective against the running lab
    POST /api/sandbox/instances/{id}/network-check       prove the lab's network isolation, now
    POST /api/sandbox/instances/{id}/terminal-ticket     single-use ticket for the terminal socket
    GET  /api/sandbox/sessions/{session_id}/labs         labs + verified objectives for a session
    GET  /api/sandbox/app/{id}/{token}/...               the lab's web app, through the platform
    WS   /api/sandbox/terminal/ws?ticket=                the browser terminal (Terminal Gateway)

Learner endpoints identify the anonymous learner by X-Learner-Token, like the learning API. The app
URL and the terminal socket cannot carry that header/cookie, so they use capabilities instead: a
random token in the app URL, and a single-use ticket for the socket.
"""

import uuid
from typing import Annotated, Any

from fastapi import APIRouter, Depends, Path, Query, Request, WebSocket
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import Response

from app.api.dependencies import (
    AppSettings,
    ClientKey,
    LearnerId,
    SandboxManagerDep,
    SandboxScopeDep,
    TerminalGatewayDep,
    enforce_sandbox_limit,
)
from app.sandbox.terminal import CLOSE_FORBIDDEN_ORIGIN, CLOSE_UNAUTHORIZED
from app.schemas.errors import ErrorResponse
from app.schemas.sandbox import (
    CurrentInstance,
    InstanceView,
    IsolationView,
    LabView,
    SessionLabs,
    StartLabRequest,
    TicketView,
    VerifyRequest,
    VerifyResponse,
)

router = APIRouter(
    prefix="/sandbox", tags=["sandbox"], dependencies=[Depends(enforce_sandbox_limit)]
)
# The web app and the terminal socket carry no learner header, so they have their own router.
public_router = APIRouter(prefix="/sandbox", tags=["sandbox"])

InstanceId = Annotated[str, Path(max_length=40)]
LabId = Annotated[str, Path(max_length=64, pattern=r"^[a-z0-9][a-z0-9-]{2,62}$")]

_ERRORS: dict[int | str, dict[str, Any]] = {
    401: {"model": ErrorResponse},
    404: {"model": ErrorResponse},
    409: {"model": ErrorResponse},
    422: {"model": ErrorResponse},
    429: {"model": ErrorResponse},
    502: {"model": ErrorResponse},
    503: {"model": ErrorResponse},
}


@router.get("/labs", response_model=list[LabView], responses=_ERRORS)
def list_labs(
    manager: SandboxManagerDep,
    cve_id: Annotated[str | None, Query(max_length=40, pattern=r"^(?i:CVE-\d{4}-\d{4,})$")] = None,
) -> list[LabView]:
    return manager.labs(cve_id.upper() if cve_id else None)


@router.get("/labs/{lab_id}", response_model=LabView, responses=_ERRORS)
def get_lab(manager: SandboxManagerDep, lab_id: LabId) -> LabView:
    return manager.lab(lab_id)


@router.post("/instances", response_model=InstanceView, responses=_ERRORS)
def start_lab(
    manager: SandboxManagerDep, learner: LearnerId, body: StartLabRequest
) -> InstanceView:
    return manager.start(learner, body.lab_id, body.session_id)


@router.get("/instances/current", response_model=CurrentInstance, responses=_ERRORS)
def current_lab(manager: SandboxManagerDep, learner: LearnerId) -> CurrentInstance:
    return manager.current(learner)


@router.get("/instances/{instance_id}", response_model=InstanceView, responses=_ERRORS)
def get_instance(
    manager: SandboxManagerDep, learner: LearnerId, instance_id: InstanceId
) -> InstanceView:
    return manager.get(learner, instance_id)


@router.post("/instances/{instance_id}/reset", response_model=InstanceView, responses=_ERRORS)
def reset_instance(
    manager: SandboxManagerDep, learner: LearnerId, instance_id: InstanceId
) -> InstanceView:
    return manager.reset(learner, instance_id)


@router.post("/instances/{instance_id}/stop", response_model=InstanceView, responses=_ERRORS)
def stop_instance(
    manager: SandboxManagerDep, learner: LearnerId, instance_id: InstanceId
) -> InstanceView:
    return manager.stop(learner, instance_id)


@router.post("/instances/{instance_id}/verify", response_model=VerifyResponse, responses=_ERRORS)
def verify_objective(
    manager: SandboxManagerDep, learner: LearnerId, instance_id: InstanceId, body: VerifyRequest
) -> VerifyResponse:
    return manager.verify(learner, instance_id, body.check_id, body.payload)


@router.post(
    "/instances/{instance_id}/network-check", response_model=IsolationView, responses=_ERRORS
)
def network_check(
    manager: SandboxManagerDep, learner: LearnerId, instance_id: InstanceId
) -> IsolationView:
    return manager.network_check(learner, instance_id)


@router.post(
    "/instances/{instance_id}/terminal-ticket", response_model=TicketView, responses=_ERRORS
)
def terminal_ticket(
    manager: SandboxManagerDep, learner: LearnerId, instance_id: InstanceId
) -> TicketView:
    return manager.terminal_ticket(learner, instance_id)


@router.get("/sessions/{session_id}/labs", response_model=SessionLabs, responses=_ERRORS)
def session_labs(
    manager: SandboxManagerDep, learner: LearnerId, session_id: InstanceId
) -> SessionLabs:
    return manager.session_labs(learner, session_id)


# -- the lab's web app ---------------------------------------------------------------------------
@public_router.api_route(
    "/app/{instance_id}/{token}/{rest:path}",
    methods=["GET", "HEAD", "POST"],
    dependencies=[Depends(enforce_sandbox_limit)],
    include_in_schema=False,
)
async def lab_app(
    request: Request,
    manager: SandboxManagerDep,
    instance_id: Annotated[str, Path(max_length=40)],
    token: Annotated[str, Path(min_length=16, max_length=64, pattern=r"^[A-Za-z0-9_-]+$")],
    rest: str,
) -> Response:
    # Use the raw (still percent-encoded) path so a request reaches the lab exactly as sent.
    marker = f"/app/{instance_id}/{token}"
    raw = request.scope.get("raw_path", b"").decode("latin-1")
    at = raw.find(marker)
    target = raw[at + len(marker) :] if at >= 0 else ""
    if not target.startswith("/"):
        return Response(status_code=404)
    query = request.scope.get("query_string", b"").decode("latin-1")
    if query:
        target = f"{target}?{query}"
    body = await request.body() if request.method == "POST" else None
    result = await run_in_threadpool(
        manager.proxy,
        instance_id,
        token,
        method=request.method,
        target=target,
        headers=dict(request.headers),
        body=body,
        prefix=request.headers.get("x-lab-prefix"),
    )
    content = b"" if request.method == "HEAD" else result.body
    return Response(content=content, status_code=result.status, headers=result.headers)


# -- the terminal --------------------------------------------------------------------------------
@public_router.websocket("/terminal/ws")
async def terminal_socket(
    websocket: WebSocket,
    scope: SandboxScopeDep,
    gateway: TerminalGatewayDep,
    settings: AppSettings,
) -> None:
    origin = websocket.headers.get("origin")
    if origin is not None and origin not in settings.cors_allowed_origins:
        await websocket.close(code=CLOSE_FORBIDDEN_ORIGIN)
        return
    ticket = websocket.query_params.get("ticket", "")
    if not 20 <= len(ticket) <= 100:
        await gateway.reject(websocket, "unauthorized", CLOSE_UNAUTHORIZED)
        return

    def redeem() -> Any:
        with scope() as manager:
            return manager.redeem_ticket(ticket)

    target = await run_in_threadpool(redeem)
    if target is None:
        await gateway.reject(websocket, "unauthorized", CLOSE_UNAUTHORIZED)
        return

    async def still_running() -> bool:
        def check() -> bool:
            with scope() as manager:
                return manager.is_running(uuid.UUID(str(target.instance_id)))

        return await run_in_threadpool(check)

    await gateway.serve(websocket, target, still_running)


__all__ = ["ClientKey", "public_router", "router"]
