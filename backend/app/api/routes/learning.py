"""Learning-session endpoints.

    POST /api/learning                              create (or resume) a session for a CVE
    GET  /api/learning/by-cve/{cve_id}              the caller's latest session for a CVE
    GET  /api/learning/{id}                         session, progress, score
    POST /api/learning/{id}/start | complete | abandon
    GET  /api/learning/{id}/hints                   hints revealed so far, and what comes next
    POST /api/learning/{id}/hints                   reveal the next hint (-5/-10/-15 by default)
    POST /api/learning/{id}/tasks/{task}/answer     submit a text answer, get feedback
    POST /api/learning/{id}/tasks/{task}/solution   reveal the solution (-30 by default)
    GET  /api/learning/{id}/tasks/{task}/solution   re-read the solution of a finished task
    POST /api/learning/{id}/tutor                   ask the AI tutor;  GET the conversation

The caller is an anonymous learner identified by the X-Learner-Token header (kept in a cookie by
the web app). A session is visible only to the token that created it.
"""

import uuid
from typing import Annotated, Any

from fastapi import APIRouter, Depends, Path, Query

from app.api.dependencies import (
    ClientKey,
    LearnerId,
    LearningServiceDep,
    enforce_learning_limit,
)
from app.schemas.errors import ErrorResponse
from app.schemas.learning import (
    AnswerRequest,
    AnswerResponse,
    CreateSessionRequest,
    HintRequest,
    HintRevealResponse,
    HintsResponse,
    SessionView,
    SolutionResponse,
    SolutionView,
    TutorHistory,
    TutorReplyView,
    TutorRequest,
)

router = APIRouter(
    prefix="/learning", tags=["learning"], dependencies=[Depends(enforce_learning_limit)]
)

SessionId = Annotated[uuid.UUID, Path(description="Learning session ID")]
TaskId = Annotated[str, Path(max_length=16, pattern=r"^t[0-9]{1,2}$")]

_ERRORS: dict[int | str, dict[str, Any]] = {
    401: {"model": ErrorResponse},
    404: {"model": ErrorResponse},
    409: {"model": ErrorResponse},
    422: {"model": ErrorResponse},
    429: {"model": ErrorResponse},
}


@router.post("", response_model=SessionView, responses=_ERRORS)
def create_session(
    service: LearningServiceDep, learner: LearnerId, client: ClientKey, body: CreateSessionRequest
) -> SessionView:
    return service.create(learner, body.cve_id, client_key=client)


@router.get("/by-cve/{cve_id}", response_model=SessionView, responses=_ERRORS)
def session_for_cve(
    service: LearningServiceDep,
    learner: LearnerId,
    cve_id: Annotated[str, Path(max_length=40)],
) -> SessionView:
    return service.latest_for_cve(learner, cve_id)


@router.get("/{session_id}", response_model=SessionView, responses=_ERRORS)
def get_session(
    service: LearningServiceDep, learner: LearnerId, session_id: SessionId
) -> SessionView:
    return service.get(learner, session_id)


@router.post("/{session_id}/start", response_model=SessionView, responses=_ERRORS)
def start_session(
    service: LearningServiceDep, learner: LearnerId, session_id: SessionId
) -> SessionView:
    return service.start(learner, session_id)


@router.post("/{session_id}/complete", response_model=SessionView, responses=_ERRORS)
def complete_session(
    service: LearningServiceDep, learner: LearnerId, session_id: SessionId
) -> SessionView:
    return service.complete(learner, session_id)


@router.post("/{session_id}/abandon", response_model=SessionView, responses=_ERRORS)
def abandon_session(
    service: LearningServiceDep, learner: LearnerId, session_id: SessionId
) -> SessionView:
    return service.abandon(learner, session_id)


@router.get("/{session_id}/hints", response_model=HintsResponse, responses=_ERRORS)
def list_hints(
    service: LearningServiceDep,
    learner: LearnerId,
    session_id: SessionId,
    task_id: Annotated[str | None, Query(max_length=16, pattern=r"^t[0-9]{1,2}$")] = None,
) -> HintsResponse:
    return service.hints(learner, session_id, task_id)


@router.post("/{session_id}/hints", response_model=HintRevealResponse, responses=_ERRORS)
def reveal_hint(
    service: LearningServiceDep, learner: LearnerId, session_id: SessionId, body: HintRequest
) -> HintRevealResponse:
    return service.reveal_hint(learner, session_id, body.task_id, body.number)


@router.post(
    "/{session_id}/tasks/{task_id}/answer", response_model=AnswerResponse, responses=_ERRORS
)
def submit_answer(
    service: LearningServiceDep,
    learner: LearnerId,
    session_id: SessionId,
    task_id: TaskId,
    body: AnswerRequest,
) -> AnswerResponse:
    return service.submit_answer(learner, session_id, task_id, body.answer)


@router.get(
    "/{session_id}/tasks/{task_id}/solution", response_model=SolutionView, responses=_ERRORS
)
def get_solution(
    service: LearningServiceDep, learner: LearnerId, session_id: SessionId, task_id: TaskId
) -> SolutionView:
    return service.solution_of(learner, session_id, task_id)


@router.post(
    "/{session_id}/tasks/{task_id}/solution", response_model=SolutionResponse, responses=_ERRORS
)
def reveal_solution(
    service: LearningServiceDep, learner: LearnerId, session_id: SessionId, task_id: TaskId
) -> SolutionResponse:
    return service.reveal_solution(learner, session_id, task_id)


@router.post("/{session_id}/tutor", response_model=TutorReplyView, responses=_ERRORS)
def ask_tutor(
    service: LearningServiceDep,
    learner: LearnerId,
    client: ClientKey,
    session_id: SessionId,
    body: TutorRequest,
) -> TutorReplyView:
    return service.ask_tutor(learner, session_id, body.question, body.task_id, client_key=client)


@router.get("/{session_id}/tutor", response_model=TutorHistory, responses=_ERRORS)
def tutor_history(
    service: LearningServiceDep, learner: LearnerId, session_id: SessionId
) -> TutorHistory:
    return service.tutor_history(learner, session_id)
