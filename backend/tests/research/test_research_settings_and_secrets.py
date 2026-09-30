"""Configuration rules for research, and credentials never leaking."""

import logging
from collections.abc import Callable
from typing import Any

import pytest
from pydantic import ValidationError

from app.config import Settings
from app.research.factory import build_llm, build_runtime
from app.research.synthesis.llm import AnthropicStructuredLLM
from app.services.research_service import ResearchService
from tests.research.conftest import RecordingQueue
from tests.research.support import CVE_ID

SECRET = "sk-ant-test-SECRET-0123456789"
GH_SECRET = "ghp_TESTSECRET0123456789"


def make(**overrides: Any) -> Settings:
    return Settings(  # type: ignore[call-arg]
        _env_file=None, database_url="sqlite://", environment="test", **overrides
    )


def test_llm_is_off_without_a_key_and_on_with_one() -> None:
    assert make().llm_enabled is False and build_llm(make()) is None
    settings = make(anthropic_api_key=SECRET)
    assert settings.llm_enabled and isinstance(build_llm(settings), AnthropicStructuredLLM)


def test_extractive_mode_ignores_the_key() -> None:
    settings = make(anthropic_api_key=SECRET, research_synthesis="extractive")
    assert not settings.llm_enabled and build_llm(settings) is None


def test_requiring_the_llm_without_a_key_fails_at_startup() -> None:
    with pytest.raises(ValidationError):
        make(research_synthesis="llm")


def test_blank_keys_count_as_unset() -> None:
    settings = make(anthropic_api_key="  ", github_token="")
    assert settings.anthropic_api_key is None and settings.github_token is None


@pytest.mark.parametrize(
    "overrides",
    [
        {"research_per_ip_runs_per_hour": 0},
        {"research_daily_run_budget": 0},
        {"research_queue_name": "bad name; drop"},
        {"research_max_documents": 0},
        {"research_fetch_max_bytes": 5},
        {"research_job_backend": "celery"},
    ],
)
def test_invalid_research_settings_are_rejected(overrides: dict[str, Any]) -> None:
    with pytest.raises(ValidationError):
        make(**overrides)


def test_secrets_are_not_in_repr_or_dumps() -> None:
    settings = make(anthropic_api_key=SECRET, github_token=GH_SECRET)
    for text in (repr(settings), str(settings), settings.model_dump_json()):
        assert SECRET not in text and GH_SECRET not in text


def test_the_github_token_is_only_sent_to_the_github_api_host() -> None:
    from app.cache import InMemorySlidingWindowLimiter

    runtime = build_runtime(make(github_token=GH_SECRET), InMemorySlidingWindowLimiter())
    try:
        client = runtime._github
        assert client is not None
        assert client._allowed_hosts == frozenset({"api.github.com"})  # type: ignore[attr-defined]
        assert client._client.headers["authorization"] == f"Bearer {GH_SECRET}"  # type: ignore[attr-defined]
        # The general web fetcher is a different client and never carries it.
        fetcher = runtime.pipeline._fetcher  # type: ignore[attr-defined]
        assert GH_SECRET not in repr(vars(fetcher))
    finally:
        runtime.close()


def test_no_secret_reaches_responses_or_logs(
    make_service: Callable[..., ResearchService],
    queue: RecordingQueue,
    caplog: pytest.LogCaptureFixture,
) -> None:
    caplog.set_level(logging.DEBUG)
    service = make_service()
    service.request(CVE_ID, client_key="203.0.113.7")
    queue.drain()
    payload = service.guide(CVE_ID).model_dump_json() + service.status(CVE_ID).model_dump_json()
    logs = "\n".join(r.getMessage() for r in caplog.records)
    for secret in (SECRET, GH_SECRET, "password"):
        assert secret not in payload and secret not in logs


def test_llm_errors_never_echo_provider_text() -> None:
    import anthropic
    import httpx2

    from app.research.synthesis.llm import LLMUnavailable

    class Broken:
        class messages:  # noqa: N801
            @staticmethod
            def parse(**kwargs: Any) -> Any:
                response = httpx2.Response(
                    401,
                    json={"error": {"message": f"invalid x-api-key {SECRET}"}},
                    request=httpx2.Request("POST", "https://api.anthropic.com/v1/messages"),
                )
                raise anthropic.AuthenticationError(
                    "invalid x-api-key " + SECRET, response=response, body=None
                )

    llm = AnthropicStructuredLLM(SECRET, client=Broken())
    with pytest.raises(LLMUnavailable) as caught:
        llm.generate(system="s", user="u")
    assert SECRET not in str(caught.value) and SECRET not in repr(caught.value)
