"""Builds the research runtime (pipeline + optional LLM) from settings."""

from dataclasses import dataclass

from app.cache import RateLimiter
from app.config import Settings
from app.integrations.http_client import ProviderHTTPClient
from app.research.discovery.base import SourceDiscoverer
from app.research.discovery.github import GitHubAdvisoryDiscoverer, GitHubRepositoryDiscoverer
from app.research.discovery.references import ReferenceDiscoverer
from app.research.fetch.safe_fetcher import PublicWebFetcher
from app.research.pipeline import PipelineConfig, ResearchPipeline
from app.research.synthesis.llm import AnthropicStructuredLLM, StructuredLLM


@dataclass
class ResearchRuntime:
    pipeline: ResearchPipeline
    llm: StructuredLLM | None
    _github: ProviderHTTPClient | None = None

    def close(self) -> None:
        if self._github is not None:
            self._github.close()


def build_llm(settings: Settings) -> StructuredLLM | None:
    if not settings.llm_enabled or settings.anthropic_api_key is None:
        return None
    return AnthropicStructuredLLM(
        settings.anthropic_api_key.get_secret_value(),
        model=settings.research_model,
        max_tokens=settings.research_max_output_tokens,
        effort=settings.research_effort,
        timeout_seconds=settings.research_llm_timeout_seconds,
    )


def build_runtime(settings: Settings, limiter: RateLimiter) -> ResearchRuntime:
    fetcher = PublicWebFetcher(
        connect_timeout=settings.research_fetch_connect_timeout_seconds,
        read_timeout=settings.research_fetch_read_timeout_seconds,
        max_bytes=settings.research_fetch_max_bytes,
        crawl_delay_seconds=settings.research_crawl_delay_seconds,
        limiter=limiter,
    )
    discoverers: list[SourceDiscoverer] = [ReferenceDiscoverer()]
    github: ProviderHTTPClient | None = None
    if settings.research_discover_github:
        headers = {
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        }
        if settings.github_token is not None:  # sent only to api.github.com (fixed host list)
            headers["Authorization"] = f"Bearer {settings.github_token.get_secret_value()}"
        github = ProviderHTTPClient(
            "github",
            allowed_hosts={"api.github.com"},
            connect_timeout=settings.provider_connect_timeout_seconds,
            read_timeout=settings.provider_read_timeout_seconds,
            max_bytes=2_000_000,
            default_headers=headers,
        )
        discoverers += [
            GitHubAdvisoryDiscoverer(github, limiter),
            GitHubRepositoryDiscoverer(github, limiter),
        ]
    config = PipelineConfig(
        max_candidates=settings.research_max_documents,
        max_sources_used=settings.research_max_sources_used,
        deadline_seconds=settings.research_deadline_seconds,
    )
    return ResearchRuntime(
        pipeline=ResearchPipeline(discoverers, fetcher, config),
        llm=build_llm(settings),
        _github=github,
    )
