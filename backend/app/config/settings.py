"""Application settings, loaded from environment variables (and an optional .env file).

No secrets have defaults here: DATABASE_URL must be provided by the environment.
"""

from functools import lru_cache
from pathlib import Path
from typing import Annotated, Literal

from pydantic import Field, SecretStr, field_validator, model_validator
from pydantic_settings import BaseSettings, NoDecode, SettingsConfigDict

from app.utils.client_ip import parse_networks

KNOWN_PROVIDERS = frozenset({"nvd", "mitre", "cisa_kev"})

# backend/app/config/settings.py -> the repository root, where the lab definitions live.
DEFAULT_LAB_DIR = Path(__file__).resolve().parents[3] / "labs"


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        # Repo-root .env for host-based development; containers get real env vars instead.
        env_file=("../.env", ".env"),
        env_file_encoding="utf-8",
        extra="ignore",
    )

    app_name: str = "CVE Learning Explorer API"
    environment: Literal["development", "test", "production"] = "development"
    log_level: Literal["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"] = "INFO"
    log_json: bool = False

    # Required: no default so a missing value fails loudly instead of using a guessable credential.
    database_url: SecretStr
    redis_url: SecretStr | None = None

    # Origins (comma-separated in the environment) allowed to call the API from a browser.
    cors_allowed_origins: Annotated[list[str], NoDecode] = Field(default_factory=list)

    # Upper bound applied to every paginated endpoint.
    max_page_size: int = Field(default=50, ge=1, le=200)

    # --- External vulnerability data providers --------------------------------------------------
    # Comma-separated provider IDs to enable; unknown IDs are rejected at startup.
    enabled_providers: Annotated[list[str], NoDecode] = Field(
        default_factory=lambda: ["nvd", "mitre", "cisa_kev"]
    )
    nvd_base_url: str = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    # Optional. Raises NVD's rate limit; only ever sent to NVD in a request header.
    nvd_api_key: SecretStr | None = None
    mitre_base_url: str = "https://cveawg.mitre.org/api/cve"
    kev_feed_url: str = (
        "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    )
    # Plain-http provider URLs are refused unless this is set (never allowed in production).
    allow_insecure_provider_urls: bool = False
    provider_connect_timeout_seconds: float = Field(default=3.0, gt=0, le=30)
    provider_read_timeout_seconds: float = Field(default=10.0, gt=0, le=60)
    provider_max_response_bytes: int = Field(default=10_000_000, ge=1_000, le=100_000_000)
    kev_max_response_bytes: int = Field(default=20_000_000, ge=1_000, le=100_000_000)

    # --- Caching (Redis, with an in-process fallback when Redis is not configured) --------------
    cache_ttl_seconds: int = Field(default=6 * 3600, ge=0)  # fresh CVE metadata
    cache_stale_ttl_seconds: int = Field(
        default=7 * 24 * 3600, ge=0
    )  # how long a stale copy is kept
    cache_negative_ttl_seconds: int = Field(default=600, ge=0)  # "provider has no such CVE"
    cache_search_ttl_seconds: int = Field(default=900, ge=0)
    kev_cache_ttl_seconds: int = Field(default=6 * 3600, ge=0)

    # --- Outbound rate limits (requests per window, per provider, shared across workers) --------
    # None means "pick a safe default" (NVD: 5/30s without a key, 50/30s with one, minus headroom).
    nvd_rate_limit_requests: int | None = Field(default=None, ge=1)
    nvd_rate_limit_window_seconds: int = Field(default=30, ge=1)
    mitre_rate_limit_requests: int = Field(default=30, ge=1)
    mitre_rate_limit_window_seconds: int = Field(default=60, ge=1)
    kev_rate_limit_requests: int = Field(default=4, ge=1)
    kev_rate_limit_window_seconds: int = Field(default=60, ge=1)
    circuit_failure_threshold: int = Field(default=3, ge=1)
    circuit_reset_seconds: float = Field(default=30.0, gt=0)

    # --- Inbound rate limit for the CVE endpoints (per client IP) -------------------------------
    api_rate_limit_requests: int = Field(default=60, ge=1)
    api_rate_limit_window_seconds: int = Field(default=60, ge=1)
    # Reverse proxies / the web app whose X-Forwarded-For header may be believed (addresses or
    # CIDRs, comma-separated). Empty: the header is ignored and the TCP peer is the client.
    trusted_proxies: Annotated[list[str], NoDecode] = Field(default_factory=list)

    # --- Research: public-source retrieval and learning-guide generation (phase 2) --------------
    research_enabled: bool = True
    # "auto": use the LLM when ANTHROPIC_API_KEY is set, else quote the sources (extractive).
    research_synthesis: Literal["auto", "llm", "extractive"] = "auto"
    # Optional. Backend only; sent to the Anthropic API and nowhere else, never logged or returned.
    anthropic_api_key: SecretStr | None = None
    research_model: str = Field(default="claude-opus-5-5", min_length=1, max_length=64)
    research_effort: Literal["low", "medium", "high", "xhigh", "max"] = "high"
    research_max_output_tokens: int = Field(default=12000, ge=1000, le=64000)
    research_llm_timeout_seconds: float = Field(default=180.0, gt=0, le=900)
    # "auto": RQ workers when Redis is configured, otherwise a thread in the API process.
    research_job_backend: Literal["auto", "rq", "thread", "inline"] = "auto"
    research_queue_name: str = Field(default="research", pattern=r"^[a-z0-9_-]{1,40}$")
    research_job_timeout_seconds: int = Field(default=600, ge=30, le=3600)
    # Cached guides are reused for this long; "refresh" is refused inside the cooldown.
    research_guide_ttl_seconds: int = Field(default=7 * 24 * 3600, ge=0)
    research_refresh_cooldown_seconds: int = Field(default=3600, ge=0)
    # An active run that has not moved for this long is considered dead and is failed.
    research_stale_run_seconds: int = Field(default=1800, ge=60)
    # Abuse and cost limits: new research runs per client IP per hour, and per day in total.
    research_per_ip_runs_per_hour: int = Field(default=5, ge=1)
    research_daily_run_budget: int = Field(default=200, ge=1)
    research_read_rate_limit_requests: int = Field(default=180, ge=1)  # status polls per minute
    research_max_documents: int = Field(default=12, ge=1, le=30)  # fetched per run
    research_max_sources_used: int = Field(default=8, ge=1, le=20)
    research_deadline_seconds: float = Field(default=120.0, gt=0, le=900)
    research_fetch_connect_timeout_seconds: float = Field(default=5.0, gt=0, le=30)
    research_fetch_read_timeout_seconds: float = Field(default=10.0, gt=0, le=60)
    research_fetch_max_bytes: int = Field(default=1_500_000, ge=10_000, le=10_000_000)
    research_crawl_delay_seconds: float = Field(default=2.0, ge=0, le=60)
    research_discover_github: bool = True
    # Optional. Raises GitHub's API rate limit; only ever sent to api.github.com.
    github_token: SecretStr | None = None

    # --- Interactive learning sessions (phase 3) ------------------------------------------------
    learning_enabled: bool = True
    # Scoring is intentionally simple and configurable; it is copied into each session at start.
    learning_start_score: int = Field(default=100, ge=1, le=10_000)
    learning_hint1_penalty: int = Field(default=5, ge=0, le=1000)
    learning_hint2_penalty: int = Field(default=10, ge=0, le=1000)
    learning_hint3_penalty: int = Field(default=15, ge=0, le=1000)
    learning_solution_penalty: int = Field(default=30, ge=0, le=1000)
    # Pedagogy: a solution can only be revealed after the student has tried the task once.
    learning_solution_requires_attempt: bool = True
    learning_max_answer_chars: int = Field(default=1000, ge=50, le=10_000)
    learning_max_question_chars: int = Field(default=500, ge=20, le=5_000)
    # Cost/abuse limits for the AI tutor (each question can be a model call).
    learning_tutor_per_session_per_hour: int = Field(default=30, ge=1)
    learning_tutor_per_client_per_hour: int = Field(default=60, ge=1)
    learning_sessions_per_client_per_hour: int = Field(default=20, ge=1)
    learning_read_rate_limit_requests: int = Field(default=240, ge=1)  # per minute per client

    # --- Sandboxed labs (phase 4) ---------------------------------------------------------------
    # Off by default: labs need a container runtime the platform is allowed to drive (ideally a
    # dedicated or rootless daemon, see docs/sandbox.md). Nothing else depends on it.
    sandbox_enabled: bool = False
    sandbox_lab_dir: Path = DEFAULT_LAB_DIR
    sandbox_docker_binary: str = Field(default="docker", min_length=1, max_length=200)
    # Optional DOCKER_HOST for a dedicated daemon (never the daemon that runs the platform itself).
    sandbox_docker_host: str | None = Field(default=None, max_length=200)
    # Lab images must come from these repositories and must already exist locally: never pulled.
    sandbox_allowed_image_prefixes: Annotated[list[str], NoDecode] = Field(
        default_factory=lambda: ["cvelearn-lab/"]
    )
    sandbox_probe_image: str = Field(default="cvelearn-lab/net-probe:1", min_length=3)
    # Each lab gets its own /28 from this pool, on its own internal (no-egress) bridge network.
    sandbox_subnet_pool: str = "10.200.0.0/16"
    # Drop traffic from lab bridges to the host itself (docker's internal networks do not).
    sandbox_manage_host_firewall: bool = True
    # Before a lab starts, prove from inside its network that the host, the internet, the cloud
    # metadata address and other labs are unreachable; refuse to start it otherwise.
    sandbox_isolation_gate: bool = True
    # Shortens every lab lease (never lengthens it): for demos and tests.
    sandbox_timeout_scale: float = Field(default=1.0, gt=0, le=1.0)
    # The container kills itself this long after its lease ends even if no cleanup worker runs.
    sandbox_container_grace_seconds: int = Field(default=60, ge=0, le=3600)
    sandbox_start_timeout_seconds: int = Field(default=90, ge=10, le=600)
    sandbox_max_active_instances: int = Field(default=20, ge=1, le=1000)
    sandbox_starts_per_learner_per_hour: int = Field(default=12, ge=1)
    # Upper bounds a lab definition may ask for (a definition above these is rejected at load).
    sandbox_max_cpus: float = Field(default=2.0, gt=0, le=16)
    sandbox_max_memory_mb: int = Field(default=1024, ge=32, le=16384)
    sandbox_max_pids: int = Field(default=512, ge=16, le=8192)
    sandbox_max_tmpfs_mb: int = Field(default=64, ge=1, le=1024)
    sandbox_max_timeout_minutes: int = Field(default=240, ge=1, le=1440)
    sandbox_cleanup_interval_seconds: float = Field(default=15.0, ge=1, le=600)
    sandbox_verify_timeout_seconds: float = Field(default=5.0, gt=0, le=30)
    sandbox_proxy_max_bytes: int = Field(default=2_000_000, ge=10_000, le=20_000_000)
    sandbox_read_rate_limit_requests: int = Field(default=300, ge=1)  # per minute per client
    # Terminal gateway: the browser gets a single-use ticket, then a WebSocket to this backend.
    # Base URL the browser should use (e.g. wss://labs.example.com); None: derive from the page.
    sandbox_terminal_public_url: str | None = Field(default=None, max_length=200)
    sandbox_terminal_ticket_ttl_seconds: int = Field(default=30, ge=5, le=300)
    sandbox_terminal_idle_seconds: int = Field(default=600, ge=30, le=7200)
    sandbox_terminal_max_per_instance: int = Field(default=2, ge=1, le=10)

    @field_validator("redis_url", "nvd_api_key", "anthropic_api_key", "github_token", mode="before")
    @classmethod
    def _empty_secret_is_unset(cls, value: object) -> object:
        return None if isinstance(value, str) and not value.strip() else value

    @field_validator("nvd_rate_limit_requests", mode="before")
    @classmethod
    def _empty_int_is_unset(cls, value: object) -> object:
        return None if isinstance(value, str) and not value.strip() else value

    @field_validator("sandbox_allowed_image_prefixes", mode="before")
    @classmethod
    def _split_prefixes(cls, value: object) -> object:
        if isinstance(value, str):
            return [item.strip() for item in value.split(",") if item.strip()]
        return value

    @field_validator("sandbox_docker_host", "sandbox_terminal_public_url", mode="before")
    @classmethod
    def _empty_text_is_unset(cls, value: object) -> object:
        return None if isinstance(value, str) and not value.strip() else value

    @field_validator("trusted_proxies", mode="before")
    @classmethod
    def _split_proxies(cls, value: object) -> object:
        if isinstance(value, str):
            return [item.strip() for item in value.split(",") if item.strip()]
        return value

    @field_validator("enabled_providers", mode="before")
    @classmethod
    def _split_providers(cls, value: object) -> object:
        if isinstance(value, str):
            return [item.strip().lower() for item in value.split(",") if item.strip()]
        return value

    @model_validator(mode="after")
    def _validate_provider_settings(self) -> "Settings":
        unknown = set(self.enabled_providers) - KNOWN_PROVIDERS
        if unknown:
            raise ValueError(f"unknown providers in ENABLED_PROVIDERS: {sorted(unknown)}")
        try:
            parse_networks(tuple(self.trusted_proxies))
        except ValueError as exc:
            raise ValueError(f"invalid TRUSTED_PROXIES entry: {exc}") from exc
        if self.allow_insecure_provider_urls and self.environment == "production":
            raise ValueError("ALLOW_INSECURE_PROVIDER_URLS must not be enabled in production")
        if self.research_synthesis == "llm" and self.anthropic_api_key is None:
            raise ValueError("RESEARCH_SYNTHESIS=llm requires ANTHROPIC_API_KEY")
        return self

    @property
    def effective_nvd_rate_limit(self) -> int:
        if self.nvd_rate_limit_requests is not None:
            return self.nvd_rate_limit_requests
        return 45 if self.nvd_api_key is not None else 4

    @field_validator("cors_allowed_origins", mode="before")
    @classmethod
    def _split_origins(cls, value: object) -> object:
        if isinstance(value, str):
            return [item.strip() for item in value.split(",") if item.strip()]
        return value

    @property
    def llm_enabled(self) -> bool:
        if self.research_synthesis == "extractive":
            return False
        return self.anthropic_api_key is not None

    @property
    def is_production(self) -> bool:
        return self.environment == "production"


@lru_cache
def get_settings() -> Settings:
    return Settings()  # values come from the environment
