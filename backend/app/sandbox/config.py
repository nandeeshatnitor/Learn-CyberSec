from dataclasses import dataclass, field
from datetime import UTC, datetime

from app.config import Settings
from app.sandbox.template import PlatformLimits


def as_utc(value: datetime) -> datetime:
    """Databases without time zones (SQLite) hand back naive datetimes; ours are always UTC."""
    return value.replace(tzinfo=UTC) if value.tzinfo is None else value


@dataclass(frozen=True)
class SandboxConfig:
    enabled: bool = True
    timeout_scale: float = 1.0
    grace_seconds: int = 60
    start_timeout_seconds: int = 90
    max_active: int = 20
    starts_per_hour: int = 12
    verify_timeout_seconds: float = 5.0
    proxy_max_bytes: int = 2_000_000
    isolation_gate: bool = True
    subnet_pool: str = "10.200.0.0/16"
    probe_image: str = "cvelearn-lab/net-probe:1"
    terminal_ticket_ttl_seconds: int = 30
    terminal_idle_seconds: int = 600
    terminal_max_per_instance: int = 2
    terminal_public_url: str | None = None
    cleanup_interval_seconds: float = 15.0
    limits: PlatformLimits = field(default_factory=PlatformLimits)

    @classmethod
    def from_settings(cls, s: Settings) -> "SandboxConfig":
        return cls(
            enabled=s.sandbox_enabled,
            timeout_scale=s.sandbox_timeout_scale,
            grace_seconds=s.sandbox_container_grace_seconds,
            start_timeout_seconds=s.sandbox_start_timeout_seconds,
            max_active=s.sandbox_max_active_instances,
            starts_per_hour=s.sandbox_starts_per_learner_per_hour,
            verify_timeout_seconds=s.sandbox_verify_timeout_seconds,
            proxy_max_bytes=s.sandbox_proxy_max_bytes,
            isolation_gate=s.sandbox_isolation_gate,
            subnet_pool=s.sandbox_subnet_pool,
            probe_image=s.sandbox_probe_image,
            terminal_ticket_ttl_seconds=s.sandbox_terminal_ticket_ttl_seconds,
            terminal_idle_seconds=s.sandbox_terminal_idle_seconds,
            terminal_max_per_instance=s.sandbox_terminal_max_per_instance,
            terminal_public_url=s.sandbox_terminal_public_url,
            cleanup_interval_seconds=s.sandbox_cleanup_interval_seconds,
            limits=PlatformLimits(
                max_cpus=s.sandbox_max_cpus,
                max_memory_mb=s.sandbox_max_memory_mb,
                max_pids=s.sandbox_max_pids,
                max_tmpfs_mb=s.sandbox_max_tmpfs_mb,
                max_timeout_minutes=s.sandbox_max_timeout_minutes,
                allowed_image_prefixes=tuple(s.sandbox_allowed_image_prefixes),
            ),
        )
