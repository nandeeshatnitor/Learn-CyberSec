"""Wiring for the candidate pipeline and the publisher (used by the API and by the job worker)."""

from sqlalchemy.orm import Session

from app.api.dependencies import (
    get_app_transport,
    get_sandbox_config,
    get_tutor_llm,
    student_limits,
)
from app.config import Settings
from app.labgen.build import CandidateBuilder
from app.labgen.generate import CandidateGenerator
from app.labgen.pipeline import CandidatePipeline, PipelineConfig
from app.labgen.publish import LabPublisher
from app.labgen.scan import CANDIDATE_IMAGE_PREFIX
from app.labgen.validate import CandidateValidator
from app.repositories import CVERepository, LabgenRepository, ResearchRepository, SandboxRepository
from app.sandbox.docker_runtime import DockerRuntime, SubprocessRunner
from app.sandbox.firewall import HostFirewall
from app.sandbox.template import PlatformLimits


def build_builder(settings: Settings) -> CandidateBuilder:
    return CandidateBuilder(
        SubprocessRunner(settings.sandbox_docker_host),
        docker=settings.sandbox_docker_binary,
        timeout=float(settings.labgen_build_timeout_seconds),
    )


def build_publisher(db: Session, settings: Settings) -> LabPublisher:
    return LabPublisher(LabgenRepository(db), build_builder(settings), student_limits(settings))


def build_pipeline(
    db: Session, settings: Settings, *, with_validator: bool = True
) -> CandidatePipeline:
    """The pipeline with a real Docker-backed builder and validator. (Generation and the admin API
    need no Docker; only the worker that builds and validates does.)"""
    runner = SubprocessRunner(settings.sandbox_docker_host)
    runtime = DockerRuntime(
        runner,
        docker=settings.sandbox_docker_binary,
        firewall=HostFirewall(runner) if settings.sandbox_manage_host_firewall else None,
    )
    config = get_sandbox_config()
    validator = (
        CandidateValidator(runtime, SandboxRepository(db), get_app_transport(), config)
        if with_validator
        else None
    )
    llm = get_tutor_llm() if settings.labgen_use_llm else None
    generator = CandidateGenerator(llm=llm)  # type: ignore[arg-type]
    return CandidatePipeline(
        LabgenRepository(db),
        ResearchRepository(db),
        CVERepository(db),
        generator,
        build_builder(settings),
        validator,
        PipelineConfig(
            base_images=list(settings.labgen_base_images),
            candidate_limits=PlatformLimits(
                allowed_image_prefixes=(CANDIDATE_IMAGE_PREFIX,),
                max_cpus=settings.sandbox_max_cpus,
                max_memory_mb=settings.sandbox_max_memory_mb,
                max_pids=settings.sandbox_max_pids,
                max_tmpfs_mb=settings.sandbox_max_tmpfs_mb,
                max_timeout_minutes=settings.sandbox_max_timeout_minutes,
            ),
        ),
    )
