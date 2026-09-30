"""research runs and source status

Revision ID: 0003
Revises: 0002
Create Date: 2026-09-30 06:39:47.296577
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0003"
down_revision: str | None = "0002"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "research_runs",
        sa.Column("cve_id", sa.String(length=32), nullable=False),
        sa.Column(
            "status",
            sa.Enum(
                "queued",
                "researching",
                "synthesizing",
                "ready",
                "failed",
                name="researchstatus",
                native_enum=False,
                length=32,
            ),
            nullable=False,
        ),
        sa.Column("stage_detail", sa.String(length=200), nullable=True),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("generation_version", sa.String(length=16), nullable=False),
        sa.Column("model_version", sa.String(length=64), nullable=True),
        sa.Column("synthesis_method", sa.String(length=16), nullable=True),
        sa.Column("sources_discovered", sa.Integer(), nullable=False),
        sa.Column("source_count", sa.Integer(), nullable=False),
        sa.Column(
            "guide",
            sa.JSON().with_variant(postgresql.JSONB(astext_type=sa.Text()), "postgresql"),
            nullable=True,
        ),
        sa.Column(
            "stats",
            sa.JSON().with_variant(postgresql.JSONB(astext_type=sa.Text()), "postgresql"),
            nullable=False,
        ),
        sa.Column("error_code", sa.String(length=32), nullable=True),
        sa.Column("error_message", sa.String(length=300), nullable=True),
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_research_runs")),
    )
    op.create_index(op.f("ix_research_runs_cve_id"), "research_runs", ["cve_id"], unique=False)
    op.create_index(
        "uq_research_runs_active_cve",
        "research_runs",
        ["cve_id"],
        unique=True,
        postgresql_where=sa.text("status IN ('queued', 'researching', 'synthesizing')"),
        sqlite_where=sa.text("status IN ('queued', 'researching', 'synthesizing')"),
    )
    op.create_table(
        "research_run_sources",
        sa.Column("run_id", sa.Uuid(), nullable=False),
        sa.Column("source_id", sa.Uuid(), nullable=True),
        sa.Column("sid", sa.String(length=8), nullable=False),
        sa.Column("sid_number", sa.Integer(), nullable=False),
        sa.Column("kind", sa.String(length=16), nullable=False),
        sa.Column("outcome", sa.String(length=24), nullable=False),
        sa.Column("outcome_detail", sa.String(length=200), nullable=True),
        sa.Column("independent_group", sa.String(length=100), nullable=True),
        sa.Column("relevance", sa.Float(), nullable=True),
        sa.Column(
            "passages",
            sa.JSON().with_variant(postgresql.JSONB(astext_type=sa.Text()), "postgresql"),
            nullable=False,
        ),
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(
            ["run_id"],
            ["research_runs.id"],
            name=op.f("fk_research_run_sources_run_id_research_runs"),
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["source_id"],
            ["sources.id"],
            name=op.f("fk_research_run_sources_source_id_sources"),
            ondelete="SET NULL",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_research_run_sources")),
        sa.UniqueConstraint("run_id", "sid", name="uq_research_run_sources_run_id_sid"),
    )
    op.create_index(
        op.f("ix_research_run_sources_run_id"), "research_run_sources", ["run_id"], unique=False
    )
    op.create_index(
        op.f("ix_research_run_sources_source_id"),
        "research_run_sources",
        ["source_id"],
        unique=False,
    )
    op.add_column(
        "sources",
        sa.Column(
            "status",
            sa.Enum(
                "discovered",
                "retrieved",
                "extracted",
                "irrelevant",
                "duplicate",
                "blocked",
                "excluded",
                "skipped",
                "failed",
                name="sourcestatus",
                native_enum=False,
                length=32,
            ),
            nullable=False,
            # Existing rows are links that were never fetched.
            server_default="discovered",
        ),
    )
    op.add_column("sources", sa.Column("content_hash", sa.String(length=64), nullable=True))
    # Source types renamed to match the research taxonomy.
    op.execute("UPDATE sources SET source_type = 'exploit_database' WHERE source_type = 'exploit_db'")
    op.execute("UPDATE sources SET source_type = 'security_blog' WHERE source_type = 'research_blog'")


def downgrade() -> None:
    # Values introduced by this revision have no earlier equivalent: map them to the closest.
    op.execute("UPDATE sources SET source_type = 'exploit_db' WHERE source_type = 'exploit_database'")
    op.execute("UPDATE sources SET source_type = 'research_blog' WHERE source_type = 'security_blog'")
    op.execute(
        "UPDATE sources SET source_type = 'other' WHERE source_type IN "
        "('github_repository', 'research', 'government')"
    )
    op.drop_column("sources", "content_hash")
    op.drop_column("sources", "status")
    op.drop_index(op.f("ix_research_run_sources_source_id"), table_name="research_run_sources")
    op.drop_index(op.f("ix_research_run_sources_run_id"), table_name="research_run_sources")
    op.drop_table("research_run_sources")
    op.drop_index(
        "uq_research_runs_active_cve",
        table_name="research_runs",
        postgresql_where=sa.text("status IN ('queued', 'researching', 'synthesizing')"),
        sqlite_where=sa.text("status IN ('queued', 'researching', 'synthesizing')"),
    )
    op.drop_index(op.f("ix_research_runs_cve_id"), table_name="research_runs")
    op.drop_table("research_runs")
