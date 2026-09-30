"""create cves sources and cve_references

Revision ID: 0001
Revises:
Create Date: 2026-09-29 09:05:32.485278
"""

from collections.abc import Sequence

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

revision: str = "0001"
down_revision: str | None = None
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "cves",
        sa.Column("cve_id", sa.String(length=32), nullable=False),
        sa.Column("description", sa.Text(), nullable=False),
        sa.Column("published_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("modified_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("cvss_score", sa.Numeric(precision=3, scale=1, asdecimal=False), nullable=True),
        sa.Column("cvss_vector", sa.String(length=255), nullable=True),
        sa.Column("severity", sa.String(length=16), nullable=True),
        sa.Column(
            "cwes",
            sa.JSON().with_variant(postgresql.JSONB(astext_type=sa.Text()), "postgresql"),
            nullable=False,
        ),
        sa.Column(
            "affected_products",
            sa.JSON().with_variant(postgresql.JSONB(astext_type=sa.Text()), "postgresql"),
            nullable=False,
        ),
        sa.Column(
            "data_origin",
            sa.Enum("seed", "nvd", name="dataorigin", native_enum=False, length=32),
            nullable=False,
        ),
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_cves")),
    )
    op.create_index(op.f("ix_cves_cve_id"), "cves", ["cve_id"], unique=True)
    op.create_table(
        "sources",
        sa.Column(
            "source_type",
            sa.Enum(
                "nvd",
                "mitre",
                "vendor_advisory",
                "github_advisory",
                "cert",
                "cisa",
                "exploit_db",
                "research_blog",
                "other",
                name="sourcetype",
                native_enum=False,
                length=32,
            ),
            nullable=False,
        ),
        sa.Column("title", sa.String(length=500), nullable=False),
        sa.Column("url", sa.String(length=2048), nullable=False),
        sa.Column("publisher", sa.String(length=255), nullable=True),
        sa.Column("retrieved_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "reliability_level",
            sa.Enum(
                "official",
                "high",
                "medium",
                "low",
                "unverified",
                name="reliabilitylevel",
                native_enum=False,
                length=32,
            ),
            nullable=False,
        ),
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_sources")),
        sa.UniqueConstraint("url", name=op.f("uq_sources_url")),
    )
    op.create_index(op.f("ix_sources_source_type"), "sources", ["source_type"], unique=False)
    op.create_table(
        "cve_references",
        sa.Column("cve_id", sa.Uuid(), nullable=False),
        sa.Column("source_id", sa.Uuid(), nullable=False),
        sa.Column(
            "tags",
            sa.JSON().with_variant(postgresql.JSONB(astext_type=sa.Text()), "postgresql"),
            nullable=False,
        ),
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(
            ["cve_id"], ["cves.id"], name=op.f("fk_cve_references_cve_id_cves"), ondelete="CASCADE"
        ),
        sa.ForeignKeyConstraint(
            ["source_id"],
            ["sources.id"],
            name=op.f("fk_cve_references_source_id_sources"),
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_cve_references")),
        sa.UniqueConstraint("cve_id", "source_id", name="uq_cve_references_cve_id_source_id"),
    )
    op.create_index(
        op.f("ix_cve_references_source_id"), "cve_references", ["source_id"], unique=False
    )


def downgrade() -> None:
    op.drop_index(op.f("ix_cve_references_source_id"), table_name="cve_references")
    op.drop_table("cve_references")
    op.drop_index(op.f("ix_sources_source_type"), table_name="sources")
    op.drop_table("sources")
    op.drop_index(op.f("ix_cves_cve_id"), table_name="cves")
    op.drop_table("cves")
