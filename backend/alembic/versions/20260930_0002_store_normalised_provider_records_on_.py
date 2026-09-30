"""store normalised provider records on cves

Revision ID: 0002
Revises: 0001
Create Date: 2026-09-30 05:45:25.187372
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0002"
down_revision: str | None = "0001"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column("cves", sa.Column("vuln_status", sa.String(length=50), nullable=True))
    op.add_column("cves", sa.Column("known_exploited", sa.Boolean(), nullable=True))
    op.add_column("cves", sa.Column("retrieved_at", sa.DateTime(timezone=True), nullable=True))
    op.add_column(
        "cves",
        sa.Column(
            "record",
            sa.JSON().with_variant(postgresql.JSONB(astext_type=sa.Text()), "postgresql"),
            nullable=True,
        ),
    )


def downgrade() -> None:
    op.drop_column("cves", "record")
    op.drop_column("cves", "retrieved_at")
    op.drop_column("cves", "known_exploited")
    op.drop_column("cves", "vuln_status")
