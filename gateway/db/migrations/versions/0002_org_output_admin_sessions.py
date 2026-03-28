"""org scoping and output policy fields

Revision ID: 0002
Revises: 0001
Create Date: 2026-03-28

"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.postgresql import JSONB

revision: str = "0002"
down_revision: str | None = "0001"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "api_keys",
        sa.Column("org_id", sa.String(), nullable=False, server_default="default"),
    )

    op.add_column(
        "audit_events",
        sa.Column("org_id", sa.String(), nullable=False, server_default="default"),
    )
    op.add_column(
        "audit_events",
        sa.Column("output_decision", sa.String(), nullable=False, server_default="ALLOW"),
    )
    op.add_column(
        "audit_events",
        sa.Column("output_policy_rationale", sa.Text(), nullable=True),
    )

    op.add_column(
        "approval_requests",
        sa.Column("org_id", sa.String(), nullable=False, server_default="default"),
    )
    op.add_column(
        "approval_requests",
        sa.Column("scope", sa.String(), nullable=False, server_default="EXECUTION"),
    )
    op.add_column(
        "approval_requests",
        sa.Column("output_payload", JSONB(), nullable=True),
    )
    op.add_column(
        "approval_requests",
        sa.Column("output_hash", sa.String(), nullable=True),
    )


def downgrade() -> None:
    op.drop_column("approval_requests", "output_hash")
    op.drop_column("approval_requests", "output_payload")
    op.drop_column("approval_requests", "scope")
    op.drop_column("approval_requests", "org_id")

    op.drop_column("audit_events", "output_policy_rationale")
    op.drop_column("audit_events", "output_decision")
    op.drop_column("audit_events", "org_id")

    op.drop_column("api_keys", "org_id")
