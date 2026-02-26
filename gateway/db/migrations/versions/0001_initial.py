"""initial schema

Revision ID: 0001
Revises:
Create Date: 2026-02-24

"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.postgresql import JSONB

revision: str = "0001"
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # --- api_keys ---
    op.create_table(
        "api_keys",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("caller_id", sa.String(), nullable=False),
        sa.Column("key_hash", sa.String(), nullable=False),
        sa.Column("role", sa.String(), nullable=False),
        sa.Column("trust_level", sa.Integer(), nullable=False),
        sa.Column("environment", sa.String(), nullable=False),
        sa.Column("is_active", sa.Boolean(), nullable=False, server_default="true"),
        sa.Column(
            "created_at",
            sa.DateTime(),
            nullable=False,
            server_default=sa.text("now()"),
        ),
        sa.Column("last_used_at", sa.DateTime(), nullable=True),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_api_keys_caller_id", "api_keys", ["caller_id"], unique=True)

    # --- audit_events ---
    op.create_table(
        "audit_events",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("request_id", sa.String(), nullable=False),
        sa.Column("trace_id", sa.String(), nullable=True),
        sa.Column("timestamp", sa.DateTime(), nullable=False),
        sa.Column("caller_id", sa.String(), nullable=False),
        sa.Column("caller_role", sa.String(), nullable=False),
        sa.Column("environment", sa.String(), nullable=False),
        sa.Column("mcp_server", sa.String(), nullable=False),
        sa.Column("tool_name", sa.String(), nullable=False),
        sa.Column("raw_args_hash", sa.String(), nullable=False),
        sa.Column("sanitized_args", JSONB(), nullable=False),
        sa.Column("risk_labels", JSONB(), nullable=False, server_default="[]"),
        sa.Column("risk_score", sa.Float(), nullable=False),
        sa.Column("matched_policy_rule", sa.String(), nullable=False),
        sa.Column("decision", sa.String(), nullable=False),
        sa.Column("approver_id", sa.String(), nullable=True),
        sa.Column("execution_status", sa.String(), nullable=True),
        sa.Column("latency_ms", sa.Integer(), nullable=False),
        sa.Column("output_hash", sa.String(), nullable=True),
        sa.Column("redaction_flags", JSONB(), nullable=False, server_default="[]"),
        sa.Column("llm_explanation", sa.Text(), nullable=True),
        sa.Column("deterministic_rationale", sa.Text(), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_audit_events_request_id", "audit_events", ["request_id"], unique=True)
    op.create_index("ix_audit_events_caller_id", "audit_events", ["caller_id"])
    op.create_index("ix_audit_events_timestamp", "audit_events", ["timestamp"])
    op.create_index("ix_audit_events_decision", "audit_events", ["decision"])

    # --- approval_requests ---
    op.create_table(
        "approval_requests",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("token", sa.String(), nullable=False),
        sa.Column("request_id", sa.String(), nullable=False),
        sa.Column("caller_id", sa.String(), nullable=False),
        sa.Column("tool_call", JSONB(), nullable=False),
        sa.Column("risk_explanation", sa.Text(), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("expires_at", sa.DateTime(), nullable=False),
        sa.Column("status", sa.String(), nullable=False, server_default="PENDING"),
        sa.Column("approver_id", sa.String(), nullable=True),
        sa.Column("decision_at", sa.DateTime(), nullable=True),
        sa.Column("approver_note", sa.Text(), nullable=True),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_approval_requests_token", "approval_requests", ["token"], unique=True)
    op.create_index("ix_approval_requests_request_id", "approval_requests", ["request_id"])
    op.create_index("ix_approval_requests_status", "approval_requests", ["status"])


def downgrade() -> None:
    op.drop_index("ix_approval_requests_status", table_name="approval_requests")
    op.drop_index("ix_approval_requests_request_id", table_name="approval_requests")
    op.drop_index("ix_approval_requests_token", table_name="approval_requests")
    op.drop_table("approval_requests")

    op.drop_index("ix_audit_events_decision", table_name="audit_events")
    op.drop_index("ix_audit_events_timestamp", table_name="audit_events")
    op.drop_index("ix_audit_events_caller_id", table_name="audit_events")
    op.drop_index("ix_audit_events_request_id", table_name="audit_events")
    op.drop_table("audit_events")

    op.drop_index("ix_api_keys_caller_id", table_name="api_keys")
    op.drop_table("api_keys")
