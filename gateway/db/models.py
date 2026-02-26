from datetime import datetime
from typing import Any

from sqlalchemy import Boolean, Float, Integer, String, Text, func
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from gateway.db.session import Base


class ApiKey(Base):
    """Stores caller identities and bcrypt-hashed API keys."""

    __tablename__ = "api_keys"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    caller_id: Mapped[str] = mapped_column(String, unique=True, index=True, nullable=False)
    key_hash: Mapped[str] = mapped_column(String, nullable=False)  # bcrypt — NEVER plaintext
    role: Mapped[str] = mapped_column(String, nullable=False)
    trust_level: Mapped[int] = mapped_column(Integer, nullable=False)  # TrustLevel IntEnum value
    environment: Mapped[str] = mapped_column(String, nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, server_default="true")
    created_at: Mapped[datetime] = mapped_column(nullable=False, server_default=func.now())
    last_used_at: Mapped[datetime | None] = mapped_column(nullable=True)


class AuditEventRow(Base):
    """Append-only audit log — mirrors gateway/models/audit.py:AuditEvent.

    Security invariants:
    - raw_args_hash stores SHA-256 hex of the original arguments, NEVER the raw args.
    - sanitized_args may contain post-redaction arguments (PII removed).
    - This table is append-only; rows are never updated or deleted.
    """

    __tablename__ = "audit_events"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    request_id: Mapped[str] = mapped_column(String, unique=True, index=True, nullable=False)
    trace_id: Mapped[str | None] = mapped_column(String, nullable=True)
    timestamp: Mapped[datetime] = mapped_column(index=True, nullable=False)
    caller_id: Mapped[str] = mapped_column(String, index=True, nullable=False)
    caller_role: Mapped[str] = mapped_column(String, nullable=False)
    environment: Mapped[str] = mapped_column(String, nullable=False)
    mcp_server: Mapped[str] = mapped_column(String, nullable=False)
    tool_name: Mapped[str] = mapped_column(String, nullable=False)
    raw_args_hash: Mapped[str] = mapped_column(String, nullable=False)  # SHA-256 hex only
    sanitized_args: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False)
    risk_labels: Mapped[list[Any]] = mapped_column(JSONB, nullable=False, server_default="[]")
    risk_score: Mapped[float] = mapped_column(Float, nullable=False)
    matched_policy_rule: Mapped[str] = mapped_column(String, nullable=False)
    decision: Mapped[str] = mapped_column(String, index=True, nullable=False)
    approver_id: Mapped[str | None] = mapped_column(String, nullable=True)
    execution_status: Mapped[str | None] = mapped_column(String, nullable=True)
    latency_ms: Mapped[int] = mapped_column(Integer, nullable=False)
    output_hash: Mapped[str | None] = mapped_column(String, nullable=True)
    redaction_flags: Mapped[list[Any]] = mapped_column(JSONB, nullable=False, server_default="[]")
    llm_explanation: Mapped[str | None] = mapped_column(Text, nullable=True)
    deterministic_rationale: Mapped[str] = mapped_column(Text, nullable=False)


class ApprovalRequestRow(Base):
    """Durable store for approval tokens — mirrors gateway/models/approval.py:ApprovalRequest.

    Redis is the fast-read path (with TTL). This table is the durability fallback —
    records survive Redis eviction and are the source of truth for audit.
    """

    __tablename__ = "approval_requests"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    token: Mapped[str] = mapped_column(String, unique=True, index=True, nullable=False)
    request_id: Mapped[str] = mapped_column(String, index=True, nullable=False)
    caller_id: Mapped[str] = mapped_column(String, nullable=False)
    tool_call: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False)  # serialized ToolCall
    risk_explanation: Mapped[str] = mapped_column(Text, nullable=False)
    created_at: Mapped[datetime] = mapped_column(nullable=False)
    expires_at: Mapped[datetime] = mapped_column(nullable=False)
    status: Mapped[str] = mapped_column(
        String, index=True, nullable=False, server_default="PENDING"
    )
    approver_id: Mapped[str | None] = mapped_column(String, nullable=True)
    decision_at: Mapped[datetime | None] = mapped_column(nullable=True)
    approver_note: Mapped[str | None] = mapped_column(Text, nullable=True)
