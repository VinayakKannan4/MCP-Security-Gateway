from datetime import datetime
from typing import Any
from pydantic import BaseModel, Field


class RedactionFlag(BaseModel):
    field: str  # which argument field was redacted
    reason: str  # e.g. "PII_EMAIL", "SECRET_TOKEN", "PATH_TRAVERSAL"
    original_hash: str  # SHA-256 of the original value (not the value itself)


class AuditEvent(BaseModel):
    request_id: str
    trace_id: str | None = None
    timestamp: datetime
    caller_id: str
    caller_role: str
    environment: str
    mcp_server: str
    tool_name: str
    raw_args_hash: str  # SHA-256 hex of serialized raw arguments
    sanitized_args: dict[str, Any]
    risk_labels: list[str] = Field(default_factory=list)
    risk_score: float
    matched_policy_rule: str
    decision: str  # ALLOW | DENY | APPROVAL_REQUIRED | SANITIZE_AND_ALLOW
    approver_id: str | None = None
    execution_status: str | None = None  # SUCCESS | TOOL_ERROR | TIMEOUT | None (not executed)
    latency_ms: int
    output_hash: str | None = None  # SHA-256 hex of tool output
    redaction_flags: list[RedactionFlag] = Field(default_factory=list)
    llm_explanation: str | None = None
    deterministic_rationale: str
