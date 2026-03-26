import secrets
from datetime import datetime
from enum import StrEnum

from pydantic import BaseModel, Field

from gateway.models.mcp import ToolCall


class ApprovalStatus(StrEnum):
    PENDING = "PENDING"
    APPROVED = "APPROVED"
    DENIED = "DENIED"
    EXPIRED = "EXPIRED"


class ApprovalRequest(BaseModel):
    token: str = Field(default_factory=lambda: secrets.token_urlsafe(32))
    request_id: str
    caller_id: str
    tool_call: ToolCall
    risk_explanation: str
    created_at: datetime
    expires_at: datetime
    status: ApprovalStatus = ApprovalStatus.PENDING
    approver_id: str | None = None
    decision_at: datetime | None = None
    approver_note: str | None = None


class ApprovalResult(BaseModel):
    token: str
    status: ApprovalStatus
    approver_id: str | None = None
    note: str | None = None
    decided_at: datetime | None = None


class ApprovalSummary(BaseModel):
    """Richer view of an approval request for dashboard listing."""

    token: str
    caller_id: str
    tool_name: str
    server: str
    status: ApprovalStatus
    created_at: datetime
    expires_at: datetime
    approver_id: str | None = None
    decided_at: datetime | None = None
