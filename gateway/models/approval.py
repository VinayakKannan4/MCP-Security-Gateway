import secrets
from datetime import datetime
from enum import Enum

from pydantic import BaseModel, Field

from gateway.models.mcp import ToolCall


class ApprovalStatus(str, Enum):
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
