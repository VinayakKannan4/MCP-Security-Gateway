from datetime import datetime
from typing import Any, Literal
from uuid import uuid4

from pydantic import BaseModel, Field

from gateway.models.policy import DecisionEnum


class ToolCall(BaseModel):
    server: str  # e.g. "filesystem-mcp"
    tool: str  # e.g. "fs.read"
    arguments: dict[str, Any]


class MCPRequest(BaseModel):
    request_id: str = Field(default_factory=lambda: str(uuid4()))
    trace_id: str | None = None
    caller_id: str
    api_key: str
    environment: Literal["dev", "staging", "prod"]
    tool_call: ToolCall
    context: str | None = None  # optional session context summary
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    # Optional: pre-approved token from a prior APPROVAL_REQUIRED response
    approval_token: str | None = None


class GatewayResponse(BaseModel):
    request_id: str
    decision: DecisionEnum
    result: dict[str, Any] | None = None  # tool output; only set if ALLOW/SANITIZE_AND_ALLOW
    sanitized_args: dict[str, Any] | None = None
    approval_token: str | None = None  # set when decision is APPROVAL_REQUIRED
    policy_explanation: str
    risk_labels: list[str] = Field(default_factory=list)
    latency_ms: int
