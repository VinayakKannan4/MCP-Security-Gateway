"""Unit tests for EnforcementPipeline.

All external dependencies (DB, Redis, agents, executor) are mocked.
No Docker or LLM key required.

Covers:
- DENY decision → steps 6–8 skipped, _write_audit still called
- ALLOW decision → all 10 steps run, GatewayResponse.decision == ALLOW
- APPROVAL_REQUIRED without token → returns early with approval_token, audit written
- APPROVAL_REQUIRED with approved token → continues to execute
- _execute raises MCPToolError → _write_audit still called (finally block)
- Unknown API key → HTTPException(401) raised in _resolve_identity
- raw_args_hash is SHA-256 of original (pre-sanitization) args
- risk assessment llm_consulted flag propagated to audit event
"""

from __future__ import annotations

import hashlib
import json
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi import HTTPException

from gateway.config import Settings
from gateway.enforcement.errors import MCPTimeoutError, MCPToolError
from gateway.enforcement.pipeline import EnforcementPipeline
from gateway.models.approval import ApprovalResult, ApprovalStatus
from gateway.models.audit import RedactionFlag
from gateway.models.identity import CallerIdentity, TrustLevel
from gateway.models.mcp import GatewayResponse, MCPRequest, ToolCall
from gateway.models.policy import DecisionEnum, PolicyDecision
from gateway.models.risk import RiskAssessment, RiskLabel


# ---------------------------------------------------------------------------
# Helpers & fixtures
# ---------------------------------------------------------------------------


def _settings() -> Settings:
    return Settings(
        environment="prod",
        database_url="postgresql+asyncpg://x:x@localhost/x",
        redis_url="redis://localhost:6379/0",
        admin_api_key="test-admin-key",
        approval_token_ttl_seconds=3600,
    )


def _tool_call(args: dict | None = None) -> ToolCall:  # type: ignore[type-arg]
    return ToolCall(server="test-mcp", tool="fs.read", arguments=args or {"path": "/tmp/file.txt"})


def _request(args: dict | None = None, approval_token: str | None = None) -> MCPRequest:  # type: ignore[type-arg]
    return MCPRequest(
        caller_id="test-caller",
        api_key="plaintext-key",
        environment="prod",
        tool_call=_tool_call(args),
        approval_token=approval_token,
    )


def _identity() -> CallerIdentity:
    return CallerIdentity(
        caller_id="test-caller",
        role="developer",
        trust_level=TrustLevel.HIGH,
        environment="prod",
        api_key_id=1,
    )


def _allow_decision() -> PolicyDecision:
    return PolicyDecision(
        decision=DecisionEnum.ALLOW,
        matched_rule="allow-developer-read",
        rationale="Developer read allowed",
    )


def _deny_decision() -> PolicyDecision:
    return PolicyDecision(
        decision=DecisionEnum.DENY,
        matched_rule="deny-all",
        rationale="No matching rule",
    )


def _approval_decision() -> PolicyDecision:
    return PolicyDecision(
        decision=DecisionEnum.APPROVAL_REQUIRED,
        matched_rule="approval-required-rule",
        rationale="Approval required for this action",
        requires_approval=True,
    )


def _safe_risk() -> RiskAssessment:
    return RiskAssessment(labels=[], score=0.1, explanation="Safe request", llm_consulted=False)


def _high_risk() -> RiskAssessment:
    return RiskAssessment(
        labels=[RiskLabel.PROMPT_INJECTION_SUSPECT],
        score=0.95,
        explanation="Prompt injection detected",
        llm_consulted=True,
    )


def _make_pipeline(
    identity: CallerIdentity | None = None,
    risk: RiskAssessment | None = None,
    decision: PolicyDecision | None = None,
    sanitized_args: dict | None = None,  # type: ignore[type-arg]
    tool_output: dict | None = None,  # type: ignore[type-arg]
    approval_token_result: str | None = None,
    check_token_status: ApprovalStatus = ApprovalStatus.APPROVED,
) -> EnforcementPipeline:
    """Build a pipeline with sensible mocked defaults."""
    settings = _settings()

    # DB mock — _resolve_identity will bcrypt-check against a fake row
    db = AsyncMock()
    redis = AsyncMock()

    # Risk classifier
    risk_classifier = AsyncMock()
    risk_classifier.classify = AsyncMock(return_value=risk or _safe_risk())

    # Argument guard
    argument_guard = AsyncMock()
    argument_guard.sanitize = AsyncMock(
        return_value=(sanitized_args or {"path": "/tmp/file.txt"}, [])
    )

    # Policy engine
    policy_engine = MagicMock()
    policy_engine.validate_tool_schema = MagicMock(return_value=(True, []))
    policy_engine.evaluate = MagicMock(return_value=decision or _allow_decision())

    # Audit logger — we check it was called
    audit_logger = AsyncMock()
    audit_logger.write = AsyncMock()

    # Approval manager
    approval_manager = AsyncMock()
    approval_manager.issue_token = AsyncMock(return_value=approval_token_result or "new-token-abc")
    approval_result = ApprovalResult(
        token="existing-token",
        status=check_token_status,
    )
    approval_manager.check_token = AsyncMock(return_value=approval_result)

    # Executor
    executor = AsyncMock()
    executor.forward = AsyncMock(return_value=tool_output or {"content": "file content"})

    pipeline = EnforcementPipeline(
        settings=settings,
        db=db,
        redis=redis,
        risk_classifier=risk_classifier,
        argument_guard=argument_guard,
        policy_engine=policy_engine,
        audit_logger=audit_logger,
        approval_manager=approval_manager,
        executor=executor,
    )

    # Patch _resolve_identity to bypass bcrypt DB query
    resolved = identity or _identity()
    pipeline._resolve_identity = AsyncMock(return_value=resolved)  # type: ignore[method-assign]

    return pipeline


# ---------------------------------------------------------------------------
# ALLOW flow
# ---------------------------------------------------------------------------


@pytest.mark.unit
@pytest.mark.asyncio
async def test_allow_flow_runs_all_steps() -> None:
    pipeline = _make_pipeline(decision=_allow_decision(), tool_output={"data": "hello"})
    req = _request()

    response = await pipeline.run(req)

    assert response.decision == DecisionEnum.ALLOW
    assert response.result == {"data": "hello"}
    assert response.approval_token is None
    pipeline._argument_guard.sanitize.assert_called_once()
    pipeline._executor.forward.assert_called_once()
    pipeline._audit_logger.write.assert_called_once()


@pytest.mark.unit
@pytest.mark.asyncio
async def test_allow_response_has_correct_request_id() -> None:
    pipeline = _make_pipeline()
    req = _request()

    response = await pipeline.run(req)

    assert response.request_id == req.request_id


@pytest.mark.unit
@pytest.mark.asyncio
async def test_allow_sanitized_args_in_response() -> None:
    sanitized = {"path": "/tmp/safe.txt"}
    pipeline = _make_pipeline(decision=_allow_decision(), sanitized_args=sanitized)
    req = _request()

    response = await pipeline.run(req)

    assert response.sanitized_args == sanitized


# ---------------------------------------------------------------------------
# DENY flow
# ---------------------------------------------------------------------------


@pytest.mark.unit
@pytest.mark.asyncio
async def test_deny_skips_sanitize_and_execute() -> None:
    pipeline = _make_pipeline(decision=_deny_decision())
    req = _request()

    response = await pipeline.run(req)

    assert response.decision == DecisionEnum.DENY
    pipeline._argument_guard.sanitize.assert_not_called()
    pipeline._executor.forward.assert_not_called()


@pytest.mark.unit
@pytest.mark.asyncio
async def test_deny_audit_still_written() -> None:
    pipeline = _make_pipeline(decision=_deny_decision())
    req = _request()

    await pipeline.run(req)

    pipeline._audit_logger.write.assert_called_once()
    event = pipeline._audit_logger.write.call_args[0][0]
    assert event.decision == "DENY"


@pytest.mark.unit
@pytest.mark.asyncio
async def test_deny_sanitized_args_none_in_response() -> None:
    pipeline = _make_pipeline(decision=_deny_decision())
    req = _request()

    response = await pipeline.run(req)

    assert response.sanitized_args is None


# ---------------------------------------------------------------------------
# APPROVAL_REQUIRED — no token → return early
# ---------------------------------------------------------------------------


@pytest.mark.unit
@pytest.mark.asyncio
async def test_approval_required_no_token_returns_early() -> None:
    pipeline = _make_pipeline(
        decision=_approval_decision(),
        approval_token_result="pending-token-xyz",
    )
    req = _request()  # no approval_token

    response = await pipeline.run(req)

    assert response.decision == DecisionEnum.APPROVAL_REQUIRED
    assert response.approval_token == "pending-token-xyz"
    pipeline._executor.forward.assert_not_called()


@pytest.mark.unit
@pytest.mark.asyncio
async def test_approval_required_no_token_audit_written() -> None:
    pipeline = _make_pipeline(decision=_approval_decision())
    req = _request()

    await pipeline.run(req)

    pipeline._audit_logger.write.assert_called_once()


# ---------------------------------------------------------------------------
# APPROVAL_REQUIRED — with valid approved token → executes
# ---------------------------------------------------------------------------


@pytest.mark.unit
@pytest.mark.asyncio
async def test_approval_required_approved_token_executes() -> None:
    pipeline = _make_pipeline(
        decision=_approval_decision(),
        check_token_status=ApprovalStatus.APPROVED,
        tool_output={"result": "approved and executed"},
    )
    req = _request(approval_token="pre-approved-token")

    response = await pipeline.run(req)

    assert response.decision == DecisionEnum.APPROVAL_REQUIRED  # decision stays same
    assert response.result == {"result": "approved and executed"}
    pipeline._executor.forward.assert_called_once()


@pytest.mark.unit
@pytest.mark.asyncio
async def test_approval_required_pending_token_issues_new() -> None:
    pipeline = _make_pipeline(
        decision=_approval_decision(),
        check_token_status=ApprovalStatus.PENDING,
        approval_token_result="newly-issued-token",
    )
    req = _request(approval_token="old-pending-token")

    response = await pipeline.run(req)

    # Should have issued a new token and NOT executed
    pipeline._approval_manager.issue_token.assert_called_once()
    pipeline._executor.forward.assert_not_called()
    assert response.approval_token == "newly-issued-token"


# ---------------------------------------------------------------------------
# Execution errors — audit still writes
# ---------------------------------------------------------------------------


@pytest.mark.unit
@pytest.mark.asyncio
async def test_mcp_tool_error_audit_still_written() -> None:
    pipeline = _make_pipeline(decision=_allow_decision())
    pipeline._executor.forward = AsyncMock(side_effect=MCPToolError(500, "server error"))
    req = _request()

    response = await pipeline.run(req)

    pipeline._audit_logger.write.assert_called_once()
    event = pipeline._audit_logger.write.call_args[0][0]
    assert event.execution_status == "TOOL_ERROR"
    assert response.decision == DecisionEnum.ALLOW  # decision wasn't changed by error


@pytest.mark.unit
@pytest.mark.asyncio
async def test_mcp_timeout_error_audit_still_written() -> None:
    pipeline = _make_pipeline(decision=_allow_decision())
    pipeline._executor.forward = AsyncMock(side_effect=MCPTimeoutError("timed out"))
    req = _request()

    await pipeline.run(req)

    pipeline._audit_logger.write.assert_called_once()
    event = pipeline._audit_logger.write.call_args[0][0]
    assert event.execution_status == "TIMEOUT"


# ---------------------------------------------------------------------------
# Auth failure — HTTPException(401)
# ---------------------------------------------------------------------------


@pytest.mark.unit
@pytest.mark.asyncio
async def test_invalid_api_key_raises_401() -> None:
    pipeline = _make_pipeline()
    pipeline._resolve_identity = AsyncMock(  # type: ignore[method-assign]
        side_effect=HTTPException(status_code=401, detail="Invalid or inactive API key")
    )
    req = _request()

    with pytest.raises(HTTPException) as exc_info:
        await pipeline.run(req)

    assert exc_info.value.status_code == 401
    # No audit — identity was never resolved
    pipeline._audit_logger.write.assert_not_called()


# ---------------------------------------------------------------------------
# raw_args_hash invariant
# ---------------------------------------------------------------------------


@pytest.mark.unit
@pytest.mark.asyncio
async def test_raw_args_hash_is_sha256_of_original_args() -> None:
    original_args = {"path": "/tmp/secret.txt", "query": "sensitive data"}
    sanitized = {"path": "/tmp/safe.txt", "query": "[REDACTED]"}

    pipeline = _make_pipeline(decision=_allow_decision(), sanitized_args=sanitized)
    req = _request(args=original_args)

    await pipeline.run(req)

    event = pipeline._audit_logger.write.call_args[0][0]
    expected_hash = hashlib.sha256(
        json.dumps(original_args, sort_keys=True).encode()
    ).hexdigest()
    assert event.raw_args_hash == expected_hash


# ---------------------------------------------------------------------------
# Risk labels propagation
# ---------------------------------------------------------------------------


@pytest.mark.unit
@pytest.mark.asyncio
async def test_risk_labels_propagated_to_audit_event() -> None:
    risk = _high_risk()
    pipeline = _make_pipeline(decision=_allow_decision(), risk=risk)
    req = _request()

    await pipeline.run(req)

    event = pipeline._audit_logger.write.call_args[0][0]
    assert "PROMPT_INJECTION_SUSPECT" in event.risk_labels
    assert event.risk_score == 0.95


@pytest.mark.unit
@pytest.mark.asyncio
async def test_llm_consulted_flag_sets_explanation_in_audit() -> None:
    risk = _high_risk()
    assert risk.llm_consulted is True

    pipeline = _make_pipeline(decision=_allow_decision(), risk=risk)
    req = _request()

    await pipeline.run(req)

    event = pipeline._audit_logger.write.call_args[0][0]
    assert event.llm_explanation == risk.explanation


@pytest.mark.unit
@pytest.mark.asyncio
async def test_llm_not_consulted_explanation_null_in_audit() -> None:
    risk = _safe_risk()
    assert risk.llm_consulted is False

    pipeline = _make_pipeline(decision=_allow_decision(), risk=risk)
    req = _request()

    await pipeline.run(req)

    event = pipeline._audit_logger.write.call_args[0][0]
    assert event.llm_explanation is None


# ---------------------------------------------------------------------------
# Schema validation failure → HTTPException(422)
# ---------------------------------------------------------------------------


@pytest.mark.unit
@pytest.mark.asyncio
async def test_schema_validation_failure_raises_422() -> None:
    pipeline = _make_pipeline()
    pipeline._policy_engine.validate_tool_schema = MagicMock(  # type: ignore[method-assign]
        return_value=(False, ["Missing required field: 'path'"])
    )
    req = _request()

    with pytest.raises(HTTPException) as exc_info:
        await pipeline.run(req)

    assert exc_info.value.status_code == 422


# ---------------------------------------------------------------------------
# Audit event fields
# ---------------------------------------------------------------------------


@pytest.mark.unit
@pytest.mark.asyncio
async def test_audit_event_has_correct_metadata() -> None:
    identity = _identity()
    pipeline = _make_pipeline(identity=identity, decision=_allow_decision())
    req = _request()

    await pipeline.run(req)

    event = pipeline._audit_logger.write.call_args[0][0]
    assert event.caller_id == identity.caller_id
    assert event.caller_role == identity.role
    assert event.environment == identity.environment
    assert event.tool_name == req.tool_call.tool
    assert event.mcp_server == req.tool_call.server
    assert event.request_id == req.request_id
    assert event.latency_ms >= 0


@pytest.mark.unit
@pytest.mark.asyncio
async def test_redaction_flags_in_audit_event() -> None:
    flag = RedactionFlag(field="path", reason="PII_EMAIL", original_hash="abc123")
    pipeline = _make_pipeline(decision=_allow_decision())
    pipeline._argument_guard.sanitize = AsyncMock(
        return_value=({"path": "[REDACTED_EMAIL]"}, [flag])
    )
    req = _request()

    await pipeline.run(req)

    event = pipeline._audit_logger.write.call_args[0][0]
    assert len(event.redaction_flags) == 1
    assert event.redaction_flags[0].reason == "PII_EMAIL"
