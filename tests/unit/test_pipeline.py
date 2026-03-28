"""Unit tests for EnforcementPipeline.

All external dependencies (DB, Redis, agents, executor) are mocked.
No Docker or LLM key required.
"""

from __future__ import annotations

import hashlib
import json
from unittest.mock import AsyncMock, MagicMock

import pytest
from fastapi import HTTPException

from gateway.config import Settings
from gateway.enforcement.errors import MCPTimeoutError, MCPToolError
from gateway.enforcement.pipeline import EnforcementPipeline
from gateway.models.approval import ApprovalResult, ApprovalScope, ApprovalStatus
from gateway.models.audit import RedactionFlag
from gateway.models.identity import CallerIdentity, TrustLevel
from gateway.models.mcp import MCPRequest, ToolCall
from gateway.models.policy import (
    DecisionEnum,
    OutputDecisionEnum,
    OutputPolicyDecision,
    PolicyDecision,
)
from gateway.models.risk import RiskAssessment, RiskLabel


def _settings() -> Settings:
    return Settings(
        environment="prod",
        database_url="postgresql+asyncpg://x:x@localhost/x",
        redis_url="redis://localhost:6379/0",
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
        org_id="acme-prod",
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


def _output_allow_decision() -> OutputPolicyDecision:
    return OutputPolicyDecision(
        decision=OutputDecisionEnum.ALLOW,
        matched_rule="output-allow-default",
        rationale="No output policy rule matched.",
        redacted_output={"content": "unused"},
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
    *,
    identity: CallerIdentity | None = None,
    risk: RiskAssessment | None = None,
    decision: PolicyDecision | None = None,
    output_policy_decision: OutputPolicyDecision | None = None,
    sanitized_args: dict | None = None,  # type: ignore[type-arg]
    tool_output: dict | None = None,  # type: ignore[type-arg]
    approval_token_result: str | None = None,
    execution_token_error: Exception | None = None,
    output_release_error: Exception | None = ValueError("missing release token"),
    output_release_payload: dict | None = None,  # type: ignore[type-arg]
    execution_approval_result: ApprovalResult | None = None,
) -> EnforcementPipeline:
    settings = _settings()
    db = AsyncMock()
    redis = AsyncMock()

    risk_classifier = AsyncMock()
    risk_classifier.classify = AsyncMock(return_value=risk or _safe_risk())

    argument_guard = AsyncMock()
    argument_guard.sanitize = AsyncMock(
        return_value=(sanitized_args or {"path": "/tmp/file.txt"}, [])
    )

    policy_engine = MagicMock()
    policy_engine.validate_tool_schema = MagicMock(return_value=(True, []))
    policy_engine.evaluate = MagicMock(return_value=decision or _allow_decision())

    output_policy_engine = MagicMock()
    output_policy_engine.evaluate = MagicMock(
        return_value=output_policy_decision or _output_allow_decision()
    )

    audit_logger = AsyncMock()
    audit_logger.write = AsyncMock()

    approval_manager = AsyncMock()
    approval_manager.issue_token = AsyncMock(return_value=approval_token_result or "new-token-abc")

    execution_result = execution_approval_result or ApprovalResult(
        token="execution-token",
        status=ApprovalStatus.USED,
        scope=ApprovalScope.EXECUTION,
        approver_id="admin-reviewer",
    )
    if execution_token_error is None:
        approval_manager.consume_execution_token = AsyncMock(return_value=execution_result)
    else:
        approval_manager.consume_execution_token = AsyncMock(side_effect=execution_token_error)

    release_result = (
        ApprovalResult(
            token="release-token",
            status=ApprovalStatus.USED,
            scope=ApprovalScope.OUTPUT_RELEASE,
            approver_id="admin-reviewer",
        ),
        output_release_payload or {"content": "stored sensitive output"},
    )
    if output_release_error is None:
        approval_manager.consume_output_token = AsyncMock(return_value=release_result)
    else:
        approval_manager.consume_output_token = AsyncMock(side_effect=output_release_error)

    executor = AsyncMock()
    executor.forward = AsyncMock(return_value=tool_output or {"content": "file content"})

    pipeline = EnforcementPipeline(
        settings=settings,
        db=db,
        redis=redis,
        risk_classifier=risk_classifier,
        argument_guard=argument_guard,
        policy_engine=policy_engine,
        output_policy_engine=output_policy_engine,
        audit_logger=audit_logger,
        approval_manager=approval_manager,
        executor=executor,
    )
    resolved = identity or _identity()
    pipeline._resolve_identity = AsyncMock(return_value=resolved)  # type: ignore[method-assign]
    return pipeline


@pytest.mark.unit
@pytest.mark.asyncio
async def test_allow_flow_runs_execution_and_output_policy() -> None:
    pipeline = _make_pipeline(tool_output={"data": "hello"})
    req = _request()

    response = await pipeline.run(req)

    assert response.decision == DecisionEnum.ALLOW
    assert response.output_decision == OutputDecisionEnum.ALLOW
    assert response.result == {"data": "hello"}
    pipeline._argument_guard.sanitize.assert_called_once()
    pipeline._executor.forward.assert_called_once_with(
        req.tool_call.server,
        req.tool_call.tool,
        {"path": "/tmp/file.txt"},
        _identity(),
        req.request_id,
    )
    pipeline._output_policy_engine.evaluate.assert_called_once()
    pipeline._audit_logger.write.assert_called_once()


@pytest.mark.unit
@pytest.mark.asyncio
async def test_deny_skips_sanitize_and_execute() -> None:
    pipeline = _make_pipeline(decision=_deny_decision())
    response = await pipeline.run(_request())

    assert response.decision == DecisionEnum.DENY
    assert response.result is None
    pipeline._argument_guard.sanitize.assert_not_called()
    pipeline._executor.forward.assert_not_called()


@pytest.mark.unit
@pytest.mark.asyncio
async def test_execution_approval_required_without_token_issues_token() -> None:
    pipeline = _make_pipeline(decision=_approval_decision(), approval_token_result="pending-token")

    response = await pipeline.run(_request())

    assert response.decision == DecisionEnum.APPROVAL_REQUIRED
    assert response.approval_token == "pending-token"
    assert response.result is None
    pipeline._executor.forward.assert_not_called()


@pytest.mark.unit
@pytest.mark.asyncio
async def test_execution_approval_token_executes_and_records_approver() -> None:
    pipeline = _make_pipeline(
        decision=_approval_decision(),
        tool_output={"result": "approved"},
    )
    req = _request(approval_token="approved-token")

    response = await pipeline.run(req)

    assert response.decision == DecisionEnum.ALLOW
    assert response.result == {"result": "approved"}
    pipeline._approval_manager.consume_execution_token.assert_called_once()
    event = pipeline._audit_logger.write.call_args[0][0]
    assert event.approver_id == "admin-reviewer"


@pytest.mark.unit
@pytest.mark.asyncio
async def test_output_redaction_returns_redacted_result_and_hashes_original_output() -> None:
    original_output = {"content": "contact jane@example.com"}
    pipeline = _make_pipeline(
        tool_output=original_output,
        output_policy_decision=OutputPolicyDecision(
            decision=OutputDecisionEnum.REDACT,
            matched_rule="redact-email",
            rationale="Matched output rule 'redact-email': redact email.",
            redacted_output={"content": "contact [REDACTED_EMAIL]"},
        ),
    )

    response = await pipeline.run(_request())

    assert response.output_decision == OutputDecisionEnum.REDACT
    assert response.result == {"content": "contact [REDACTED_EMAIL]"}
    event = pipeline._audit_logger.write.call_args[0][0]
    expected_hash = hashlib.sha256(
        json.dumps(original_output, sort_keys=True).encode()
    ).hexdigest()
    assert event.output_hash == expected_hash
    assert event.output_decision == "REDACT"


@pytest.mark.unit
@pytest.mark.asyncio
async def test_output_approval_required_withholds_result_and_issues_release_token() -> None:
    sensitive_output = {"rows": [{"email": "ceo@example.com"}]}
    pipeline = _make_pipeline(
        tool_output=sensitive_output,
        output_policy_decision=OutputPolicyDecision(
            decision=OutputDecisionEnum.APPROVAL_REQUIRED,
            matched_rule="require-approval-sensitive-egress",
            rationale="Matched output rule 'require-approval-sensitive-egress': review required.",
        ),
        approval_token_result="output-token-123",
    )

    response = await pipeline.run(_request())

    assert response.decision == DecisionEnum.ALLOW
    assert response.output_decision == OutputDecisionEnum.APPROVAL_REQUIRED
    assert response.result is None
    assert response.approval_token == "output-token-123"
    issued_request = pipeline._approval_manager.issue_token.call_args[0][0]
    assert issued_request.scope == ApprovalScope.OUTPUT_RELEASE
    assert issued_request.output_payload == sensitive_output
    assert issued_request.org_id == "acme-prod"


@pytest.mark.unit
@pytest.mark.asyncio
async def test_output_release_token_returns_stored_output_without_reexecution() -> None:
    released_output = {"content": "stored sensitive output"}
    pipeline = _make_pipeline(
        output_release_error=None,
        output_release_payload=released_output,
    )
    req = _request(approval_token="release-token")

    response = await pipeline.run(req)

    assert response.decision == DecisionEnum.ALLOW
    assert response.output_decision == OutputDecisionEnum.ALLOW
    assert response.result == released_output
    pipeline._approval_manager.consume_output_token.assert_called_once()
    pipeline._executor.forward.assert_not_called()
    pipeline._output_policy_engine.evaluate.assert_not_called()
    event = pipeline._audit_logger.write.call_args[0][0]
    assert event.execution_status == "APPROVED_OUTPUT_RELEASE"


@pytest.mark.unit
@pytest.mark.asyncio
async def test_invalid_output_release_token_denies_without_reexecution() -> None:
    pipeline = _make_pipeline(output_release_error=ValueError("used token"))

    response = await pipeline.run(_request(approval_token="bad-token"))

    assert response.decision == DecisionEnum.DENY
    assert response.output_decision == OutputDecisionEnum.DENY
    assert response.result is None
    pipeline._executor.forward.assert_not_called()


@pytest.mark.unit
@pytest.mark.asyncio
async def test_tool_errors_still_write_audit() -> None:
    pipeline = _make_pipeline()
    pipeline._executor.forward = AsyncMock(side_effect=MCPToolError(500, "server error"))

    response = await pipeline.run(_request())

    assert response.result is None
    event = pipeline._audit_logger.write.call_args[0][0]
    assert event.execution_status == "TOOL_ERROR"


@pytest.mark.unit
@pytest.mark.asyncio
async def test_timeout_errors_still_write_audit() -> None:
    pipeline = _make_pipeline()
    pipeline._executor.forward = AsyncMock(side_effect=MCPTimeoutError("timed out"))

    await pipeline.run(_request())

    event = pipeline._audit_logger.write.call_args[0][0]
    assert event.execution_status == "TIMEOUT"


@pytest.mark.unit
@pytest.mark.asyncio
async def test_invalid_api_key_raises_401_without_audit() -> None:
    pipeline = _make_pipeline()
    pipeline._resolve_identity = AsyncMock(  # type: ignore[method-assign]
        side_effect=HTTPException(status_code=401, detail="Invalid or inactive API key")
    )

    with pytest.raises(HTTPException) as exc_info:
        await pipeline.run(_request())

    assert exc_info.value.status_code == 401
    pipeline._audit_logger.write.assert_not_called()


@pytest.mark.unit
@pytest.mark.asyncio
async def test_audit_event_preserves_raw_args_hash_llm_explanation_and_org_id() -> None:
    original_args = {"path": "/tmp/secret.txt", "query": "sensitive data"}
    risk = _high_risk()
    pipeline = _make_pipeline(risk=risk, tool_output={"data": "hello"})

    await pipeline.run(_request(args=original_args))

    event = pipeline._audit_logger.write.call_args[0][0]
    expected_hash = hashlib.sha256(
        json.dumps(original_args, sort_keys=True).encode()
    ).hexdigest()
    assert event.raw_args_hash == expected_hash
    assert event.llm_explanation == risk.explanation
    assert event.org_id == "acme-prod"


@pytest.mark.unit
@pytest.mark.asyncio
async def test_redaction_flags_are_written_to_audit() -> None:
    flag = RedactionFlag(field="path", reason="PII_EMAIL", original_hash="abc123")
    pipeline = _make_pipeline()
    pipeline._argument_guard.sanitize = AsyncMock(
        return_value=({"path": "[REDACTED_EMAIL]"}, [flag])
    )

    await pipeline.run(_request())

    event = pipeline._audit_logger.write.call_args[0][0]
    assert len(event.redaction_flags) == 1
    assert event.redaction_flags[0].reason == "PII_EMAIL"
