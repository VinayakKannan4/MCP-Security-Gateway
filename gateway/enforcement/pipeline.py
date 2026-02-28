"""EnforcementPipeline — orchestrates the 10-step MCP request lifecycle.

Step order:
    1.  validate_ingress     — parse + type-check MCPRequest envelope
    2.  resolve_identity     — lookup CallerIdentity from api_keys table
    3.  validate_schema      — check args against tool schema
    4.  classify_risk        — RiskClassifierAgent (advisory only)
    5.  evaluate_policy      — PolicyEngine.evaluate() ← AUTHORITATIVE
    6.  sanitize_arguments   — ArgumentGuardAgent (skipped if DENY)
    7.  check_approval       — issue / verify approval token (skipped if DENY)
    8.  execute              — MCPExecutor.forward() (skipped if DENY / pending approval)
    9.  write_audit          — AuditLogger.write() ← ALWAYS RUNS (finally block)
    10. build_response       — GatewayResponse

Critical invariants:
    - Step 5 (PolicyEngine) is AUTHORITATIVE. LLM risk score is advisory only.
    - raw_args_hash is SHA-256 of original args — raw args are never stored.
    - write_audit (step 9) runs in a finally block regardless of outcome.
    - DENY skips steps 6–8.
"""

from __future__ import annotations

import hashlib
import json
import logging
import time
from datetime import datetime, timedelta
from typing import Any

import bcrypt
from fastapi import HTTPException
from redis.asyncio import Redis
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from gateway.agents.argument_guard import ArgumentGuardAgent
from gateway.agents.risk_classifier import RiskClassifierAgent
from gateway.approval.manager import ApprovalManager
from gateway.audit.logger import AuditLogger
from gateway.config import Settings
from gateway.db.models import ApiKey
from gateway.enforcement.errors import MCPTimeoutError, MCPToolError
from gateway.enforcement.executor import MCPExecutor
from gateway.models.approval import ApprovalRequest, ApprovalStatus
from gateway.models.audit import AuditEvent, RedactionFlag
from gateway.models.identity import CallerIdentity, TrustLevel
from gateway.models.mcp import GatewayResponse, MCPRequest
from gateway.models.policy import DecisionEnum, PolicyDecision
from gateway.models.risk import RiskAssessment
from gateway.policy.engine import PolicyEngine

logger = logging.getLogger(__name__)

_DEFAULT_RISK = RiskAssessment(
    labels=[],
    score=0.0,
    explanation="Not classified — pipeline did not reach risk assessment step.",
)
_DEFAULT_DECISION = PolicyDecision(
    decision=DecisionEnum.DENY,
    matched_rule="pipeline-error",
    rationale="Pipeline did not complete normally.",
)


class EnforcementPipeline:
    def __init__(
        self,
        settings: Settings,
        db: AsyncSession,
        redis: Redis[str],
        risk_classifier: RiskClassifierAgent,
        argument_guard: ArgumentGuardAgent,
        policy_engine: PolicyEngine,
        audit_logger: AuditLogger,
        approval_manager: ApprovalManager,
        executor: MCPExecutor,
    ) -> None:
        self._settings = settings
        self._db = db
        self._redis = redis
        self._risk_classifier = risk_classifier
        self._argument_guard = argument_guard
        self._policy_engine = policy_engine
        self._audit_logger = audit_logger
        self._approval_manager = approval_manager
        self._executor = executor

    # ------------------------------------------------------------------
    # Public entry point
    # ------------------------------------------------------------------

    async def run(self, request: MCPRequest) -> GatewayResponse:
        """Execute all 10 pipeline steps.

        _write_audit (step 9) runs in the finally block and always executes
        once identity has been resolved (step 2).
        """
        start_time = time.monotonic()

        identity: CallerIdentity | None = None
        risk: RiskAssessment = _DEFAULT_RISK
        decision: PolicyDecision = _DEFAULT_DECISION
        sanitized_args: dict[str, Any] = {}
        redaction_flags: list[RedactionFlag] = []
        tool_output: dict[str, Any] | None = None
        approval_token: str | None = None
        execution_status: str | None = None

        try:
            # Step 1 — validate envelope
            self._validate_ingress(request)

            # Step 2 — resolve caller identity (raises 401 on failure)
            identity = await self._resolve_identity(request)

            # Step 3 — validate tool schema (raises 422 on violation)
            self._validate_schema(request)

            # Step 4 — classify risk (advisory; cannot override policy)
            risk = await self._classify_risk(request)

            # Step 5 — evaluate policy (AUTHORITATIVE)
            decision = self._evaluate_policy(request, identity)

            if decision.decision != DecisionEnum.DENY:
                # Step 6 — sanitize arguments
                sanitized_args, redaction_flags = await self._sanitize_arguments(request)

                if decision.decision == DecisionEnum.APPROVAL_REQUIRED:
                    # Step 7 — check / issue approval token
                    pending_token = await self._check_approval(request, identity, risk)
                    if pending_token is None:
                        # Token approved — fall through to execute
                        tool_output, execution_status = await self._execute_safe(
                            request, sanitized_args
                        )
                    else:
                        # Approval pending — return early (audit still writes via finally)
                        approval_token = pending_token
                else:
                    # Step 8 — execute (ALLOW / SANITIZE_AND_ALLOW)
                    tool_output, execution_status = await self._execute_safe(
                        request, sanitized_args
                    )

        except HTTPException:
            raise  # Let FastAPI handle 401 / 422 — audit still runs if identity is set
        except Exception as exc:
            logger.exception("Unhandled exception in enforcement pipeline: %s", exc)
            decision = PolicyDecision(
                decision=DecisionEnum.DENY,
                matched_rule="pipeline-exception",
                rationale=f"Internal pipeline error: {type(exc).__name__}",
            )

        finally:
            # Step 9 — always write audit once identity is known
            if identity is not None:
                latency_ms = int((time.monotonic() - start_time) * 1000)
                event = AuditEvent(
                    request_id=request.request_id,
                    trace_id=request.trace_id,
                    timestamp=datetime.utcnow(),
                    caller_id=identity.caller_id,
                    caller_role=identity.role,
                    environment=identity.environment,
                    mcp_server=request.tool_call.server,
                    tool_name=request.tool_call.tool,
                    raw_args_hash=hashlib.sha256(
                        json.dumps(request.tool_call.arguments, sort_keys=True).encode()
                    ).hexdigest(),
                    sanitized_args=sanitized_args,
                    risk_labels=[label.value for label in risk.labels],
                    risk_score=risk.score,
                    matched_policy_rule=decision.matched_rule,
                    decision=decision.decision.value,
                    latency_ms=latency_ms,
                    redaction_flags=redaction_flags,
                    deterministic_rationale=decision.rationale,
                    execution_status=execution_status,
                    llm_explanation=risk.explanation if risk.llm_consulted else None,
                )
                await self._audit_logger.write(event)

        # Step 10 — build response
        latency_ms = int((time.monotonic() - start_time) * 1000)
        return GatewayResponse(
            request_id=request.request_id,
            decision=decision.decision,
            result=tool_output,
            sanitized_args=sanitized_args if decision.decision != DecisionEnum.DENY else None,
            approval_token=approval_token,
            policy_explanation=decision.rationale,
            risk_labels=[label.value for label in risk.labels],
            latency_ms=latency_ms,
        )

    # ------------------------------------------------------------------
    # Pipeline step implementations
    # ------------------------------------------------------------------

    def _validate_ingress(self, request: MCPRequest) -> None:
        """Step 1 — validate the MCPRequest envelope."""
        if not request.tool_call.tool:
            raise HTTPException(status_code=422, detail="tool_call.tool must be non-empty")
        if not request.tool_call.server:
            raise HTTPException(status_code=422, detail="tool_call.server must be non-empty")

    async def _resolve_identity(self, request: MCPRequest) -> CallerIdentity:
        """Step 2 — verify API key and return CallerIdentity.

        Queries all active api_keys rows and bcrypt-compares the provided key.
        Raises HTTPException(401) if the key is invalid or inactive.
        """
        result = await self._db.execute(select(ApiKey).where(ApiKey.is_active == True))  # noqa: E712
        rows = result.scalars().all()

        for row in rows:
            if bcrypt.checkpw(request.api_key.encode(), row.key_hash.encode()):
                return CallerIdentity(
                    caller_id=row.caller_id,
                    role=row.role,
                    trust_level=TrustLevel(row.trust_level),
                    environment=row.environment,
                    api_key_id=row.id,
                )

        raise HTTPException(status_code=401, detail="Invalid or inactive API key")

    def _validate_schema(self, request: MCPRequest) -> None:
        """Step 3 — validate tool arguments against the policy schema."""
        valid, violations = self._policy_engine.validate_tool_schema(request)
        if not valid:
            raise HTTPException(
                status_code=422,
                detail=f"Tool schema validation failed: {'; '.join(violations)}",
            )

    async def _classify_risk(self, request: MCPRequest) -> RiskAssessment:
        """Step 4 — classify risk (advisory; cannot override policy)."""
        return await self._risk_classifier.classify(
            request.tool_call, context=request.context
        )

    def _evaluate_policy(
        self, request: MCPRequest, identity: CallerIdentity
    ) -> PolicyDecision:
        """Step 5 — evaluate policy. AUTHORITATIVE — cannot be overridden."""
        return self._policy_engine.evaluate(request, identity)

    async def _sanitize_arguments(
        self, request: MCPRequest
    ) -> tuple[dict[str, Any], list[RedactionFlag]]:
        """Step 6 — sanitize arguments via ArgumentGuardAgent."""
        return await self._argument_guard.sanitize(request.tool_call)

    async def _check_approval(
        self,
        request: MCPRequest,
        identity: CallerIdentity,
        risk: RiskAssessment,
    ) -> str | None:
        """Step 7 — check or issue an approval token.

        Returns:
            None  — existing token is APPROVED; proceed to execution.
            str   — new (or existing PENDING) token; caller should return early.
        """
        if request.approval_token:
            try:
                result = await self._approval_manager.check_token(request.approval_token)
                if result.status == ApprovalStatus.APPROVED:
                    return None  # Approved — continue to execute
            except ValueError:
                pass  # Token not found; fall through to issue a new one

        # Issue a new approval request
        now = datetime.utcnow()
        approval_req = ApprovalRequest(
            request_id=request.request_id,
            caller_id=identity.caller_id,
            tool_call=request.tool_call,
            risk_explanation=risk.explanation,
            created_at=now,
            expires_at=now + timedelta(seconds=self._settings.approval_token_ttl_seconds),
        )
        return await self._approval_manager.issue_token(approval_req)

    async def _execute_safe(
        self,
        request: MCPRequest,
        sanitized_args: dict[str, Any],
    ) -> tuple[dict[str, Any] | None, str]:
        """Step 8 — execute the tool call. Returns (output, execution_status).

        MCPToolError and MCPTimeoutError are caught here so audit always writes.
        """
        try:
            output = await self._executor.forward(
                request.tool_call.server,
                request.tool_call.tool,
                sanitized_args,
            )
            return output, "SUCCESS"
        except MCPToolError:
            return None, "TOOL_ERROR"
        except MCPTimeoutError:
            return None, "TIMEOUT"
