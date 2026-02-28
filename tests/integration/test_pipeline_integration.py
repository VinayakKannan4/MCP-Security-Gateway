"""Integration tests for EnforcementPipeline.

Requires Docker test stack:
    docker compose -f docker-compose.test.yml up -d
    DATABASE_URL="postgresql+asyncpg://gateway:gateway@localhost:5433/gateway_test" \\
        uv run alembic upgrade head

Covers:
- Full ALLOW flow: audit event persisted to DB with decision="ALLOW"
- Full DENY flow: audit event persisted with decision="DENY", no tool execution
- APPROVAL_REQUIRED: token written to Redis + Postgres; subsequent approved request executes
"""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock

import bcrypt
import pytest
import pytest_asyncio
from redis.asyncio import Redis
from sqlalchemy.ext.asyncio import AsyncSession

from gateway.approval.manager import ApprovalManager
from gateway.audit.logger import AuditLogger
from gateway.audit.query import AuditQuery
from gateway.config import Settings
from gateway.db.models import ApiKey
from gateway.enforcement.pipeline import EnforcementPipeline
from gateway.models.approval import ApprovalStatus
from gateway.models.identity import CallerIdentity, TrustLevel
from gateway.models.mcp import MCPRequest, ToolCall
from gateway.models.policy import DecisionEnum, PolicyDecision
from gateway.models.risk import RiskAssessment

# ---------------------------------------------------------------------------
# Shared test config
# ---------------------------------------------------------------------------

TEST_API_KEY = "integration-test-key-abc123"
TEST_CALLER_ID = "integration-test-caller"


def _settings() -> Settings:
    return Settings(
        environment="prod",
        database_url="postgresql+asyncpg://gateway:gateway@localhost:5433/gateway_test",
        redis_url="redis://localhost:6380/0",
        admin_api_key="test-admin",
        approval_token_ttl_seconds=60,
    )


def _tool_call(args: dict | None = None) -> ToolCall:  # type: ignore[type-arg]
    return ToolCall(server="test-mcp", tool="fs.read", arguments=args or {"path": "/tmp/f.txt"})


def _request(approval_token: str | None = None) -> MCPRequest:
    return MCPRequest(
        caller_id=TEST_CALLER_ID,
        api_key=TEST_API_KEY,
        environment="prod",
        tool_call=_tool_call(),
        approval_token=approval_token,
    )


def _safe_risk() -> RiskAssessment:
    return RiskAssessment(labels=[], score=0.0, explanation="Safe", llm_consulted=False)


# ---------------------------------------------------------------------------
# Fixtures — seed an API key row so _resolve_identity can verify it
# ---------------------------------------------------------------------------


@pytest_asyncio.fixture
async def seeded_api_key(db_session: AsyncSession) -> ApiKey:
    """Insert a test API key into the DB for _resolve_identity to find."""
    hashed = bcrypt.hashpw(TEST_API_KEY.encode(), bcrypt.gensalt()).decode()
    row = ApiKey(
        caller_id=TEST_CALLER_ID,
        key_hash=hashed,
        role="developer",
        trust_level=TrustLevel.HIGH.value,
        environment="prod",
        is_active=True,
    )
    db_session.add(row)
    await db_session.commit()
    return row


def _build_pipeline(
    db_session: AsyncSession,
    redis_client: Redis,  # type: ignore[type-arg]
    decision: PolicyDecision,
    tool_output: dict | None = None,  # type: ignore[type-arg]
) -> EnforcementPipeline:
    """Build a pipeline with mocked agents but real DB + Redis."""
    settings = _settings()

    risk_classifier = AsyncMock()
    risk_classifier.classify = AsyncMock(return_value=_safe_risk())

    argument_guard = AsyncMock()
    argument_guard.sanitize = AsyncMock(return_value=({"path": "/tmp/f.txt"}, []))

    policy_engine = MagicMock()
    policy_engine.validate_tool_schema = MagicMock(return_value=(True, []))
    policy_engine.evaluate = MagicMock(return_value=decision)

    audit_logger = AuditLogger(db_session)
    approval_manager = ApprovalManager(session=db_session, redis=redis_client)

    executor = AsyncMock()
    executor.forward = AsyncMock(return_value=tool_output or {"content": "file data"})

    return EnforcementPipeline(
        settings=settings,
        db=db_session,
        redis=redis_client,
        risk_classifier=risk_classifier,
        argument_guard=argument_guard,
        policy_engine=policy_engine,
        audit_logger=audit_logger,
        approval_manager=approval_manager,
        executor=executor,
    )


# ---------------------------------------------------------------------------
# ALLOW flow
# ---------------------------------------------------------------------------


@pytest.mark.integration
@pytest.mark.asyncio
async def test_allow_flow_persists_audit_event(
    db_session: AsyncSession,
    redis_client: Redis,  # type: ignore[type-arg]
    seeded_api_key: ApiKey,
) -> None:
    decision = PolicyDecision(
        decision=DecisionEnum.ALLOW,
        matched_rule="allow-developer",
        rationale="Developer allow",
    )
    pipeline = _build_pipeline(db_session, redis_client, decision, tool_output={"data": "ok"})
    req = _request()

    response = await pipeline.run(req)

    assert response.decision == DecisionEnum.ALLOW
    assert response.result == {"data": "ok"}

    # Verify audit event persisted to DB
    query = AuditQuery(db_session)
    event = await query.get_by_request_id(req.request_id)
    assert event is not None
    assert event.decision == "ALLOW"
    assert event.caller_id == TEST_CALLER_ID
    assert event.execution_status == "SUCCESS"


# ---------------------------------------------------------------------------
# DENY flow
# ---------------------------------------------------------------------------


@pytest.mark.integration
@pytest.mark.asyncio
async def test_deny_flow_persists_audit_event(
    db_session: AsyncSession,
    redis_client: Redis,  # type: ignore[type-arg]
    seeded_api_key: ApiKey,
) -> None:
    decision = PolicyDecision(
        decision=DecisionEnum.DENY,
        matched_rule="catch-all-deny",
        rationale="No matching rule",
    )
    pipeline = _build_pipeline(db_session, redis_client, decision)
    req = _request()

    response = await pipeline.run(req)

    assert response.decision == DecisionEnum.DENY
    assert response.result is None
    pipeline._executor.forward.assert_not_called()  # type: ignore[attr-defined]

    # Verify audit event persisted
    query = AuditQuery(db_session)
    event = await query.get_by_request_id(req.request_id)
    assert event is not None
    assert event.decision == "DENY"
    assert event.execution_status is None


# ---------------------------------------------------------------------------
# APPROVAL_REQUIRED flow
# ---------------------------------------------------------------------------


@pytest.mark.integration
@pytest.mark.asyncio
async def test_approval_required_token_written_to_redis_and_postgres(
    db_session: AsyncSession,
    redis_client: Redis,  # type: ignore[type-arg]
    seeded_api_key: ApiKey,
) -> None:
    decision = PolicyDecision(
        decision=DecisionEnum.APPROVAL_REQUIRED,
        matched_rule="approval-rule",
        rationale="Requires approval",
        requires_approval=True,
    )
    pipeline = _build_pipeline(db_session, redis_client, decision)
    req = _request()

    response = await pipeline.run(req)

    assert response.decision == DecisionEnum.APPROVAL_REQUIRED
    assert response.approval_token is not None
    pipeline._executor.forward.assert_not_called()  # type: ignore[attr-defined]

    # Token should be in Redis
    from gateway.cache.redis_client import get_json
    data = await get_json(redis_client, f"approval:{response.approval_token}")
    assert data is not None
    assert data["status"] == "PENDING"

    # Token should be in Postgres
    approval_manager = ApprovalManager(session=db_session, redis=redis_client)
    result = await approval_manager.check_token(response.approval_token)
    assert result.status == ApprovalStatus.PENDING


@pytest.mark.integration
@pytest.mark.asyncio
async def test_approval_required_then_approved_executes(
    db_session: AsyncSession,
    redis_client: Redis,  # type: ignore[type-arg]
    seeded_api_key: ApiKey,
) -> None:
    """Simulate the full approval workflow: issue token → approve → re-invoke."""
    decision = PolicyDecision(
        decision=DecisionEnum.APPROVAL_REQUIRED,
        matched_rule="approval-rule",
        rationale="Requires approval",
        requires_approval=True,
    )
    pipeline = _build_pipeline(db_session, redis_client, decision, tool_output={"file": "data"})

    # First request — no token → issued
    req1 = _request()
    response1 = await pipeline.run(req1)
    assert response1.approval_token is not None
    token = response1.approval_token

    # Approve the token
    approval_manager = ApprovalManager(session=db_session, redis=redis_client)
    await approval_manager.approve(token, approver_id="admin-user")

    # Second request — with approved token → executes
    req2 = _request(approval_token=token)
    response2 = await pipeline.run(req2)

    assert response2.result == {"file": "data"}
    pipeline._executor.forward.assert_called_once()  # type: ignore[attr-defined]
