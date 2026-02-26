"""Integration tests for ApprovalManager against real Redis + Postgres."""

from datetime import datetime, timedelta

import pytest
from redis.asyncio import Redis

from gateway.approval.manager import ApprovalManager
from gateway.cache.redis_client import get_json
from gateway.models.approval import ApprovalRequest, ApprovalStatus
from gateway.models.mcp import ToolCall


def make_approval_request(request_id: str = "req-approval-integ-001") -> ApprovalRequest:
    now = datetime(2026, 2, 24, 12, 0, 0)
    return ApprovalRequest(
        request_id=request_id,
        caller_id="integ-agent",
        tool_call=ToolCall(
            server="filesystem-mcp",
            tool="fs.write",
            arguments={"path": "/data/output.csv"},
        ),
        risk_explanation="High-risk write — requires approval",
        created_at=now,
        expires_at=now + timedelta(hours=1),
    )


# ---------------------------------------------------------------------------
# issue_token
# ---------------------------------------------------------------------------


@pytest.mark.integration
async def test_issue_token_stores_in_redis(
    approval_manager: ApprovalManager, redis_client: Redis
) -> None:
    request = make_approval_request("req-issue-redis-001")
    token = await approval_manager.issue_token(request)

    data = await get_json(redis_client, f"approval:{token}")
    assert data is not None
    assert data["status"] == "PENDING"
    assert data["token"] == token


@pytest.mark.integration
async def test_issue_token_sets_redis_ttl(
    approval_manager: ApprovalManager, redis_client: Redis
) -> None:
    request = make_approval_request("req-issue-ttl-001")
    token = await approval_manager.issue_token(request)

    ttl = await redis_client.ttl(f"approval:{token}")
    assert ttl > 0


# ---------------------------------------------------------------------------
# check_token — Redis fast path
# ---------------------------------------------------------------------------


@pytest.mark.integration
async def test_check_token_redis_fast_path(
    approval_manager: ApprovalManager,
) -> None:
    request = make_approval_request("req-check-redis-001")
    token = await approval_manager.issue_token(request)

    result = await approval_manager.check_token(token)

    assert result.token == token
    assert result.status == ApprovalStatus.PENDING


# ---------------------------------------------------------------------------
# check_token — Postgres fallback
# ---------------------------------------------------------------------------


@pytest.mark.integration
async def test_check_token_postgres_fallback(
    approval_manager: ApprovalManager, redis_client: Redis
) -> None:
    request = make_approval_request("req-check-pg-001")
    token = await approval_manager.issue_token(request)

    # Manually evict the Redis key to force Postgres fallback
    await redis_client.delete(f"approval:{token}")
    assert await get_json(redis_client, f"approval:{token}") is None

    result = await approval_manager.check_token(token)

    assert result.token == token
    assert result.status == ApprovalStatus.PENDING


@pytest.mark.integration
async def test_check_token_raises_for_unknown_token(
    approval_manager: ApprovalManager,
) -> None:
    with pytest.raises(ValueError, match="not found"):
        await approval_manager.check_token("completely-unknown-token")


# ---------------------------------------------------------------------------
# approve
# ---------------------------------------------------------------------------


@pytest.mark.integration
async def test_approve_returns_approved_result(
    approval_manager: ApprovalManager,
) -> None:
    request = make_approval_request("req-approve-001")
    token = await approval_manager.issue_token(request)

    result = await approval_manager.approve(token, approver_id="admin-1", note="LGTM")

    assert result.status == ApprovalStatus.APPROVED
    assert result.approver_id == "admin-1"
    assert result.note == "LGTM"
    assert result.decided_at is not None


@pytest.mark.integration
async def test_approve_invalidates_redis_key(
    approval_manager: ApprovalManager, redis_client: Redis
) -> None:
    request = make_approval_request("req-approve-redis-001")
    token = await approval_manager.issue_token(request)
    assert await get_json(redis_client, f"approval:{token}") is not None

    await approval_manager.approve(token, approver_id="admin-1")

    assert await get_json(redis_client, f"approval:{token}") is None


@pytest.mark.integration
async def test_approve_decision_persisted_in_postgres(
    approval_manager: ApprovalManager, redis_client: Redis
) -> None:
    """After approve + Redis eviction, check_token reads APPROVED from Postgres."""
    request = make_approval_request("req-approve-pg-001")
    token = await approval_manager.issue_token(request)
    await approval_manager.approve(token, approver_id="admin-1")

    # Redis key was deleted by approve — Postgres is the only source now
    result = await approval_manager.check_token(token)
    assert result.status == ApprovalStatus.APPROVED
    assert result.approver_id == "admin-1"


@pytest.mark.integration
async def test_approve_already_approved_raises(
    approval_manager: ApprovalManager,
) -> None:
    request = make_approval_request("req-double-approve-001")
    token = await approval_manager.issue_token(request)
    await approval_manager.approve(token, approver_id="admin-1")

    with pytest.raises(ValueError, match="already decided"):
        await approval_manager.approve(token, approver_id="admin-1")


# ---------------------------------------------------------------------------
# deny
# ---------------------------------------------------------------------------


@pytest.mark.integration
async def test_deny_returns_denied_result(
    approval_manager: ApprovalManager,
) -> None:
    request = make_approval_request("req-deny-001")
    token = await approval_manager.issue_token(request)

    result = await approval_manager.deny(token, approver_id="admin-2", note="Too risky")

    assert result.status == ApprovalStatus.DENIED
    assert result.approver_id == "admin-2"
    assert result.note == "Too risky"


@pytest.mark.integration
async def test_deny_decision_persisted_in_postgres(
    approval_manager: ApprovalManager,
) -> None:
    request = make_approval_request("req-deny-pg-001")
    token = await approval_manager.issue_token(request)
    await approval_manager.deny(token, approver_id="admin-2")

    result = await approval_manager.check_token(token)
    assert result.status == ApprovalStatus.DENIED


@pytest.mark.integration
async def test_deny_already_denied_raises(
    approval_manager: ApprovalManager,
) -> None:
    request = make_approval_request("req-double-deny-001")
    token = await approval_manager.issue_token(request)
    await approval_manager.deny(token, approver_id="admin-2")

    with pytest.raises(ValueError, match="already decided"):
        await approval_manager.deny(token, approver_id="admin-2")
