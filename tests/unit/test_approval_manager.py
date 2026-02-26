"""Unit tests for gateway/approval/manager.py and gateway/approval/notifier.py.

Uses fakeredis for Redis and a mocked AsyncSession for Postgres.
No real infrastructure required.
"""

import logging
from datetime import datetime, timedelta
from unittest.mock import AsyncMock, MagicMock

import fakeredis.aioredis
import pytest

from gateway.approval.manager import ApprovalManager
from gateway.approval.notifier import ApprovalNotifier
from gateway.cache.redis_client import get_json
from gateway.db.models import ApprovalRequestRow
from gateway.models.approval import ApprovalRequest, ApprovalResult, ApprovalStatus
from gateway.models.mcp import ToolCall


# ---------------------------------------------------------------------------
# Helpers / fixtures
# ---------------------------------------------------------------------------


def make_tool_call() -> ToolCall:
    return ToolCall(server="filesystem-mcp", tool="fs.write", arguments={"path": "/data/out.csv"})


def make_approval_request(**overrides: object) -> ApprovalRequest:
    now = datetime(2026, 2, 24, 12, 0, 0)
    defaults: dict[str, object] = {
        "request_id": "req-approval-001",
        "caller_id": "agent-x",
        "tool_call": make_tool_call(),
        "risk_explanation": "High-risk write operation requires human sign-off",
        "created_at": now,
        "expires_at": now + timedelta(hours=1),
    }
    defaults.update(overrides)
    return ApprovalRequest(**defaults)  # type: ignore[arg-type]


def make_approval_request_row(
    request: ApprovalRequest, status: str = "PENDING"
) -> ApprovalRequestRow:
    return ApprovalRequestRow(
        token=request.token,
        request_id=request.request_id,
        caller_id=request.caller_id,
        tool_call=request.tool_call.model_dump(),
        risk_explanation=request.risk_explanation,
        created_at=request.created_at,
        expires_at=request.expires_at,
        status=status,
        approver_id=None,
        decision_at=None,
        approver_note=None,
    )


@pytest.fixture
async def redis() -> fakeredis.aioredis.FakeRedis:  # type: ignore[misc]
    client = fakeredis.aioredis.FakeRedis(decode_responses=True)
    yield client
    await client.aclose()


@pytest.fixture
def mock_session() -> MagicMock:
    session = MagicMock()
    session.add = MagicMock()
    session.commit = AsyncMock()
    session.execute = AsyncMock()
    return session


# ---------------------------------------------------------------------------
# issue_token
# ---------------------------------------------------------------------------


@pytest.mark.unit
async def test_issue_token_returns_token(mock_session: MagicMock, redis: fakeredis.aioredis.FakeRedis) -> None:
    request = make_approval_request()
    token = await ApprovalManager(mock_session, redis).issue_token(request)
    assert token == request.token


@pytest.mark.unit
async def test_issue_token_stores_in_redis(mock_session: MagicMock, redis: fakeredis.aioredis.FakeRedis) -> None:
    request = make_approval_request()
    token = await ApprovalManager(mock_session, redis).issue_token(request)

    data = await get_json(redis, f"approval:{token}")
    assert data is not None
    assert data["status"] == "PENDING"
    assert data["token"] == token
    assert data["request_id"] == request.request_id


@pytest.mark.unit
async def test_issue_token_sets_redis_ttl(mock_session: MagicMock, redis: fakeredis.aioredis.FakeRedis) -> None:
    request = make_approval_request()
    token = await ApprovalManager(mock_session, redis).issue_token(request)

    ttl = await redis.ttl(f"approval:{token}")
    assert ttl > 0


@pytest.mark.unit
async def test_issue_token_stores_in_postgres(mock_session: MagicMock, redis: fakeredis.aioredis.FakeRedis) -> None:
    request = make_approval_request()
    await ApprovalManager(mock_session, redis).issue_token(request)

    mock_session.add.assert_called_once()
    added = mock_session.add.call_args[0][0]
    assert isinstance(added, ApprovalRequestRow)
    assert added.token == request.token
    assert added.status == "PENDING"
    assert added.caller_id == request.caller_id


@pytest.mark.unit
async def test_issue_token_commits_to_postgres(mock_session: MagicMock, redis: fakeredis.aioredis.FakeRedis) -> None:
    request = make_approval_request()
    await ApprovalManager(mock_session, redis).issue_token(request)
    mock_session.commit.assert_awaited_once()


@pytest.mark.unit
async def test_issue_token_serializes_tool_call_as_dict(mock_session: MagicMock, redis: fakeredis.aioredis.FakeRedis) -> None:
    request = make_approval_request()
    await ApprovalManager(mock_session, redis).issue_token(request)

    added: ApprovalRequestRow = mock_session.add.call_args[0][0]
    assert isinstance(added.tool_call, dict)
    assert added.tool_call["tool"] == "fs.write"
    assert added.tool_call["server"] == "filesystem-mcp"


# ---------------------------------------------------------------------------
# check_token — Redis fast path
# ---------------------------------------------------------------------------


@pytest.mark.unit
async def test_check_token_redis_fast_path(mock_session: MagicMock, redis: fakeredis.aioredis.FakeRedis) -> None:
    """check_token should return from Redis without hitting Postgres."""
    request = make_approval_request()
    await ApprovalManager(mock_session, redis).issue_token(request)

    # Reset execute mock so we can assert it was NOT called
    mock_session.execute = AsyncMock()

    result = await ApprovalManager(mock_session, redis).check_token(request.token)

    assert result.token == request.token
    assert result.status == ApprovalStatus.PENDING
    mock_session.execute.assert_not_awaited()


# ---------------------------------------------------------------------------
# check_token — Postgres fallback
# ---------------------------------------------------------------------------


@pytest.mark.unit
async def test_check_token_postgres_fallback_when_redis_miss(mock_session: MagicMock, redis: fakeredis.aioredis.FakeRedis) -> None:
    """check_token falls back to Postgres when key is not in Redis."""
    request = make_approval_request()
    row = make_approval_request_row(request)
    mock_result = MagicMock()
    mock_result.scalar_one_or_none.return_value = row
    mock_session.execute = AsyncMock(return_value=mock_result)

    # Nothing stored in Redis — Postgres fallback should kick in
    result = await ApprovalManager(mock_session, redis).check_token(request.token)

    assert result.token == request.token
    assert result.status == ApprovalStatus.PENDING
    mock_session.execute.assert_awaited_once()


@pytest.mark.unit
async def test_check_token_raises_for_unknown_token(mock_session: MagicMock, redis: fakeredis.aioredis.FakeRedis) -> None:
    mock_result = MagicMock()
    mock_result.scalar_one_or_none.return_value = None
    mock_session.execute = AsyncMock(return_value=mock_result)

    with pytest.raises(ValueError, match="not found"):
        await ApprovalManager(mock_session, redis).check_token("no-such-token")


# ---------------------------------------------------------------------------
# approve
# ---------------------------------------------------------------------------


@pytest.mark.unit
async def test_approve_returns_approved_result(mock_session: MagicMock, redis: fakeredis.aioredis.FakeRedis) -> None:
    request = make_approval_request()
    row = make_approval_request_row(request, status="PENDING")

    select_mock = MagicMock()
    select_mock.scalar_one_or_none.return_value = row
    update_mock = MagicMock()
    mock_session.execute = AsyncMock(side_effect=[select_mock, update_mock])

    result = await ApprovalManager(mock_session, redis).approve(
        request.token, approver_id="admin-1", note="Looks good"
    )

    assert result.status == ApprovalStatus.APPROVED
    assert result.approver_id == "admin-1"
    assert result.note == "Looks good"
    assert result.decided_at is not None


@pytest.mark.unit
async def test_approve_commits_postgres(mock_session: MagicMock, redis: fakeredis.aioredis.FakeRedis) -> None:
    request = make_approval_request()
    row = make_approval_request_row(request)

    select_mock = MagicMock()
    select_mock.scalar_one_or_none.return_value = row
    mock_session.execute = AsyncMock(side_effect=[select_mock, MagicMock()])

    await ApprovalManager(mock_session, redis).approve(request.token, approver_id="admin-1")

    mock_session.commit.assert_awaited_once()


@pytest.mark.unit
async def test_approve_invalidates_redis_cache(mock_session: MagicMock, redis: fakeredis.aioredis.FakeRedis) -> None:
    """After approve, the Redis key should be deleted so Postgres is authoritative."""
    request = make_approval_request()
    # Pre-store token in Redis
    await ApprovalManager(mock_session, redis).issue_token(request)
    assert await get_json(redis, f"approval:{request.token}") is not None

    # Now approve — should delete the Redis key
    row = make_approval_request_row(request)
    select_mock = MagicMock()
    select_mock.scalar_one_or_none.return_value = row
    mock_session.execute = AsyncMock(side_effect=[select_mock, MagicMock()])

    await ApprovalManager(mock_session, redis).approve(request.token, approver_id="admin-1")

    assert await get_json(redis, f"approval:{request.token}") is None


@pytest.mark.unit
async def test_approve_already_decided_raises(mock_session: MagicMock, redis: fakeredis.aioredis.FakeRedis) -> None:
    request = make_approval_request()
    row = make_approval_request_row(request, status="APPROVED")  # already decided

    mock_result = MagicMock()
    mock_result.scalar_one_or_none.return_value = row
    mock_session.execute = AsyncMock(return_value=mock_result)

    with pytest.raises(ValueError, match="already decided"):
        await ApprovalManager(mock_session, redis).approve(request.token, approver_id="admin-1")


@pytest.mark.unit
async def test_approve_unknown_token_raises(mock_session: MagicMock, redis: fakeredis.aioredis.FakeRedis) -> None:
    mock_result = MagicMock()
    mock_result.scalar_one_or_none.return_value = None
    mock_session.execute = AsyncMock(return_value=mock_result)

    with pytest.raises(ValueError, match="not found"):
        await ApprovalManager(mock_session, redis).approve("ghost-token", approver_id="admin-1")


# ---------------------------------------------------------------------------
# deny
# ---------------------------------------------------------------------------


@pytest.mark.unit
async def test_deny_returns_denied_result(mock_session: MagicMock, redis: fakeredis.aioredis.FakeRedis) -> None:
    request = make_approval_request()
    row = make_approval_request_row(request, status="PENDING")

    select_mock = MagicMock()
    select_mock.scalar_one_or_none.return_value = row
    mock_session.execute = AsyncMock(side_effect=[select_mock, MagicMock()])

    result = await ApprovalManager(mock_session, redis).deny(
        request.token, approver_id="admin-2", note="Too risky"
    )

    assert result.status == ApprovalStatus.DENIED
    assert result.approver_id == "admin-2"
    assert result.note == "Too risky"


@pytest.mark.unit
async def test_deny_invalidates_redis_cache(mock_session: MagicMock, redis: fakeredis.aioredis.FakeRedis) -> None:
    request = make_approval_request()
    await ApprovalManager(mock_session, redis).issue_token(request)

    row = make_approval_request_row(request)
    select_mock = MagicMock()
    select_mock.scalar_one_or_none.return_value = row
    mock_session.execute = AsyncMock(side_effect=[select_mock, MagicMock()])

    await ApprovalManager(mock_session, redis).deny(request.token, approver_id="admin-2")

    assert await get_json(redis, f"approval:{request.token}") is None


@pytest.mark.unit
async def test_deny_already_denied_raises(mock_session: MagicMock, redis: fakeredis.aioredis.FakeRedis) -> None:
    request = make_approval_request()
    row = make_approval_request_row(request, status="DENIED")

    mock_result = MagicMock()
    mock_result.scalar_one_or_none.return_value = row
    mock_session.execute = AsyncMock(return_value=mock_result)

    with pytest.raises(ValueError, match="already decided"):
        await ApprovalManager(mock_session, redis).deny(request.token, approver_id="admin-2")


# ---------------------------------------------------------------------------
# ApprovalNotifier — token never logged
# ---------------------------------------------------------------------------


@pytest.mark.unit
async def test_notify_pending_does_not_log_token(caplog: pytest.LogCaptureFixture) -> None:
    request = make_approval_request()
    notifier = ApprovalNotifier()

    with caplog.at_level(logging.INFO, logger="gateway.approval.notifier"):
        await notifier.notify_pending(request)

    assert request.token not in caplog.text
    assert "APPROVAL_REQUIRED" in caplog.text
    assert request.request_id in caplog.text


@pytest.mark.unit
async def test_notify_decision_does_not_log_token(caplog: pytest.LogCaptureFixture) -> None:
    result = ApprovalResult(
        token="super-secret-token",
        status=ApprovalStatus.APPROVED,
        approver_id="admin-1",
    )
    notifier = ApprovalNotifier()

    with caplog.at_level(logging.INFO, logger="gateway.approval.notifier"):
        await notifier.notify_decision(result)

    assert "super-secret-token" not in caplog.text
    assert "APPROVAL_DECIDED" in caplog.text
