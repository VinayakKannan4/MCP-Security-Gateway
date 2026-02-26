"""Unit tests for gateway/audit/logger.py and gateway/audit/query.py.

All tests use mocked AsyncSession — no real DB required.
"""

from datetime import datetime
from unittest.mock import AsyncMock, MagicMock, call

import pytest

from gateway.audit.logger import AuditLogger
from gateway.audit.query import AuditQuery, _row_to_event
from gateway.db.models import AuditEventRow
from gateway.models.audit import AuditEvent, RedactionFlag


# ---------------------------------------------------------------------------
# Helpers / fixtures
# ---------------------------------------------------------------------------


def make_audit_event(**overrides: object) -> AuditEvent:
    defaults: dict[str, object] = {
        "request_id": "req-test-001",
        "trace_id": None,
        "timestamp": datetime(2026, 2, 24, 12, 0, 0),
        "caller_id": "test-caller",
        "caller_role": "developer",
        "environment": "dev",
        "mcp_server": "filesystem-mcp",
        "tool_name": "fs.read",
        "raw_args_hash": "a" * 64,  # 64-char fake SHA-256 hex
        "sanitized_args": {"path": "/data/report.csv"},
        "risk_labels": ["LOW_READONLY"],
        "risk_score": 0.1,
        "matched_policy_rule": "developer-read-dev",
        "decision": "ALLOW",
        "approver_id": None,
        "execution_status": "SUCCESS",
        "latency_ms": 42,
        "output_hash": None,
        "redaction_flags": [],
        "llm_explanation": None,
        "deterministic_rationale": "Matched developer-read-dev rule",
    }
    defaults.update(overrides)
    return AuditEvent(**defaults)  # type: ignore[arg-type]


def make_audit_event_row(event: AuditEvent) -> AuditEventRow:
    """Build an ORM row with the same data as a Pydantic AuditEvent (for query mocks)."""
    row = AuditEventRow(
        request_id=event.request_id,
        trace_id=event.trace_id,
        timestamp=event.timestamp,
        caller_id=event.caller_id,
        caller_role=event.caller_role,
        environment=event.environment,
        mcp_server=event.mcp_server,
        tool_name=event.tool_name,
        raw_args_hash=event.raw_args_hash,
        sanitized_args=event.sanitized_args,
        risk_labels=list(event.risk_labels),
        risk_score=event.risk_score,
        matched_policy_rule=event.matched_policy_rule,
        decision=event.decision,
        approver_id=event.approver_id,
        execution_status=event.execution_status,
        latency_ms=event.latency_ms,
        output_hash=event.output_hash,
        redaction_flags=[f.model_dump() for f in event.redaction_flags],
        llm_explanation=event.llm_explanation,
        deterministic_rationale=event.deterministic_rationale,
    )
    return row


@pytest.fixture
def mock_session() -> MagicMock:
    session = MagicMock()
    session.add = MagicMock()
    session.commit = AsyncMock()
    session.execute = AsyncMock()
    return session


# ---------------------------------------------------------------------------
# AuditLogger.write()
# ---------------------------------------------------------------------------


@pytest.mark.unit
async def test_write_calls_session_add(mock_session: MagicMock) -> None:
    event = make_audit_event()
    await AuditLogger(mock_session).write(event)
    mock_session.add.assert_called_once()
    added = mock_session.add.call_args[0][0]
    assert isinstance(added, AuditEventRow)


@pytest.mark.unit
async def test_write_calls_session_commit(mock_session: MagicMock) -> None:
    event = make_audit_event()
    await AuditLogger(mock_session).write(event)
    mock_session.commit.assert_awaited_once()


@pytest.mark.unit
async def test_write_stores_raw_args_hash_not_raw_args(mock_session: MagicMock) -> None:
    event = make_audit_event(raw_args_hash="b" * 64)
    await AuditLogger(mock_session).write(event)
    added: AuditEventRow = mock_session.add.call_args[0][0]
    assert added.raw_args_hash == "b" * 64
    # The ORM row has no "raw_args" attribute — only the hash
    assert not hasattr(added, "raw_args")


@pytest.mark.unit
async def test_write_serializes_redaction_flags_to_dicts(mock_session: MagicMock) -> None:
    flags = [
        RedactionFlag(field="email", reason="PII_EMAIL", original_hash="c" * 64),
        RedactionFlag(field="token", reason="SECRET_TOKEN", original_hash="d" * 64),
    ]
    event = make_audit_event(redaction_flags=flags)
    await AuditLogger(mock_session).write(event)
    added: AuditEventRow = mock_session.add.call_args[0][0]
    assert added.redaction_flags == [
        {"field": "email", "reason": "PII_EMAIL", "original_hash": "c" * 64},
        {"field": "token", "reason": "SECRET_TOKEN", "original_hash": "d" * 64},
    ]


@pytest.mark.unit
async def test_write_maps_all_scalar_fields(mock_session: MagicMock) -> None:
    event = make_audit_event(
        caller_id="agent-x",
        tool_name="sql.query",
        decision="DENY",
        latency_ms=99,
        risk_score=0.95,
    )
    await AuditLogger(mock_session).write(event)
    added: AuditEventRow = mock_session.add.call_args[0][0]
    assert added.caller_id == "agent-x"
    assert added.tool_name == "sql.query"
    assert added.decision == "DENY"
    assert added.latency_ms == 99
    assert added.risk_score == 0.95


@pytest.mark.unit
async def test_write_does_not_raise_when_commit_fails(mock_session: MagicMock) -> None:
    """write() must swallow exceptions — audit must never crash the pipeline."""
    mock_session.commit = AsyncMock(side_effect=RuntimeError("DB connection lost"))
    event = make_audit_event()
    # Should not raise
    await AuditLogger(mock_session).write(event)


@pytest.mark.unit
async def test_write_does_not_raise_when_add_fails(mock_session: MagicMock) -> None:
    mock_session.add = MagicMock(side_effect=RuntimeError("constraint violation"))
    event = make_audit_event()
    await AuditLogger(mock_session).write(event)


# ---------------------------------------------------------------------------
# AuditQuery — _row_to_event conversion
# ---------------------------------------------------------------------------


@pytest.mark.unit
def test_row_to_event_roundtrip() -> None:
    """ORM row → Pydantic AuditEvent preserves all fields."""
    original = make_audit_event(
        redaction_flags=[
            RedactionFlag(field="email", reason="PII_EMAIL", original_hash="e" * 64)
        ]
    )
    row = make_audit_event_row(original)
    recovered = _row_to_event(row)
    assert recovered.request_id == original.request_id
    assert recovered.raw_args_hash == original.raw_args_hash
    assert recovered.sanitized_args == original.sanitized_args
    assert len(recovered.redaction_flags) == 1
    assert recovered.redaction_flags[0].field == "email"
    assert recovered.redaction_flags[0].reason == "PII_EMAIL"


@pytest.mark.unit
def test_row_to_event_empty_redaction_flags() -> None:
    event = make_audit_event(redaction_flags=[])
    row = make_audit_event_row(event)
    recovered = _row_to_event(row)
    assert recovered.redaction_flags == []


# ---------------------------------------------------------------------------
# AuditQuery.get_by_request_id()
# ---------------------------------------------------------------------------


@pytest.mark.unit
async def test_get_by_request_id_returns_event_when_found(mock_session: MagicMock) -> None:
    event = make_audit_event(request_id="req-found")
    row = make_audit_event_row(event)
    mock_result = MagicMock()
    mock_result.scalar_one_or_none.return_value = row
    mock_session.execute = AsyncMock(return_value=mock_result)

    result = await AuditQuery(mock_session).get_by_request_id("req-found")

    assert result is not None
    assert result.request_id == "req-found"


@pytest.mark.unit
async def test_get_by_request_id_returns_none_when_missing(mock_session: MagicMock) -> None:
    mock_result = MagicMock()
    mock_result.scalar_one_or_none.return_value = None
    mock_session.execute = AsyncMock(return_value=mock_result)

    result = await AuditQuery(mock_session).get_by_request_id("req-missing")

    assert result is None


# ---------------------------------------------------------------------------
# AuditQuery.list_by_caller()
# ---------------------------------------------------------------------------


@pytest.mark.unit
async def test_list_by_caller_returns_events(mock_session: MagicMock) -> None:
    events = [make_audit_event(request_id=f"req-{i}", caller_id="caller-a") for i in range(3)]
    rows = [make_audit_event_row(e) for e in events]
    mock_result = MagicMock()
    mock_result.scalars.return_value.all.return_value = rows
    mock_session.execute = AsyncMock(return_value=mock_result)

    results = await AuditQuery(mock_session).list_by_caller("caller-a")

    assert len(results) == 3
    assert all(r.caller_id == "caller-a" for r in results)


@pytest.mark.unit
async def test_list_by_caller_returns_empty_list_when_none(mock_session: MagicMock) -> None:
    mock_result = MagicMock()
    mock_result.scalars.return_value.all.return_value = []
    mock_session.execute = AsyncMock(return_value=mock_result)

    results = await AuditQuery(mock_session).list_by_caller("nobody")

    assert results == []


# ---------------------------------------------------------------------------
# AuditQuery.list_by_decision()
# ---------------------------------------------------------------------------


@pytest.mark.unit
async def test_list_by_decision_returns_filtered_events(mock_session: MagicMock) -> None:
    denied = [make_audit_event(request_id=f"req-{i}", decision="DENY") for i in range(2)]
    rows = [make_audit_event_row(e) for e in denied]
    mock_result = MagicMock()
    mock_result.scalars.return_value.all.return_value = rows
    mock_session.execute = AsyncMock(return_value=mock_result)

    results = await AuditQuery(mock_session).list_by_decision("DENY")

    assert len(results) == 2
    assert all(r.decision == "DENY" for r in results)


# ---------------------------------------------------------------------------
# AuditQuery.list_recent()
# ---------------------------------------------------------------------------


@pytest.mark.unit
async def test_list_recent_returns_all_events(mock_session: MagicMock) -> None:
    events = [make_audit_event(request_id=f"req-{i}") for i in range(5)]
    rows = [make_audit_event_row(e) for e in events]
    mock_result = MagicMock()
    mock_result.scalars.return_value.all.return_value = rows
    mock_session.execute = AsyncMock(return_value=mock_result)

    results = await AuditQuery(mock_session).list_recent(limit=5)

    assert len(results) == 5
