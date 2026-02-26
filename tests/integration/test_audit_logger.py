"""Integration tests for AuditLogger and AuditQuery against a real Postgres DB."""

from datetime import datetime

import pytest

from gateway.audit.logger import AuditLogger
from gateway.audit.query import AuditQuery
from gateway.models.audit import AuditEvent, RedactionFlag


def make_audit_event(**overrides: object) -> AuditEvent:
    defaults: dict[str, object] = {
        "request_id": "req-integ-001",
        "trace_id": None,
        "timestamp": datetime(2026, 2, 24, 12, 0, 0),
        "caller_id": "integ-caller",
        "caller_role": "developer",
        "environment": "dev",
        "mcp_server": "filesystem-mcp",
        "tool_name": "fs.read",
        "raw_args_hash": "a" * 64,
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


# ---------------------------------------------------------------------------
# write + get_by_request_id roundtrip
# ---------------------------------------------------------------------------


@pytest.mark.integration
async def test_write_and_read_by_request_id(
    audit_logger: AuditLogger, audit_query: AuditQuery
) -> None:
    event = make_audit_event(request_id="req-rw-001")
    await audit_logger.write(event)

    result = await audit_query.get_by_request_id("req-rw-001")

    assert result is not None
    assert result.request_id == "req-rw-001"
    assert result.caller_id == "integ-caller"
    assert result.decision == "ALLOW"
    assert result.raw_args_hash == "a" * 64
    assert result.latency_ms == 42


@pytest.mark.integration
async def test_raw_args_hash_stored_not_raw_args(
    audit_logger: AuditLogger, audit_query: AuditQuery
) -> None:
    event = make_audit_event(request_id="req-hash-001", raw_args_hash="b" * 64)
    await audit_logger.write(event)

    result = await audit_query.get_by_request_id("req-hash-001")
    assert result is not None
    assert result.raw_args_hash == "b" * 64


@pytest.mark.integration
async def test_sanitized_args_jsonb_roundtrip(
    audit_logger: AuditLogger, audit_query: AuditQuery
) -> None:
    args = {"path": "/data/file.csv", "encoding": "utf-8", "max_bytes": 1024}
    event = make_audit_event(request_id="req-jsonb-001", sanitized_args=args)
    await audit_logger.write(event)

    result = await audit_query.get_by_request_id("req-jsonb-001")
    assert result is not None
    assert result.sanitized_args == args


@pytest.mark.integration
async def test_redaction_flags_jsonb_roundtrip(
    audit_logger: AuditLogger, audit_query: AuditQuery
) -> None:
    flags = [
        RedactionFlag(field="email", reason="PII_EMAIL", original_hash="c" * 64),
        RedactionFlag(field="token", reason="SECRET_TOKEN", original_hash="d" * 64),
    ]
    event = make_audit_event(request_id="req-flags-001", redaction_flags=flags)
    await audit_logger.write(event)

    result = await audit_query.get_by_request_id("req-flags-001")
    assert result is not None
    assert len(result.redaction_flags) == 2
    assert result.redaction_flags[0].field == "email"
    assert result.redaction_flags[0].reason == "PII_EMAIL"
    assert result.redaction_flags[1].field == "token"


@pytest.mark.integration
async def test_get_by_request_id_returns_none_for_missing(
    audit_query: AuditQuery,
) -> None:
    result = await audit_query.get_by_request_id("req-does-not-exist")
    assert result is None


# ---------------------------------------------------------------------------
# list_by_caller
# ---------------------------------------------------------------------------


@pytest.mark.integration
async def test_list_by_caller_returns_only_matching_events(
    audit_logger: AuditLogger, audit_query: AuditQuery
) -> None:
    await audit_logger.write(make_audit_event(request_id="req-caller-a1", caller_id="caller-a"))
    await audit_logger.write(make_audit_event(request_id="req-caller-a2", caller_id="caller-a"))
    await audit_logger.write(make_audit_event(request_id="req-caller-b1", caller_id="caller-b"))

    results = await audit_query.list_by_caller("caller-a")

    assert len(results) == 2
    assert all(r.caller_id == "caller-a" for r in results)


@pytest.mark.integration
async def test_list_by_caller_returns_empty_for_unknown(
    audit_query: AuditQuery,
) -> None:
    results = await audit_query.list_by_caller("nobody")
    assert results == []


# ---------------------------------------------------------------------------
# list_by_decision
# ---------------------------------------------------------------------------


@pytest.mark.integration
async def test_list_by_decision_filters_correctly(
    audit_logger: AuditLogger, audit_query: AuditQuery
) -> None:
    await audit_logger.write(
        make_audit_event(request_id="req-deny-01", decision="DENY", caller_id="c1")
    )
    await audit_logger.write(
        make_audit_event(request_id="req-deny-02", decision="DENY", caller_id="c2")
    )
    await audit_logger.write(
        make_audit_event(request_id="req-allow-01", decision="ALLOW", caller_id="c3")
    )

    denied = await audit_query.list_by_decision("DENY")
    allowed = await audit_query.list_by_decision("ALLOW")

    assert len(denied) == 2
    assert all(r.decision == "DENY" for r in denied)
    assert len(allowed) == 1
    assert allowed[0].decision == "ALLOW"


# ---------------------------------------------------------------------------
# list_recent
# ---------------------------------------------------------------------------


@pytest.mark.integration
async def test_list_recent_returns_all_written_events(
    audit_logger: AuditLogger, audit_query: AuditQuery
) -> None:
    for i in range(3):
        await audit_logger.write(make_audit_event(request_id=f"req-recent-{i:02d}"))

    results = await audit_query.list_recent(limit=10)
    request_ids = {r.request_id for r in results}

    assert {"req-recent-00", "req-recent-01", "req-recent-02"}.issubset(request_ids)


# ---------------------------------------------------------------------------
# write() never raises — even on DB errors
# ---------------------------------------------------------------------------


@pytest.mark.integration
async def test_write_does_not_raise_on_duplicate_request_id(
    audit_logger: AuditLogger,
) -> None:
    event = make_audit_event(request_id="req-dup-001")
    await audit_logger.write(event)
    # Second write with same request_id hits unique constraint — must not raise
    await audit_logger.write(event)
