"""Filtered audit log reads for the dashboard API.

All queries return Pydantic AuditEvent objects (not raw ORM rows) and are
ordered by timestamp DESC so the most recent events come first.
"""

from sqlalchemy import desc, select
from sqlalchemy.ext.asyncio import AsyncSession

from gateway.db.models import AuditEventRow
from gateway.models.audit import AuditEvent, RedactionFlag


def _row_to_event(row: AuditEventRow) -> AuditEvent:
    """Convert a SQLAlchemy ORM row back to a Pydantic AuditEvent."""
    return AuditEvent(
        request_id=row.request_id,
        trace_id=row.trace_id,
        timestamp=row.timestamp,
        caller_id=row.caller_id,
        caller_role=row.caller_role,
        environment=row.environment,
        mcp_server=row.mcp_server,
        tool_name=row.tool_name,
        raw_args_hash=row.raw_args_hash,
        sanitized_args=row.sanitized_args,
        risk_labels=list(row.risk_labels),
        risk_score=row.risk_score,
        matched_policy_rule=row.matched_policy_rule,
        decision=row.decision,
        approver_id=row.approver_id,
        execution_status=row.execution_status,
        latency_ms=row.latency_ms,
        output_hash=row.output_hash,
        redaction_flags=[RedactionFlag(**f) for f in row.redaction_flags],
        llm_explanation=row.llm_explanation,
        deterministic_rationale=row.deterministic_rationale,
    )


class AuditQuery:
    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def get_by_request_id(self, request_id: str) -> AuditEvent | None:
        """Fetch a single audit event by its unique request ID."""
        result = await self._session.execute(
            select(AuditEventRow).where(AuditEventRow.request_id == request_id)
        )
        row = result.scalar_one_or_none()
        return _row_to_event(row) if row is not None else None

    async def list_by_caller(
        self, caller_id: str, limit: int = 50, offset: int = 0
    ) -> list[AuditEvent]:
        """List audit events for a specific caller, newest first."""
        result = await self._session.execute(
            select(AuditEventRow)
            .where(AuditEventRow.caller_id == caller_id)
            .order_by(desc(AuditEventRow.timestamp))
            .limit(limit)
            .offset(offset)
        )
        return [_row_to_event(r) for r in result.scalars().all()]

    async def list_by_decision(self, decision: str, limit: int = 50) -> list[AuditEvent]:
        """List audit events filtered by decision (ALLOW, DENY, etc.), newest first."""
        result = await self._session.execute(
            select(AuditEventRow)
            .where(AuditEventRow.decision == decision)
            .order_by(desc(AuditEventRow.timestamp))
            .limit(limit)
        )
        return [_row_to_event(r) for r in result.scalars().all()]

    async def list_recent(self, limit: int = 100) -> list[AuditEvent]:
        """List the most recent audit events across all callers."""
        result = await self._session.execute(
            select(AuditEventRow).order_by(desc(AuditEventRow.timestamp)).limit(limit)
        )
        return [_row_to_event(r) for r in result.scalars().all()]
