"""Append-only audit logger.

Critical invariants:
- write() ALWAYS runs — it must never raise, even on DB error.
- raw_args are NEVER stored — only raw_args_hash (SHA-256 hex).
- Rows are never updated or deleted after insertion.
"""

import logging

from sqlalchemy.ext.asyncio import AsyncSession

from gateway.db.models import AuditEventRow
from gateway.models.audit import AuditEvent

logger = logging.getLogger(__name__)


class AuditLogger:
    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def write(self, event: AuditEvent) -> None:
        """Persist an audit event. Never raises — errors are logged and swallowed.

        This method is called at pipeline step 9 regardless of whether the
        request was ALLOW, DENY, or errored. It must not crash the pipeline.
        """
        try:
            row = AuditEventRow(
                request_id=event.request_id,
                trace_id=event.trace_id,
                timestamp=event.timestamp,
                caller_id=event.caller_id,
                caller_role=event.caller_role,
                environment=event.environment,
                mcp_server=event.mcp_server,
                tool_name=event.tool_name,
                raw_args_hash=event.raw_args_hash,  # SHA-256 hex — never raw args
                sanitized_args=event.sanitized_args,
                risk_labels=list(event.risk_labels),
                risk_score=event.risk_score,
                matched_policy_rule=event.matched_policy_rule,
                decision=event.decision,
                approver_id=event.approver_id,
                execution_status=event.execution_status,
                latency_ms=event.latency_ms,
                output_hash=event.output_hash,
                redaction_flags=[flag.model_dump() for flag in event.redaction_flags],
                llm_explanation=event.llm_explanation,
                deterministic_rationale=event.deterministic_rationale,
            )
            self._session.add(row)
            await self._session.commit()
            logger.debug("audit write request_id=%s decision=%s", event.request_id, event.decision)
        except Exception:
            logger.exception(
                "AuditLogger.write() failed — audit record lost for request_id=%s",
                event.request_id,
            )
            # Reset session state so it remains usable for any subsequent calls.
            # With savepoint-mode sessions this rolls back to the savepoint;
            # in production this resets the connection from the aborted transaction.
            try:
                await self._session.rollback()
            except Exception:
                pass
