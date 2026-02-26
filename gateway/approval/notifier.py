"""Approval notification stub.

Logs pending/decided events at INFO level. Token value is NEVER logged —
only request_id and caller metadata are emitted.

Future: replace log statements with webhook POST or Slack message.
"""

import logging

from gateway.models.approval import ApprovalRequest, ApprovalResult

logger = logging.getLogger(__name__)


class ApprovalNotifier:
    async def notify_pending(self, request: ApprovalRequest) -> None:
        """Notify that a request is waiting for human approval."""
        logger.info(
            "APPROVAL_REQUIRED request_id=%s caller=%s tool=%s.%s",
            request.request_id,
            request.caller_id,
            request.tool_call.server,
            request.tool_call.tool,
            # token is intentionally omitted — never log token values
        )

    async def notify_decision(self, result: ApprovalResult) -> None:
        """Notify that a human has made an approval decision."""
        logger.info(
            "APPROVAL_DECIDED status=%s approver=%s",
            result.status.value,
            result.approver_id,
            # token is intentionally omitted — never log token values
        )
