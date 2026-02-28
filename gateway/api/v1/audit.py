"""Audit query endpoints — all require X-Admin-Key header."""

from fastapi import APIRouter, Depends, HTTPException

from gateway.api.deps import get_audit_query, require_admin
from gateway.audit.query import AuditQuery
from gateway.models.audit import AuditEvent

router = APIRouter()


@router.get("/", response_model=list[AuditEvent], dependencies=[Depends(require_admin)])
async def list_recent(
    limit: int = 50,
    query: AuditQuery = Depends(get_audit_query),
) -> list[AuditEvent]:
    """Return the most recent audit events across all callers."""
    return await query.list_recent(limit=limit)


@router.get("/{request_id}", response_model=AuditEvent, dependencies=[Depends(require_admin)])
async def get_event(
    request_id: str,
    query: AuditQuery = Depends(get_audit_query),
) -> AuditEvent:
    """Fetch a single audit event by its request ID."""
    event = await query.get_by_request_id(request_id)
    if event is None:
        raise HTTPException(status_code=404, detail=f"Audit event not found: {request_id!r}")
    return event
