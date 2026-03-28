"""Audit query endpoints — all require an admin bearer session."""

from fastapi import APIRouter, Depends, HTTPException

from gateway.api.deps import get_audit_query, require_admin
from gateway.audit.query import AuditQuery
from gateway.models.audit import AuditEvent
from gateway.models.identity import CallerIdentity

router = APIRouter()


@router.get("/", response_model=list[AuditEvent])
async def list_recent(
    limit: int = 50,
    query: AuditQuery = Depends(get_audit_query),
    admin: CallerIdentity = Depends(require_admin),
) -> list[AuditEvent]:
    """Return the most recent audit events across all callers."""
    return await query.list_recent(limit=limit, org_id=admin.org_id)


@router.get("/{request_id}", response_model=AuditEvent)
async def get_event(
    request_id: str,
    query: AuditQuery = Depends(get_audit_query),
    admin: CallerIdentity = Depends(require_admin),
) -> AuditEvent:
    """Fetch a single audit event by its request ID."""
    event = await query.get_by_request_id(request_id, org_id=admin.org_id)
    if event is None:
        raise HTTPException(status_code=404, detail=f"Audit event not found: {request_id!r}")
    return event
