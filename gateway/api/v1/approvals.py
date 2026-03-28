"""Approval management endpoints — all require an admin bearer session."""

from fastapi import APIRouter, Depends, HTTPException, Query

from gateway.api.deps import get_approval_manager, require_admin
from gateway.approval.manager import ApprovalManager
from gateway.models.approval import ApprovalResult, ApprovalStatus, ApprovalSummary
from gateway.models.identity import CallerIdentity

router = APIRouter()


@router.get("/", response_model=list[ApprovalSummary])
async def list_approvals(
    status: str | None = Query(
        default=None,
        description="Filter by status: PENDING, APPROVED, DENIED, EXPIRED, USED",
    ),
    limit: int = Query(default=50, le=200),
    manager: ApprovalManager = Depends(get_approval_manager),
    admin: CallerIdentity = Depends(require_admin),
) -> list[ApprovalSummary]:
    """List approval requests, optionally filtered by status."""
    status_filter = ApprovalStatus(status) if status else None
    return await manager.list_requests(
        status_filter=status_filter,
        limit=limit,
        org_id=admin.org_id,
    )


@router.get("/{token}", response_model=ApprovalResult)
async def get_approval(
    token: str,
    manager: ApprovalManager = Depends(get_approval_manager),
    admin: CallerIdentity = Depends(require_admin),
) -> ApprovalResult:
    """Fetch the current status of an approval token."""
    try:
        return await manager.check_token(token, expected_org_id=admin.org_id)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.post("/{token}/approve", response_model=ApprovalResult)
async def approve(
    token: str,
    note: str = Query(default=""),
    manager: ApprovalManager = Depends(get_approval_manager),
    admin: CallerIdentity = Depends(require_admin),
) -> ApprovalResult:
    """Approve a pending approval token."""
    try:
        return await manager.approve(
            token,
            admin.caller_id,
            note,
            expected_org_id=admin.org_id,
        )
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.post("/{token}/deny", response_model=ApprovalResult)
async def deny(
    token: str,
    note: str = Query(default=""),
    manager: ApprovalManager = Depends(get_approval_manager),
    admin: CallerIdentity = Depends(require_admin),
) -> ApprovalResult:
    """Deny a pending approval token."""
    try:
        return await manager.deny(
            token,
            admin.caller_id,
            note,
            expected_org_id=admin.org_id,
        )
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
