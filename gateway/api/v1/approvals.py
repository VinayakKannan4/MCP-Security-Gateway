"""Approval management endpoints — all require X-Admin-Key header."""

from fastapi import APIRouter, Depends, HTTPException, Query

from gateway.api.deps import get_approval_manager, require_admin
from gateway.approval.manager import ApprovalManager
from gateway.models.approval import ApprovalResult

router = APIRouter()


@router.get("/{token}", response_model=ApprovalResult, dependencies=[Depends(require_admin)])
async def get_approval(
    token: str,
    manager: ApprovalManager = Depends(get_approval_manager),
) -> ApprovalResult:
    """Fetch the current status of an approval token."""
    try:
        return await manager.check_token(token)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.post(
    "/{token}/approve", response_model=ApprovalResult, dependencies=[Depends(require_admin)]
)
async def approve(
    token: str,
    approver_id: str = Query(...),
    note: str = Query(default=""),
    manager: ApprovalManager = Depends(get_approval_manager),
) -> ApprovalResult:
    """Approve a pending approval token."""
    try:
        return await manager.approve(token, approver_id, note)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.post(
    "/{token}/deny", response_model=ApprovalResult, dependencies=[Depends(require_admin)]
)
async def deny(
    token: str,
    approver_id: str = Query(...),
    note: str = Query(default=""),
    manager: ApprovalManager = Depends(get_approval_manager),
) -> ApprovalResult:
    """Deny a pending approval token."""
    try:
        return await manager.deny(token, approver_id, note)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
