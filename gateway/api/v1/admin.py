"""Admin session endpoints."""

from fastapi import APIRouter, Depends, Header, HTTPException

from gateway.api.deps import get_admin_session_manager, require_admin
from gateway.auth.admin_sessions import AdminSessionManager
from gateway.models.admin import AdminLoginRequest, AdminSessionResponse
from gateway.models.identity import CallerIdentity

router = APIRouter()


@router.post("/login", response_model=AdminSessionResponse)
async def login(
    payload: AdminLoginRequest,
    manager: AdminSessionManager = Depends(get_admin_session_manager),
) -> AdminSessionResponse:
    """Exchange an admin API key for a short-lived bearer session."""
    return await manager.login(payload.api_key)


@router.get("/me", response_model=CallerIdentity)
async def me(identity: CallerIdentity = Depends(require_admin)) -> CallerIdentity:
    """Return the current admin session identity."""
    return identity


@router.post("/logout")
async def logout(
    authorization: str = Header(...),
    manager: AdminSessionManager = Depends(get_admin_session_manager),
) -> dict[str, str]:
    """Invalidate the current admin session."""
    scheme, _, token = authorization.partition(" ")
    if scheme != "Bearer" or not token:
        raise HTTPException(status_code=401, detail="Bearer admin session required")
    await manager.logout(token)
    return {"status": "ok"}
