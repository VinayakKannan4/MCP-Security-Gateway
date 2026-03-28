"""FastAPI dependency providers.

All dependencies are resolved per-request except singletons stored on app.state
(agents, policy engine, executor) which are created once in the lifespan.
"""

from __future__ import annotations

from collections.abc import AsyncGenerator

from fastapi import Depends, Header, HTTPException, Request
from redis.asyncio import Redis
from sqlalchemy.ext.asyncio import AsyncSession

from gateway.approval.manager import ApprovalManager
from gateway.audit.logger import AuditLogger
from gateway.audit.query import AuditQuery
from gateway.auth.admin_sessions import AdminSessionManager
from gateway.auth.api_keys import ApiKeyAuthenticator
from gateway.enforcement.pipeline import EnforcementPipeline
from gateway.models.identity import CallerIdentity


async def get_db(request: Request) -> AsyncGenerator[AsyncSession, None]:
    """Yield a new DB session per request from the app-state sessionmaker."""
    async with request.app.state.db_sessionmaker() as session:
        yield session


async def get_redis(request: Request) -> Redis:
    """Return the shared Redis client from app state."""
    redis: Redis = request.app.state.redis
    return redis


async def get_pipeline(
    request: Request,
    db: AsyncSession = Depends(get_db),
    redis: Redis = Depends(get_redis),
) -> EnforcementPipeline:
    """Build a pipeline with a per-request DB session; agents are app-state singletons."""
    return EnforcementPipeline(
        settings=request.app.state.settings,
        db=db,
        redis=redis,
        risk_classifier=request.app.state.risk_classifier,
        argument_guard=request.app.state.argument_guard,
        policy_engine=request.app.state.policy_engine,
        output_policy_engine=request.app.state.output_policy_engine,
        audit_logger=AuditLogger(db),
        approval_manager=ApprovalManager(session=db, redis=redis),
        executor=request.app.state.executor,
    )


async def get_approval_manager(
    db: AsyncSession = Depends(get_db),
    redis: Redis = Depends(get_redis),
) -> ApprovalManager:
    """Build an ApprovalManager with a per-request DB session."""
    return ApprovalManager(session=db, redis=redis)


async def get_audit_query(
    db: AsyncSession = Depends(get_db),
) -> AuditQuery:
    """Build an AuditQuery with a per-request DB session."""
    return AuditQuery(session=db)


async def get_api_key_authenticator(
    db: AsyncSession = Depends(get_db),
) -> ApiKeyAuthenticator:
    return ApiKeyAuthenticator(session=db)


async def get_admin_session_manager(
    request: Request,
    redis: Redis = Depends(get_redis),
    authenticator: ApiKeyAuthenticator = Depends(get_api_key_authenticator),
) -> AdminSessionManager:
    return AdminSessionManager(
        settings=request.app.state.settings,
        redis=redis,
        authenticator=authenticator,
    )


async def require_admin(
    authorization: str = Header(...),
    manager: AdminSessionManager = Depends(get_admin_session_manager),
) -> CallerIdentity:
    """Require a valid Bearer admin session and return the admin identity."""
    scheme, _, token = authorization.partition(" ")
    if scheme != "Bearer" or not token:
        raise HTTPException(status_code=401, detail="Bearer admin session required")
    return await manager.get_identity(token)
