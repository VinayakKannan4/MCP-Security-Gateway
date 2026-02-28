"""FastAPI dependency providers.

All dependencies are resolved per-request except singletons stored on app.state
(agents, policy engine, executor) which are created once in the lifespan.
"""

from collections.abc import AsyncGenerator

from fastapi import Depends, Header, HTTPException, Request
from redis.asyncio import Redis
from sqlalchemy.ext.asyncio import AsyncSession

from gateway.approval.manager import ApprovalManager
from gateway.audit.logger import AuditLogger
from gateway.audit.query import AuditQuery
from gateway.enforcement.pipeline import EnforcementPipeline


async def get_db(request: Request) -> AsyncGenerator[AsyncSession, None]:
    """Yield a new DB session per request from the app-state sessionmaker."""
    async with request.app.state.db_sessionmaker() as session:
        yield session


async def get_redis(request: Request) -> Redis[str]:
    """Return the shared Redis client from app state."""
    redis: Redis[str] = request.app.state.redis
    return redis


async def get_pipeline(
    request: Request,
    db: AsyncSession = Depends(get_db),
    redis: Redis[str] = Depends(get_redis),
) -> EnforcementPipeline:
    """Build a pipeline with a per-request DB session; agents are app-state singletons."""
    return EnforcementPipeline(
        settings=request.app.state.settings,
        db=db,
        redis=redis,
        risk_classifier=request.app.state.risk_classifier,
        argument_guard=request.app.state.argument_guard,
        policy_engine=request.app.state.policy_engine,
        audit_logger=AuditLogger(db),
        approval_manager=ApprovalManager(session=db, redis=redis),
        executor=request.app.state.executor,
    )


async def get_approval_manager(
    db: AsyncSession = Depends(get_db),
    redis: Redis[str] = Depends(get_redis),
) -> ApprovalManager:
    """Build an ApprovalManager with a per-request DB session."""
    return ApprovalManager(session=db, redis=redis)


async def get_audit_query(
    db: AsyncSession = Depends(get_db),
) -> AuditQuery:
    """Build an AuditQuery with a per-request DB session."""
    return AuditQuery(session=db)


async def require_admin(
    request: Request,
    x_admin_key: str = Header(...),
) -> None:
    """Require a valid X-Admin-Key header for admin-gated endpoints."""
    if x_admin_key != request.app.state.settings.admin_api_key:
        raise HTTPException(status_code=403, detail="Invalid admin key")
