"""Unit tests for Redis-backed admin sessions."""

import json
from datetime import datetime, timedelta
from unittest.mock import AsyncMock, MagicMock

import fakeredis.aioredis
import pytest
from fastapi import HTTPException

from gateway.auth.admin_sessions import AdminSessionManager
from gateway.config import Settings
from gateway.models.identity import CallerIdentity, TrustLevel


@pytest.fixture
def settings() -> Settings:
    return Settings(
        environment="dev",
        database_url="postgresql+asyncpg://x:x@localhost/x",
        redis_url="redis://localhost:6379/0",
        admin_session_ttl_seconds=600,
    )


@pytest.fixture
async def redis() -> fakeredis.aioredis.FakeRedis:  # type: ignore[misc]
    client = fakeredis.aioredis.FakeRedis(decode_responses=True)
    yield client
    await client.aclose()


def _admin_identity() -> CallerIdentity:
    return CallerIdentity(
        caller_id="dashboard-admin",
        role="admin",
        trust_level=TrustLevel.ADMIN,
        environment="prod",
        api_key_id=9,
        org_id="acme-prod",
    )


@pytest.mark.unit
@pytest.mark.asyncio
async def test_login_creates_bearer_session(
    settings: Settings,
    redis: fakeredis.aioredis.FakeRedis,
) -> None:
    authenticator = MagicMock()
    authenticator.resolve = AsyncMock(return_value=_admin_identity())
    manager = AdminSessionManager(settings=settings, redis=redis, authenticator=authenticator)

    session = await manager.login("plaintext-admin-key")

    assert session.caller_id == "dashboard-admin"
    assert session.org_id == "acme-prod"
    assert session.session_token

    identity = await manager.get_identity(session.session_token)
    assert identity.trust_level == TrustLevel.ADMIN
    assert identity.org_id == "acme-prod"


@pytest.mark.unit
@pytest.mark.asyncio
async def test_login_rejects_non_admin_identity(
    settings: Settings,
    redis: fakeredis.aioredis.FakeRedis,
) -> None:
    authenticator = MagicMock()
    authenticator.resolve = AsyncMock(
        return_value=CallerIdentity(
            caller_id="developer-1",
            role="developer",
            trust_level=TrustLevel.HIGH,
            environment="prod",
            api_key_id=10,
            org_id="acme-prod",
        )
    )
    manager = AdminSessionManager(settings=settings, redis=redis, authenticator=authenticator)

    with pytest.raises(HTTPException) as exc_info:
        await manager.login("plaintext-dev-key")

    assert exc_info.value.status_code == 403


@pytest.mark.unit
@pytest.mark.asyncio
async def test_get_identity_rejects_expired_session(
    settings: Settings,
    redis: fakeredis.aioredis.FakeRedis,
) -> None:
    authenticator = MagicMock()
    manager = AdminSessionManager(settings=settings, redis=redis, authenticator=authenticator)

    await redis.set(
        "admin-session:expired-token",
        json.dumps(
            {
                "caller_id": "dashboard-admin",
                "role": "admin",
                "environment": "prod",
                "api_key_id": 9,
                "org_id": "acme-prod",
                "expires_at": (datetime.utcnow() - timedelta(minutes=1)).isoformat(),
            }
        ),
    )

    with pytest.raises(HTTPException) as exc_info:
        await manager.get_identity("expired-token")

    assert exc_info.value.status_code == 401


@pytest.mark.unit
@pytest.mark.asyncio
async def test_logout_removes_session(
    settings: Settings,
    redis: fakeredis.aioredis.FakeRedis,
) -> None:
    authenticator = MagicMock()
    authenticator.resolve = AsyncMock(return_value=_admin_identity())
    manager = AdminSessionManager(settings=settings, redis=redis, authenticator=authenticator)

    session = await manager.login("plaintext-admin-key")
    await manager.logout(session.session_token)

    with pytest.raises(HTTPException):
        await manager.get_identity(session.session_token)
