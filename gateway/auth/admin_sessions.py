"""Short-lived admin sessions backed by Redis."""

from __future__ import annotations

import secrets
from datetime import datetime, timedelta

from fastapi import HTTPException
from redis.asyncio import Redis

from gateway.auth.api_keys import ApiKeyAuthenticator
from gateway.cache.redis_client import delete, get_json, set_json
from gateway.config import Settings
from gateway.models.admin import AdminSessionData, AdminSessionResponse
from gateway.models.identity import CallerIdentity, TrustLevel

_KEY_PREFIX = "admin-session:"


class AdminSessionManager:
    def __init__(
        self,
        settings: Settings,
        redis: Redis,
        authenticator: ApiKeyAuthenticator,
    ) -> None:
        self._settings = settings
        self._redis = redis
        self._authenticator = authenticator

    async def login(self, api_key: str) -> AdminSessionResponse:
        identity = await self._authenticator.resolve(api_key)
        if identity.role != "admin":
            raise HTTPException(status_code=403, detail="Admin access required")

        expires_at = datetime.utcnow() + timedelta(seconds=self._settings.admin_session_ttl_seconds)
        session_token = secrets.token_urlsafe(32)
        session = AdminSessionData(
            caller_id=identity.caller_id,
            role=identity.role,
            environment=identity.environment,
            api_key_id=identity.api_key_id,
            org_id=identity.org_id,
            expires_at=expires_at,
        )
        await set_json(
            self._redis,
            f"{_KEY_PREFIX}{session_token}",
            session.model_dump(mode="json"),
            ttl=self._settings.admin_session_ttl_seconds,
        )
        return AdminSessionResponse(
            session_token=session_token,
            caller_id=session.caller_id,
            role=session.role,
            environment=session.environment,
            api_key_id=session.api_key_id,
            org_id=session.org_id,
            expires_at=session.expires_at,
        )

    async def get_identity(self, session_token: str) -> CallerIdentity:
        data = await get_json(self._redis, f"{_KEY_PREFIX}{session_token}")
        if data is None:
            raise HTTPException(status_code=401, detail="Invalid or expired admin session")

        expires_at = datetime.fromisoformat(data["expires_at"])
        if expires_at <= datetime.utcnow():
            await delete(self._redis, f"{_KEY_PREFIX}{session_token}")
            raise HTTPException(status_code=401, detail="Invalid or expired admin session")

        return CallerIdentity(
            caller_id=data["caller_id"],
            role=data["role"],
            trust_level=TrustLevel.ADMIN,
            environment=data["environment"],
            api_key_id=data["api_key_id"],
            org_id=data["org_id"],
        )

    async def logout(self, session_token: str) -> None:
        await delete(self._redis, f"{_KEY_PREFIX}{session_token}")
