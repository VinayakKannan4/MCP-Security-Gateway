"""API key resolution shared by gateway and admin auth flows."""

from __future__ import annotations

import bcrypt
from fastapi import HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from gateway.db.models import ApiKey
from gateway.models.identity import CallerIdentity, TrustLevel


class ApiKeyAuthenticator:
    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def resolve(self, api_key: str) -> CallerIdentity:
        result = await self._session.execute(select(ApiKey).where(ApiKey.is_active == True))  # noqa: E712
        rows = result.scalars().all()

        for row in rows:
            if bcrypt.checkpw(api_key.encode(), row.key_hash.encode()):
                return CallerIdentity(
                    caller_id=row.caller_id,
                    role=row.role,
                    trust_level=TrustLevel(row.trust_level),
                    environment=row.environment,
                    api_key_id=row.id,
                    org_id=row.org_id,
                )

        raise HTTPException(status_code=401, detail="Invalid or inactive API key")
