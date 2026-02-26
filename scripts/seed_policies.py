"""Seed the database with a dev API key for local development.

Usage:
    uv run python scripts/seed_policies.py

Prints the plaintext API key once. Only the bcrypt hash is stored in the DB.
Run `alembic upgrade head` before this script to ensure tables exist.
"""

import asyncio
import secrets
import sys

import bcrypt
from sqlalchemy import select
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

# Ensure project root is on the path when run as a script
sys.path.insert(0, ".")

from gateway.config import settings
from gateway.db.models import ApiKey


async def seed() -> None:
    engine = create_async_engine(settings.database_url, echo=False)
    session_factory = async_sessionmaker(engine, expire_on_commit=False)

    async with session_factory() as session:
        # Check if dev-agent already exists to avoid duplicate inserts
        result = await session.execute(
            select(ApiKey).where(ApiKey.caller_id == "dev-agent")
        )
        existing = result.scalar_one_or_none()
        if existing is not None:
            print("dev-agent already exists in api_keys — skipping insert.")
            await engine.dispose()
            return

        # Generate a cryptographically random plaintext key
        plaintext_key = secrets.token_urlsafe(32)

        # Hash with bcrypt — only the hash is stored
        key_hash = bcrypt.hashpw(plaintext_key.encode(), bcrypt.gensalt()).decode()

        row = ApiKey(
            caller_id="dev-agent",
            key_hash=key_hash,
            role="developer",
            trust_level=2,  # TrustLevel.MEDIUM
            environment="dev",
            is_active=True,
        )
        session.add(row)
        await session.commit()

    await engine.dispose()

    print("=" * 60)
    print("Dev API key created.")
    print(f"  caller_id : dev-agent")
    print(f"  role      : developer")
    print(f"  api_key   : {plaintext_key}")
    print()
    print("Save this key — it will not be shown again.")
    print("=" * 60)


if __name__ == "__main__":
    asyncio.run(seed())
