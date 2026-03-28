"""Seed the database with local development API keys.

Usage:
    uv run python scripts/seed_policies.py

Prints plaintext API keys once. Only bcrypt hashes are stored in the DB.
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
    generated_keys: list[tuple[str, str, str, str]] = []

    async with session_factory() as session:
        for caller_id, role, trust_level in [
            ("dev-agent", "developer", 2),
            ("dashboard-admin", "admin", 4),
        ]:
            result = await session.execute(
                select(ApiKey).where(ApiKey.caller_id == caller_id)
            )
            existing = result.scalar_one_or_none()
            if existing is not None:
                print(f"{caller_id} already exists in api_keys — skipping insert.")
                continue

            plaintext_key = secrets.token_urlsafe(32)
            key_hash = bcrypt.hashpw(plaintext_key.encode(), bcrypt.gensalt()).decode()

            session.add(
                ApiKey(
                    caller_id=caller_id,
                    key_hash=key_hash,
                    role=role,
                    trust_level=trust_level,
                    environment="dev",
                    org_id="local-dev",
                    is_active=True,
                )
            )
            generated_keys.append((caller_id, role, "local-dev", plaintext_key))

        await session.commit()

    await engine.dispose()

    if not generated_keys:
        print("No new API keys were created.")
        return

    print("=" * 60)
    print("Local API keys created.")
    for caller_id, role, org_id, plaintext_key in generated_keys:
        print(f"  caller_id : {caller_id}")
        print(f"  role      : {role}")
        print(f"  org_id    : {org_id}")
        print(f"  api_key   : {plaintext_key}")
        print()
    print("Save these keys — they will not be shown again.")
    print("=" * 60)


if __name__ == "__main__":
    asyncio.run(seed())
