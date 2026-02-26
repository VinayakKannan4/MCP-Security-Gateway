"""Shared fixtures for integration tests.

Requires the test Docker stack to be running:
    docker compose -f docker-compose.test.yml up -d

And migrations applied once:
    DATABASE_URL="postgresql+asyncpg://gateway:gateway@localhost:5433/gateway_test" \\
        uv run alembic upgrade head

Test DB  : postgresql+asyncpg://gateway:gateway@localhost:5433/gateway_test
Test Redis: redis://localhost:6380/0

Isolation strategy:
- DB: each test gets its own engine + connection. The connection wraps the test
  in an outer transaction that is rolled back at teardown (savepoint mode means
  session.commit() inside app code creates/releases savepoints, not real commits).
  No table truncation or recreating needed — rollback restores the clean state.
- Redis: flushdb() after each test.

Note on event loops: asyncpg connections are bound to the event loop that created
them. By creating a fresh engine inside the function-scoped fixture, everything
(engine, connection, session) lives in the same per-test event loop, avoiding the
cross-loop "another operation is in progress" error that occurs when a session-scoped
engine is shared with function-scoped test loops.
"""

import pytest_asyncio
from redis.asyncio import Redis
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine

from gateway.approval.manager import ApprovalManager
from gateway.audit.logger import AuditLogger
from gateway.audit.query import AuditQuery

TEST_DATABASE_URL = "postgresql+asyncpg://gateway:gateway@localhost:5433/gateway_test"
TEST_REDIS_URL = "redis://localhost:6380/0"


# ---------------------------------------------------------------------------
# Per-test DB session with savepoint-based isolation
#
# A new engine (and connection) is created per test so everything stays within
# the same event loop. session.commit() inside app code creates/releases
# SAVEPOINTs rather than committing the outer transaction, so the entire test
# is rolled back at teardown.
# ---------------------------------------------------------------------------


@pytest_asyncio.fixture
async def db_session() -> AsyncSession:  # type: ignore[misc]
    engine = create_async_engine(TEST_DATABASE_URL, echo=False)
    conn = await engine.connect()
    await conn.begin()  # outer transaction — never committed

    session = AsyncSession(
        bind=conn,
        expire_on_commit=False,
        join_transaction_mode="create_savepoint",
    )

    yield session  # type: ignore[misc]

    await session.close()
    await conn.rollback()  # undo all changes written during this test
    await conn.close()
    await engine.dispose()


# ---------------------------------------------------------------------------
# Per-test Redis client — flushes all keys after each test
# ---------------------------------------------------------------------------


@pytest_asyncio.fixture
async def redis_client() -> Redis:  # type: ignore[misc]
    client: Redis[str] = Redis.from_url(TEST_REDIS_URL, decode_responses=True)
    yield client  # type: ignore[misc]
    await client.flushdb()
    await client.aclose()


# ---------------------------------------------------------------------------
# Convenience fixtures wired to db_session + redis_client
# ---------------------------------------------------------------------------


@pytest_asyncio.fixture
async def audit_logger(db_session: AsyncSession) -> AuditLogger:
    return AuditLogger(db_session)


@pytest_asyncio.fixture
async def audit_query(db_session: AsyncSession) -> AuditQuery:
    return AuditQuery(db_session)


@pytest_asyncio.fixture
async def approval_manager(db_session: AsyncSession, redis_client: Redis) -> ApprovalManager:
    return ApprovalManager(db_session, redis_client)
