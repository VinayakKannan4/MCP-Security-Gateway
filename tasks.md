# Phase 2 Tasks — Persistence Layer

**Status**: Phase 1 complete (77/77 unit tests passing). Phase 2 not started.
**Branch**: `phase2`
**No Docker needed** until Group 7 (integration tests). Groups 1–5 are pure Python + unit tests.

---

## Prerequisite — add fakeredis dev dep

```bash
/Users/vinayakkannan/.local/bin/uv add --dev fakeredis
```

---

## Group 1 — DB Foundation

### 1a. `gateway/db/__init__.py`
Empty package marker.

### 1b. `gateway/db/session.py`
- `engine = create_async_engine(settings.database_url, echo=False)`
- `async_session_factory = async_sessionmaker(engine, expire_on_commit=False)`
- `Base = DeclarativeBase()` — imported by all ORM models
- `get_db() -> AsyncGenerator[AsyncSession, None]` — FastAPI dependency

### 1c. `gateway/db/models.py`
Three SQLAlchemy ORM tables (import `Base` from `session.py`):

**`ApiKey`** (`api_keys` table):
- `id: Mapped[int]` — primary key
- `caller_id: Mapped[str]` — unique, indexed
- `key_hash: Mapped[str]` — bcrypt hash, NEVER plaintext
- `role: Mapped[str]`
- `trust_level: Mapped[int]` — maps to `TrustLevel` IntEnum
- `environment: Mapped[str]`
- `is_active: Mapped[bool]` — default True
- `created_at: Mapped[datetime]` — server_default=now()
- `last_used_at: Mapped[datetime | None]`

**`AuditEventRow`** (`audit_events` table):
- Mirror every field from `gateway/models/audit.py:AuditEvent`
- `raw_args_hash: Mapped[str]` — SHA-256 hex, NEVER raw args
- `sanitized_args: Mapped[dict]` — `JSONB` column type
- `redaction_flags: Mapped[list]` — `JSONB` column type
- `risk_labels: Mapped[list]` — `JSONB` column type
- `request_id: Mapped[str]` — unique, indexed
- `timestamp: Mapped[datetime]` — indexed (for range queries)
- `caller_id: Mapped[str]` — indexed

**`ApprovalRequestRow`** (`approval_requests` table):
- Mirror every field from `gateway/models/approval.py:ApprovalRequest`
- `token: Mapped[str]` — unique, indexed (lookup key)
- `tool_call: Mapped[dict]` — `JSONB` column type
- `status: Mapped[str]` — default "PENDING", indexed

**Verify**: `python -c "from gateway.db.models import ApiKey, AuditEventRow, ApprovalRequestRow"` — no errors.

---

## Group 2 — Alembic Setup

### 2a. `alembic.ini` (project root)
- `script_location = gateway/db/migrations`
- `sqlalchemy.url` — leave as placeholder (overridden in env.py via settings)

### 2b. `gateway/db/migrations/env.py`
- Async env (use `run_async_migrations`)
- Import `Base` from `gateway.db.models`
- Pull DB URL from `gateway.config.settings.database_url`
- `target_metadata = Base.metadata`

### 2c. `gateway/db/migrations/script.py.mako`
Standard Alembic template (copy from alembic default).

### 2d. `gateway/db/migrations/versions/0001_initial.py`
- `op.create_table("api_keys", ...)` — all columns
- `op.create_table("audit_events", ...)` — all columns, JSONB for dicts/lists
- `op.create_table("approval_requests", ...)` — all columns, JSONB for tool_call
- Create all indexes defined in the models

**Note**: `JSONB` requires `from sqlalchemy.dialects.postgresql import JSONB` in the migration.

---

## Group 3 — Redis Client

### 3a. `gateway/cache/__init__.py`
Empty package marker.

### 3b. `gateway/cache/redis_client.py`
```python
# get_redis() -> AsyncGenerator[Redis, None]   FastAPI dependency
# Typed helpers:
#   set_json(client, key, value: dict, ttl: int) -> None
#   get_json(client, key) -> dict | None
#   delete(client, key) -> None
```
- Use `redis.asyncio.Redis.from_url(settings.redis_url, decode_responses=True)`
- `set_json` must always set TTL — never store without expiry (security invariant)

### 3c. Unit test: `tests/unit/test_redis_client.py`
- Use `fakeredis.aioredis.FakeRedis` as the client
- Test `set_json → get_json` roundtrip
- Test TTL expiry (fakeredis supports time manipulation)
- Test `get_json` returns `None` for missing key
- Mark `@pytest.mark.unit`

---

## Group 4 — Audit Layer

### 4a. `gateway/audit/__init__.py`
Empty package marker.

### 4b. `gateway/audit/logger.py`
```python
class AuditLogger:
    def __init__(self, session: AsyncSession) -> None: ...
    async def write(self, event: AuditEvent) -> None:
        # Map AuditEvent → AuditEventRow
        # session.add(row); await session.commit()
        # NEVER store raw args — AuditEvent already enforces raw_args_hash
```
- Must be safe to call even if the request errored (no exceptions should propagate out)
- Wrap commit in try/except — log error but do not re-raise (audit must not crash the pipeline)

### 4c. `gateway/audit/query.py`
```python
class AuditQuery:
    def __init__(self, session: AsyncSession) -> None: ...
    async def get_by_request_id(self, request_id: str) -> AuditEvent | None: ...
    async def list_by_caller(self, caller_id: str, limit: int = 50, offset: int = 0) -> list[AuditEvent]: ...
    async def list_by_decision(self, decision: str, limit: int = 50) -> list[AuditEvent]: ...
    async def list_recent(self, limit: int = 100) -> list[AuditEvent]: ...
```
- All queries ordered by `timestamp DESC`
- Return Pydantic `AuditEvent` objects (not ORM rows) — convert in query methods

### 4d. Unit test: `tests/unit/test_audit_logger.py`
- Mock `AsyncSession` (use `unittest.mock.AsyncMock`)
- Verify `write()` calls `session.add()` with an `AuditEventRow`
- Verify `raw_args_hash` is stored, not raw args
- Verify `write()` does not raise even when `session.commit()` raises
- Mark `@pytest.mark.unit`

---

## Group 5 — Approval Layer

### 5a. `gateway/approval/__init__.py`
Empty package marker.

### 5b. `gateway/approval/manager.py`
```python
class ApprovalManager:
    def __init__(self, session: AsyncSession, redis: Redis) -> None: ...

    async def issue_token(self, request: ApprovalRequest) -> str:
        # 1. Store full ApprovalRequest JSON in Redis with TTL
        #    key = f"approval:{request.token}"
        #    ttl = settings.approval_token_ttl_seconds
        # 2. Store ApprovalRequestRow in Postgres for durability
        # 3. Return request.token

    async def check_token(self, token: str) -> ApprovalResult:
        # 1. Try Redis first (fast path)
        # 2. Fall back to Postgres SELECT if Redis miss
        # 3. Return ApprovalResult; raise ValueError if not found

    async def approve(self, token: str, approver_id: str, note: str = "") -> ApprovalResult:
        # 1. check_token (raises if not found or already decided)
        # 2. Update status=APPROVED in both Redis + Postgres
        # 3. Return ApprovalResult

    async def deny(self, token: str, approver_id: str, note: str = "") -> ApprovalResult:
        # Same as approve but status=DENIED
```
- Tokens are already `secrets.token_urlsafe(32)` from the Pydantic model's `default_factory`
- Redis key pattern: `approval:{token}`
- Always set TTL on Redis writes — never store without expiry

### 5c. `gateway/approval/notifier.py`
```python
class ApprovalNotifier:
    async def notify_pending(self, request: ApprovalRequest) -> None:
        # Stub: log at INFO level
        # Future: POST to webhook URL from settings
        logger.info("APPROVAL_REQUIRED request_id=%s token=%s", request.request_id, "***")

    async def notify_decision(self, result: ApprovalResult) -> None:
        # Stub: log at INFO level
        logger.info("APPROVAL_DECIDED status=%s", result.status)
```
- Never log the token value — log `"***"` or omit

### 5d. Unit test: `tests/unit/test_approval_manager.py`
- Use `fakeredis.aioredis.FakeRedis` + mocked `AsyncSession`
- Test `issue_token → check_token` roundtrip (Redis fast path)
- Test `check_token` Postgres fallback when Redis miss
- Test `approve` updates status in both Redis + Postgres
- Test `deny` updates status
- Test `check_token` raises on unknown token
- Mark `@pytest.mark.unit`

---

## Group 6 — Infrastructure Files

### 6a. `docker-compose.yml`
Services:
- `postgres`: `postgres:17-alpine`, port 5432, volume for data persistence
- `redis`: `redis:7-alpine`, port 6379
- `otel-collector`: `otel/opentelemetry-collector:latest`, port 4317
- `gateway`: build from `Dockerfile` (to be created in Phase 4), depends on postgres+redis

### 6b. `docker-compose.test.yml`
- `postgres` + `redis` only (no gateway, no otel)
- Use separate DB name `gateway_test` to avoid clobbering dev data

### 6c. `.env.example`
```
ENVIRONMENT=dev
DATABASE_URL=postgresql+asyncpg://gateway:gateway@localhost:5432/gateway
REDIS_URL=redis://localhost:6379/0
ANTHROPIC_API_KEY=sk-ant-...
ADMIN_API_KEY=...
APPROVAL_TOKEN_TTL_SECONDS=3600
OTEL_ENABLED=false
```

### 6d. `scripts/seed_policies.py`
- Load `policies/default.yaml`
- Insert a test `ApiKey` row for local dev (caller_id="dev-agent", role="developer", trust_level=2)
- Print the plaintext API key once (never store it — only the bcrypt hash goes in DB)

---

## Group 7 — Integration Tests (requires Docker)

> **Start Docker first**: `docker compose -f docker-compose.test.yml up -d`
> **Run migrations**: `/Users/vinayakkannan/.local/bin/uv run alembic upgrade head`

### 7a. `tests/integration/__init__.py`
Empty package marker.

### 7b. `tests/integration/conftest.py`
```python
# Fixtures:
# - db_engine: create_async_engine pointing at test DB
# - db_session: AsyncSession, rolls back after each test
# - redis_client: real Redis connection to test instance
# - audit_logger: AuditLogger(session)
# - approval_manager: ApprovalManager(session, redis)
```
- Each test gets a clean DB state via rollback (not drop/recreate — faster)

### 7c. `tests/integration/test_audit_logger.py`
- Write an `AuditEvent` → query it back by `request_id`
- Verify `raw_args_hash` stored correctly
- Verify `sanitized_args` JSONB roundtrip
- Verify `list_by_caller` returns correct rows
- Verify `list_by_decision` filters correctly
- Mark `@pytest.mark.integration`

### 7d. `tests/integration/test_approval_manager.py`
- Full `issue → check → approve` flow against real Redis + Postgres
- Verify Redis TTL is set (use `redis.ttl(key)`)
- Verify Postgres fallback when Redis key manually deleted
- Verify cannot approve an already-decided token
- Mark `@pytest.mark.integration`

---

## Run Commands

```bash
# After each group — run unit tests to verify nothing broke
/Users/vinayakkannan/.local/bin/uv run python -m pytest -m unit

# After Group 7 (with Docker running)
docker compose -f docker-compose.test.yml up -d
/Users/vinayakkannan/.local/bin/uv run alembic upgrade head
/Users/vinayakkannan/.local/bin/uv run python -m pytest -m integration
```

---

## CLAUDE.md Updates Needed After Phase 2

Add these entries to the Key File Map table in `CLAUDE.md`:

| What | Where |
|------|-------|
| **SQLAlchemy ORM models** | `gateway/db/models.py` |
| **Async DB session** | `gateway/db/session.py` |
| **Redis client + helpers** | `gateway/cache/redis_client.py` |
| **Audit logger** | `gateway/audit/logger.py` |
| **Audit query** | `gateway/audit/query.py` |
| **Approval manager** | `gateway/approval/manager.py` |
| **Approval notifier** | `gateway/approval/notifier.py` |
