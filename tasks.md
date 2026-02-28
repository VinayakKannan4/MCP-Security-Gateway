# Phase 4 Tasks — API + Enforcement Pipeline

**Status**: Not started — 153/153 tests passing from Phase 3 (131 unit + 22 integration).
**Branch**: `phase3` (open PR or merge, then cut `phase4`)

---

## Context for This Session

### Commands
```bash
# Package manager: uv (NOT pip, NOT poetry)
# uv binary: /Users/vinayakkannan/.local/bin/uv
/Users/vinayakkannan/.local/bin/uv sync                                     # install deps
/Users/vinayakkannan/.local/bin/uv run python -m pytest -m unit -v         # unit tests (no Docker)
/Users/vinayakkannan/.local/bin/uv run python -m pytest -m integration -v  # integration (needs Docker)
/Users/vinayakkannan/.local/bin/uv run python -m pytest -v                 # all tests
/Users/vinayakkannan/.local/bin/uv run mypy gateway/ --strict              # type check
/Users/vinayakkannan/.local/bin/uv run ruff check gateway/ tests/          # lint
# pytest is NOT in PATH — must use `python -m pytest`
```

### Python version: 3.14.3 (managed by uv)

### Key existing files Phase 4 depends on

| What | Path |
|------|------|
| Pydantic models (MCPRequest, ToolCall, GatewayResponse) | `gateway/models/mcp.py` |
| RiskAssessment, RiskLabel | `gateway/models/risk.py` |
| PolicyDecision, DecisionEnum | `gateway/models/policy.py` |
| AuditEvent, RedactionFlag | `gateway/models/audit.py` |
| CallerIdentity, TrustLevel | `gateway/models/identity.py` |
| ApprovalRequest, ApprovalStatus | `gateway/models/approval.py` |
| App settings (Settings class) | `gateway/config.py` |
| Policy engine (deterministic, AUTHORITATIVE) | `gateway/policy/engine.py` |
| Schema validator | `gateway/policy/schema_validator.py` |
| YAML policy loader | `gateway/policy/loader.py` |
| RiskClassifierAgent | `gateway/agents/risk_classifier.py` |
| ArgumentGuardAgent | `gateway/agents/argument_guard.py` |
| BaseAgent | `gateway/agents/base.py` |
| AuditLogger (write) + AuditQuery (read) | `gateway/audit/` |
| ApprovalManager + Notifier | `gateway/approval/` |
| SQLAlchemy ORM models (ApiKey, AuditEventRow, ApprovalRequestRow) | `gateway/db/models.py` |
| Async DB session + Base | `gateway/db/session.py` |
| Redis client | `gateway/cache/redis_client.py` |
| Default policy | `policies/default.yaml` |

### Architecture invariants (MUST NOT be violated)

1. **PolicyEngine is AUTHORITATIVE** — `_evaluate_policy` result is final. LLM risk score from step 4 is advisory only. A DENY cannot be overridden.
2. **Never store raw tool arguments** — always store `raw_args_hash` (SHA-256 hex). Sanitized args may be stored.
3. **`_write_audit` always runs** — wrap `pipeline.run()` in `try/finally`. Runs even if `_execute` raises.
4. **Agents do not call each other** — only `EnforcementPipeline` routes calls between agents.
5. **No LangChain** — Anthropic SDK or OpenAI-compat SDK (Groq) calls only.
6. **DENY skips steps 6–8** — `_sanitize_arguments`, `_check_approval`, and `_execute` are skipped.

### Existing DB schema (from `gateway/db/models.py`)

`api_keys` table columns relevant to `_resolve_identity`:
- `key_hash: str` — bcrypt hash of the API key
- `caller_id: str`
- `role: str` — e.g. `"analyst"`, `"developer"`, `"admin"`
- `trust_level: str` — from `TrustLevel` enum
- `environment: str` — `"dev"` | `"staging"` | `"prod"`
- `is_active: bool`

`_resolve_identity` must:
1. Query `api_keys` where `is_active = true`
2. Iterate rows and bcrypt-compare `request.api_key` against each `key_hash`
3. Return `CallerIdentity` on match; raise `HTTPException(401)` if none match or inactive

### LLM provider (already wired in Phase 3)

Groq free tier via OpenAI-compat API. Config in `.env`:
```
LLM_PROVIDER=openai_compat
LLM_BASE_URL=https://api.groq.com/openai/v1
LLM_API_KEY=gsk_...
```
- `RiskClassifierAgent` uses `settings.risk_classifier_model` (default: `llama-3.3-70b-versatile`)
- `ArgumentGuardAgent` uses `settings.argument_guard_model` (default: `llama-3.1-8b-instant`)
- Unit tests mock `_call` — no real API key needed

---

## Phase 3 Complete ✅

All 4 groups done:
- `BaseAgent` — provider-aware (Anthropic or OpenAI-compat/Groq), retry loop, `_extract_tag`
- `RiskClassifierAgent` — heuristic fast-path (score >= 0.8 skips LLM) + `llama-3.3-70b-versatile` fallback
- `ArgumentGuardAgent` — deterministic PII/secret redaction + `llama-3.1-8b-instant` LLM review
- Unit tests — 32 new tests, all agents mocked

---

## Phase 4 — API + Enforcement Pipeline

Wire all phases into the full 10-step request lifecycle. New files to create:

| File | What it does |
|------|------|
| `gateway/enforcement/pipeline.py` | 10-step `EnforcementPipeline.run()` |
| `gateway/enforcement/executor.py` | `MCPExecutor` — HTTP forward to upstream MCP server |
| `gateway/enforcement/errors.py` | `MCPToolError`, `MCPTimeoutError` exception types |
| `gateway/main.py` | FastAPI app factory with lifespan |
| `gateway/api/v1/gateway.py` | `POST /v1/gateway/invoke` endpoint |
| `gateway/api/v1/approvals.py` | Approval CRUD endpoints (admin-gated) |
| `gateway/api/v1/audit.py` | Audit query endpoints (admin-gated) |
| `gateway/api/deps.py` | FastAPI `Depends()` providers |

---

## Group 1 — EnforcementPipeline

### `gateway/enforcement/errors.py`

```python
class MCPToolError(Exception):
    """Raised when the upstream MCP server returns a non-2xx response."""
    def __init__(self, status_code: int, body: str) -> None: ...

class MCPTimeoutError(Exception):
    """Raised when the upstream MCP server call exceeds mcp_tool_timeout_seconds."""
```

### `gateway/enforcement/pipeline.py`

```python
import hashlib, time
from datetime import datetime

class EnforcementPipeline:
    def __init__(
        self,
        settings: Settings,
        db: AsyncSession,
        redis: RedisClient,
        risk_classifier: RiskClassifierAgent,
        argument_guard: ArgumentGuardAgent,
        policy_engine: PolicyEngine,
        audit_logger: AuditLogger,
        approval_manager: ApprovalManager,
        executor: MCPExecutor,
    ) -> None: ...

    async def run(self, request: MCPRequest) -> GatewayResponse:
        """Execute all 10 steps. _write_audit runs in finally block."""
        ...
```

#### Step-by-step implementation notes

**Step 1 — `_validate_ingress`**
- Input is already a parsed `MCPRequest` (FastAPI handles JSON parsing)
- Validate that `tool_call.tool` is a non-empty string, `tool_call.server` is non-empty
- Raise `HTTPException(422)` for invalid envelope

**Step 2 — `_resolve_identity`**
- Query `api_keys` table: `SELECT * FROM api_keys WHERE is_active = true`
- For each row: `bcrypt.checkpw(request.api_key.encode(), row.key_hash.encode())`
- On match: return `CallerIdentity(caller_id=row.caller_id, role=row.role, trust_level=TrustLevel(row.trust_level), environment=row.environment)`
- No match: raise `HTTPException(401, detail="Invalid or inactive API key")`
- Import: `import bcrypt` (already in dependencies)

**Step 3 — `_validate_schema`**
- Delegate to existing `SchemaValidator(policy_config).validate(request.tool_call)`
- `SchemaValidator` is in `gateway/policy/schema_validator.py`
- On failure: raise `HTTPException(422, detail=validation_error_message)`

**Step 4 — `_classify_risk`**
- Call `await self._risk_classifier.classify(request.tool_call, context=request.context)`
- Returns `RiskAssessment` — **advisory only, stored in audit log, does NOT affect policy decision**

**Step 5 — `_evaluate_policy`**
- Call `self._policy_engine.evaluate(request.tool_call, identity)`
- Returns `PolicyDecision` — **this is the authoritative final decision**
- If `decision == DecisionEnum.DENY`: skip steps 6–8, go directly to step 9

**Step 6 — `_sanitize_arguments`** (skipped if DENY)
- Call `await self._argument_guard.sanitize(request.tool_call)`
- Returns `(sanitized_args, redaction_flags)`

**Step 7 — `_check_approval`** (skipped if DENY)
- If `decision == DecisionEnum.APPROVAL_REQUIRED`:
  - Check if `request.approval_token` is set → if so, verify it via `ApprovalManager.check_token()`
  - If token is APPROVED: continue to step 8
  - If token is PENDING/DENIED or no token: call `ApprovalManager.issue_token()`, return early `GatewayResponse` with `decision=APPROVAL_REQUIRED` and `approval_token` set
  - `_write_audit` must still run (in `finally`)

**Step 8 — `_execute`** (skipped if DENY or APPROVAL_REQUIRED without approved token)
- Call `await self._executor.forward(request.tool_call.server, request.tool_call.tool, sanitized_args)`
- Returns `dict[str, Any]` tool output
- Let `MCPToolError` and `MCPTimeoutError` propagate — they are caught in `run()` and turned into `GatewayResponse` with decision=DENY and an error message; audit still written

**Step 9 — `_write_audit`** (ALWAYS runs — in `finally`)
```python
event = AuditEvent(
    request_id=request.request_id,
    trace_id=request.trace_id,
    timestamp=datetime.utcnow(),
    caller_id=identity.caller_id,
    caller_role=identity.role,
    environment=identity.environment,
    mcp_server=request.tool_call.server,
    tool_name=request.tool_call.tool,
    raw_args_hash=hashlib.sha256(json.dumps(request.tool_call.arguments, sort_keys=True).encode()).hexdigest(),
    sanitized_args=sanitized_args,       # {} if step 6 was skipped
    risk_labels=[l.value for l in risk.labels],
    risk_score=risk.score,
    matched_policy_rule=decision.matched_rule,
    decision=decision.decision.value,
    latency_ms=int((time.monotonic() - start_time) * 1000),
    redaction_flags=redaction_flags,     # [] if step 6 was skipped
    deterministic_rationale=decision.rationale,
)
await self._audit_logger.write(event)
```

**Step 10 — `_build_response`**
```python
return GatewayResponse(
    request_id=request.request_id,
    decision=decision.decision,
    result=tool_output,                  # None if not executed
    sanitized_args=sanitized_args,       # None if DENY
    approval_token=approval_token,       # None unless APPROVAL_REQUIRED
    policy_explanation=decision.rationale,
    risk_labels=[l.value for l in risk.labels],
    latency_ms=event.latency_ms,
)
```

---

## Group 2 — MCPExecutor

### `gateway/enforcement/executor.py`

```python
import httpx
from gateway.enforcement.errors import MCPToolError, MCPTimeoutError

class MCPExecutor:
    def __init__(self, settings: Settings) -> None:
        self._base_urls: dict[str, str] = settings.mcp_server_base_urls
        self._client = httpx.AsyncClient(timeout=settings.mcp_tool_timeout_seconds)

    async def forward(
        self,
        server: str,
        tool: str,
        sanitized_args: dict[str, Any],
    ) -> dict[str, Any]:
        base_url = self._base_urls.get(server)
        if base_url is None:
            raise MCPToolError(404, f"Unknown MCP server: {server!r}")
        url = f"{base_url.rstrip('/')}/tools/{tool}"
        try:
            response = await self._client.post(url, json=sanitized_args)
        except httpx.TimeoutException as exc:
            raise MCPTimeoutError(f"Timeout calling {server}/{tool}") from exc
        if response.status_code >= 300:
            raise MCPToolError(response.status_code, response.text)
        return response.json()
```

New config fields to add to `gateway/config.py`:
```python
mcp_server_base_urls: dict[str, str] = Field(default_factory=dict)
# e.g. {"filesystem-mcp": "http://localhost:9001"}
mcp_tool_timeout_seconds: float = 30.0
```

---

## Group 3 — FastAPI App + Endpoints

### `gateway/main.py`

```python
from contextlib import asynccontextmanager
from fastapi import FastAPI

@asynccontextmanager
async def lifespan(app: FastAPI):
    # startup: init DB engine, Redis, load policy, build agent + pipeline singletons
    # store on app.state so deps can access them
    yield
    # shutdown: close DB pool, close Redis

def create_app(settings: Settings | None = None) -> FastAPI:
    app = FastAPI(title="MCP Security Gateway", lifespan=lifespan)
    app.include_router(gateway_router, prefix="/v1/gateway")
    app.include_router(approvals_router, prefix="/v1/approvals")
    app.include_router(audit_router, prefix="/v1/audit")

    @app.get("/health")
    async def health() -> dict[str, str]:
        return {"status": "ok"}

    @app.get("/readyz")
    async def readyz() -> dict[str, str]:
        # check DB + Redis connectivity
        return {"status": "ready"}

    return app
```

### `gateway/api/v1/gateway.py`

```python
@router.post("/invoke", response_model=GatewayResponse)
async def invoke(
    request: MCPRequest,
    pipeline: EnforcementPipeline = Depends(get_pipeline),
) -> GatewayResponse:
    return await pipeline.run(request)
```

### `gateway/api/v1/approvals.py`

All endpoints require `X-Admin-Key` header = `settings.admin_api_key`.

```python
@router.get("/{token}", response_model=ApprovalRequest)
async def get_approval(token: str, manager=Depends(get_approval_manager)) -> ApprovalRequest:
    return await manager.check_token(token)

@router.post("/{token}/approve", response_model=ApprovalRequest)
async def approve(token: str, approver_id: str, manager=Depends(get_approval_manager)) -> ApprovalRequest:
    return await manager.approve(token, approver_id)

@router.post("/{token}/deny", response_model=ApprovalRequest)
async def deny(token: str, approver_id: str, manager=Depends(get_approval_manager)) -> ApprovalRequest:
    return await manager.deny(token, approver_id)
```

### `gateway/api/v1/audit.py`

All endpoints require `X-Admin-Key` header.

```python
@router.get("/", response_model=list[AuditEvent])
async def list_recent(limit: int = 50, query=Depends(get_audit_query)) -> list[AuditEvent]:
    return await query.list_recent(limit=limit)

@router.get("/{request_id}", response_model=AuditEvent)
async def get_event(request_id: str, query=Depends(get_audit_query)) -> AuditEvent:
    event = await query.get_by_request_id(request_id)
    if event is None:
        raise HTTPException(404)
    return event
```

---

## Group 4 — Dependencies + Auth

### `gateway/api/deps.py`

```python
from fastapi import Depends, Header, HTTPException, Request
from sqlalchemy.ext.asyncio import AsyncSession

async def get_db(request: Request) -> AsyncGenerator[AsyncSession, None]:
    """Yield a new DB session per request."""
    async with request.app.state.db_sessionmaker() as session:
        yield session

async def get_redis(request: Request) -> RedisClient:
    return request.app.state.redis

async def get_pipeline(
    request: Request,
    db: AsyncSession = Depends(get_db),
    redis: RedisClient = Depends(get_redis),
) -> EnforcementPipeline:
    """Build pipeline with per-request DB session; agents are singletons on app.state."""
    return EnforcementPipeline(
        settings=request.app.state.settings,
        db=db,
        redis=redis,
        risk_classifier=request.app.state.risk_classifier,
        argument_guard=request.app.state.argument_guard,
        policy_engine=request.app.state.policy_engine,
        audit_logger=AuditLogger(db),
        approval_manager=ApprovalManager(redis, db, request.app.state.settings),
        executor=request.app.state.executor,
    )

async def require_admin(
    x_admin_key: str = Header(...),
    request: Request = None,
) -> None:
    if x_admin_key != request.app.state.settings.admin_api_key:
        raise HTTPException(403, detail="Invalid admin key")
```

Auth note: Bearer token (`Authorization: Bearer <api_key>`) is validated inside `_resolve_identity` in the pipeline, not as HTTP middleware. This keeps auth in the audit trail.

---

## Group 5 — Unit + Integration Tests

### `tests/unit/test_pipeline.py`

Mock all dependencies (DB, Redis, agents, executor). Cover:
- DENY decision → steps 6–8 skipped, `_write_audit` still called
- ALLOW decision → all 10 steps run in order, `GatewayResponse.decision == ALLOW`
- APPROVAL_REQUIRED without token → returns early with `approval_token` set, audit written
- APPROVAL_REQUIRED with valid approved token → continues to execute
- `_execute` raises `MCPToolError` → `_write_audit` still called (finally block)
- Unknown API key → `HTTPException(401)` raised in `_resolve_identity`
- Risk assessment `llm_consulted` flag propagated to `AuditEvent.risk_labels`
- `raw_args_hash` in audit event is SHA-256 of the original (pre-sanitization) args

### `tests/unit/test_executor.py`

Mock `httpx.AsyncClient`. Cover:
- Successful POST → returns parsed JSON dict
- Non-2xx response → raises `MCPToolError` with correct status code
- `httpx.TimeoutException` → raises `MCPTimeoutError`
- Unknown server name (not in `mcp_server_base_urls`) → raises `MCPToolError(404, ...)`

### `tests/integration/test_pipeline_integration.py`

Requires Docker stack (`docker compose -f docker-compose.test.yml up -d`). Cover:
- Full ALLOW flow end-to-end: audit event persisted to DB with `decision="ALLOW"`
- Full DENY flow: audit event persisted with `decision="DENY"`, no tool execution
- APPROVAL_REQUIRED: approval token written to Redis + Postgres; subsequent request with approved token executes

---

## Run Commands

```bash
# Unit tests (no Docker, no LLM key needed)
/Users/vinayakkannan/.local/bin/uv run python -m pytest -m unit -v

# Integration tests (requires Docker stack)
docker compose -f docker-compose.test.yml up -d
/Users/vinayakkannan/.local/bin/uv run python -m pytest -m integration -v

# All tests
/Users/vinayakkannan/.local/bin/uv run python -m pytest -v

# Type check
/Users/vinayakkannan/.local/bin/uv run mypy gateway/ --strict

# Lint
/Users/vinayakkannan/.local/bin/uv run ruff check gateway/ tests/
```

---

## Notes

- `EnforcementPipeline` is the only place that calls agents — agents never call each other
- Agent instances (`RiskClassifierAgent`, `ArgumentGuardAgent`) are **stateless singletons** — create once in `lifespan`, store on `app.state`, reuse across requests
- `PolicyEngine` and `MCPExecutor` are also singletons on `app.state`
- `AuditLogger` and `ApprovalManager` take a **per-request** `AsyncSession` — do not reuse sessions across requests
- The bcrypt check in `_resolve_identity` is O(n×cost) where n = number of API keys — cache by SHA-256(api_key) in Redis with a short TTL (e.g. 60s) if performance matters
- `mcp_server_base_urls` is a `dict[str, str]` in Settings; set via env as JSON: `MCP_SERVER_BASE_URLS={"filesystem-mcp":"http://localhost:9001"}`
- Phase 5 will add `RedTeamAttackerAgent` (test-only, assert `ENVIRONMENT != "prod"`) and the 10-scenario benchmark suite
