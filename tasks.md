# Phase 6 Tasks — UI + Infrastructure

**Status**: Phase 5 complete — 195 unit/scenario tests + 22 integration tests passing.
**Branch**: `phase5` (merge or open PR, then cut `phase6`)

---

## Context for This Session

### Commands
```bash
# Package manager: uv (NOT pip, NOT poetry)
# uv binary: /Users/vinayakkannan/.local/bin/uv
/Users/vinayakkannan/.local/bin/uv sync                                     # install deps
/Users/vinayakkannan/.local/bin/uv run python -m pytest -m unit -v         # unit tests (no Docker)
/Users/vinayakkannan/.local/bin/uv run python -m pytest -m integration -v  # integration (needs Docker)
/Users/vinayakkannan/.local/bin/uv run python -m pytest -m scenario -v     # scenario tests
/Users/vinayakkannan/.local/bin/uv run python -m pytest -v                 # all tests
/Users/vinayakkannan/.local/bin/uv run ruff check gateway/ tests/          # lint
/Users/vinayakkannan/.local/bin/uv run ruff format gateway/ tests/         # format
/Users/vinayakkannan/.local/bin/uv run mypy gateway/ --strict              # type check
# pytest is NOT in PATH — must use `python -m pytest`
# ruff: install with `uv pip install ruff` if missing from venv
```

### Python version: 3.14.3 (managed by uv)

### Architecture invariants (MUST NOT be violated)

1. **PolicyEngine is AUTHORITATIVE** — DENY decisions cannot be overridden by LLM agents
2. **Never store raw tool arguments** — always store `raw_args_hash` (SHA-256 hex)
3. **`RedTeamAttackerAgent` is test-only** — must assert `settings.environment != "prod"` at instantiation; NEVER import in any `gateway/` module (only in `tests/` and `scripts/`)
4. **Audit write (step 9) always runs** — even on DENY or error (finally block)
5. **Agents do not call each other** — only `EnforcementPipeline` orchestrates
6. **No LangChain** — Anthropic SDK or OpenAI-compat SDK (Groq) calls only

---

## Completed Phases (reference only)

| Phase | Tests | Key files |
|-------|-------|-----------|
| **1 — Foundation** | 77 unit | `gateway/policy/`, `gateway/models/`, `policies/default.yaml` |
| **2 — Persistence** | 143 (121u+22i) | `gateway/db/`, `gateway/audit/`, `gateway/approval/`, `gateway/cache/` |
| **3 — LLM Agents** | 153 (131u+22i) | `gateway/agents/base.py`, `risk_classifier.py`, `argument_guard.py` |
| **4 — API + Pipeline** | 202 (180u+22i) | `gateway/enforcement/pipeline.py`, `gateway/main.py`, `gateway/api/v1/` |
| **5 — Benchmark** | 217 (195u+22i) | `gateway/agents/red_team.py`, `tests/scenarios/`, `scripts/run_benchmark.py` |

### Key existing files Phase 6 depends on

| What | Path |
|------|------|
| FastAPI app factory | `gateway/main.py` |
| Health + readyz endpoints | `gateway/api/v1/gateway.py` |
| Audit query (dashboard reads) | `gateway/audit/query.py` |
| Approval endpoints | `gateway/api/v1/approvals.py` |
| Audit endpoints | `gateway/api/v1/audit.py` |
| App settings (incl. otel_enabled, otel_endpoint) | `gateway/config.py` |
| Existing docker-compose (postgres + redis) | `docker-compose.yml` |
| Test docker-compose | `docker-compose.test.yml` |
| Seed script | `scripts/seed_policies.py` |
| Benchmark script | `scripts/run_benchmark.py` |

### LLM provider (already wired)

Groq free tier via OpenAI-compat API. Config in `.env`:
```
LLM_PROVIDER=openai_compat
LLM_BASE_URL=https://api.groq.com/openai/v1
LLM_API_KEY=gsk_...
```

### API surface (already implemented)

| Endpoint | Auth | Description |
|----------|------|-------------|
| `POST /v1/gateway/invoke` | `api_key` in body | Main enforcement endpoint |
| `GET /v1/approvals/{token}` | none | Fetch approval request details |
| `POST /v1/approvals/{token}/approve` | `X-Admin-Key` | Approve a pending request |
| `POST /v1/approvals/{token}/deny` | `X-Admin-Key` | Deny a pending request |
| `GET /v1/audit/` | `X-Admin-Key` | List recent audit events |
| `GET /v1/audit/{request_id}` | `X-Admin-Key` | Fetch single audit event |
| `GET /health` | none | Liveness probe |
| `GET /readyz` | none | Readiness probe (checks DB + Redis) |

---

## Phase 6 — UI + Infrastructure

### Goals

1. **React dashboard** — real-time view of audit events and approval queue, served at `http://localhost:3000`
2. **Full Docker Compose stack** — add `ui`, `otel-collector`, `grafana`, and `jaeger` services to the existing `docker-compose.yml`
3. **OpenTelemetry instrumentation** — wire `gateway/observability/otel.py` into `gateway/main.py` so traces and metrics flow to the collector when `OTEL_ENABLED=true`
4. **GitHub Actions CI/CD** — lint → type-check → unit tests → scenario tests on every PR; integration tests on merge to `main`
5. **Makefile** — developer-friendly aliases for common commands

---

## Group 1 — OpenTelemetry Instrumentation

### `gateway/observability/__init__.py`
Empty.

### `gateway/observability/otel.py`

Wire OpenTelemetry tracing into the FastAPI app. The packages are already installed (`opentelemetry-sdk`, `opentelemetry-instrumentation-fastapi`).

```python
"""OpenTelemetry setup — call configure_otel(app, settings) in main.py lifespan."""
from fastapi import FastAPI
from gateway.config import Settings

def configure_otel(app: FastAPI, settings: Settings) -> None:
    """Attach OTel tracing to the FastAPI app if OTEL_ENABLED=true.

    No-ops silently if otel_enabled is False so tests and local dev are unaffected.
    Uses OTLP gRPC exporter pointing at settings.otel_endpoint.
    """
    ...
```

Call `configure_otel(app, settings)` inside `create_app()` in `gateway/main.py` after the app is created.

Add unit test `tests/unit/test_otel.py`:
- `configure_otel` is a no-op when `settings.otel_enabled = False`
- `configure_otel` does not raise when `settings.otel_enabled = True` (mock the SDK)

---

## Group 2 — React Dashboard UI

### Directory: `ui/`

A minimal React + TypeScript single-page app. Use **Vite** as the build tool.

```
ui/
  package.json          # Vite + React + TypeScript + shadcn/ui + axios
  vite.config.ts
  tsconfig.json
  index.html
  src/
    main.tsx
    App.tsx
    api/
      client.ts         # axios instance pointed at VITE_API_BASE_URL
      audit.ts          # GET /v1/audit/ → AuditEvent[]
      approvals.ts      # GET/POST /v1/approvals/:token
    components/
      AuditTable.tsx    # Paginated table of audit events (request_id, tool, decision, latency_ms)
      ApprovalCard.tsx  # Shows pending approval details + Approve/Deny buttons
      DecisionBadge.tsx # Colour-coded ALLOW/DENY/APPROVAL_REQUIRED/SANITIZE_AND_ALLOW
    pages/
      AuditPage.tsx     # Wraps AuditTable, auto-refreshes every 5s
      ApprovalsPage.tsx # Lists PENDING approvals from audit log
    App.tsx             # React Router: / → AuditPage, /approvals → ApprovalsPage
```

**Design constraints:**
- No auth UI — the `X-Admin-Key` is injected via `VITE_ADMIN_KEY` env var at build time (dev only; not for production deployments)
- Auto-refresh audit table every 5 seconds (`useEffect` + `setInterval`)
- DecisionBadge: ALLOW = green, DENY = red, APPROVAL_REQUIRED = amber, SANITIZE_AND_ALLOW = blue
- AuditTable columns: timestamp, caller_id, tool_name, decision (badge), matched_policy_rule, latency_ms

---

## Group 3 — Full Docker Compose Stack

### Updated `docker-compose.yml`

Add services to the existing file:

```yaml
services:
  # --- existing ---
  gateway:      # FastAPI on :8000
  postgres:     # PostgreSQL on :5432
  redis:        # Redis on :6379

  # --- new ---
  ui:
    build: ./ui
    ports: ["3000:80"]   # nginx serves the built Vite bundle
    environment:
      - VITE_API_BASE_URL=http://localhost:8000
    depends_on: [gateway]

  otel-collector:
    image: otel/opentelemetry-collector-contrib:latest
    ports: ["4317:4317"]   # gRPC receiver
    volumes: ["./otel-collector-config.yaml:/etc/otel/config.yaml"]
    command: ["--config=/etc/otel/config.yaml"]

  jaeger:
    image: jaegertracing/all-in-one:latest
    ports:
      - "16686:16686"   # Jaeger UI
      - "14250:14250"   # gRPC from collector

  grafana:
    image: grafana/grafana:latest
    ports: ["3001:3000"]
    volumes: ["grafana_data:/var/lib/grafana"]
    environment:
      - GF_SECURITY_ADMIN_PASSWORD=admin
```

Also create:
- `otel-collector-config.yaml` — receives from gateway (4317), exports to Jaeger (14250)
- `ui/Dockerfile` — multi-stage: `node:20-alpine` build → `nginx:alpine` serve
- `ui/nginx.conf` — SPA fallback: `try_files $uri /index.html`

---

## Group 4 — GitHub Actions CI/CD

### `.github/workflows/ci.yml`

```yaml
name: CI
on:
  push:
    branches: [main]
  pull_request:

jobs:
  lint-and-typecheck:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: astral-sh/setup-uv@v3
      - run: uv sync
      - run: uv run ruff check gateway/ tests/
      - run: uv run mypy gateway/ --strict

  unit-and-scenario:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: astral-sh/setup-uv@v3
      - run: uv sync
      - run: uv run python -m pytest -m "unit or scenario" -v --tb=short

  integration:
    runs-on: ubuntu-latest
    if: github.ref == 'refs/heads/main'   # only on merge to main
    services:
      postgres:
        image: postgres:16
        env:
          POSTGRES_USER: gateway
          POSTGRES_PASSWORD: gateway
          POSTGRES_DB: gateway
        options: >-
          --health-cmd pg_isready
          --health-interval 10s
          --health-timeout 5s
          --health-retries 5
        ports: ["5432:5432"]
      redis:
        image: redis:7
        ports: ["6379:6379"]
    steps:
      - uses: actions/checkout@v4
      - uses: astral-sh/setup-uv@v3
      - run: uv sync
      - run: uv run alembic upgrade head
        env:
          DATABASE_URL: postgresql+asyncpg://gateway:gateway@localhost:5432/gateway
      - run: uv run python -m pytest -m integration -v --tb=short
        env:
          DATABASE_URL: postgresql+asyncpg://gateway:gateway@localhost:5432/gateway
          REDIS_URL: redis://localhost:6379/0
```

---

## Group 5 — Makefile

### `Makefile`

```makefile
UV := /Users/vinayakkannan/.local/bin/uv

.PHONY: install test test-unit test-scenario test-integration lint fmt typecheck up down migrate seed benchmark

install:
	$(UV) sync

test:
	$(UV) run python -m pytest -v

test-unit:
	$(UV) run python -m pytest -m unit -v

test-scenario:
	$(UV) run python -m pytest -m scenario -v

test-integration:
	$(UV) run python -m pytest -m integration -v

lint:
	$(UV) run ruff check gateway/ tests/

fmt:
	$(UV) run ruff format gateway/ tests/

typecheck:
	$(UV) run mypy gateway/ --strict

up:
	docker compose up -d

down:
	docker compose down

migrate:
	$(UV) run alembic upgrade head

seed:
	$(UV) run python scripts/seed_policies.py

benchmark:
	$(UV) run python scripts/run_benchmark.py
```

---

## New files to create

| File | Description |
|------|-------------|
| `gateway/observability/__init__.py` | Empty |
| `gateway/observability/otel.py` | `configure_otel(app, settings)` — OTel setup |
| `tests/unit/test_otel.py` | Unit tests for OTel setup (SDK mocked) |
| `ui/package.json` | Vite + React + TypeScript dependencies |
| `ui/vite.config.ts` | Vite config with proxy to `:8000` |
| `ui/tsconfig.json` | TypeScript config |
| `ui/index.html` | Entry HTML |
| `ui/src/main.tsx` | React root mount |
| `ui/src/App.tsx` | React Router with two pages |
| `ui/src/api/client.ts` | axios base instance |
| `ui/src/api/audit.ts` | Audit API calls |
| `ui/src/api/approvals.ts` | Approval API calls |
| `ui/src/components/AuditTable.tsx` | Paginated audit table |
| `ui/src/components/ApprovalCard.tsx` | Approval detail + action buttons |
| `ui/src/components/DecisionBadge.tsx` | Colour-coded decision pill |
| `ui/src/pages/AuditPage.tsx` | Auto-refreshing audit page |
| `ui/src/pages/ApprovalsPage.tsx` | Approval queue page |
| `ui/Dockerfile` | Multi-stage build: node→nginx |
| `ui/nginx.conf` | SPA fallback config |
| `docker-compose.yml` | Updated — add ui, otel-collector, jaeger, grafana |
| `otel-collector-config.yaml` | OTLP receiver + Jaeger exporter |
| `.github/workflows/ci.yml` | Lint + unit + scenario + integration CI |
| `Makefile` | Developer convenience targets |

---

## Run Commands

```bash
# Unit + scenario tests (no Docker)
/Users/vinayakkannan/.local/bin/uv run python -m pytest -m "unit or scenario" -v

# Full stack
docker compose up -d
# Gateway:  http://localhost:8000/docs
# Dashboard: http://localhost:3000
# Jaeger:   http://localhost:16686
# Grafana:  http://localhost:3001

# CI equivalent (local)
/Users/vinayakkannan/.local/bin/uv run ruff check gateway/ tests/
/Users/vinayakkannan/.local/bin/uv run mypy gateway/ --strict
/Users/vinayakkannan/.local/bin/uv run python -m pytest -m "unit or scenario" -v
```

---

## Notes

- The `otel_enabled` flag and `otel_endpoint` setting already exist in `gateway/config.py`. OTel SDK packages (`opentelemetry-sdk`, `opentelemetry-instrumentation-fastapi`) are already installed.
- The `docker-compose.yml` already has `gateway`, `postgres`, and `redis` services from Phase 2. Only add/update services; do not remove what's there.
- The Vite dev server proxy (`/v1 → http://localhost:8000`) lets the UI work without CORS issues during local development.
- `VITE_ADMIN_KEY` is a build-time env var — acceptable for a local dev dashboard, not for production.
- Before implementing `configure_otel`, read `gateway/main.py` to understand the `create_app` / `lifespan` pattern so OTel is initialized at the right lifecycle point.
- Phase 6 is the final phase. When complete, update `tasks.md` with a note that the project is done.
