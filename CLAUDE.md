# CLAUDE.md — MCP Security Gateway

## Critical Invariants (NEVER VIOLATE)

1. **PolicyEngine is AUTHORITATIVE.** LLM output cannot override a DENY decision. Step 5 of the pipeline is the final word.
2. **Never store raw tool arguments.** Always store `raw_args_hash` (SHA-256 hex) in the audit log. Sanitized args (post-redaction) may be stored.
3. **RedTeamAttackerAgent is test-only.** Must assert `settings.ENVIRONMENT != "prod"` before instantiation. Never import it in non-test, non-script modules.
4. **Audit writes always happen.** `AuditLogger.write()` runs in step 9 regardless of whether the request was ALLOW, DENY, or errored.
5. **Agents do not call each other.** Only `EnforcementPipeline` (via `coordinator.py`) routes calls between agents. No agent imports another agent.
6. **No LangChain.** Direct Anthropic SDK calls only. This is a deliberate OSS credibility and auditability decision.

---

## Quick Commands

```bash
# Package manager: uv (not pip, not poetry)
# uv binary is at: /Users/vinayakkannan/.local/bin/uv
# Add to PATH: source $HOME/.local/bin/env  OR use full path
/Users/vinayakkannan/.local/bin/uv sync      # Install all deps
/Users/vinayakkannan/.local/bin/uv run python -m pytest -m unit                  # Fast unit tests (no external deps)
/Users/vinayakkannan/.local/bin/uv run python -m pytest -m integration           # Integration tests (requires Docker stack)
/Users/vinayakkannan/.local/bin/uv run python -m pytest -m scenario              # Security benchmark scenarios
/Users/vinayakkannan/.local/bin/uv run python -m pytest                          # All tests
/Users/vinayakkannan/.local/bin/uv run mypy gateway/ --strict                    # Type check
/Users/vinayakkannan/.local/bin/uv run ruff check gateway/ tests/                # Lint
/Users/vinayakkannan/.local/bin/uv run ruff format gateway/ tests/               # Format

# Dev stack
docker compose up                 # Start gateway + postgres + redis + ui + otel
docker compose -f docker-compose.test.yml up -d  # Test stack only

# Database
/Users/vinayakkannan/.local/bin/uv run alembic upgrade head       # Run migrations
/Users/vinayakkannan/.local/bin/uv run alembic revision --autogenerate -m "description"  # New migration

# Benchmark
/Users/vinayakkannan/.local/bin/uv run python scripts/run_benchmark.py   # Run all 10 security scenarios
/Users/vinayakkannan/.local/bin/uv run python scripts/seed_policies.py  # Load example policies
```

---

## Key File Map

| What | Where |
|------|-------|
| **10-step request lifecycle** | `gateway/enforcement/pipeline.py` |
| **Deterministic policy engine** | `gateway/policy/engine.py` |
| **Path/SQL/URL constraint checkers** | `gateway/policy/constraints.py` |
| **YAML policy loader** | `gateway/policy/loader.py` |
| **LLM agent base class** | `gateway/agents/base.py` |
| **Risk classifier** | `gateway/agents/risk_classifier.py` |
| **Argument guard / sanitizer** | `gateway/agents/argument_guard.py` |
| **Approval token manager** | `gateway/approval/manager.py` |
| **Audit logger** | `gateway/audit/logger.py` |
| **Pydantic schemas** | `gateway/models/` |
| **FastAPI app factory** | `gateway/main.py` |
| **Core gateway endpoint** | `gateway/api/v1/gateway.py` |
| **App settings** | `gateway/config.py` |
| **Default policy** | `policies/default.yaml` |

---

## Request Lifecycle (10 Steps)

```
1. validate_ingress()    → parse + type-check MCPRequest
2. resolve_identity()    → lookup CallerIdentity from api_keys table
3. validate_schema()     → check args against tool schema → DENY if invalid
4. classify_risk()       → RiskClassifierAgent (heuristics first, LLM if needed)
5. evaluate_policy()     → PolicyEngine.evaluate() ← AUTHORITATIVE
6. sanitize_arguments()  → ArgumentGuardAgent (skipped if DENY)
7. check_approval()      → if APPROVAL_REQUIRED: issue token, return early
8. execute()             → MCPExecutor.forward() (skipped if DENY)
9. write_audit()         → AuditLogger.write() ← ALWAYS RUNS
10. build_response()     → GatewayResponse with decision + metadata
```

**Step 5 is authoritative.** If DENY, steps 6–8 are skipped. LLM risk score from step 4 is attached to the audit log but cannot change the decision.

---

## LLM Agent Conventions

- All agents inherit from `BaseAgent` in `gateway/agents/base.py`
- Structured output via XML tags in prompts (e.g. `<risk_labels>`, `<explanation>`) — no function calling
- Agents must have a configurable timeout (default 10s via `LLM_TIMEOUT_SECONDS`)
- Log LLM inputs/outputs at `DEBUG` level (not `INFO` — they are verbose)
- LLM never sees: caller_id, raw API keys, internal policy rule names, raw args (only sanitized preview)
- Every agent call returns a typed Pydantic model (never raw strings)

---

## Adding a New Tool

1. Add tool schema to `policies/default.yaml` under `tool_schemas`
2. Add constraint rules under `rules` (at minimum: one deny for untrusted, one allow for authorized roles)
3. Add unit tests in `tests/unit/test_policy_engine.py` (cover allow, deny, and edge cases)
4. Add at least one attack scenario and one safe scenario in `tests/scenarios/`
5. Update `docs/policies/policy-schema.md` if adding a new constraint type

---

## Adding a New Agent

1. Create `gateway/agents/<name>.py` inheriting from `BaseAgent`
2. Define `SYSTEM_PROMPT` as a class constant
3. Implement `parse_response(raw: str) -> YourOutputModel` using XML tag extraction
4. Add to `gateway/agents/__init__.py`
5. Wire into `gateway/enforcement/pipeline.py` at the appropriate step
6. Add unit tests with mocked LLM responses in `tests/unit/test_<name>.py`
7. Update `CLAUDE.md` Key File Map above

---

## Dependency Choices (do not change without discussion)

| Concern | Choice | Reason |
|---------|--------|--------|
| LLM calls | `anthropic` SDK directly | No LangChain — determinism, auditability, OSS credibility |
| DB ORM | SQLAlchemy async + asyncpg | Async-first, typed |
| Redis | `redis[hiredis]` async | Approval token state + rate limiting |
| Config | `pydantic-settings` | Type-safe env vars |
| Migrations | `alembic` | Standard SQLAlchemy migrations |
| Package manager | `uv` | Fast, lockfile-based |
| Linting | `ruff` | Fast, replaces flake8+isort+black |
| Type checking | `mypy --strict` | Catch type errors early |
| Testing | `pytest` + `pytest-asyncio` | Async-native test support |

---

## Security Rules for Code Review

- Never log raw tool arguments (only their SHA-256 hash)
- Never log API keys or approval token values
- All API endpoints except `/health` and `/readyz` require authentication
- Admin endpoints (approvals, audit reads) require a separate admin token
- Approval tokens are cryptographically random (`secrets.token_urlsafe(32)`)
- Redis TTL enforced on all approval tokens
- Exception handlers must never expose stack traces or internal state in responses
