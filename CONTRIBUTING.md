# Contributing — MCP Security Gateway

## Prerequisites

- Python 3.12+
- [uv](https://docs.astral.sh/uv/) (package manager)
- Docker + Docker Compose
- Git

## Setup

```bash
git clone https://github.com/your-org/MCP-Security-Gateway.git
cd MCP-Security-Gateway

# Install dependencies
uv sync

# Start infrastructure (postgres, redis, otel)
docker compose up postgres redis otel-collector -d

# Run database migrations
uv run alembic upgrade head

# Seed example policies
uv run python scripts/seed_policies.py

# Verify everything works
uv run pytest -m unit
```

## Development Workflow

### Running Tests

```bash
uv run pytest -m unit                    # Fast, no external deps (~5s)
uv run pytest -m integration            # Requires Docker stack (~30s)
uv run pytest -m scenario               # Security benchmark scenarios
uv run pytest --cov=gateway             # With coverage report
```

### Code Quality

All of these must pass before submitting a PR:

```bash
uv run ruff check gateway/ tests/       # Linting
uv run ruff format --check gateway/ tests/  # Formatting check
uv run mypy gateway/ --strict           # Type checking
uv run bandit -r gateway/               # Security scan
```

Auto-fix formatting:
```bash
uv run ruff format gateway/ tests/
```

### Running the Full Stack

```bash
docker compose up                       # All services
# Gateway: http://localhost:8000
# API docs: http://localhost:8000/docs
# Dashboard: http://localhost:3000
```

## Commit Conventions

Use [Conventional Commits](https://www.conventionalcommits.org/):

```
feat: add new constraint type for domain allowlists
fix: correct path traversal detection for URL-encoded sequences
test: add scenario for indirect prompt injection
docs: update policy schema reference for sql constraints
refactor: extract common XML parsing into base agent
chore: update anthropic SDK to 0.x.x
```

Types: `feat`, `fix`, `test`, `docs`, `refactor`, `chore`, `perf`, `ci`

## Pull Request Process

1. Create a feature branch from `main`: `git checkout -b feat/your-feature`
2. Make changes, write tests
3. Ensure all quality gates pass (ruff, mypy, bandit, pytest -m unit)
4. Open a PR with a description covering: what changed, why, and how to test
5. PRs must pass CI before merge

## Checklist: Adding a New Tool

- [ ] Add tool schema to `policies/default.yaml` under `tool_schemas`
- [ ] Add at least two rules under `rules`: one DENY for untrusted callers, one ALLOW/APPROVAL_REQUIRED for authorized roles
- [ ] Add unit tests in `tests/unit/test_policy_engine.py` covering: allow (happy path), deny (unauthorized role), deny (constraint violation)
- [ ] Add at least one attack scenario in `tests/scenarios/attack/`
- [ ] Add at least one safe scenario in `tests/scenarios/safe/`
- [ ] Update `docs/policies/policy-schema.md` with the new tool's constraint options

## Checklist: Adding a New Agent

- [ ] Create `gateway/agents/<name>.py` inheriting from `BaseAgent`
- [ ] Define `SYSTEM_PROMPT` as a class-level constant
- [ ] Implement `parse_response(raw: str) -> YourOutputModel` using XML tag extraction
- [ ] Add a configurable timeout via `settings.LLM_TIMEOUT_SECONDS`
- [ ] Export from `gateway/agents/__init__.py`
- [ ] Wire into `gateway/enforcement/pipeline.py` at the appropriate step
- [ ] Add unit tests with mocked LLM responses in `tests/unit/test_<name>.py`
- [ ] Update `CLAUDE.md` Key File Map

## Checklist: Adding a New Policy Constraint Type

- [ ] Add the constraint checker function to `gateway/policy/constraints.py`
- [ ] The function must be a pure function (no I/O, no LLM calls)
- [ ] Add the constraint config type to `gateway/models/policy.py`
- [ ] Wire into `gateway/policy/engine.py` under the appropriate rule matcher
- [ ] Add unit tests in `tests/unit/test_constraints.py`
- [ ] Document the new constraint in `docs/policies/policy-schema.md`

## Architecture Constraints (Read Before Contributing)

See [ARCHITECTURE.md](ARCHITECTURE.md) for full details. Key rules:

1. **PolicyEngine is AUTHORITATIVE** — LLM agents are advisory only
2. **Never store raw tool arguments** — only SHA-256 hashes in audit logs
3. **RedTeamAttackerAgent is test-only** — never deploy in production
4. **No LangChain** — direct Anthropic SDK calls only
5. **Agents do not call each other** — only the pipeline orchestrates agent calls
