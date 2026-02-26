# Phase 3 Tasks — LLM Agents Layer

**Status**: Not started — 143/143 tests passing from Phase 2 (121 unit + 22 integration).
**Branch**: `phase2` (open PR or merge, then cut `phase3`)

---

## Phase 2 Complete ✅

All 7 groups done:
- DB models + Alembic migrations
- Redis client (TTL-required `set_json`)
- AuditLogger (never raises, never stores raw args) + AuditQuery
- ApprovalManager (Redis fast path + Postgres durability)
- Docker Compose dev + test stacks
- Integration tests (savepoint-based per-test isolation)

---

## Phase 3 — LLM Agents Layer

The agents live in `gateway/agents/`. They make Anthropic SDK calls.
No LangChain. All agents return typed Pydantic models.
Agents do NOT call each other — pipeline.py orchestrates.

---

## Group 1 — BaseAgent

### `gateway/agents/__init__.py`
Empty init — export `BaseAgent`, `RiskClassifierAgent`, `ArgumentGuardAgent`.

### `gateway/agents/base.py`

Abstract class all agents inherit from.

```python
class BaseAgent(ABC):
    def __init__(self, settings: Settings) -> None:
        self._client = AsyncAnthropic(api_key=settings.anthropic_api_key)
        self._model = settings.llm_model
        self._timeout = settings.llm_timeout_seconds
        self._max_retries = settings.llm_max_retries

    async def _call(self, system: str, prompt: str) -> str:
        """Make an Anthropic messages.create call with timeout + retry.
        Returns the raw text of the first content block.
        Raises on final failure (callers handle).
        """
        ...

    @staticmethod
    def _extract_tag(raw: str, tag: str) -> str | None:
        """Return content inside <tag>...</tag>, stripped. None if not found."""
        ...

    @abstractmethod
    def parse_response(self, raw: str) -> BaseModel: ...
```

Key behaviours:
- Retry loop up to `_max_retries` times on `APIError` / timeout
- Log prompt at DEBUG before call, log response at DEBUG after
- LLM never sees: caller_id, raw API keys, policy rule names, raw tool args

---

## Group 2 — RiskClassifierAgent

### `gateway/agents/risk_classifier.py`

Input: `ToolCall`, optional `context: str`
Output: `RiskAssessment` (from `gateway/models/risk.py`)

```python
class RiskClassifierAgent(BaseAgent):
    SYSTEM_PROMPT: ClassVar[str] = """..."""

    async def classify(self, tool_call: ToolCall, context: str | None = None) -> RiskAssessment:
        # 1. Run deterministic heuristics first
        heuristic_result = self._run_heuristics(tool_call)
        if heuristic_result.score >= 0.8:
            return heuristic_result  # skip LLM — fast path

        # 2. Call LLM for nuanced classification
        prompt = self._build_prompt(tool_call, context, heuristic_result)
        raw = await self._call(self.SYSTEM_PROMPT, prompt)
        result = self.parse_response(raw)
        result.llm_consulted = True
        result.triggered_heuristics = heuristic_result.triggered_heuristics
        return result

    def _run_heuristics(self, tool_call: ToolCall) -> RiskAssessment:
        """Regex patterns against serialized args string. Returns score 0.0–1.0.
        Patterns checked:
        - PROMPT_INJECTION: "ignore.*instructions", "system prompt", "jailbreak", etc.
        - PATH_TRAVERSAL: "../", "%2e%2e%2f", "..\\", etc.
        - SHELL_INJECTION: "; rm -rf", "| bash", "$(", "`" etc.
        - PII patterns: email, SSN (XXX-XX-XXXX), credit card (16-digit)
        Score rules:
          - PROMPT_INJECTION → 0.95 (hard high)
          - SHELL_INJECTION  → 0.95
          - PATH_TRAVERSAL   → 0.85
          - PII only         → 0.5
          - None             → 0.0
        """
        ...

    def parse_response(self, raw: str) -> RiskAssessment:
        """Extract <risk_labels>, <risk_score>, <explanation> XML tags."""
        ...
```

**SYSTEM_PROMPT** tells the LLM to:
- Classify the tool call into zero or more `RiskLabel` values
- Output a `risk_score` float between 0.0–1.0
- Explain its reasoning in `<explanation>`
- Never reveal internal policy rules

XML tags in response: `<risk_labels>`, `<risk_score>`, `<explanation>`

---

## Group 3 — ArgumentGuardAgent

### `gateway/agents/argument_guard.py`

Input: `ToolCall`
Output: `tuple[dict[str, Any], list[RedactionFlag]]` (sanitized args, flags)

```python
class ArgumentGuardAgent(BaseAgent):
    SYSTEM_PROMPT: ClassVar[str] = """..."""

    async def sanitize(
        self, tool_call: ToolCall
    ) -> tuple[dict[str, Any], list[RedactionFlag]]:
        # Phase 1: deterministic redaction (always runs)
        sanitized, flags = self._deterministic_sanitize(tool_call.arguments)

        # Phase 2: LLM inspection only if deterministic phase flagged ambiguity
        if self._needs_llm_review(flags, tool_call):
            prompt = self._build_prompt(tool_call, sanitized)
            raw = await self._call(self.SYSTEM_PROMPT, prompt)
            llm_flags = self._parse_llm_flags(raw)
            # Apply LLM-suggested redactions on top of deterministic ones
            sanitized, flags = self._apply_llm_flags(sanitized, flags, llm_flags)

        return sanitized, flags

    def _deterministic_sanitize(
        self, args: dict[str, Any]
    ) -> tuple[dict[str, Any], list[RedactionFlag]]:
        """Regex-based redaction. Patterns:
        - Email addresses → "[REDACTED_EMAIL]"
        - SSN (XXX-XX-XXXX) → "[REDACTED_SSN]"
        - Credit card numbers (16-digit runs) → "[REDACTED_CC]"
        - API key / token patterns (sk-..., Bearer ..., etc.) → "[REDACTED_SECRET]"
        - Path traversal sequences (../*, %2e%2e*) → normalized path
        Flag: original_hash = SHA-256 hex of original value
        """
        ...

    def parse_response(self, raw: str) -> list[dict[str, Any]]:
        """Extract <redaction_flags> XML block → list of {field, reason, original_hash}."""
        ...
```

**SYSTEM_PROMPT** tells the LLM to:
- Inspect tool arguments for PII, secrets, or dangerous patterns
- Suggest any additional fields that should be redacted
- Output `<redaction_flags>` as JSON array inside the tag
- Never fabricate data — only report what's present

---

## Group 4 — Unit Tests

### `tests/unit/test_base_agent.py`
- `_extract_tag` finds tag content correctly
- `_extract_tag` returns None for missing tags
- `_call` returns text on success (mock `AsyncAnthropic`)
- `_call` retries up to `max_retries` on `APIError`
- `_call` raises after exhausting retries

### `tests/unit/test_risk_classifier.py`
- Heuristic path: prompt injection pattern → score >= 0.8, LLM not called
- Heuristic path: shell injection → score >= 0.8, LLM not called
- Heuristic path: path traversal → score >= 0.8, LLM not called
- Heuristic path: no patterns → score 0.0, LLM called
- LLM path: `parse_response` correctly extracts XML tags → `RiskAssessment`
- LLM path: `parse_response` handles missing tags with safe defaults
- PII heuristic: email in args → `PII_SENSITIVE` label + score 0.5
- `llm_consulted=True` only when LLM was actually called

### `tests/unit/test_argument_guard.py`
- Email in args → redacted to `[REDACTED_EMAIL]` + `RedactionFlag` with reason `PII_EMAIL`
- SSN pattern → redacted + flagged
- API key pattern → redacted + flagged with reason `SECRET_TOKEN`
- Path traversal → normalized + flagged
- Clean args → empty flags, args unchanged
- `_needs_llm_review` returns False for empty flags (no LLM call on clean args)
- LLM path invoked when flags present (mock LLM response with additional flag)
- `original_hash` in flag is SHA-256 of original value (not `[REDACTED_*]`)

---

## Run Commands

```bash
# Unit tests (no Docker, no LLM key needed — all agents mocked)
/Users/vinayakkannan/.local/bin/uv run python -m pytest -m unit -v

# All tests (integration requires Docker)
/Users/vinayakkannan/.local/bin/uv run python -m pytest -v

# Type check
/Users/vinayakkannan/.local/bin/uv run mypy gateway/ --strict

# Lint
/Users/vinayakkannan/.local/bin/uv run ruff check gateway/ tests/
```

---

## Notes

- No real Anthropic API key needed for unit tests — mock `AsyncAnthropic` using `unittest.mock.AsyncMock`
- Agents must NOT be tested with live API calls in the unit suite — always mock `_call`
- If you want to do a live smoke test: set `ANTHROPIC_API_KEY` in `.env` and call `classify()` manually in a scratch script
- Phase 4 will wire these agents into `gateway/enforcement/pipeline.py`

---

## CLAUDE.md — already updated ✅

Key File Map already has entries for all Phase 3 files (`gateway/agents/`).
