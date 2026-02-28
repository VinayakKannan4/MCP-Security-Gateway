"""Unit tests for ArgumentGuardAgent.

All LLM calls are mocked — no real API key required.
Covers: deterministic redaction, LLM path, original_hash integrity, clean args.
"""

import hashlib
from unittest.mock import AsyncMock, patch

import pytest

from gateway.agents.argument_guard import ArgumentGuardAgent
from gateway.config import Settings
from gateway.models.mcp import ToolCall


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def settings() -> Settings:
    return Settings(
        llm_provider="openai_compat",
        llm_base_url="http://localhost",
        llm_api_key="test-key",
        argument_guard_model="test-model",
        llm_timeout_seconds=5.0,
        llm_max_retries=0,
        database_url="postgresql+asyncpg://x:x@localhost/x",
        redis_url="redis://localhost:6379/0",
    )


@pytest.fixture
def agent(settings: Settings) -> ArgumentGuardAgent:
    with patch("gateway.agents.base.AsyncOpenAI"):
        return ArgumentGuardAgent(settings)


def _tool_call(args: dict) -> ToolCall:  # type: ignore[type-arg]
    return ToolCall(server="test-mcp", tool="test.tool", arguments=args)


def _sha256(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


# ---------------------------------------------------------------------------
# Deterministic redaction
# ---------------------------------------------------------------------------

@pytest.mark.unit
@pytest.mark.asyncio
async def test_email_redacted(agent: ArgumentGuardAgent) -> None:
    tc = _tool_call({"contact": "alice@example.com"})
    agent._call = AsyncMock(return_value="<redaction_flags>[]</redaction_flags>")  # type: ignore[method-assign]

    sanitized, flags = await agent.sanitize(tc)

    assert sanitized["contact"] == "[REDACTED_EMAIL]"
    assert len(flags) == 1
    assert flags[0].reason == "PII_EMAIL"
    assert flags[0].field == "contact"
    assert flags[0].original_hash == _sha256("alice@example.com")


@pytest.mark.unit
@pytest.mark.asyncio
async def test_ssn_redacted(agent: ArgumentGuardAgent) -> None:
    tc = _tool_call({"id_number": "123-45-6789"})
    agent._call = AsyncMock(return_value="<redaction_flags>[]</redaction_flags>")  # type: ignore[method-assign]

    sanitized, flags = await agent.sanitize(tc)

    assert sanitized["id_number"] == "[REDACTED_SSN]"
    assert flags[0].reason == "PII_SSN"
    assert flags[0].original_hash == _sha256("123-45-6789")


@pytest.mark.unit
@pytest.mark.asyncio
async def test_api_key_redacted(agent: ArgumentGuardAgent) -> None:
    tc = _tool_call({"token": "sk-abcdefghijklmnopqrstuvwxyz"})
    agent._call = AsyncMock(return_value="<redaction_flags>[]</redaction_flags>")  # type: ignore[method-assign]

    sanitized, flags = await agent.sanitize(tc)

    assert sanitized["token"] == "[REDACTED_SECRET]"
    assert flags[0].reason == "SECRET_TOKEN"


@pytest.mark.unit
@pytest.mark.asyncio
async def test_path_traversal_normalized(agent: ArgumentGuardAgent) -> None:
    tc = _tool_call({"path": "../../etc/passwd"})
    agent._call = AsyncMock(return_value="<redaction_flags>[]</redaction_flags>")  # type: ignore[method-assign]

    sanitized, flags = await agent.sanitize(tc)

    assert "../" not in sanitized["path"]
    assert flags[0].reason == "PATH_TRAVERSAL"


@pytest.mark.unit
@pytest.mark.asyncio
async def test_clean_args_no_flags_no_llm_call(agent: ArgumentGuardAgent) -> None:
    agent._call = AsyncMock()  # type: ignore[method-assign]
    tc = _tool_call({"path": "/data/report.csv", "limit": 100})

    sanitized, flags = await agent.sanitize(tc)

    agent._call.assert_not_called()
    assert flags == []
    assert sanitized == {"path": "/data/report.csv", "limit": 100}


# ---------------------------------------------------------------------------
# _needs_llm_review
# ---------------------------------------------------------------------------

@pytest.mark.unit
def test_needs_llm_review_false_for_empty_flags(agent: ArgumentGuardAgent) -> None:
    tc = _tool_call({"x": "clean"})
    assert agent._needs_llm_review([], tc) is False


@pytest.mark.unit
def test_needs_llm_review_true_when_flags_present(agent: ArgumentGuardAgent) -> None:
    from gateway.models.audit import RedactionFlag
    flag = RedactionFlag(field="x", reason="PII_EMAIL", original_hash="abc")
    tc = _tool_call({"x": "[REDACTED_EMAIL]"})
    assert agent._needs_llm_review([flag], tc) is True


# ---------------------------------------------------------------------------
# LLM path: LLM suggests additional redaction
# ---------------------------------------------------------------------------

@pytest.mark.unit
@pytest.mark.asyncio
async def test_llm_adds_additional_flag(agent: ArgumentGuardAgent) -> None:
    """Deterministic phase catches email; LLM additionally flags 'notes' field."""
    notes_value = "Internal project notes — confidential business strategy"
    tc = _tool_call({
        "email": "user@example.com",
        "notes": notes_value,
    })
    # LLM says to also redact 'notes' (deterministic didn't catch it)
    llm_response = (
        '<redaction_flags>[{"field": "notes", "reason": "SENSITIVE_DATA", '
        f'"original_hash": "{_sha256(notes_value)}"}}]</redaction_flags>'
    )
    agent._call = AsyncMock(return_value=llm_response)  # type: ignore[method-assign]

    sanitized, flags = await agent.sanitize(tc)

    agent._call.assert_called_once()
    assert sanitized["email"] == "[REDACTED_EMAIL]"
    assert sanitized["notes"] == "[REDACTED_SENSITIVE]"
    assert len(flags) == 2  # noqa: PLR2004
    reasons = {f.reason for f in flags}
    assert "PII_EMAIL" in reasons
    assert "SENSITIVE_DATA" in reasons


# ---------------------------------------------------------------------------
# original_hash integrity
# ---------------------------------------------------------------------------

@pytest.mark.unit
@pytest.mark.asyncio
async def test_original_hash_is_sha256_of_original_value(agent: ArgumentGuardAgent) -> None:
    original = "secret@internal.org"
    tc = _tool_call({"user": original})
    agent._call = AsyncMock(return_value="<redaction_flags>[]</redaction_flags>")  # type: ignore[method-assign]

    _, flags = await agent.sanitize(tc)

    assert flags[0].original_hash == _sha256(original)
    # Hash must NOT be of the redacted placeholder
    assert flags[0].original_hash != _sha256("[REDACTED_EMAIL]")


# ---------------------------------------------------------------------------
# parse_response / _parse_llm_flags
# ---------------------------------------------------------------------------

@pytest.mark.unit
def test_parse_llm_flags_valid_json(agent: ArgumentGuardAgent) -> None:
    raw = '<redaction_flags>[{"field": "pw", "reason": "SECRET_TOKEN", "original_hash": "abc123"}]</redaction_flags>'
    flags = agent._parse_llm_flags(raw)
    assert len(flags) == 1
    assert flags[0]["field"] == "pw"
    assert flags[0]["reason"] == "SECRET_TOKEN"


@pytest.mark.unit
def test_parse_llm_flags_empty_array(agent: ArgumentGuardAgent) -> None:
    assert agent._parse_llm_flags("<redaction_flags>[]</redaction_flags>") == []


@pytest.mark.unit
def test_parse_llm_flags_missing_tag_returns_empty(agent: ArgumentGuardAgent) -> None:
    assert agent._parse_llm_flags("The model returned garbage.") == []


@pytest.mark.unit
def test_parse_llm_flags_invalid_json_returns_empty(agent: ArgumentGuardAgent) -> None:
    assert agent._parse_llm_flags("<redaction_flags>not valid json</redaction_flags>") == []
