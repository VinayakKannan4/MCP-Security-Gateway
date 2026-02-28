"""Unit tests for BaseAgent.

All LLM calls are mocked — no real API key required.
"""

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from pydantic import BaseModel

from gateway.agents.base import BaseAgent
from gateway.config import Settings
from gateway.models.risk import RiskAssessment


# ---------------------------------------------------------------------------
# Minimal concrete subclass for testing the abstract BaseAgent
# ---------------------------------------------------------------------------

class _ConcreteAgent(BaseAgent):
    def parse_response(self, raw: str) -> BaseModel:
        return RiskAssessment(labels=[], score=0.0, explanation=raw)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def openai_settings() -> Settings:
    return Settings(
        llm_provider="openai_compat",
        llm_base_url="http://localhost",
        llm_api_key="test-key",
        llm_model="test-model",
        llm_timeout_seconds=5.0,
        llm_max_retries=2,
        # suppress DB/redis validation
        database_url="postgresql+asyncpg://x:x@localhost/x",
        redis_url="redis://localhost:6379/0",
    )


@pytest.fixture
def agent(openai_settings: Settings) -> _ConcreteAgent:
    with patch("gateway.agents.base.AsyncOpenAI"):
        return _ConcreteAgent(openai_settings)


# ---------------------------------------------------------------------------
# _extract_tag tests
# ---------------------------------------------------------------------------

@pytest.mark.unit
def test_extract_tag_found() -> None:
    raw = "<risk_score>0.75</risk_score>"
    assert BaseAgent._extract_tag(raw, "risk_score") == "0.75"


@pytest.mark.unit
def test_extract_tag_not_found() -> None:
    assert BaseAgent._extract_tag("no tags here", "missing") is None


@pytest.mark.unit
def test_extract_tag_multiline() -> None:
    raw = "<explanation>\n  line one\n  line two\n</explanation>"
    result = BaseAgent._extract_tag(raw, "explanation")
    assert result is not None
    assert "line one" in result
    assert "line two" in result


@pytest.mark.unit
def test_extract_tag_strips_whitespace() -> None:
    raw = "<risk_labels>  HIGH_DESTRUCTIVE  </risk_labels>"
    assert BaseAgent._extract_tag(raw, "risk_labels") == "HIGH_DESTRUCTIVE"


# ---------------------------------------------------------------------------
# _call tests — mock the underlying OpenAI client
# ---------------------------------------------------------------------------

@pytest.mark.unit
@pytest.mark.asyncio
async def test_call_returns_text_on_success(agent: _ConcreteAgent) -> None:
    mock_resp = MagicMock()
    mock_resp.choices = [MagicMock()]
    mock_resp.choices[0].message.content = "hello world"

    agent._openai_client = MagicMock()  # type: ignore[assignment]
    agent._openai_client.chat.completions.create = AsyncMock(return_value=mock_resp)  # type: ignore[union-attr]

    result = await agent._call("system", "prompt")
    assert result == "hello world"


@pytest.mark.unit
@pytest.mark.asyncio
async def test_call_retries_on_timeout_then_succeeds(agent: _ConcreteAgent) -> None:
    mock_resp = MagicMock()
    mock_resp.choices = [MagicMock()]
    mock_resp.choices[0].message.content = "recovered"

    agent._openai_client = MagicMock()  # type: ignore[assignment]
    agent._openai_client.chat.completions.create = AsyncMock(  # type: ignore[union-attr]
        side_effect=[asyncio.TimeoutError(), mock_resp]
    )

    result = await agent._call("system", "prompt")
    assert result == "recovered"
    assert agent._openai_client.chat.completions.create.call_count == 2  # type: ignore[union-attr]


@pytest.mark.unit
@pytest.mark.asyncio
async def test_call_raises_after_exhausting_retries(agent: _ConcreteAgent) -> None:
    agent._openai_client = MagicMock()  # type: ignore[assignment]
    agent._openai_client.chat.completions.create = AsyncMock(  # type: ignore[union-attr]
        side_effect=asyncio.TimeoutError()
    )

    with pytest.raises(asyncio.TimeoutError):
        await agent._call("system", "prompt")

    # max_retries=2 means 3 total attempts (0, 1, 2)
    assert agent._openai_client.chat.completions.create.call_count == 3  # type: ignore[union-attr]


@pytest.mark.unit
@pytest.mark.asyncio
async def test_call_returns_empty_string_on_none_content(agent: _ConcreteAgent) -> None:
    mock_resp = MagicMock()
    mock_resp.choices = [MagicMock()]
    mock_resp.choices[0].message.content = None

    agent._openai_client = MagicMock()  # type: ignore[assignment]
    agent._openai_client.chat.completions.create = AsyncMock(return_value=mock_resp)  # type: ignore[union-attr]

    result = await agent._call("system", "prompt")
    assert result == ""
