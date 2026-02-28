"""Unit tests for RedTeamAttackerAgent.

All LLM calls are mocked — no real API key required.
Covers: prod guard, dev instantiation, generate(), parse_response(), missing tags.
"""
from unittest.mock import AsyncMock, patch

import pytest

from gateway.agents.red_team import AttackScenario, RedTeamAttackerAgent
from gateway.config import Settings

# ---------------------------------------------------------------------------
# Sample LLM response used across multiple tests
# ---------------------------------------------------------------------------

_SAMPLE_LLM_RESPONSE = """\
<attack_name>path_traversal_etc_passwd</attack_name>
<attack_type>PATH_TRAVERSAL</attack_type>
<attack_arg_field>path</attack_arg_field>
<attack_arg_value>/data/../../../../etc/passwd</attack_arg_value>
<description>Attempts to escape the allowed path prefix via repeated traversal sequences.</description>
"""

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def dev_settings() -> Settings:
    return Settings(
        environment="dev",
        llm_provider="openai_compat",
        llm_base_url="http://localhost",
        llm_api_key="test-key",
        llm_timeout_seconds=5.0,
        llm_max_retries=0,
        database_url="postgresql+asyncpg://x:x@localhost/x",
        redis_url="redis://localhost:6379/0",
    )


@pytest.fixture
def prod_settings() -> Settings:
    return Settings(
        environment="prod",
        llm_provider="openai_compat",
        llm_base_url="http://localhost",
        llm_api_key="test-key",
        llm_timeout_seconds=5.0,
        llm_max_retries=0,
        database_url="postgresql+asyncpg://x:x@localhost/x",
        redis_url="redis://localhost:6379/0",
    )


@pytest.fixture
def agent(dev_settings: Settings) -> RedTeamAttackerAgent:
    with patch("gateway.agents.base.AsyncOpenAI"):
        return RedTeamAttackerAgent(dev_settings)


# ---------------------------------------------------------------------------
# Test 1 — prod guard raises AssertionError
# ---------------------------------------------------------------------------


@pytest.mark.unit
def test_init_raises_in_prod(prod_settings: Settings) -> None:
    """RedTeamAttackerAgent must not be instantiated in production."""
    with pytest.raises(AssertionError, match="must NOT be instantiated in production"):
        with patch("gateway.agents.base.AsyncOpenAI"):
            RedTeamAttackerAgent(prod_settings)


# ---------------------------------------------------------------------------
# Test 2 — dev instantiation succeeds
# ---------------------------------------------------------------------------


@pytest.mark.unit
def test_init_succeeds_in_dev(dev_settings: Settings) -> None:
    """RedTeamAttackerAgent instantiates without error in dev."""
    with patch("gateway.agents.base.AsyncOpenAI"):
        agent = RedTeamAttackerAgent(dev_settings)
    assert agent is not None


# ---------------------------------------------------------------------------
# Test 3 — generate() calls _call once and returns AttackScenario
# ---------------------------------------------------------------------------


@pytest.mark.unit
@pytest.mark.asyncio
async def test_generate_calls_llm_once(agent: RedTeamAttackerAgent) -> None:
    """generate() calls _call exactly once and returns a valid AttackScenario."""
    agent._call = AsyncMock(return_value=_SAMPLE_LLM_RESPONSE)  # type: ignore[method-assign]

    result = await agent.generate(
        tool="fs.read", server="filesystem-mcp", attack_type="PATH_TRAVERSAL"
    )

    agent._call.assert_called_once()
    assert isinstance(result, AttackScenario)
    assert result.name != ""
    assert result.attack_type != ""
    assert result.description != ""
    assert result.tool_call.tool == "fs.read"
    assert result.tool_call.server == "filesystem-mcp"


# ---------------------------------------------------------------------------
# Test 4 — parse_response() extracts all XML tags correctly
# ---------------------------------------------------------------------------


@pytest.mark.unit
def test_parse_response_well_formed(agent: RedTeamAttackerAgent) -> None:
    """parse_response() correctly extracts all fields from a well-formed LLM reply."""
    result = agent.parse_response(
        _SAMPLE_LLM_RESPONSE, tool="fs.read", server="filesystem-mcp"
    )

    assert result.name == "path_traversal_etc_passwd"
    assert result.attack_type == "PATH_TRAVERSAL"
    assert result.description == (
        "Attempts to escape the allowed path prefix via repeated traversal sequences."
    )
    assert result.tool_call.tool == "fs.read"
    assert result.tool_call.server == "filesystem-mcp"
    assert result.tool_call.arguments == {"path": "/data/../../../../etc/passwd"}


# ---------------------------------------------------------------------------
# Test 5 — parse_response() returns sensible defaults when tags are missing
# ---------------------------------------------------------------------------


@pytest.mark.unit
def test_parse_response_missing_tags(agent: RedTeamAttackerAgent) -> None:
    """parse_response() returns safe defaults when XML tags are absent."""
    result = agent.parse_response("no tags here at all", tool="sql.query", server="db-mcp")

    assert result.name == "unnamed_attack"
    assert result.attack_type == "UNKNOWN"
    assert result.description == "No description."
    assert result.tool_call.tool == "sql.query"
    assert result.tool_call.server == "db-mcp"
    # field defaults to "path", value defaults to ""
    assert result.tool_call.arguments == {"path": ""}
