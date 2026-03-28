"""Unit tests for MCPExecutor.

All HTTP calls are mocked via httpx.AsyncClient. No real network required.
Covers: success, signed forwarding, non-2xx error, timeout, unknown server.
"""

from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest

from gateway.config import Settings
from gateway.enforcement.errors import MCPTimeoutError, MCPToolError
from gateway.enforcement.executor import MCPExecutor
from gateway.models.identity import CallerIdentity, TrustLevel


@pytest.fixture
def settings() -> Settings:
    return Settings(
        mcp_server_base_urls={
            "test-mcp": "http://localhost:9001",
            "slash-mcp": "http://localhost:9002/",
        },
        mcp_server_shared_secrets={
            "test-mcp": "shared-secret",
            "slash-mcp": "slash-secret",
        },
        mcp_tool_timeout_seconds=5.0,
        database_url="postgresql+asyncpg://x:x@localhost/x",
        redis_url="redis://localhost:6379/0",
    )


@pytest.fixture
def executor(settings: Settings) -> MCPExecutor:
    with patch("gateway.enforcement.executor.httpx.AsyncClient"):
        return MCPExecutor(settings)


@pytest.fixture
def identity() -> CallerIdentity:
    return CallerIdentity(
        caller_id="agent-1",
        role="developer",
        trust_level=TrustLevel.HIGH,
        environment="prod",
        api_key_id=7,
        org_id="acme-prod",
    )


def _mock_response(status_code: int, json_body: dict | None = None, text: str = "") -> MagicMock:  # type: ignore[type-arg]
    resp = MagicMock()
    resp.status_code = status_code
    resp.text = text
    if json_body is not None:
        resp.json.return_value = json_body
    return resp


@pytest.mark.unit
@pytest.mark.asyncio
async def test_forward_success_adds_gateway_auth_headers(
    executor: MCPExecutor,
    identity: CallerIdentity,
) -> None:
    expected = {"result": "ok", "data": [1, 2, 3]}
    executor._client.post = AsyncMock(return_value=_mock_response(200, json_body=expected))

    result = await executor.forward(
        "test-mcp",
        "fs.read",
        {"path": "/tmp/file.txt"},
        identity,
        "req-123",
    )

    assert result == expected
    executor._client.post.assert_called_once()
    _, kwargs = executor._client.post.call_args
    assert kwargs["json"] == {"path": "/tmp/file.txt"}
    assert kwargs["headers"]["X-MCP-Gateway-Request-Id"] == "req-123"
    assert kwargs["headers"]["X-MCP-Gateway-Caller-Id"] == identity.caller_id
    assert kwargs["headers"]["X-MCP-Gateway-Org-Id"] == identity.org_id
    assert kwargs["headers"]["X-MCP-Gateway-Body-SHA256"]
    assert kwargs["headers"]["X-MCP-Gateway-Signature"]


@pytest.mark.unit
@pytest.mark.asyncio
async def test_forward_strips_trailing_slash(
    executor: MCPExecutor,
    identity: CallerIdentity,
) -> None:
    executor._client.post = AsyncMock(return_value=_mock_response(200, json_body={}))

    await executor.forward("slash-mcp", "tool.name", {}, identity, "req-456")

    executor._client.post.assert_called_once()
    assert executor._client.post.call_args.args[0] == "http://localhost:9002/tools/tool.name"


@pytest.mark.unit
@pytest.mark.asyncio
async def test_forward_non_2xx_raises_mcp_tool_error(
    executor: MCPExecutor,
    identity: CallerIdentity,
) -> None:
    executor._client.post = AsyncMock(
        return_value=_mock_response(500, text="internal server error")
    )

    with pytest.raises(MCPToolError) as exc_info:
        await executor.forward("test-mcp", "fs.read", {}, identity, "req-123")

    assert exc_info.value.status_code == 500
    assert "internal server error" in exc_info.value.body


@pytest.mark.unit
@pytest.mark.asyncio
async def test_forward_404_from_mcp_server(
    executor: MCPExecutor,
    identity: CallerIdentity,
) -> None:
    executor._client.post = AsyncMock(return_value=_mock_response(404, text="not found"))

    with pytest.raises(MCPToolError) as exc_info:
        await executor.forward("test-mcp", "unknown.tool", {}, identity, "req-123")

    assert exc_info.value.status_code == 404


@pytest.mark.unit
@pytest.mark.asyncio
async def test_forward_timeout_raises_mcp_timeout_error(
    executor: MCPExecutor,
    identity: CallerIdentity,
) -> None:
    executor._client.post = AsyncMock(side_effect=httpx.TimeoutException("timed out"))

    with pytest.raises(MCPTimeoutError):
        await executor.forward("test-mcp", "fs.read", {}, identity, "req-123")


@pytest.mark.unit
@pytest.mark.asyncio
async def test_forward_unknown_server_raises_mcp_tool_error(
    executor: MCPExecutor,
    identity: CallerIdentity,
) -> None:
    with pytest.raises(MCPToolError) as exc_info:
        await executor.forward("nonexistent-mcp", "fs.read", {}, identity, "req-123")

    assert exc_info.value.status_code == 404
    assert "nonexistent-mcp" in exc_info.value.body


@pytest.mark.unit
@pytest.mark.asyncio
async def test_forward_missing_shared_secret_raises_mcp_tool_error(
    settings: Settings,
    identity: CallerIdentity,
) -> None:
    settings.mcp_server_base_urls["unsigned-mcp"] = "http://localhost:9003"
    with patch("gateway.enforcement.executor.httpx.AsyncClient"):
        executor = MCPExecutor(settings)

    with pytest.raises(MCPToolError) as exc_info:
        await executor.forward("unsigned-mcp", "fs.read", {}, identity, "req-123")

    assert exc_info.value.status_code == 503
    assert "Missing shared secret" in exc_info.value.body


@pytest.mark.unit
@pytest.mark.asyncio
async def test_forward_300_redirect_treated_as_error(
    executor: MCPExecutor,
    identity: CallerIdentity,
) -> None:
    executor._client.post = AsyncMock(return_value=_mock_response(301, text="redirect"))

    with pytest.raises(MCPToolError) as exc_info:
        await executor.forward("test-mcp", "fs.read", {}, identity, "req-123")

    assert exc_info.value.status_code == 301
