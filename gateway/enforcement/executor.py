"""MCPExecutor — forwards sanitized tool calls to upstream MCP servers via HTTP."""

from typing import Any

import httpx

from gateway.config import Settings
from gateway.enforcement.errors import MCPTimeoutError, MCPToolError


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
        """POST sanitized arguments to the upstream MCP server.

        Raises:
            MCPToolError: if server is unknown or returns non-2xx response.
            MCPTimeoutError: if the request exceeds the configured timeout.
        """
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

        return response.json()  # type: ignore[no-any-return]

    async def aclose(self) -> None:
        """Close the underlying httpx client."""
        await self._client.aclose()
