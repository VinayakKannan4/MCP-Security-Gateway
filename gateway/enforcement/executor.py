"""MCPExecutor — forwards sanitized tool calls to upstream MCP servers via HTTP."""

import hashlib
import hmac
import json
from datetime import UTC, datetime
from typing import Any

import httpx

from gateway.config import Settings
from gateway.enforcement.errors import MCPTimeoutError, MCPToolError
from gateway.models.identity import CallerIdentity


class MCPExecutor:
    def __init__(self, settings: Settings) -> None:
        self._base_urls: dict[str, str] = settings.mcp_server_base_urls
        self._shared_secrets: dict[str, str] = settings.mcp_server_shared_secrets
        self._client = httpx.AsyncClient(timeout=settings.mcp_tool_timeout_seconds)

    async def forward(
        self,
        server: str,
        tool: str,
        sanitized_args: dict[str, Any],
        identity: CallerIdentity,
        request_id: str,
    ) -> dict[str, Any]:
        """POST sanitized arguments to the upstream MCP server.

        Raises:
            MCPToolError: if server is unknown or returns non-2xx response.
            MCPTimeoutError: if the request exceeds the configured timeout.
        """
        base_url = self._base_urls.get(server)
        if base_url is None:
            raise MCPToolError(404, f"Unknown MCP server: {server!r}")
        secret = self._shared_secrets.get(server)
        if not secret:
            raise MCPToolError(503, f"Missing shared secret for MCP server: {server!r}")

        url = f"{base_url.rstrip('/')}/tools/{tool}"
        headers = self._build_auth_headers(
            secret=secret,
            request_id=request_id,
            identity=identity,
            tool=tool,
            body=sanitized_args,
        )
        try:
            response = await self._client.post(url, json=sanitized_args, headers=headers)
        except httpx.TimeoutException as exc:
            raise MCPTimeoutError(f"Timeout calling {server}/{tool}") from exc

        if response.status_code >= 300:
            raise MCPToolError(response.status_code, response.text)

        return response.json()  # type: ignore[no-any-return]

    async def aclose(self) -> None:
        """Close the underlying httpx client."""
        await self._client.aclose()

    def _build_auth_headers(
        self,
        secret: str,
        request_id: str,
        identity: CallerIdentity,
        tool: str,
        body: dict[str, Any],
    ) -> dict[str, str]:
        timestamp = datetime.now(UTC).isoformat()
        body_hash = hashlib.sha256(
            json.dumps(body, sort_keys=True, default=str).encode()
        ).hexdigest()
        signing_payload = "\n".join(
            [
                timestamp,
                request_id,
                identity.caller_id,
                identity.org_id,
                tool,
                body_hash,
            ]
        ).encode()
        signature = hmac.new(secret.encode(), signing_payload, hashlib.sha256).hexdigest()
        return {
            "X-MCP-Gateway-Timestamp": timestamp,
            "X-MCP-Gateway-Request-Id": request_id,
            "X-MCP-Gateway-Caller-Id": identity.caller_id,
            "X-MCP-Gateway-Org-Id": identity.org_id,
            "X-MCP-Gateway-Body-SHA256": body_hash,
            "X-MCP-Gateway-Signature": signature,
        }
