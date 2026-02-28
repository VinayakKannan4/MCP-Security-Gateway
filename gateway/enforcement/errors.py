"""Custom exception types for the MCP enforcement pipeline."""


class MCPToolError(Exception):
    """Raised when the upstream MCP server returns a non-2xx response."""

    def __init__(self, status_code: int, body: str) -> None:
        self.status_code = status_code
        self.body = body
        super().__init__(f"MCP tool error {status_code}: {body}")


class MCPTimeoutError(Exception):
    """Raised when the upstream MCP server call exceeds mcp_tool_timeout_seconds."""
