"""POST /v1/gateway/invoke — main enforcement endpoint."""

from fastapi import APIRouter, Depends

from gateway.api.deps import get_pipeline
from gateway.enforcement.pipeline import EnforcementPipeline
from gateway.models.mcp import GatewayResponse, MCPRequest

router = APIRouter()


@router.post("/invoke", response_model=GatewayResponse)
async def invoke(
    request: MCPRequest,
    pipeline: EnforcementPipeline = Depends(get_pipeline),
) -> GatewayResponse:
    """Run the full 10-step enforcement pipeline for an MCP tool call."""
    return await pipeline.run(request)
