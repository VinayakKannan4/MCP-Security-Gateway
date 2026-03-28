"""FastAPI application factory for the MCP Security Gateway."""

from __future__ import annotations

import logging
from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager

import redis.asyncio as aioredis
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from gateway.agents.argument_guard import ArgumentGuardAgent
from gateway.agents.risk_classifier import RiskClassifierAgent
from gateway.api.v1 import admin as admin_router_module
from gateway.api.v1 import approvals as approvals_router_module
from gateway.api.v1 import audit as audit_router_module
from gateway.api.v1 import gateway as gateway_router_module
from gateway.config import Settings
from gateway.config import settings as default_settings
from gateway.enforcement.executor import MCPExecutor
from gateway.observability.otel import configure_otel
from gateway.policy.engine import PolicyEngine
from gateway.policy.loader import load_policy_for_environment
from gateway.policy.output_engine import OutputPolicyEngine

logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    """Application lifespan: initialize resources on startup, clean up on shutdown."""
    cfg: Settings = app.state.settings

    # --- Startup ---

    # Database engine + sessionmaker
    engine = create_async_engine(cfg.database_url, echo=False)
    app.state.db_sessionmaker = async_sessionmaker(engine, expire_on_commit=False)

    # Redis client
    redis_client = aioredis.from_url(cfg.redis_url, decode_responses=True)
    app.state.redis = redis_client

    # Policy engine (singleton — stateless, immutable after init)
    policy = load_policy_for_environment(cfg.policy_dir, cfg.environment)
    app.state.policy_engine = PolicyEngine(policy)
    app.state.output_policy_engine = OutputPolicyEngine(policy)

    # LLM agent singletons (stateless — safe to reuse across requests)
    app.state.risk_classifier = RiskClassifierAgent(cfg)
    app.state.argument_guard = ArgumentGuardAgent(cfg)

    # MCP executor singleton
    app.state.executor = MCPExecutor(cfg)

    logger.info("MCP Security Gateway started (environment=%s)", cfg.environment)

    yield

    # --- Shutdown ---
    await app.state.executor.aclose()
    await redis_client.close()
    await engine.dispose()

    logger.info("MCP Security Gateway shut down")


def create_app(settings: Settings | None = None) -> FastAPI:
    """Create and configure the FastAPI application."""
    cfg = settings or default_settings

    app = FastAPI(
        title="MCP Security Gateway",
        description="Policy-aware multi-agent security gateway for MCP tool calls",
        version="0.1.0",
        lifespan=lifespan,
    )

    # Store settings on app.state so lifespan + deps can access them
    app.state.settings = cfg

    # CORS — allow the React UI (localhost:3000) to call the gateway API
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["http://localhost:3000"],
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # OpenTelemetry (no-op when OTEL_ENABLED=false)
    configure_otel(app, cfg)

    # Routers
    app.include_router(gateway_router_module.router, prefix="/v1/gateway", tags=["gateway"])
    app.include_router(admin_router_module.router, prefix="/v1/admin", tags=["admin"])
    app.include_router(approvals_router_module.router, prefix="/v1/approvals", tags=["approvals"])
    app.include_router(audit_router_module.router, prefix="/v1/audit", tags=["audit"])

    @app.get("/health", tags=["health"])
    async def health() -> dict[str, str]:
        return {"status": "ok"}

    @app.get("/readyz", tags=["health"])
    async def readyz() -> dict[str, str]:
        """Check DB and Redis connectivity."""
        try:
            await app.state.redis.ping()
        except Exception as exc:
            logger.warning("Redis readyz check failed: %s", exc)
            return {"status": "degraded", "reason": "redis_unavailable"}

        return {"status": "ready"}

    return app


# Module-level app instance for uvicorn / gunicorn
app = create_app()
