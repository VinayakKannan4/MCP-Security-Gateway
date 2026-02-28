"""Shared fixtures for scenario tests.

Scenario tests are DETERMINISTIC — they call PolicyEngine.evaluate() directly.
No LLM calls, no DB, no Docker needed. Fast to run (<1s total).
All scenario tests use @pytest.mark.scenario.
"""
from pathlib import Path

import pytest

from gateway.models.identity import CallerIdentity, TrustLevel
from gateway.models.mcp import MCPRequest, ToolCall
from gateway.models.policy import PolicyConfig
from gateway.policy.engine import PolicyEngine
from gateway.policy.loader import load_policy

# Note: policy_dir fixture already defined in root tests/conftest.py


@pytest.fixture(scope="session")
def scenario_policy(policy_dir: Path) -> PolicyConfig:
    return load_policy(policy_dir / "default.yaml")


@pytest.fixture(scope="session")
def scenario_engine(scenario_policy: PolicyConfig) -> PolicyEngine:
    return PolicyEngine(scenario_policy)


def make_request(
    tool: str,
    server: str,
    args: dict,
    role: str,
    trust_level: TrustLevel,
    environment: str = "prod",
) -> tuple[MCPRequest, CallerIdentity]:
    """Build (MCPRequest, CallerIdentity) for a scenario test."""
    identity = CallerIdentity(
        caller_id=f"scenario-{role}",
        role=role,
        trust_level=trust_level,
        environment=environment,
        api_key_id=1,
    )
    request = MCPRequest(
        caller_id=identity.caller_id,
        api_key="test-key",
        environment=environment,
        tool_call=ToolCall(server=server, tool=tool, arguments=args),
    )
    return request, identity
