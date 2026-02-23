"""
Shared test fixtures.
"""

import pytest
from pathlib import Path

from gateway.models.identity import CallerIdentity, TrustLevel
from gateway.models.policy import PolicyConfig
from gateway.policy.loader import load_policy


@pytest.fixture(scope="session")
def policy_dir() -> Path:
    return Path(__file__).parent.parent / "policies"


@pytest.fixture(scope="session")
def default_policy(policy_dir: Path) -> PolicyConfig:
    return load_policy(policy_dir / "default.yaml")


@pytest.fixture
def analyst_identity() -> CallerIdentity:
    return CallerIdentity(
        caller_id="test-analyst",
        role="analyst",
        trust_level=TrustLevel.MEDIUM,
        environment="prod",
        api_key_id=1,
    )


@pytest.fixture
def developer_identity() -> CallerIdentity:
    return CallerIdentity(
        caller_id="test-developer",
        role="developer",
        trust_level=TrustLevel.HIGH,
        environment="prod",
        api_key_id=2,
    )


@pytest.fixture
def developer_dev_identity() -> CallerIdentity:
    return CallerIdentity(
        caller_id="test-developer",
        role="developer",
        trust_level=TrustLevel.HIGH,
        environment="dev",
        api_key_id=2,
    )


@pytest.fixture
def admin_identity() -> CallerIdentity:
    return CallerIdentity(
        caller_id="test-admin",
        role="admin",
        trust_level=TrustLevel.ADMIN,
        environment="prod",
        api_key_id=3,
    )


@pytest.fixture
def admin_dev_identity() -> CallerIdentity:
    return CallerIdentity(
        caller_id="test-admin",
        role="admin",
        trust_level=TrustLevel.ADMIN,
        environment="dev",
        api_key_id=3,
    )


@pytest.fixture
def untrusted_identity() -> CallerIdentity:
    return CallerIdentity(
        caller_id="test-untrusted",
        role="unknown",
        trust_level=TrustLevel.UNTRUSTED,
        environment="prod",
        api_key_id=99,
    )
