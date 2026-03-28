"""Unit tests for deterministic output inspection."""

import pytest

from gateway.models.identity import CallerIdentity, TrustLevel
from gateway.models.policy import (
    OutputConstraintConfig,
    OutputDecisionEnum,
    OutputPatternConstraint,
    OutputPolicyRule,
    PolicyConfig,
)
from gateway.policy.output_engine import OutputPolicyEngine


def _identity(environment: str = "prod") -> CallerIdentity:
    return CallerIdentity(
        caller_id="agent-1",
        role="developer",
        trust_level=TrustLevel.HIGH,
        environment=environment,
        api_key_id=5,
        org_id="acme-prod",
    )


@pytest.mark.unit
def test_redacts_nested_field_paths_and_list_wildcards() -> None:
    engine = OutputPolicyEngine(
        PolicyConfig(
            name="test-policy",
            output_rules=[
                OutputPolicyRule(
                    name="redact-email",
                    description="Redact emails in nested rows",
                    priority=50,
                    tools=["sql.query"],
                    roles=["*"],
                    environments=["*"],
                    decision=OutputDecisionEnum.REDACT,
                    constraints=OutputConstraintConfig(
                        patterns=[
                            OutputPatternConstraint(
                                field="rows.*.email",
                                pattern=r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b",
                                label="PII_EMAIL",
                                replacement="[REDACTED_EMAIL]",
                            )
                        ]
                    ),
                )
            ],
        )
    )

    result = engine.evaluate(
        tool="sql.query",
        output={"rows": [{"email": "alice@example.com"}, {"email": "bob@example.com"}]},
        identity=_identity(),
    )

    assert result.decision == OutputDecisionEnum.REDACT
    assert result.redacted_output == {
        "rows": [
            {"email": "[REDACTED_EMAIL]"},
            {"email": "[REDACTED_EMAIL]"},
        ]
    }
    assert result.matched_labels == ["PII_EMAIL"]


@pytest.mark.unit
def test_denies_private_key_material_anywhere_in_output() -> None:
    engine = OutputPolicyEngine(
        PolicyConfig(
            name="test-policy",
            output_rules=[
                OutputPolicyRule(
                    name="deny-private-key",
                    description="Never release private keys",
                    priority=100,
                    tools=["*"],
                    roles=["*"],
                    environments=["*"],
                    decision=OutputDecisionEnum.DENY,
                    constraints=OutputConstraintConfig(
                        patterns=[
                            OutputPatternConstraint(
                                field="*",
                                pattern=r"-----BEGIN (?:RSA|OPENSSH) PRIVATE KEY-----",
                                label="PRIVATE_KEY",
                            )
                        ]
                    ),
                )
            ],
        )
    )

    result = engine.evaluate(
        tool="fs.read",
        output={
            "content": "-----BEGIN RSA PRIVATE KEY-----\nsecret\n-----END RSA PRIVATE KEY-----"
        },
        identity=_identity(),
    )

    assert result.decision == OutputDecisionEnum.DENY
    assert result.redacted_output is None
    assert result.matched_labels == ["PRIVATE_KEY"]


@pytest.mark.unit
def test_large_output_redaction_replaces_payload_with_sentinel() -> None:
    engine = OutputPolicyEngine(
        PolicyConfig(
            name="test-policy",
            output_rules=[
                OutputPolicyRule(
                    name="truncate-large-output",
                    description="Hide oversized payloads",
                    priority=40,
                    tools=["fs.read"],
                    roles=["*"],
                    environments=["*"],
                    decision=OutputDecisionEnum.REDACT,
                    constraints=OutputConstraintConfig(max_output_length=10),
                )
            ],
        )
    )

    result = engine.evaluate(
        tool="fs.read",
        output={"content": "0123456789abcdef"},
        identity=_identity(),
    )

    assert result.decision == OutputDecisionEnum.REDACT
    assert result.redacted_output == {"_redacted": "[OUTPUT_TOO_LARGE]"}
    assert result.matched_labels == ["MAX_OUTPUT_LENGTH"]


@pytest.mark.unit
def test_no_matching_rule_allows_output() -> None:
    engine = OutputPolicyEngine(PolicyConfig(name="test-policy"))

    result = engine.evaluate(
        tool="fs.read",
        output={"content": "ok"},
        identity=_identity(environment="dev"),
    )

    assert result.decision == OutputDecisionEnum.ALLOW
    assert result.redacted_output == {"content": "ok"}
