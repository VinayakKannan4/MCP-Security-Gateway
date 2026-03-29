from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

import yaml

from gateway.agents.argument_guard import _REDACTION_RULES, ArgumentGuardAgent
from gateway.config import Settings
from gateway.models.identity import CallerIdentity, TrustLevel
from gateway.models.mcp import MCPRequest, ToolCall
from gateway.policy.engine import PolicyEngine
from gateway.policy.loader import load_policy_for_environment

REPO_ROOT = Path(__file__).resolve().parents[2]
DATASET_DIR = REPO_ROOT / "evals" / "datasets"
FIXTURE_DIR = REPO_ROOT / "tests" / "evals" / "fixtures"
DATASET_FILES = {
    "train": DATASET_DIR / "train.yaml",
    "dev": DATASET_DIR / "dev.yaml",
    "held_out": DATASET_DIR / "held_out.yaml",
}
EXPECTED_KEYS = [
    "id",
    "split",
    "tenant_org",
    "caller_role",
    "trust_level",
    "environment",
    "tool_call",
    "context",
    "expected_decision",
    "expected_requires_approval",
    "expected_sanitization",
    "output_fixture",
    "expected_output_decision",
    "attack_family",
    "tags",
    "latency_budget_ms",
]
ALLOWED_LATENCY_BUDGETS = {10, 20, 25}
REPLACEMENT_BY_REASON = {
    reason: replacement for _pattern, replacement, reason in _REDACTION_RULES
}


def _load_yaml_rows(path: Path) -> list[dict]:
    with path.open() as handle:
        rows = yaml.safe_load(handle)
    assert isinstance(rows, list)
    return rows


def _load_all_rows() -> list[dict]:
    rows: list[dict] = []
    for split, path in DATASET_FILES.items():
        split_rows = _load_yaml_rows(path)
        assert all(row["split"] == split for row in split_rows)
        rows.extend(split_rows)
    return rows


def _family_name(row: dict) -> str:
    family_tags = [tag for tag in row["tags"] if tag.startswith("family:")]
    assert len(family_tags) == 1
    return family_tags[0].split(":", 1)[1]


def _identity(row: dict) -> CallerIdentity:
    return CallerIdentity(
        caller_id=f"eval-{row['caller_role']}",
        role=row["caller_role"],
        trust_level=TrustLevel(row["trust_level"]),
        environment=row["environment"],
        api_key_id=1,
        org_id=row["tenant_org"],
    )


def _request(row: dict) -> MCPRequest:
    return MCPRequest(
        caller_id=f"eval-{row['caller_role']}",
        api_key="test-key",
        environment=row["environment"],
        tool_call=ToolCall(**row["tool_call"]),
        context=row["context"],
    )


def test_dataset_shape_and_split_separation() -> None:
    rows = _load_all_rows()
    assert len(rows) == 116
    assert len(_load_yaml_rows(DATASET_FILES["train"])) == 68
    assert len(_load_yaml_rows(DATASET_FILES["dev"])) == 24
    assert len(_load_yaml_rows(DATASET_FILES["held_out"])) == 24

    ids: set[str] = set()
    family_to_split: dict[str, str] = {}

    for row in rows:
        assert list(row) == EXPECTED_KEYS
        assert row["id"] not in ids
        ids.add(row["id"])
        assert row["split"] in DATASET_FILES
        assert row["environment"] in {"dev", "staging", "prod"}
        assert row["expected_decision"] in {"ALLOW", "DENY", "APPROVAL_REQUIRED"}
        assert row["expected_output_decision"] in {
            "ALLOW",
            "REDACT",
            "APPROVAL_REQUIRED",
            "DENY",
            None,
        }
        assert row["expected_requires_approval"] == (
            row["expected_decision"] == "APPROVAL_REQUIRED"
        )
        assert isinstance(row["expected_sanitization"], list)
        for item in row["expected_sanitization"]:
            assert list(item) == ["field", "reason", "replacement"]
            assert REPLACEMENT_BY_REASON[item["reason"]] == item["replacement"]
        assert row["latency_budget_ms"] in ALLOWED_LATENCY_BUDGETS
        assert any(tag.startswith("variant:") for tag in row["tags"])

        family = _family_name(row)
        if family in family_to_split:
            assert family_to_split[family] == row["split"]
        else:
            family_to_split[family] = row["split"]

        if row["attack_family"] is None:
            assert "attack" not in row["tags"]
        else:
            assert row["attack_family"] == family
            assert "attack" in row["tags"]

        if row["expected_decision"] == "DENY":
            assert row["output_fixture"] is None
            assert row["expected_output_decision"] is None
            assert row["expected_sanitization"] == []
        if row["output_fixture"] is None:
            assert row["expected_output_decision"] is None


def test_dataset_rows_are_schema_valid() -> None:
    policies = {
        env: load_policy_for_environment(REPO_ROOT / "policies", env)
        for env in ("dev", "staging", "prod")
    }
    request_engines = {env: PolicyEngine(policy) for env, policy in policies.items()}

    with patch("gateway.agents.base.AsyncOpenAI"):
        guard = ArgumentGuardAgent(
            Settings(
                environment="dev",
                llm_provider="openai_compat",
                llm_base_url="http://localhost",
                llm_api_key="test-key",
                argument_guard_model="test-model",
                database_url="postgresql+asyncpg://x:x@localhost/x",
                redis_url="redis://localhost:6379/0",
            )
        )

    for row in _load_all_rows():
        request = _request(row)
        engine = request_engines[row["environment"]]
        valid, violations = engine.validate_tool_schema(request)
        assert valid, (row["id"], violations)

        sanitized_args, flags = guard._deterministic_sanitize(row["tool_call"]["arguments"])
        actual_sanitization = [
            {
                "field": flag.field,
                "reason": flag.reason,
                "replacement": REPLACEMENT_BY_REASON[flag.reason],
            }
            for flag in flags
        ]
        if row["expected_decision"] == "DENY":
            assert row["expected_sanitization"] == []
        else:
            assert actual_sanitization == row["expected_sanitization"], (
                row["id"],
                actual_sanitization,
                sanitized_args,
            )


def test_regression_fixtures_are_exact_subsets() -> None:
    full_dataset = {row["id"]: row for row in _load_all_rows()}
    fixture_paths = [
        FIXTURE_DIR / "policy_regressions.yaml",
        FIXTURE_DIR / "output_regressions.yaml",
    ]

    for fixture_path in fixture_paths:
        for row in _load_yaml_rows(fixture_path):
            assert row["id"] in full_dataset
            assert row == full_dataset[row["id"]]
