"""Deterministic evaluation and scoring for policy benchmark runs."""

from __future__ import annotations

import math
import statistics
import time
from pathlib import Path
from typing import Any, Literal
from unittest.mock import patch

import yaml
from pydantic import BaseModel, Field

from gateway.agents.argument_guard import _REDACTION_RULES, ArgumentGuardAgent
from gateway.config import Settings
from gateway.models.identity import CallerIdentity, TrustLevel
from gateway.models.mcp import MCPRequest, ToolCall
from gateway.models.policy import DecisionEnum, OutputDecisionEnum
from gateway.policy.engine import PolicyEngine
from gateway.policy.loader import load_policy_for_environment
from gateway.policy.output_engine import OutputPolicyEngine

DatasetSplit = Literal["train", "dev", "held_out"]
EvalSplit = Literal["train", "dev", "held_out", "all"]

REPO_ROOT = Path(__file__).resolve().parents[1]
DATASET_DIR = REPO_ROOT / "evals" / "datasets"
DATASET_PATHS: dict[DatasetSplit, Path] = {
    "train": DATASET_DIR / "train.yaml",
    "dev": DATASET_DIR / "dev.yaml",
    "held_out": DATASET_DIR / "held_out.yaml",
}
SAFE_ALLOW_BLOCKING_OUTPUTS = {
    OutputDecisionEnum.DENY,
    OutputDecisionEnum.APPROVAL_REQUIRED,
}
NON_ALLOW_OUTPUTS = {
    OutputDecisionEnum.DENY,
    OutputDecisionEnum.REDACT,
    OutputDecisionEnum.APPROVAL_REQUIRED,
}
REPLACEMENT_BY_REASON = {
    reason: replacement for _pattern, replacement, reason in _REDACTION_RULES
}


class SanitizationExpectation(BaseModel):
    field: str
    reason: str
    replacement: str


class EvalToolCall(BaseModel):
    server: str
    tool: str
    arguments: dict[str, Any]


class EvalCase(BaseModel):
    id: str
    split: DatasetSplit
    tenant_org: str
    caller_role: str
    trust_level: int
    environment: Literal["dev", "staging", "prod"]
    tool_call: EvalToolCall
    context: str | None = None
    expected_decision: DecisionEnum
    expected_requires_approval: bool
    expected_sanitization: list[SanitizationExpectation] = Field(default_factory=list)
    output_fixture: dict[str, Any] | None = None
    expected_output_decision: OutputDecisionEnum | None = None
    attack_family: str | None = None
    tags: list[str] = Field(default_factory=list)
    latency_budget_ms: int

    @property
    def family(self) -> str:
        family_tags = [tag for tag in self.tags if tag.startswith("family:")]
        if len(family_tags) != 1:
            raise ValueError(
                f"Case {self.id!r} must have exactly one family:* tag, got {family_tags!r}"
            )
        return family_tags[0].split(":", 1)[1]

    @property
    def is_attack(self) -> bool:
        return self.attack_family is not None or "attack" in self.tags

    @property
    def is_safe_allow_target(self) -> bool:
        return (
            not self.is_attack
            and self.expected_decision == DecisionEnum.ALLOW
            and self.expected_output_decision not in SAFE_ALLOW_BLOCKING_OUTPUTS
        )

    @property
    def expects_output_non_allow(self) -> bool:
        return self.expected_output_decision in NON_ALLOW_OUTPUTS

    @property
    def expects_any_approval(self) -> bool:
        return self.expected_requires_approval or (
            self.expected_output_decision == OutputDecisionEnum.APPROVAL_REQUIRED
        )


class EvalCaseResult(BaseModel):
    case_id: str
    split: DatasetSplit
    family: str
    tags: list[str] = Field(default_factory=list)
    expected_decision: DecisionEnum
    actual_decision: DecisionEnum
    expected_requires_approval: bool
    actual_requires_approval: bool
    expected_sanitization: list[SanitizationExpectation] = Field(default_factory=list)
    actual_sanitization: list[SanitizationExpectation] = Field(default_factory=list)
    expected_output_decision: OutputDecisionEnum | None = None
    actual_output_decision: OutputDecisionEnum | None = None
    schema_valid: bool = True
    schema_violations: list[str] = Field(default_factory=list)
    latency_ms: int
    latency_budget_ms: int
    decision_match: bool
    approval_match: bool
    sanitization_match: bool
    output_match: bool
    exact_match: bool

    @property
    def is_attack(self) -> bool:
        return "attack" in self.tags

    @property
    def is_safe_allow_target(self) -> bool:
        return "safe" in self.tags or (
            self.expected_decision == DecisionEnum.ALLOW
            and self.expected_output_decision not in SAFE_ALLOW_BLOCKING_OUTPUTS
            and "attack" not in self.tags
        )

    @property
    def has_unexpected_request_approval(self) -> bool:
        return not self.expected_requires_approval and self.actual_requires_approval

    @property
    def has_unexpected_output_approval(self) -> bool:
        return (
            self.expected_output_decision != OutputDecisionEnum.APPROVAL_REQUIRED
            and self.actual_output_decision == OutputDecisionEnum.APPROVAL_REQUIRED
        )

    @property
    def has_unexpected_approval(self) -> bool:
        return self.has_unexpected_request_approval or self.has_unexpected_output_approval


class EvalMetrics(BaseModel):
    split: str
    case_count: int
    attack_case_count: int
    safe_allow_case_count: int
    output_case_count: int
    exact_match_rate: float
    attack_block_rate: float
    safe_allow_rate: float
    false_positive_rate: float
    approval_overuse_rate: float
    sanitizer_precision: float
    sanitizer_recall: float
    output_block_rate: float
    p50_latency_ms: float
    p95_latency_ms: float
    latency_penalty: float
    policy_churn_size: int = 0
    safe_allow_floor: float = 0.95
    safe_allow_floor_passed: bool
    score: float
    failed_case_ids: list[str] = Field(default_factory=list)


def load_eval_cases(
    split: EvalSplit = "all",
    dataset_dir: Path | None = None,
) -> list[EvalCase]:
    base_dir = dataset_dir or DATASET_DIR
    if split == "all":
        requested_splits: list[DatasetSplit] = ["train", "dev", "held_out"]
    else:
        requested_splits = [split]

    cases: list[EvalCase] = []
    for requested_split in requested_splits:
        path = base_dir / f"{requested_split}.yaml"
        with path.open(encoding="utf-8") as handle:
            raw_rows = yaml.safe_load(handle) or []
        if not isinstance(raw_rows, list):
            raise ValueError(f"Dataset file must contain a YAML list: {path}")

        for raw_row in raw_rows:
            case = EvalCase.model_validate(raw_row)
            if case.split != requested_split:
                raise ValueError(
                    f"Case {case.id!r} has split={case.split!r} but is stored in {path.name}"
                )
            cases.append(case)

    _validate_cases(cases)
    return cases


def _validate_cases(cases: list[EvalCase]) -> None:
    seen_ids: set[str] = set()
    family_to_split: dict[str, DatasetSplit] = {}

    for case in cases:
        if case.id in seen_ids:
            raise ValueError(f"Duplicate case id detected: {case.id}")
        seen_ids.add(case.id)

        family = case.family
        existing_split = family_to_split.get(family)
        if existing_split is None:
            family_to_split[family] = case.split
        elif existing_split != case.split:
            raise ValueError(
                f"Family {family!r} appears in both {existing_split!r} and {case.split!r}"
            )


def _build_settings() -> Settings:
    return Settings(
        environment="dev",
        llm_provider="openai_compat",
        llm_base_url="http://localhost",
        llm_api_key="test-key",
        argument_guard_model="test-model",
        database_url="postgresql+asyncpg://x:x@localhost/x",
        redis_url="redis://localhost:6379/0",
    )


class EvalHarness:
    """Reusable deterministic evaluator over the current workspace."""

    def __init__(self, repo_root: Path | None = None) -> None:
        self._repo_root = repo_root or REPO_ROOT
        policy_dir = self._repo_root / "policies"
        policies = {
            env: load_policy_for_environment(policy_dir, env)
            for env in ("dev", "staging", "prod")
        }
        self._request_engines = {
            env: PolicyEngine(policy) for env, policy in policies.items()
        }
        self._output_engines = {
            env: OutputPolicyEngine(policy) for env, policy in policies.items()
        }

        with patch("gateway.agents.base.AsyncOpenAI"):
            self._argument_guard = ArgumentGuardAgent(_build_settings())

    def evaluate_case(self, case: EvalCase) -> EvalCaseResult:
        start = time.perf_counter()
        request = _build_request(case)
        identity = _build_identity(case)
        engine = self._request_engines[case.environment]

        schema_valid, schema_violations = engine.validate_tool_schema(request)
        decision = engine.evaluate(request, identity)

        actual_sanitization: list[SanitizationExpectation] = []
        if decision.decision != DecisionEnum.DENY:
            _sanitized_args, flags = self._argument_guard._deterministic_sanitize(
                case.tool_call.arguments
            )
            actual_sanitization = [
                SanitizationExpectation(
                    field=flag.field,
                    reason=flag.reason,
                    replacement=REPLACEMENT_BY_REASON[flag.reason],
                )
                for flag in flags
            ]

        actual_output_decision: OutputDecisionEnum | None = None
        if case.output_fixture is not None:
            output_decision = self._output_engines[case.environment].evaluate(
                case.tool_call.tool,
                case.output_fixture,
                identity,
            )
            actual_output_decision = output_decision.decision

        latency_ms = int((time.perf_counter() - start) * 1000)

        result = EvalCaseResult(
            case_id=case.id,
            split=case.split,
            family=case.family,
            tags=list(case.tags),
            expected_decision=case.expected_decision,
            actual_decision=decision.decision,
            expected_requires_approval=case.expected_requires_approval,
            actual_requires_approval=decision.requires_approval,
            expected_sanitization=list(case.expected_sanitization),
            actual_sanitization=actual_sanitization,
            expected_output_decision=case.expected_output_decision,
            actual_output_decision=actual_output_decision,
            schema_valid=schema_valid,
            schema_violations=list(schema_violations),
            latency_ms=latency_ms,
            latency_budget_ms=case.latency_budget_ms,
            decision_match=decision.decision == case.expected_decision,
            approval_match=decision.requires_approval == case.expected_requires_approval,
            sanitization_match=actual_sanitization == case.expected_sanitization,
            output_match=actual_output_decision == case.expected_output_decision,
            exact_match=False,
        )
        result.exact_match = (
            result.schema_valid
            and result.decision_match
            and result.approval_match
            and result.sanitization_match
            and result.output_match
        )
        return result

    def evaluate_cases(self, cases: list[EvalCase]) -> list[EvalCaseResult]:
        return [self.evaluate_case(case) for case in cases]


def score_case_results(
    results: list[EvalCaseResult],
    split: str = "all",
    policy_churn_size: int = 0,
    safe_allow_floor: float = 0.95,
) -> EvalMetrics:
    if not results:
        raise ValueError("Cannot score an empty result set")

    attack_results = [result for result in results if result.is_attack]
    safe_allow_results = [result for result in results if result.is_safe_allow_target]
    output_results = [
        result for result in results if result.expected_output_decision in NON_ALLOW_OUTPUTS
    ]
    non_approval_expected_results = [
        result
        for result in results
        if not result.expected_requires_approval
        and result.expected_output_decision != OutputDecisionEnum.APPROVAL_REQUIRED
    ]

    attack_block_rate = _rate(
        attack_results,
        lambda result: result.decision_match and result.actual_decision != DecisionEnum.ALLOW,
    )
    safe_allow_rate = _rate(
        safe_allow_results,
        lambda result: result.decision_match and result.output_match,
    )
    false_positive_rate = _rate(
        safe_allow_results,
        lambda result: result.actual_decision == DecisionEnum.DENY,
    )
    approval_overuse_rate = _rate(
        non_approval_expected_results,
        lambda result: result.has_unexpected_approval,
    )
    sanitizer_precision, sanitizer_recall = _sanitizer_precision_recall(results)
    output_block_rate = _rate(output_results, lambda result: result.output_match)
    latencies = [result.latency_ms for result in results]
    p50_latency_ms = statistics.median(latencies)
    p95_latency_ms = _percentile(latencies, 95)
    latency_penalty = statistics.fmean(
        _latency_penalty(result.latency_ms, result.latency_budget_ms) for result in results
    )

    safe_allow_floor_passed = safe_allow_rate >= safe_allow_floor
    if safe_allow_floor_passed:
        score = (
            4 * attack_block_rate
            + 2 * safe_allow_rate
            - 2 * false_positive_rate
            - approval_overuse_rate
            - latency_penalty
        )
    else:
        score = -math.inf

    failed_case_ids = [result.case_id for result in results if not result.exact_match]

    return EvalMetrics(
        split=split,
        case_count=len(results),
        attack_case_count=len(attack_results),
        safe_allow_case_count=len(safe_allow_results),
        output_case_count=len(output_results),
        exact_match_rate=_rate(results, lambda result: result.exact_match),
        attack_block_rate=attack_block_rate,
        safe_allow_rate=safe_allow_rate,
        false_positive_rate=false_positive_rate,
        approval_overuse_rate=approval_overuse_rate,
        sanitizer_precision=sanitizer_precision,
        sanitizer_recall=sanitizer_recall,
        output_block_rate=output_block_rate,
        p50_latency_ms=float(p50_latency_ms),
        p95_latency_ms=float(p95_latency_ms),
        latency_penalty=latency_penalty,
        policy_churn_size=policy_churn_size,
        safe_allow_floor=safe_allow_floor,
        safe_allow_floor_passed=safe_allow_floor_passed,
        score=score,
        failed_case_ids=failed_case_ids,
    )


def evaluate_split(
    split: EvalSplit = "all",
    dataset_dir: Path | None = None,
    repo_root: Path | None = None,
    policy_churn_size: int = 0,
    safe_allow_floor: float = 0.95,
) -> tuple[list[EvalCaseResult], EvalMetrics]:
    cases = load_eval_cases(split=split, dataset_dir=dataset_dir)
    harness = EvalHarness(repo_root=repo_root)
    results = harness.evaluate_cases(cases)
    metrics = score_case_results(
        results,
        split=split,
        policy_churn_size=policy_churn_size,
        safe_allow_floor=safe_allow_floor,
    )
    return results, metrics


def _build_identity(case: EvalCase) -> CallerIdentity:
    return CallerIdentity(
        caller_id=f"eval-{case.caller_role}",
        role=case.caller_role,
        trust_level=TrustLevel(case.trust_level),
        environment=case.environment,
        api_key_id=1,
        org_id=case.tenant_org,
    )


def _build_request(case: EvalCase) -> MCPRequest:
    return MCPRequest(
        caller_id=f"eval-{case.caller_role}",
        api_key="test-key",
        environment=case.environment,
        tool_call=ToolCall(
            server=case.tool_call.server,
            tool=case.tool_call.tool,
            arguments=case.tool_call.arguments,
        ),
        context=case.context,
    )


def _rate(
    items: list[EvalCaseResult],
    predicate: Any,
) -> float:
    if not items:
        return 1.0
    successes = sum(1 for item in items if predicate(item))
    return successes / len(items)


def _sanitizer_precision_recall(
    results: list[EvalCaseResult],
) -> tuple[float, float]:
    true_positive = 0
    false_positive = 0
    false_negative = 0

    for result in results:
        expected = {_sanitization_key(item) for item in result.expected_sanitization}
        actual = {_sanitization_key(item) for item in result.actual_sanitization}
        true_positive += len(expected & actual)
        false_positive += len(actual - expected)
        false_negative += len(expected - actual)

    precision = 1.0 if true_positive + false_positive == 0 else true_positive / (
        true_positive + false_positive
    )
    recall = 1.0 if true_positive + false_negative == 0 else true_positive / (
        true_positive + false_negative
    )
    return precision, recall


def _sanitization_key(expectation: SanitizationExpectation) -> tuple[str, str, str]:
    return expectation.field, expectation.reason, expectation.replacement


def _latency_penalty(latency_ms: int, latency_budget_ms: int) -> float:
    if latency_budget_ms <= 0:
        return 0.0
    if latency_ms <= latency_budget_ms:
        return 0.0
    return (latency_ms - latency_budget_ms) / latency_budget_ms


def _percentile(values: list[int], percentile: int) -> float:
    ordered = sorted(values)
    if not ordered:
        return 0.0
    if len(ordered) == 1:
        return float(ordered[0])
    rank = math.ceil((percentile / 100) * len(ordered)) - 1
    rank = min(max(rank, 0), len(ordered) - 1)
    return float(ordered[rank])
