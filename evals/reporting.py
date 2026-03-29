"""Report formatting helpers for eval runs."""

from __future__ import annotations

import math
from typing import Any

from evals.scoring import EvalCaseResult, EvalMetrics


def build_report_payload(
    metrics: EvalMetrics,
    results: list[EvalCaseResult],
) -> dict[str, Any]:
    failures = [
        {
            "case_id": result.case_id,
            "split": result.split,
            "family": result.family,
            "expected_decision": result.expected_decision.value,
            "actual_decision": result.actual_decision.value,
            "expected_requires_approval": result.expected_requires_approval,
            "actual_requires_approval": result.actual_requires_approval,
            "expected_output_decision": (
                result.expected_output_decision.value
                if result.expected_output_decision is not None
                else None
            ),
            "actual_output_decision": (
                result.actual_output_decision.value
                if result.actual_output_decision is not None
                else None
            ),
            "expected_sanitization": [
                item.model_dump(mode="json") for item in result.expected_sanitization
            ],
            "actual_sanitization": [
                item.model_dump(mode="json") for item in result.actual_sanitization
            ],
            "schema_valid": result.schema_valid,
            "schema_violations": list(result.schema_violations),
            "latency_ms": result.latency_ms,
        }
        for result in results
        if not result.exact_match
    ]

    return {
        "metrics": metrics.model_dump(mode="json"),
        "failures": failures,
    }


def render_markdown_report(
    metrics: EvalMetrics,
    results: list[EvalCaseResult],
) -> str:
    lines = [
        "# Eval Report",
        "",
        f"- Split: `{metrics.split}`",
        f"- Cases: `{metrics.case_count}`",
        f"- Score: `{_format_score(metrics.score)}`",
        f"- Exact match rate: `{metrics.exact_match_rate:.3f}`",
        f"- Attack block rate: `{metrics.attack_block_rate:.3f}`",
        f"- Safe allow rate: `{metrics.safe_allow_rate:.3f}`",
        f"- False positive rate: `{metrics.false_positive_rate:.3f}`",
        f"- Approval overuse rate: `{metrics.approval_overuse_rate:.3f}`",
        (
            f"- Sanitizer precision / recall: `{metrics.sanitizer_precision:.3f}` / "
            f"`{metrics.sanitizer_recall:.3f}`"
        ),
        f"- Output block rate: `{metrics.output_block_rate:.3f}`",
        f"- p50 / p95 latency ms: `{metrics.p50_latency_ms:.1f}` / `{metrics.p95_latency_ms:.1f}`",
        f"- Latency penalty: `{metrics.latency_penalty:.3f}`",
        f"- Safe allow floor passed: `{metrics.safe_allow_floor_passed}`",
    ]

    failed_results = [result for result in results if not result.exact_match]
    if not failed_results:
        lines.extend(["", "## Failures", "", "None."])
        return "\n".join(lines)

    lines.extend(["", "## Failures", ""])
    for result in failed_results[:15]:
        lines.append(
            f"- `{result.case_id}`: expected `{result.expected_decision.value}`"
            f" / `{_format_optional_decision(result.expected_output_decision)}`, got"
            f" `{result.actual_decision.value}` /"
            f" `{_format_optional_decision(result.actual_output_decision)}`"
        )
    if len(failed_results) > 15:
        lines.append(f"- ... and `{len(failed_results) - 15}` more failures")

    return "\n".join(lines)


def _format_optional_decision(decision: Any) -> str:
    if decision is None:
        return "None"
    return decision.value


def _format_score(score: float) -> str:
    if math.isinf(score) and score < 0:
        return "-inf"
    return f"{score:.3f}"
