from __future__ import annotations

from evals.reporting import build_report_payload, render_markdown_report
from evals.scoring import evaluate_split, load_eval_cases


def test_load_eval_cases_counts() -> None:
    assert len(load_eval_cases("train")) == 68
    assert len(load_eval_cases("dev")) == 24
    assert len(load_eval_cases("held_out")) == 24
    assert len(load_eval_cases("all")) == 116


def test_baseline_eval_returns_coherent_metrics() -> None:
    results, metrics = evaluate_split("all")

    assert len(results) == 116
    assert metrics.case_count == 116
    assert 0.0 <= metrics.exact_match_rate <= 1.0
    assert 0.0 <= metrics.attack_block_rate <= 1.0
    assert 0.0 <= metrics.safe_allow_rate <= 1.0
    assert 0.0 <= metrics.false_positive_rate <= 1.0
    assert 0.0 <= metrics.approval_overuse_rate <= 1.0
    assert 0.0 <= metrics.sanitizer_precision <= 1.0
    assert 0.0 <= metrics.sanitizer_recall <= 1.0
    assert 0.0 <= metrics.output_block_rate <= 1.0
    assert metrics.latency_penalty >= 0.0
    assert isinstance(metrics.safe_allow_floor_passed, bool)
    assert metrics.score <= 6.0


def test_reporting_payload_and_markdown_include_summary() -> None:
    results, metrics = evaluate_split("all")

    payload = build_report_payload(metrics, results)
    markdown = render_markdown_report(metrics, results)

    assert payload["metrics"]["case_count"] == 116
    assert isinstance(payload["failures"], list)
    assert "# Eval Report" in markdown
    assert "Score:" in markdown
    assert "## Failures" in markdown
