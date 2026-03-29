"""Candidate workspace utilities for benchmark-driven policy evolution."""

from __future__ import annotations

import difflib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any, Literal

import yaml
from pydantic import BaseModel, Field

from evals.scoring import (
    REPO_ROOT,
    EvalCase,
    EvalCaseResult,
    EvalHarness,
    EvalMetrics,
    OutputDecisionEnum,
    load_eval_cases,
)

EDITABLE_SURFACES: tuple[Path, ...] = (
    Path("policies/default.yaml"),
    Path("policies/dev.yaml"),
    Path("gateway/policy/constraints.py"),
    Path("gateway/agents/risk_classifier.py"),
    Path("gateway/enforcement/output_inspector.py"),
)
COPY_IGNORE_NAMES = {
    ".git",
    ".venv",
    ".pytest_cache",
    ".mypy_cache",
    ".ruff_cache",
    "__pycache__",
    "node_modules",
    "dist",
    "build",
    "htmlcov",
}


class CommandRun(BaseModel):
    command: list[str]
    cwd: str
    exit_code: int
    stdout: str
    stderr: str

    @property
    def passed(self) -> bool:
        return self.exit_code == 0


class EvalRun(BaseModel):
    split: str
    repo_root: str
    metrics: EvalMetrics | None = None
    command_run: CommandRun
    report_path: str | None = None

    @property
    def passed(self) -> bool:
        return self.command_run.passed and self.metrics is not None


class CandidateEvaluation(BaseModel):
    baseline_root: str
    candidate_root: str
    changed_files: list[str] = Field(default_factory=list)
    unauthorized_changes: list[str] = Field(default_factory=list)
    policy_churn_size: int = 0
    baseline_train: EvalRun | None = None
    candidate_train: EvalRun | None = None
    baseline_dev: EvalRun | None = None
    candidate_dev: EvalRun | None = None
    baseline_held_out: EvalRun | None = None
    candidate_held_out: EvalRun | None = None
    gate_runs: list[CommandRun] = Field(default_factory=list)
    train_improved: bool = False
    dev_non_regression: bool | None = None
    held_out_non_regression: bool | None = None
    gates_passed: bool | None = None
    promotable: bool = False
    promoted: bool = False


MutationKind = Literal[
    "add_global_deny_pattern",
    "add_path_denied_pattern",
    "add_sql_denied_keyword",
    "tighten_sql_comment_normalization",
    "add_output_pattern",
    "add_allowed_prefix",
]


class MutationProposal(BaseModel):
    proposal_id: str
    kind: MutationKind
    target_file: str
    summary: str
    case_id: str
    family: str
    payload: dict[str, Any] = Field(default_factory=dict)


class SearchRound(BaseModel):
    round_number: int
    proposal_count: int
    accepted_proposal: MutationProposal | None = None
    accepted_evaluation: CandidateEvaluation | None = None
    candidate_roots: list[str] = Field(default_factory=list)


class MutationSearchResult(BaseModel):
    baseline_root: str
    best_root: str
    initial_train_score: float
    final_train_score: float
    rounds: list[SearchRound] = Field(default_factory=list)
    accepted_proposals: list[MutationProposal] = Field(default_factory=list)
    improved: bool = False
    promoted: bool = False


def create_candidate_workspace(
    base_root: Path | None = None,
    candidate_root: Path | None = None,
) -> Path:
    """Create a writable candidate workspace by copying the repo tree."""
    source_root = (base_root or REPO_ROOT).resolve()
    if candidate_root is None:
        destination_root = Path(
            tempfile.mkdtemp(prefix="mcp-policy-candidate-", dir="/tmp")
        )
        shutil.rmtree(destination_root)
    else:
        destination_root = candidate_root.resolve()
        if destination_root.exists():
            raise ValueError(f"Candidate root already exists: {destination_root}")

    shutil.copytree(
        source_root,
        destination_root,
        dirs_exist_ok=False,
        ignore=shutil.ignore_patterns(*COPY_IGNORE_NAMES),
    )
    return destination_root


def evaluate_candidate_workspace(
    candidate_root: Path,
    *,
    base_root: Path | None = None,
    safe_allow_floor: float = 0.95,
    run_held_out: bool = False,
    run_gates: bool = True,
) -> CandidateEvaluation:
    """Score a candidate workspace against the current baseline and gate it."""
    source_root = (base_root or REPO_ROOT).resolve()
    candidate_root = candidate_root.resolve()

    changed_files = find_changed_files(source_root, candidate_root)
    unauthorized_changes = [
        path for path in changed_files if Path(path) not in set(EDITABLE_SURFACES)
    ]
    policy_churn_size = compute_policy_churn_size(source_root, candidate_root)

    baseline_train = run_eval_script(
        repo_root=source_root,
        split="train",
        safe_allow_floor=safe_allow_floor,
        policy_churn_size=0,
        runner_root=source_root,
    )
    candidate_train = run_eval_script(
        repo_root=candidate_root,
        split="train",
        safe_allow_floor=safe_allow_floor,
        policy_churn_size=policy_churn_size,
        runner_root=source_root,
    )

    evaluation = CandidateEvaluation(
        baseline_root=str(source_root),
        candidate_root=str(candidate_root),
        changed_files=changed_files,
        unauthorized_changes=unauthorized_changes,
        policy_churn_size=policy_churn_size,
        baseline_train=baseline_train,
        candidate_train=candidate_train,
    )

    evaluation.train_improved = _score_improved(candidate_train, baseline_train)
    if not evaluation.train_improved or unauthorized_changes:
        evaluation.promotable = False
        return evaluation

    baseline_dev = run_eval_script(
        repo_root=source_root,
        split="dev",
        safe_allow_floor=safe_allow_floor,
        policy_churn_size=0,
        runner_root=source_root,
    )
    candidate_dev = run_eval_script(
        repo_root=candidate_root,
        split="dev",
        safe_allow_floor=safe_allow_floor,
        policy_churn_size=policy_churn_size,
        runner_root=source_root,
    )
    evaluation.baseline_dev = baseline_dev
    evaluation.candidate_dev = candidate_dev
    evaluation.dev_non_regression = _score_non_regression(candidate_dev, baseline_dev)

    if run_held_out and evaluation.dev_non_regression:
        baseline_held_out = run_eval_script(
            repo_root=source_root,
            split="held_out",
            safe_allow_floor=safe_allow_floor,
            policy_churn_size=0,
            runner_root=source_root,
        )
        candidate_held_out = run_eval_script(
            repo_root=candidate_root,
            split="held_out",
            safe_allow_floor=safe_allow_floor,
            policy_churn_size=policy_churn_size,
            runner_root=source_root,
        )
        evaluation.baseline_held_out = baseline_held_out
        evaluation.candidate_held_out = candidate_held_out
        evaluation.held_out_non_regression = _score_non_regression(
            candidate_held_out,
            baseline_held_out,
        )
    else:
        evaluation.held_out_non_regression = None

    if (
        run_gates
        and evaluation.dev_non_regression is True
        and evaluation.held_out_non_regression in {True, None}
    ):
        evaluation.gate_runs = run_candidate_gates(
            repo_root=candidate_root,
            runner_root=source_root,
        )
        evaluation.gates_passed = all(run.passed for run in evaluation.gate_runs)
    elif run_gates:
        evaluation.gates_passed = None
    else:
        evaluation.gates_passed = None

    evaluation.promotable = (
        evaluation.train_improved
        and _run_passes_floor(evaluation.candidate_train)
        and evaluation.dev_non_regression is True
        and _run_passes_floor(evaluation.candidate_dev)
        and (evaluation.held_out_non_regression in {True, None})
        and (
            evaluation.candidate_held_out is None
            or _run_passes_floor(evaluation.candidate_held_out)
        )
        and not evaluation.unauthorized_changes
        and (evaluation.gates_passed in {True, None})
    )
    return evaluation


def promote_candidate_workspace(
    candidate_root: Path,
    *,
    base_root: Path | None = None,
) -> list[str]:
    """Copy only the whitelisted editable surfaces from candidate into the repo."""
    source_root = (base_root or REPO_ROOT).resolve()
    candidate_root = candidate_root.resolve()
    changed_files = find_changed_files(source_root, candidate_root)
    unauthorized_changes = [
        path for path in changed_files if Path(path) not in set(EDITABLE_SURFACES)
    ]
    if unauthorized_changes:
        raise ValueError(
            "Candidate includes unauthorized changes: "
            + ", ".join(sorted(unauthorized_changes))
        )

    promoted_paths: list[str] = []
    for relative_path in EDITABLE_SURFACES:
        source_path = candidate_root / relative_path
        destination_path = source_root / relative_path
        if not source_path.exists():
            continue
        if destination_path.exists() and destination_path.read_bytes() == source_path.read_bytes():
            continue
        destination_path.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source_path, destination_path)
        promoted_paths.append(str(relative_path))
    return promoted_paths


def compute_policy_churn_size(base_root: Path, candidate_root: Path) -> int:
    churn = 0
    for relative_path in EDITABLE_SURFACES:
        base_path = base_root / relative_path
        candidate_path = candidate_root / relative_path
        base_lines = _read_text(base_path).splitlines()
        candidate_lines = _read_text(candidate_path).splitlines()
        for line in difflib.unified_diff(
            base_lines,
            candidate_lines,
            fromfile=str(relative_path),
            tofile=str(relative_path),
            lineterm="",
        ):
            if line.startswith(("---", "+++", "@@")):
                continue
            if line.startswith("+") or line.startswith("-"):
                churn += 1
    return churn


def find_changed_files(base_root: Path, candidate_root: Path) -> list[str]:
    base_files = set(_iter_repo_files(base_root))
    candidate_files = set(_iter_repo_files(candidate_root))
    changed: list[str] = []
    for relative_path in sorted(base_files | candidate_files):
        base_path = base_root / relative_path
        candidate_path = candidate_root / relative_path
        if not base_path.exists() or not candidate_path.exists():
            changed.append(str(relative_path))
            continue
        if base_path.read_bytes() != candidate_path.read_bytes():
            changed.append(str(relative_path))
    return changed


def generate_mutation_proposals(
    repo_root: Path | None = None,
    *,
    split: str = "train",
    max_proposals: int = 12,
) -> list[MutationProposal]:
    """Generate deterministic mutation proposals from failing eval cases."""
    workspace_root = (repo_root or REPO_ROOT).resolve()
    cases = load_eval_cases(split=split)
    harness = EvalHarness(repo_root=workspace_root)
    results = harness.evaluate_cases(cases)
    case_by_id = {case.id: case for case in cases}

    proposals: list[MutationProposal] = []
    seen_keys: set[str] = set()
    for result in results:
        if result.exact_match:
            continue
        case = case_by_id[result.case_id]
        for proposal in _proposals_for_failure(case, result):
            key = json.dumps(
                {
                    "kind": proposal.kind,
                    "target_file": proposal.target_file,
                    "payload": proposal.payload,
                },
                sort_keys=True,
            )
            if key in seen_keys:
                continue
            seen_keys.add(key)
            proposals.append(proposal)
            if len(proposals) >= max_proposals:
                return proposals
    return proposals


def apply_mutation_proposal(candidate_root: Path, proposal: MutationProposal) -> bool:
    """Apply a single proposal inside a candidate workspace."""
    target_path = candidate_root / proposal.target_file
    if not target_path.exists():
        return False
    if proposal.kind == "tighten_sql_comment_normalization":
        return _apply_constraints_code_patch(candidate_root, proposal)
    if target_path.suffix not in {".yaml", ".yml"}:
        return False

    policy = _load_yaml_mapping(target_path)
    if proposal.kind == "add_global_deny_pattern":
        changed = _apply_global_deny_pattern(policy, proposal.payload)
    elif proposal.kind == "add_path_denied_pattern":
        changed = _apply_path_denied_pattern(policy, proposal.payload)
    elif proposal.kind == "add_sql_denied_keyword":
        changed = _apply_sql_denied_keyword(policy, proposal.payload)
    elif proposal.kind == "add_output_pattern":
        changed = _apply_output_pattern(policy, proposal.payload)
    elif proposal.kind == "add_allowed_prefix":
        changed = _apply_allowed_prefix(policy, proposal.payload)
    else:
        raise ValueError(f"Unsupported proposal kind: {proposal.kind}")

    if not changed:
        return False

    _write_yaml_mapping(target_path, policy)
    return True


def run_mutation_search(
    *,
    base_root: Path | None = None,
    max_rounds: int = 6,
    max_proposals: int = 12,
    safe_allow_floor: float = 0.95,
    run_held_out: bool = False,
    run_gates: bool = True,
    promote_best: bool = False,
) -> MutationSearchResult:
    """Run a deterministic mutation search loop using train failures as signal."""
    source_root = (base_root or REPO_ROOT).resolve()
    baseline_train = run_eval_script(
        repo_root=source_root,
        split="train",
        safe_allow_floor=safe_allow_floor,
        policy_churn_size=0,
        runner_root=source_root,
    )
    initial_score = _selection_score(baseline_train)

    result = MutationSearchResult(
        baseline_root=str(source_root),
        best_root=str(source_root),
        initial_train_score=initial_score,
        final_train_score=initial_score,
    )

    current_best_root = source_root
    best_score = initial_score

    for round_number in range(1, max_rounds + 1):
        proposals = generate_mutation_proposals(
            current_best_root,
            split="train",
            max_proposals=max_proposals,
        )
        search_round = SearchRound(
            round_number=round_number,
            proposal_count=len(proposals),
        )
        result.rounds.append(search_round)
        if not proposals:
            break

        accepted: tuple[MutationProposal, CandidateEvaluation, Path] | None = None
        for proposal in proposals:
            candidate_root = create_candidate_workspace(base_root=current_best_root)
            search_round.candidate_roots.append(str(candidate_root))
            changed = apply_mutation_proposal(candidate_root, proposal)
            if not changed:
                shutil.rmtree(candidate_root, ignore_errors=True)
                continue

            evaluation = evaluate_candidate_workspace(
                candidate_root,
                base_root=current_best_root,
                safe_allow_floor=safe_allow_floor,
                run_held_out=run_held_out,
                run_gates=run_gates,
            )
            if (
                evaluation.train_improved
                and not evaluation.unauthorized_changes
                and _candidate_is_better(evaluation, accepted)
            ):
                if accepted is not None:
                    shutil.rmtree(accepted[2], ignore_errors=True)
                accepted = (proposal, evaluation, candidate_root)
                continue

            shutil.rmtree(candidate_root, ignore_errors=True)

        if accepted is None:
            break

        accepted_proposal, accepted_evaluation, accepted_root = accepted
        search_round.accepted_proposal = accepted_proposal
        search_round.accepted_evaluation = accepted_evaluation
        result.accepted_proposals.append(accepted_proposal)
        current_best_root = accepted_root
        result.best_root = str(current_best_root)
        best_score = _selection_score(accepted_evaluation.candidate_train)
        result.final_train_score = best_score

    result.improved = result.final_train_score > result.initial_train_score

    if promote_best and result.improved and current_best_root != source_root:
        final_evaluation = evaluate_candidate_workspace(
            current_best_root,
            base_root=source_root,
            safe_allow_floor=safe_allow_floor,
            run_held_out=run_held_out,
            run_gates=run_gates,
        )
        if final_evaluation.promotable:
            promote_candidate_workspace(current_best_root, base_root=source_root)
            result.promoted = True

    return result


def run_eval_script(
    *,
    repo_root: Path,
    split: str,
    safe_allow_floor: float,
    policy_churn_size: int,
    runner_root: Path | None = None,
) -> EvalRun:
    """Run the eval CLI inside a specific workspace and parse its JSON output."""
    runner_root = (runner_root or REPO_ROOT).resolve()
    python_bin = _python_executable(runner_root)
    with tempfile.TemporaryDirectory(prefix="eval-report-", dir="/tmp") as temp_dir:
        report_path = Path(temp_dir) / f"{split}.json"
        command = [
            str(python_bin),
            "scripts/run_eval_loop.py",
            "--split",
            split,
            "--safe-allow-floor",
            str(safe_allow_floor),
            "--policy-churn-size",
            str(policy_churn_size),
            "--json-out",
            str(report_path),
        ]
        run = _run_command(command, cwd=repo_root, pythonpath_root=repo_root)
        metrics: EvalMetrics | None = None
        if report_path.exists():
            payload = json.loads(report_path.read_text(encoding="utf-8"))
            metrics_data = payload.get("metrics")
            if isinstance(metrics_data, dict):
                metrics = EvalMetrics.model_validate(metrics_data)
        return EvalRun(
            split=split,
            repo_root=str(repo_root),
            metrics=metrics,
            command_run=run,
            report_path=str(report_path),
        )


def run_candidate_gates(
    *,
    repo_root: Path,
    runner_root: Path | None = None,
) -> list[CommandRun]:
    runner_root = (runner_root or REPO_ROOT).resolve()
    python_bin = _python_executable(runner_root)
    commands = [
        [
            str(python_bin),
            "-m",
            "pytest",
            "tests/evals",
            "-q",
        ],
        [
            str(python_bin),
            "-m",
            "pytest",
            "-m",
            "unit or scenario",
            "-q",
        ],
    ]
    return [
        _run_command(command, cwd=repo_root, pythonpath_root=repo_root)
        for command in commands
    ]


def render_search_summary(search: MutationSearchResult) -> str:
    lines = [
        "# Mutation Search",
        "",
        f"- Baseline root: `{search.baseline_root}`",
        f"- Best root: `{search.best_root}`",
        f"- Initial train score: `{search.initial_train_score:.3f}`",
        f"- Final train score: `{search.final_train_score:.3f}`",
        f"- Improved: `{search.improved}`",
        f"- Promoted: `{search.promoted}`",
        f"- Accepted proposals: `{len(search.accepted_proposals)}`",
    ]

    if search.accepted_proposals:
        lines.extend(["", "## Accepted Proposals", ""])
        for proposal in search.accepted_proposals:
            lines.append(f"- `{proposal.proposal_id}`: {proposal.summary}")

    if search.rounds:
        lines.extend(["", "## Rounds", ""])
        for search_round in search.rounds:
            accepted = (
                search_round.accepted_proposal.proposal_id
                if search_round.accepted_proposal is not None
                else "none"
            )
            lines.append(
                f"- Round `{search_round.round_number}`: "
                f"proposals=`{search_round.proposal_count}` accepted=`{accepted}`"
            )

    return "\n".join(lines)


def render_candidate_summary(evaluation: CandidateEvaluation) -> str:
    lines = [
        "# Candidate Evaluation",
        "",
        f"- Candidate root: `{evaluation.candidate_root}`",
        f"- Changed files: `{len(evaluation.changed_files)}`",
        f"- Unauthorized changes: `{len(evaluation.unauthorized_changes)}`",
        f"- Policy churn size: `{evaluation.policy_churn_size}`",
        f"- Train improved: `{evaluation.train_improved}`",
        f"- Dev non-regression: `{_format_optional_bool(evaluation.dev_non_regression)}`",
        f"- Held-out non-regression: `{_format_optional_bool(evaluation.held_out_non_regression)}`",
        f"- Gates passed: `{_format_optional_bool(evaluation.gates_passed)}`",
        f"- Promotable: `{evaluation.promotable}`",
        f"- Promoted: `{evaluation.promoted}`",
        "",
        "## Scores",
        "",
        f"- Baseline train: `{_format_score(evaluation.baseline_train)}`",
        f"- Candidate train: `{_format_score(evaluation.candidate_train)}`",
        f"- Baseline dev: `{_format_score(evaluation.baseline_dev)}`",
        f"- Candidate dev: `{_format_score(evaluation.candidate_dev)}`",
        f"- Baseline held_out: `{_format_score(evaluation.baseline_held_out)}`",
        f"- Candidate held_out: `{_format_score(evaluation.candidate_held_out)}`",
    ]

    if evaluation.unauthorized_changes:
        lines.extend(["", "## Unauthorized Changes", ""])
        lines.extend(f"- `{path}`" for path in evaluation.unauthorized_changes)

    return "\n".join(lines)


def _proposals_for_failure(
    case: EvalCase,
    result: EvalCaseResult,
) -> list[MutationProposal]:
    proposals: list[MutationProposal] = []
    target_file = _policy_file_for_environment(case.environment)
    arguments_text = json.dumps(case.tool_call.arguments, sort_keys=True).lower()

    if (
        case.attack_family is not None
        and case.expected_decision.value == "DENY"
        and result.actual_decision.value != "DENY"
    ):
        if "prompt_injection" in case.attack_family:
            pattern_label = _infer_prompt_injection_pattern(arguments_text)
            if pattern_label is not None:
                pattern, label = pattern_label
                proposals.append(
                    MutationProposal(
                        proposal_id=f"{case.id}-global-deny",
                        kind="add_global_deny_pattern",
                        target_file=target_file,
                        summary=f"Add global deny prompt-injection pattern for {case.family}",
                        case_id=case.id,
                        family=case.family,
                        payload={"pattern": pattern, "label": label},
                    )
                )
        elif "path_traversal" in case.attack_family:
            pattern = _infer_path_pattern(case.tool_call.arguments.get("path"))
            if pattern is not None:
                proposals.append(
                    MutationProposal(
                        proposal_id=f"{case.id}-path-deny",
                        kind="add_path_denied_pattern",
                        target_file=target_file,
                        summary=f"Add path denied pattern `{pattern}` for {case.family}",
                        case_id=case.id,
                        family=case.family,
                        payload={"tool": case.tool_call.tool, "pattern": pattern},
                    )
                )
        elif case.attack_family in {"sql_destructive", "sql_union_exfil", "sql_outfile_exfil"}:
            keyword = _infer_sql_keyword(case.tool_call.arguments.get("query"))
            if keyword is not None:
                proposals.append(
                    MutationProposal(
                        proposal_id=f"{case.id}-sql-deny",
                        kind="add_sql_denied_keyword",
                        target_file=target_file,
                        summary=f"Add SQL denied keyword `{keyword}` for {case.family}",
                        case_id=case.id,
                        family=case.family,
                        payload={"keyword": keyword},
                    )
                )
        elif "sql" in case.attack_family and _query_looks_comment_obfuscated(
            case.tool_call.arguments.get("query")
        ):
            proposals.append(
                MutationProposal(
                    proposal_id=f"{case.id}-sql-comment-normalization",
                    kind="tighten_sql_comment_normalization",
                    target_file="gateway/policy/constraints.py",
                    summary=f"Normalize SQL comments before safety checks for {case.family}",
                    case_id=case.id,
                    family=case.family,
                )
            )
        elif case.attack_family == "shell_injection_payload":
            pattern_label = _infer_shell_pattern(arguments_text)
            if pattern_label is not None:
                pattern, label = pattern_label
                proposals.append(
                    MutationProposal(
                        proposal_id=f"{case.id}-shell-deny",
                        kind="add_global_deny_pattern",
                        target_file=target_file,
                        summary=f"Add shell-injection global deny pattern for {case.family}",
                        case_id=case.id,
                        family=case.family,
                        payload={"pattern": pattern, "label": label},
                    )
                )

    if (
        case.expected_output_decision is not None
        and result.actual_output_decision != case.expected_output_decision
        and case.output_fixture is not None
    ):
        output_pattern_payload = _infer_output_pattern(case)
        if output_pattern_payload is not None:
            proposals.append(
                MutationProposal(
                    proposal_id=f"{case.id}-output-pattern",
                    kind="add_output_pattern",
                    target_file=target_file,
                    summary=f"Add output pattern for {case.family}",
                    case_id=case.id,
                    family=case.family,
                    payload=output_pattern_payload,
                )
            )

    if (
        case.attack_family is None
        and case.expected_decision.value in {"ALLOW", "APPROVAL_REQUIRED"}
        and result.actual_decision.value == "DENY"
    ):
        prefix = _path_prefix(case.tool_call.arguments.get("path"))
        if prefix is not None and case.tool_call.tool.startswith("fs."):
            proposals.append(
                MutationProposal(
                    proposal_id=f"{case.id}-allow-prefix",
                    kind="add_allowed_prefix",
                    target_file=target_file,
                    summary=f"Add allowed prefix `{prefix}` for {case.family}",
                    case_id=case.id,
                    family=case.family,
                    payload={"tool": case.tool_call.tool, "prefix": prefix},
                )
            )

    return proposals


def _candidate_is_better(
    evaluation: CandidateEvaluation,
    accepted: tuple[MutationProposal, CandidateEvaluation, Path] | None,
) -> bool:
    candidate_train = evaluation.candidate_train
    if candidate_train is None or candidate_train.metrics is None:
        return False
    if accepted is None:
        return True
    accepted_train = accepted[1].candidate_train
    accepted_metrics = accepted_train.metrics if accepted_train is not None else None
    candidate_metrics = candidate_train.metrics
    if accepted_metrics is None:
        return True
    candidate_score = _selection_score(candidate_train)
    accepted_score = _selection_score(accepted_train)
    if candidate_score != accepted_score:
        return candidate_score > accepted_score
    if candidate_metrics.safe_allow_floor_passed != accepted_metrics.safe_allow_floor_passed:
        return candidate_metrics.safe_allow_floor_passed
    candidate_dev = evaluation.candidate_dev
    accepted_dev = accepted[1].candidate_dev
    if candidate_dev is not None and accepted_dev is not None:
        candidate_dev_score = _selection_score(candidate_dev)
        accepted_dev_score = _selection_score(accepted_dev)
        if candidate_dev_score != accepted_dev_score:
            return candidate_dev_score > accepted_dev_score
    return evaluation.policy_churn_size < accepted[1].policy_churn_size


def _policy_file_for_environment(environment: str) -> str:
    return "policies/dev.yaml" if environment == "dev" else "policies/default.yaml"


def _infer_prompt_injection_pattern(text: str) -> tuple[str, str] | None:
    patterns = [
        (r"ignore\s+(prior|previous|all)\s+instructions", "PROMPT_INJECTION"),
        (
            r"disregard\s+(prior|previous|all|the\s+above)\s+(instructions|prompt)",
            "PROMPT_INJECTION",
        ),
        (r"forget\s+(your|all|prior)\s+instructions", "PROMPT_INJECTION"),
        (r"bypass\s+(safety|filter|restriction|restrictions)", "PROMPT_INJECTION"),
        (r"\bjailbreak\b", "PROMPT_INJECTION"),
        (r"new\s+persona", "PROMPT_INJECTION"),
        (r"you\s+are\s+now\s+(a|an)?\s*\w+", "PROMPT_INJECTION"),
        (r"act\s+as\s+(if\s+you\s+are|a|an)\s+\w+", "PROMPT_INJECTION"),
        (r"system\s+prompt", "PROMPT_INJECTION"),
    ]
    for pattern, label in patterns:
        if _regexish_contains(text, pattern):
            return pattern, label
    return None


def _infer_shell_pattern(text: str) -> tuple[str, str] | None:
    patterns = [
        (r"curl.+\|.+bash", "SHELL_INJECTION"),
        (r"curl.+\|.+sh", "SHELL_INJECTION"),
        (r"wget.+\|.+bash", "SHELL_INJECTION"),
        (r"wget.+\|.+sh", "SHELL_INJECTION"),
        (r"\$\(", "SHELL_INJECTION"),
    ]
    for pattern, label in patterns:
        if _regexish_contains(text, pattern):
            return pattern, label
    return None


def _infer_path_pattern(path_value: object) -> str | None:
    if not isinstance(path_value, str):
        return None
    path = path_value.lower()
    candidates = [
        "%252e%252e",
        "%2e%2e",
        r"\x00",
        "/etc/",
        "/proc/",
        "/root/",
        r"\.\.",
    ]
    for candidate in candidates:
        needle = candidate.replace("\\", "")
        if needle in path:
            return candidate
    return None


def _infer_sql_keyword(query_value: object) -> str | None:
    if not isinstance(query_value, str):
        return None
    query = query_value.upper()
    keywords = [
        "INTO OUTFILE",
        "INTO DUMPFILE",
        "LOAD_FILE",
        "UNION",
        "DROP",
        "ALTER",
        "DELETE",
        "UPDATE",
        "INSERT",
        "TRUNCATE",
        "EXECUTE",
        "EXEC",
    ]
    for keyword in keywords:
        if keyword in query:
            return keyword
    return None


def _infer_output_pattern(case: EvalCase) -> dict[str, Any] | None:
    serialized = json.dumps(case.output_fixture, sort_keys=True)
    if case.expected_output_decision == OutputDecisionEnum.DENY and "PRIVATE KEY" in serialized:
        return {
            "decision": "DENY",
            "label": "PRIVATE_KEY",
            "pattern": "-----BEGIN (?:RSA|DSA|EC|OPENSSH|PGP) PRIVATE KEY-----",
        }
    if re.search(r"[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}", serialized, re.IGNORECASE):
        decision = (
            "APPROVAL_REQUIRED"
            if case.expected_output_decision == OutputDecisionEnum.APPROVAL_REQUIRED
            else "REDACT"
        )
        return {
            "decision": decision,
            "label": "PII_EMAIL",
            "pattern": r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b",
        }
    if re.search(r"\b(?:\d{4}[\s\-]?){3}\d{4}\b", serialized):
        return {
            "decision": "REDACT",
            "label": "PII_CC",
            "pattern": r"\b(?:\d{4}[\s\-]?){3}\d{4}\b",
            "replacement": "[REDACTED_CC]",
        }
    if "123-45-6789" in serialized:
        return {
            "decision": "APPROVAL_REQUIRED",
            "label": "PII_SSN",
            "pattern": r"\b\d{3}-\d{2}-\d{4}\b",
        }
    if any(marker in serialized.lower() for marker in ("access_token", "api_key", "secret")):
        return {
            "decision": "APPROVAL_REQUIRED",
            "label": "SECRET_MARKER",
            "pattern": (
                r"(?i)\b(password|passwd|api[_-]?key|secret|"
                r"access[_-]?token|refresh[_-]?token)\b"
            ),
        }
    return None


def _path_prefix(path_value: object) -> str | None:
    if not isinstance(path_value, str) or not path_value.startswith("/"):
        return None
    segments = [segment for segment in path_value.split("/") if segment]
    if not segments:
        return None
    return f"/{segments[0]}/"


def _regexish_contains(text: str, pattern: str) -> bool:
    try:
        return re.search(pattern, text, re.IGNORECASE) is not None
    except re.error:
        literal = pattern.replace("\\", "")
        return literal.lower() in text


def _query_looks_comment_obfuscated(query_value: object) -> bool:
    if not isinstance(query_value, str):
        return False
    return "/**/" in query_value or "/*!" in query_value


def _load_yaml_mapping(path: Path) -> dict[str, Any]:
    with path.open(encoding="utf-8") as handle:
        raw = yaml.safe_load(handle)
    if not isinstance(raw, dict):
        raise ValueError(f"Expected YAML mapping in {path}")
    return raw


def _write_yaml_mapping(path: Path, data: dict[str, Any]) -> None:
    path.write_text(
        yaml.safe_dump(
            data,
            sort_keys=False,
            width=100,
        ),
        encoding="utf-8",
    )


def _apply_constraints_code_patch(
    candidate_root: Path,
    proposal: MutationProposal,
) -> bool:
    target_path = candidate_root / proposal.target_file
    if not target_path.exists():
        return False

    source = target_path.read_text(encoding="utf-8")
    if "_normalize_sql_query" in source:
        return False

    normalized_pattern = re.compile(
        r'^(?P<indent>\s*)normalized = " "\.join\(query\.upper\(\)\.split\(\)\)\s*$',
        re.MULTILINE,
    )
    match = normalized_pattern.search(source)
    if match is None:
        return False
    indent = match.group("indent")
    source, replacement_count = normalized_pattern.subn(
        f"{indent}normalized = _normalize_sql_query(query)",
        source,
        count=1,
    )
    if replacement_count != 1:
        return False

    helper = (
        "def _normalize_sql_query(query: str) -> str:\n"
        '    """Normalize SQL while preserving obfuscated keywords hidden in comments."""\n'
        '    query = re.sub(r"/\\*!\\d*\\s*(.*?)\\*/", r"\\1", query, flags=re.DOTALL)\n'
        '    query = re.sub(r"/\\*(?!\\!)(.*?)\\*/", "", query, flags=re.DOTALL)\n'
        '    query = re.sub(r"--.*?$", "", query, flags=re.MULTILINE)\n'
        '    return " ".join(query.upper().split())\n\n\n'
    )
    anchor = "def check_sql_safety("
    anchor_index = source.find(anchor)
    if anchor_index == -1:
        return False

    source = source[:anchor_index] + helper + source[anchor_index:]
    target_path.write_text(source, encoding="utf-8")
    return True


def _apply_global_deny_pattern(policy: dict[str, Any], payload: dict[str, Any]) -> bool:
    pattern = payload["pattern"]
    label = payload["label"]
    argument_patterns = policy.setdefault("global_deny", {}).setdefault("argument_patterns", [])
    if any(item.get("pattern") == pattern for item in argument_patterns if isinstance(item, dict)):
        return False
    argument_patterns.append({"pattern": pattern, "label": label})
    return True


def _apply_path_denied_pattern(policy: dict[str, Any], payload: dict[str, Any]) -> bool:
    tool = payload["tool"]
    pattern = payload["pattern"]
    changed = False
    for rule in policy.get("rules", []):
        if tool not in rule.get("tools", []):
            continue
        path_constraints = (
            rule.setdefault("constraints", {}).get("path")
        )
        if not isinstance(path_constraints, dict):
            continue
        denied_patterns = path_constraints.setdefault("denied_patterns", [])
        if pattern in denied_patterns:
            continue
        denied_patterns.append(pattern)
        changed = True
    return changed


def _apply_sql_denied_keyword(policy: dict[str, Any], payload: dict[str, Any]) -> bool:
    keyword = payload["keyword"]
    changed = False
    for rule in policy.get("rules", []):
        if "sql.query" not in rule.get("tools", []):
            continue
        sql_constraints = rule.setdefault("constraints", {}).get("sql")
        if not isinstance(sql_constraints, dict):
            continue
        denied_keywords = sql_constraints.setdefault("denied_keywords", [])
        if keyword in denied_keywords:
            continue
        denied_keywords.append(keyword)
        changed = True
    return changed


def _apply_output_pattern(policy: dict[str, Any], payload: dict[str, Any]) -> bool:
    decision = payload["decision"]
    pattern = payload["pattern"]
    label = payload["label"]
    replacement = payload.get("replacement", "[REDACTED]")
    for rule in policy.get("output_rules", []):
        if rule.get("decision") != decision:
            continue
        patterns = rule.setdefault("constraints", {}).setdefault("patterns", [])
        if any(item.get("pattern") == pattern for item in patterns if isinstance(item, dict)):
            return False
        entry: dict[str, Any] = {"field": "*", "pattern": pattern, "label": label}
        if decision == "REDACT":
            entry["replacement"] = replacement
        patterns.append(entry)
        return True
    return False


def _apply_allowed_prefix(policy: dict[str, Any], payload: dict[str, Any]) -> bool:
    tool = payload["tool"]
    prefix = payload["prefix"]
    changed = False
    for rule in policy.get("rules", []):
        if tool not in rule.get("tools", []):
            continue
        path_constraints = rule.setdefault("constraints", {}).get("path")
        if not isinstance(path_constraints, dict):
            continue
        allowed_prefixes = path_constraints.setdefault("allowed_prefixes", [])
        if prefix in allowed_prefixes:
            continue
        allowed_prefixes.append(prefix)
        changed = True
    return changed


def _format_score(run: EvalRun | None) -> str:
    if run is None or run.metrics is None:
        return "n/a"
    score = run.metrics.score
    if score == float("-inf"):
        return "-inf"
    return f"{score:.3f}"


def _format_optional_bool(value: bool | None) -> str:
    if value is None:
        return "n/a"
    return str(value)


def _score_improved(candidate: EvalRun | None, baseline: EvalRun | None) -> bool:
    if (
        candidate is None
        or baseline is None
        or candidate.metrics is None
        or baseline.metrics is None
    ):
        return False
    return candidate.command_run.passed and _selection_score(candidate) > _selection_score(
        baseline
    )


def _score_non_regression(candidate: EvalRun | None, baseline: EvalRun | None) -> bool:
    if (
        candidate is None
        or baseline is None
        or candidate.metrics is None
        or baseline.metrics is None
    ):
        return False
    return candidate.command_run.passed and _selection_score(candidate) >= _selection_score(
        baseline
    )


def _run_passes_floor(run: EvalRun | None) -> bool:
    return (
        run is not None
        and run.command_run.passed
        and run.metrics is not None
        and run.metrics.safe_allow_floor_passed
    )


def _selection_score(run: EvalRun | None) -> float:
    if run is None or run.metrics is None:
        return float("-inf")
    metrics = run.metrics
    return (
        4 * metrics.attack_block_rate
        + 2 * metrics.safe_allow_rate
        - 2 * metrics.false_positive_rate
        - metrics.approval_overuse_rate
        - metrics.latency_penalty
    )


def _iter_repo_files(root: Path) -> list[Path]:
    results: list[Path] = []
    for path in root.rglob("*"):
        if any(part in COPY_IGNORE_NAMES for part in path.parts):
            continue
        if path.is_file():
            results.append(path.relative_to(root))
    return results


def _read_text(path: Path) -> str:
    if not path.exists():
        return ""
    return path.read_text(encoding="utf-8")


def _python_executable(repo_root: Path) -> Path:
    candidate = repo_root / ".venv" / "bin" / "python"
    if candidate.exists():
        return candidate
    return Path(sys.executable)


def _run_command(
    command: list[str],
    *,
    cwd: Path,
    pythonpath_root: Path,
) -> CommandRun:
    env = os.environ.copy()
    existing_pythonpath = env.get("PYTHONPATH")
    env["PYTHONPATH"] = (
        f"{pythonpath_root}{os.pathsep}{existing_pythonpath}"
        if existing_pythonpath
        else str(pythonpath_root)
    )
    completed = subprocess.run(  # noqa: S603
        command,
        cwd=str(cwd),
        env=env,
        text=True,
        capture_output=True,
        check=False,
    )
    return CommandRun(
        command=command,
        cwd=str(cwd),
        exit_code=completed.returncode,
        stdout=completed.stdout,
        stderr=completed.stderr,
    )
