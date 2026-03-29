from __future__ import annotations

from pathlib import Path

from evals import mutate_policy
from evals.mutate_policy import (
    CommandRun,
    EvalRun,
    MutationProposal,
    apply_mutation_proposal,
    compute_policy_churn_size,
    create_candidate_workspace,
    evaluate_candidate_workspace,
    find_changed_files,
    generate_mutation_proposals,
    promote_candidate_workspace,
    run_mutation_search,
)
from evals.scoring import EvalMetrics


def test_detect_changed_files_and_promote_only_editable(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setattr(
        mutate_policy,
        "EDITABLE_SURFACES",
        (
            Path("policies/default.yaml"),
            Path("gateway/policy/constraints.py"),
        ),
    )
    monkeypatch.setattr(mutate_policy, "COPY_IGNORE_NAMES", set())

    base_root = tmp_path / "base"
    candidate_root = tmp_path / "candidate"
    (base_root / "policies").mkdir(parents=True)
    (base_root / "gateway/policy").mkdir(parents=True)
    (base_root / "README.md").write_text("base\n", encoding="utf-8")
    (base_root / "policies/default.yaml").write_text("version: 1\n", encoding="utf-8")
    (base_root / "gateway/policy/constraints.py").write_text(
        "ALLOWED = True\n",
        encoding="utf-8",
    )

    created_candidate = create_candidate_workspace(
        base_root=base_root,
        candidate_root=candidate_root,
    )
    assert created_candidate == candidate_root.resolve()

    (candidate_root / "policies/default.yaml").write_text("version: 2\n", encoding="utf-8")
    (candidate_root / "gateway/policy/constraints.py").write_text(
        "ALLOWED = False\n",
        encoding="utf-8",
    )
    (candidate_root / "README.md").write_text("changed\n", encoding="utf-8")

    changed_files = find_changed_files(base_root, candidate_root)
    assert "README.md" in changed_files
    assert "policies/default.yaml" in changed_files
    assert compute_policy_churn_size(base_root, candidate_root) > 0

    try:
        promote_candidate_workspace(candidate_root, base_root=base_root)
    except ValueError as exc:
        assert "README.md" in str(exc)
    else:
        raise AssertionError("promotion should fail on unauthorized changes")


def test_identical_candidate_workspace_is_not_improved(tmp_path: Path) -> None:
    candidate_root = tmp_path / "candidate"
    create_candidate_workspace(candidate_root=candidate_root)

    evaluation = evaluate_candidate_workspace(
        candidate_root,
        run_held_out=False,
        run_gates=False,
    )

    assert evaluation.unauthorized_changes == []
    assert evaluation.policy_churn_size == 0
    assert evaluation.train_improved is False
    assert evaluation.dev_non_regression is None
    assert evaluation.gates_passed is None
    assert evaluation.promotable is False


def test_apply_mutation_proposal_updates_yaml(tmp_path: Path) -> None:
    candidate_root = tmp_path / "candidate"
    policy_path = candidate_root / "policies"
    policy_path.mkdir(parents=True)
    (policy_path / "default.yaml").write_text(
        "global_deny:\n  argument_patterns: []\nrules: []\noutput_rules: []\n",
        encoding="utf-8",
    )

    proposal = MutationProposal(
        proposal_id="p1",
        kind="add_global_deny_pattern",
        target_file="policies/default.yaml",
        summary="add prompt injection deny",
        case_id="case-1",
        family="prompt_injection_ignore_instructions",
        payload={
            "pattern": r"ignore\s+(prior|previous|all)\s+instructions",
            "label": "PROMPT_INJECTION",
        },
    )

    changed = apply_mutation_proposal(candidate_root, proposal)

    assert changed is True
    contents = (policy_path / "default.yaml").read_text(encoding="utf-8")
    assert "PROMPT_INJECTION" in contents
    assert "ignore\\s+(prior|previous|all)\\s+instructions" in contents


def test_apply_mutation_proposal_patches_constraints_code(tmp_path: Path) -> None:
    candidate_root = tmp_path / "candidate"
    constraints_dir = candidate_root / "gateway" / "policy"
    constraints_dir.mkdir(parents=True)
    (constraints_dir / "constraints.py").write_text(
        (
            "import re\n\n"
            "def check_sql_safety(query, config):\n"
            '    normalized = " ".join(query.upper().split())\n'
            "    return True, normalized\n"
        ),
        encoding="utf-8",
    )

    proposal = MutationProposal(
        proposal_id="p2",
        kind="tighten_sql_comment_normalization",
        target_file="gateway/policy/constraints.py",
        summary="normalize SQL comments",
        case_id="case-2",
        family="sql_comment_obfuscation",
    )

    changed = apply_mutation_proposal(candidate_root, proposal)

    assert changed is True
    contents = (constraints_dir / "constraints.py").read_text(encoding="utf-8")
    assert "_normalize_sql_query" in contents
    assert 'normalized = _normalize_sql_query(query)' in contents


def test_generate_mutation_proposals_returns_proposal_objects() -> None:
    proposals = generate_mutation_proposals(max_proposals=5)

    assert isinstance(proposals, list)
    for proposal in proposals:
        assert proposal.proposal_id
        assert proposal.target_file


def test_run_mutation_search_stops_cleanly_without_signal(monkeypatch) -> None:
    monkeypatch.setattr(mutate_policy, "generate_mutation_proposals", lambda *args, **kwargs: [])
    search = run_mutation_search(
        max_rounds=1,
        max_proposals=4,
        run_gates=False,
    )

    assert search.improved is False
    assert search.accepted_proposals == []
    assert len(search.rounds) == 1
    assert search.rounds[0].proposal_count == 0


def test_candidate_promotion_still_requires_safe_allow_floor(
    monkeypatch,
    tmp_path: Path,
) -> None:
    def make_eval_run(
        split: str,
        *,
        safe_allow_rate: float,
        false_positive_rate: float,
        score: float = float("-inf"),
    ) -> EvalRun:
        return EvalRun(
            split=split,
            repo_root=str(tmp_path),
            metrics=EvalMetrics(
                split=split,
                case_count=10,
                attack_case_count=4,
                safe_allow_case_count=6,
                output_case_count=0,
                exact_match_rate=0.5,
                attack_block_rate=1.0,
                safe_allow_rate=safe_allow_rate,
                false_positive_rate=false_positive_rate,
                approval_overuse_rate=0.0,
                sanitizer_precision=1.0,
                sanitizer_recall=1.0,
                output_block_rate=1.0,
                p50_latency_ms=1.0,
                p95_latency_ms=1.0,
                latency_penalty=0.0,
                policy_churn_size=1,
                safe_allow_floor=0.95,
                safe_allow_floor_passed=False,
                score=score,
                failed_case_ids=["case-1"],
            ),
            command_run=CommandRun(
                command=["python", "scripts/run_eval_loop.py"],
                cwd=str(tmp_path),
                exit_code=0,
                stdout="",
                stderr="",
            ),
            report_path=None,
        )

    base_root = tmp_path / "base"
    candidate_root = tmp_path / "candidate"
    (base_root / "policies").mkdir(parents=True)
    (base_root / "policies" / "default.yaml").write_text(
        "global_deny:\n  argument_patterns: []\nrules: []\noutput_rules: []\n",
        encoding="utf-8",
    )
    create_candidate_workspace(base_root=base_root, candidate_root=candidate_root)
    (candidate_root / "policies" / "default.yaml").write_text(
        (
            "global_deny:\n"
            "  argument_patterns:\n"
            "    - pattern: foo\n"
            "      label: BAR\n"
            "rules: []\n"
            "output_rules: []\n"
        ),
        encoding="utf-8",
    )

    runs = iter(
        [
            make_eval_run("train", safe_allow_rate=0.80, false_positive_rate=0.20),
            make_eval_run("train", safe_allow_rate=0.85, false_positive_rate=0.15),
            make_eval_run("dev", safe_allow_rate=0.82, false_positive_rate=0.18),
            make_eval_run("dev", safe_allow_rate=0.86, false_positive_rate=0.14),
        ]
    )
    monkeypatch.setattr(mutate_policy, "run_eval_script", lambda **kwargs: next(runs))

    evaluation = evaluate_candidate_workspace(
        candidate_root,
        base_root=base_root,
        run_held_out=False,
        run_gates=False,
    )

    assert evaluation.train_improved is True
    assert evaluation.dev_non_regression is True
    assert evaluation.promotable is False
