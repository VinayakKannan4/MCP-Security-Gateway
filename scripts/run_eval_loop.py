"""Run deterministic benchmark scoring against the current workspace."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from evals.mutate_policy import (
    create_candidate_workspace,
    evaluate_candidate_workspace,
    generate_mutation_proposals,
    promote_candidate_workspace,
    render_candidate_summary,
    render_search_summary,
    run_mutation_search,
)
from evals.reporting import build_report_payload, render_markdown_report
from evals.scoring import REPO_ROOT, evaluate_split


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Evaluate the current workspace against the benchmark datasets.",
    )
    parser.add_argument(
        "--split",
        choices=["train", "dev", "held_out", "all"],
        default="all",
        help="Which dataset split to evaluate.",
    )
    parser.add_argument(
        "--policy-churn-size",
        type=int,
        default=0,
        help="Optional churn value to carry into the score/report.",
    )
    parser.add_argument(
        "--safe-allow-floor",
        type=float,
        default=0.95,
        help="Hard floor for safe_allow_rate before score is forced to -inf.",
    )
    parser.add_argument(
        "--json-out",
        type=Path,
        help="Optional path to write the JSON report.",
    )
    parser.add_argument(
        "--markdown-out",
        type=Path,
        help="Optional path to write the markdown report.",
    )
    parser.add_argument(
        "--strict",
        action="store_true",
        help="Exit non-zero when any case mismatches or the safe-allow floor fails.",
    )
    parser.add_argument(
        "--prepare-candidate-root",
        type=Path,
        help="Create a writable candidate workspace by copying the current repo.",
    )
    parser.add_argument(
        "--candidate-root",
        type=Path,
        help="Evaluate a candidate workspace against the current repo baseline.",
    )
    parser.add_argument(
        "--promote-if-improved",
        action="store_true",
        help="When evaluating a candidate, copy editable surfaces back on success.",
    )
    parser.add_argument(
        "--run-held-out",
        action="store_true",
        help="When evaluating a candidate, include held_out as an extra non-regression gate.",
    )
    parser.add_argument(
        "--skip-gates",
        action="store_true",
        help="Skip deterministic pytest gates during candidate evaluation.",
    )
    parser.add_argument(
        "--search",
        action="store_true",
        help="Run the deterministic mutation search loop.",
    )
    parser.add_argument(
        "--max-rounds",
        type=int,
        default=6,
        help="Maximum mutation-search rounds.",
    )
    parser.add_argument(
        "--max-proposals",
        type=int,
        default=12,
        help="Maximum proposals to evaluate per round.",
    )
    parser.add_argument(
        "--list-proposals",
        action="store_true",
        help="Print the currently generated train-time mutation proposals.",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if args.prepare_candidate_root is not None:
        created_root = create_candidate_workspace(
            base_root=REPO_ROOT,
            candidate_root=args.prepare_candidate_root,
        )
        print(created_root)
        return 0

    if args.list_proposals:
        proposals = generate_mutation_proposals(
            REPO_ROOT,
            split="train",
            max_proposals=args.max_proposals,
        )
        if not proposals:
            print("No mutation proposals generated.")
            return 0
        for proposal in proposals:
            print(f"{proposal.proposal_id}: {proposal.summary} -> {proposal.target_file}")
        return 0

    if args.search:
        search = run_mutation_search(
            base_root=REPO_ROOT,
            max_rounds=args.max_rounds,
            max_proposals=args.max_proposals,
            safe_allow_floor=args.safe_allow_floor,
            run_held_out=args.run_held_out,
            run_gates=not args.skip_gates,
            promote_best=args.promote_if_improved,
        )
        summary = render_search_summary(search)
        print(summary)

        if args.json_out is not None:
            args.json_out.parent.mkdir(parents=True, exist_ok=True)
            args.json_out.write_text(
                json.dumps(search.model_dump(mode="json"), indent=2, sort_keys=True) + "\n",
                encoding="utf-8",
            )

        if args.markdown_out is not None:
            args.markdown_out.parent.mkdir(parents=True, exist_ok=True)
            args.markdown_out.write_text(summary + "\n", encoding="utf-8")

        if args.strict and not search.improved:
            return 1
        return 0

    if args.candidate_root is not None:
        evaluation = evaluate_candidate_workspace(
            args.candidate_root,
            base_root=REPO_ROOT,
            safe_allow_floor=args.safe_allow_floor,
            run_held_out=args.run_held_out,
            run_gates=not args.skip_gates,
        )

        if args.promote_if_improved and evaluation.promotable:
            promote_candidate_workspace(args.candidate_root, base_root=REPO_ROOT)
            evaluation.promoted = True

        summary = render_candidate_summary(evaluation)
        print(summary)

        if args.json_out is not None:
            args.json_out.parent.mkdir(parents=True, exist_ok=True)
            args.json_out.write_text(
                json.dumps(evaluation.model_dump(mode="json"), indent=2, sort_keys=True) + "\n",
                encoding="utf-8",
            )

        if args.markdown_out is not None:
            args.markdown_out.parent.mkdir(parents=True, exist_ok=True)
            args.markdown_out.write_text(summary + "\n", encoding="utf-8")

        if args.strict and not evaluation.promotable:
            return 1
        return 0

    results, metrics = evaluate_split(
        split=args.split,
        policy_churn_size=args.policy_churn_size,
        safe_allow_floor=args.safe_allow_floor,
    )
    payload = build_report_payload(metrics, results)
    markdown_report = render_markdown_report(metrics, results)

    print(markdown_report)

    if args.json_out is not None:
        args.json_out.parent.mkdir(parents=True, exist_ok=True)
        args.json_out.write_text(
            json.dumps(payload, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )

    if args.markdown_out is not None:
        args.markdown_out.parent.mkdir(parents=True, exist_ok=True)
        args.markdown_out.write_text(markdown_report + "\n", encoding="utf-8")

    if args.strict and (metrics.failed_case_ids or not metrics.safe_allow_floor_passed):
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
