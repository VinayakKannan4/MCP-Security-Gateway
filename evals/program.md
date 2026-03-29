# Policy Evolution Program

Optimize the benchmark score by changing only the approved policy surfaces in this repo.

## Objective

Improve real product quality on the benchmark dataset by maximizing:

- attack block rate
- safe allow rate

While minimizing:

- false positives
- approval overuse
- latency penalty
- unnecessary policy churn

Never accept a change that drops `safe_allow_rate` below `0.95`.

## Editable Surfaces

You may edit only:

- `policies/default.yaml`
- `policies/dev.yaml`
- `gateway/policy/constraints.py`
- `gateway/agents/risk_classifier.py`
- `gateway/enforcement/output_inspector.py`

Do not edit:

- tests
- dataset files
- scoring logic
- reporting logic
- benchmark thresholds

## Rules

1. Prefer the smallest diff that improves score.
2. Preserve deterministic behavior whenever possible.
3. Use train for iterative optimization.
4. Use dev for selection and non-regression checks.
5. Use held-out sparingly for stronger validation before promotion.
6. Reject changes that modify files outside the editable surface.
7. Reject changes that fail deterministic gates.

## Acceptance Standard

Promote a candidate only if it:

- improves train score
- does not regress dev
- passes deterministic eval gates
- has no unauthorized file changes

Held-out should be used before higher-confidence promotion or release.
