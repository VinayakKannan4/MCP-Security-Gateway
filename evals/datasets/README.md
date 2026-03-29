# Evaluation Datasets v1

This directory contains the hand-authored v1 benchmark dataset for benchmark-driven policy evolution in this repo. Most rows are grounded in the current deterministic product behavior, while the challenge rows intentionally encode harder target behavior that the current policy stack does not fully satisfy yet.

## Files

- `train.yaml`: 68 rows
- `dev.yaml`: 24 rows
- `held_out.yaml`: 24 rows
- `../../tests/evals/fixtures/policy_regressions.yaml`: 18-row request-policy regression subset
- `../../tests/evals/fixtures/output_regressions.yaml`: 8-row output-policy regression subset

Total rows: 116

## Schema

Each YAML row uses this schema:

- `id`: unique string identifier
- `split`: `train | dev | held_out`
- `tenant_org`: organization identifier carried into `CallerIdentity.org_id`
- `caller_role`: caller role used for policy matching
- `trust_level`: integer trust level used for `CallerIdentity.trust_level`
- `environment`: `dev | staging | prod`
- `tool_call`: mapping with `server`, `tool`, and `arguments`
- `context`: request context string or `null`
- `expected_decision`: request-time decision from `PolicyEngine`
- `expected_requires_approval`: request-time approval boolean only
- `expected_sanitization`: deterministic sanitizer expectations as a list of objects with `field`, `reason`, and `replacement`
- `output_fixture`: output payload used to exercise `OutputPolicyEngine`, or `null`
- `expected_output_decision`: output-time decision from `OutputPolicyEngine`, or `null`
- `attack_family`: concrete attack family name for attack rows, otherwise `null`
- `tags`: flat list of analysis tags including `family:*` and `variant:*`
- `latency_budget_ms`: conservative deterministic latency budget

## Family Coverage

Attack families:

- `prompt_injection_ignore_instructions`
- `prompt_injection_bypass_restrictions`
- `prompt_injection_roleplay`
- `prompt_injection_jailbreak_language`
- `prompt_injection_system_prompt_exfil`
- `prompt_injection_new_persona`
- `path_traversal_plain`
- `path_traversal_encoded`
- `sql_destructive`
- `sql_comment_obfuscation`
- `sql_union_exfil`
- `sql_outfile_exfil`
- `sql_versioned_comment_exfil`
- `shell_injection_payload`

Safe workflow families:

- `safe_fs_read_data`
- `safe_fs_read_reports`
- `safe_sql_select_analytics`
- `safe_fs_write_dev`
- `prod_fs_write_requires_approval`
- `prod_sql_admin_requires_approval`

Sanitization families:

- `sanitize_email`
- `sanitize_ssn`
- `sanitize_secret_token`
- `sanitize_path_traversal_sequence`

Output inspection families:

- `output_private_key_deny`
- `output_pii_redact`
- `output_payment_card_redact`
- `output_sensitive_prod_approval`

## Split Strategy

Whole-family split separation is enforced. No attack family, safe workflow family, sanitization family, or output family appears in more than one split.

- `train`: 14 families, 68 rows
- `dev`: 7 families, 24 rows
- `held_out`: 7 families, 24 rows

## Labeling Sources

These files were used as the ground truth for labels and expectations:

- `policies/default.yaml`
- `policies/dev.yaml`
- `gateway/policy/engine.py`
- `gateway/policy/constraints.py`
- `gateway/policy/output_engine.py`
- `gateway/agents/argument_guard.py`
- `gateway/agents/risk_classifier.py`
- `tests/scenarios/attack/test_attack_scenarios.py`
- `tests/scenarios/safe/test_safe_scenarios.py`
- `tests/unit/test_constraints.py`
- `tests/unit/test_output_engine.py`
- `tests/unit/test_argument_guard.py`
- `tests/unit/test_policy_engine.py`

## Assumptions

- `expected_decision` is sourced from the authoritative request-layer policy intent. For the harder challenge families, the label may intentionally disagree with the current implementation so the benchmark can drive policy evolution.
- `dev` rows are evaluated against `policies/dev.yaml`; `staging` and `prod` rows are evaluated against `policies/default.yaml` via `load_policy_for_environment(...)`.
- `expected_sanitization` captures the deterministic regex pass from `ArgumentGuardAgent`. For request-time `DENY` rows, the list is empty because the enforcement pipeline skips sanitization after a deny decision.
- `output_fixture` is only populated for rows intended to exercise output inspection. Non-output rows leave `output_fixture` and `expected_output_decision` as `null`.
- The dataset avoids dynamic hashes and records only stable sanitizer replacement values.
- The challenge rows currently focus on broader prompt-injection language, SQL comment obfuscation, and payment-card egress redaction, because those create meaningful search signal for the mutation loop.
