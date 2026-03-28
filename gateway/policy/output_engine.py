"""Deterministic output / egress inspection."""

from __future__ import annotations

import copy
import fnmatch
import json
import re
from typing import Any

from gateway.models.identity import CallerIdentity
from gateway.models.policy import (
    OutputDecisionEnum,
    OutputPatternConstraint,
    OutputPolicyDecision,
    OutputPolicyRule,
    PolicyConfig,
)


class OutputPolicyEngine:
    def __init__(self, policy: PolicyConfig) -> None:
        self._sorted_rules = sorted(policy.output_rules, key=lambda r: -r.priority)

    def evaluate(
        self,
        tool: str,
        output: dict[str, Any],
        identity: CallerIdentity,
    ) -> OutputPolicyDecision:
        for rule in self._sorted_rules:
            if not self._rule_matches(rule, tool, identity):
                continue

            matched, matched_labels, redacted = self._apply_constraints(output, rule)
            if not matched:
                continue
            label_suffix = (
                f" Labels: {', '.join(matched_labels)}." if matched_labels else ""
            )

            return OutputPolicyDecision(
                decision=rule.decision,
                matched_rule=rule.name,
                rationale=f"Matched output rule '{rule.name}': {rule.description}.{label_suffix}",
                redacted_output=redacted,
                matched_labels=matched_labels,
            )

        return OutputPolicyDecision(
            decision=OutputDecisionEnum.ALLOW,
            matched_rule="output-allow-default",
            rationale="No output policy rule matched.",
            redacted_output=output,
        )

    def _rule_matches(
        self,
        rule: OutputPolicyRule,
        tool: str,
        identity: CallerIdentity,
    ) -> bool:
        if not any(fnmatch.fnmatch(tool, pattern) for pattern in rule.tools):
            return False
        if "*" not in rule.roles and identity.role not in rule.roles:
            return False
        if "*" not in rule.environments and identity.environment not in rule.environments:
            return False
        return True

    def _apply_constraints(
        self,
        output: dict[str, Any],
        rule: OutputPolicyRule,
    ) -> tuple[bool, list[str], dict[str, Any] | None]:
        matched_labels: list[str] = []
        redacted_output = copy.deepcopy(output)
        serialized = json.dumps(output, default=str)

        if (
            rule.constraints.max_output_length is not None
            and len(serialized) > rule.constraints.max_output_length
        ):
            matched_labels.append("MAX_OUTPUT_LENGTH")
            if rule.decision == OutputDecisionEnum.REDACT:
                redacted_output = {"_redacted": "[OUTPUT_TOO_LARGE]"}

        for pattern in rule.constraints.patterns:
            did_match = False
            if pattern.field == "*":
                redacted_output, did_match = self._apply_pattern_recursive(
                    redacted_output,
                    pattern,
                )
            else:
                redacted_output, did_match = self._apply_pattern_to_field_path(
                    redacted_output,
                    pattern,
                )

            if did_match:
                matched_labels.append(pattern.label)

        if not matched_labels:
            return False, [], None

        if rule.decision == OutputDecisionEnum.REDACT:
            return True, matched_labels, redacted_output
        return True, matched_labels, None

    def _apply_pattern_recursive(
        self,
        obj: Any,
        pattern: OutputPatternConstraint,
    ) -> tuple[Any, bool]:
        matched = False
        if isinstance(obj, dict):
            updated: dict[str, Any] = {}
            for key, value in obj.items():
                updated[key], child_matched = self._apply_pattern_recursive(value, pattern)
                matched = matched or child_matched
            return updated, matched
        if isinstance(obj, list):
            updated_list: list[Any] = []
            for item in obj:
                updated_item, child_matched = self._apply_pattern_recursive(item, pattern)
                updated_list.append(updated_item)
                matched = matched or child_matched
            return updated_list, matched
        if isinstance(obj, str):
            if re.search(pattern.pattern, obj, re.IGNORECASE):
                return re.sub(pattern.pattern, pattern.replacement, obj, flags=re.IGNORECASE), True
        return obj, matched

    def _apply_pattern_to_field_path(
        self,
        output: dict[str, Any],
        pattern: OutputPatternConstraint,
    ) -> tuple[dict[str, Any], bool]:
        segments = pattern.field.split(".")
        updated, matched = self._apply_pattern_to_segments(output, segments, pattern)
        if not isinstance(updated, dict):
            return output, matched
        return updated, matched

    def _apply_pattern_to_segments(
        self,
        obj: Any,
        segments: list[str],
        pattern: OutputPatternConstraint,
    ) -> tuple[Any, bool]:
        if not segments:
            return self._apply_pattern_to_leaf(obj, pattern)

        current = segments[0]
        remaining = segments[1:]
        matched = False

        if isinstance(obj, dict):
            updated = dict(obj)
            if current == "*":
                for key, value in updated.items():
                    updated[key], child_matched = self._apply_pattern_to_segments(
                        value,
                        remaining,
                        pattern,
                    )
                    matched = matched or child_matched
                return updated, matched
            if current not in updated:
                return obj, False
            updated[current], matched = self._apply_pattern_to_segments(
                updated[current],
                remaining,
                pattern,
            )
            return updated, matched

        if isinstance(obj, list):
            updated_list = list(obj)
            if current == "*":
                for index, value in enumerate(updated_list):
                    updated_list[index], child_matched = self._apply_pattern_to_segments(
                        value,
                        remaining,
                        pattern,
                    )
                    matched = matched or child_matched
                return updated_list, matched
            if current.isdigit():
                index = int(current)
                if index >= len(updated_list):
                    return obj, False
                updated_list[index], matched = self._apply_pattern_to_segments(
                    updated_list[index],
                    remaining,
                    pattern,
                )
                return updated_list, matched

        return obj, False

    def _apply_pattern_to_leaf(
        self,
        value: Any,
        pattern: OutputPatternConstraint,
    ) -> tuple[Any, bool]:
        if not isinstance(value, str):
            return value, False
        if not re.search(pattern.pattern, value, re.IGNORECASE):
            return value, False
        return (
            re.sub(
                pattern.pattern,
                pattern.replacement,
                value,
                flags=re.IGNORECASE,
            ),
            True,
        )
