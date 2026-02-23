"""
Deterministic policy engine — Layer 1 of the enforcement model.

This is the AUTHORITATIVE security enforcement layer.
No LLM calls. No I/O. Fully deterministic and unit-testable.

The LLM risk classifier (Layer 2) may inform the audit log,
but it CANNOT override a DENY decision from this engine.
"""

import fnmatch
import re

from gateway.models.identity import CallerIdentity, TrustLevel
from gateway.models.mcp import MCPRequest
from gateway.models.policy import (
    ConstraintConfig,
    DecisionEnum,
    PolicyConfig,
    PolicyDecision,
    PolicyRule,
)
from gateway.policy.constraints import (
    check_argument_patterns,
    check_global_deny_patterns,
    check_path_safety,
    check_sql_safety,
    check_url_safety,
)
from gateway.policy.schema_validator import validate_tool_args


class PolicyEngine:
    """
    Evaluates MCP requests against a loaded PolicyConfig.

    Usage:
        engine = PolicyEngine(policy)
        decision = engine.evaluate(request, identity)
    """

    def __init__(self, policy: PolicyConfig) -> None:
        self._policy = policy
        # Pre-sort rules by priority (descending) for fast evaluation
        self._sorted_rules = sorted(policy.rules, key=lambda r: -r.priority)

    def validate_tool_schema(
        self, request: MCPRequest
    ) -> tuple[bool, list[str]]:
        """
        Validate tool arguments against the tool schema (step 3).
        Returns (valid: bool, violations: list[str]).
        """
        violations = validate_tool_args(
            request.tool_call.tool,
            request.tool_call.arguments,
            self._policy,
        )
        return len(violations) == 0, violations

    def evaluate(
        self,
        request: MCPRequest,
        identity: CallerIdentity,
    ) -> PolicyDecision:
        """
        Evaluate an MCP request against the policy.

        This is the AUTHORITATIVE enforcement decision.
        Returns a PolicyDecision — this cannot be overridden by LLM agents.
        """
        tool = request.tool_call.tool
        arguments = request.tool_call.arguments

        # --- Step 1: Check global deny tools ---
        for denied_tool_pattern in self._policy.global_deny.tools:
            if fnmatch.fnmatch(tool, denied_tool_pattern):
                return PolicyDecision(
                    decision=DecisionEnum.DENY,
                    matched_rule="global-deny-tools",
                    rationale=f"Tool '{tool}' matches global deny pattern: {denied_tool_pattern}",
                )

        # --- Step 2: Check global deny argument patterns ---
        passed, reason = check_global_deny_patterns(
            arguments,
            self._policy.global_deny.argument_patterns,
        )
        if not passed:
            return PolicyDecision(
                decision=DecisionEnum.DENY,
                matched_rule="global-deny-argument-patterns",
                rationale=reason,
            )

        # --- Step 3: Match rules in priority order ---
        for rule in self._sorted_rules:
            if not self._rule_matches(rule, tool, identity):
                continue

            # Rule matches — now check constraints
            constraint_results = self._check_constraints(
                rule.constraints,
                request.tool_call.tool,
                arguments,
            )

            failed_constraints = [r for r in constraint_results if not r[0]]
            if failed_constraints:
                # Constraint(s) failed — skip this rule and try the next one
                continue

            constraints_applied = [r[2] for r in constraint_results]
            return PolicyDecision(
                decision=rule.decision,
                matched_rule=rule.name,
                rationale=f"Matched rule '{rule.name}' (priority={rule.priority}): {rule.description}",
                requires_approval=rule.decision == DecisionEnum.APPROVAL_REQUIRED,
                constraints_applied=constraints_applied,
            )

        # --- No rule matched: catch-all deny ---
        return PolicyDecision(
            decision=DecisionEnum.DENY,
            matched_rule="catch-all-deny",
            rationale=f"No policy rule matched tool='{tool}' role='{identity.role}' env='{identity.environment}'",
        )

    def _rule_matches(
        self,
        rule: PolicyRule,
        tool: str,
        identity: CallerIdentity,
    ) -> bool:
        """Check if a rule applies to this tool + caller without running constraints."""
        # Tool match (glob pattern)
        if not any(fnmatch.fnmatch(tool, pattern) for pattern in rule.tools):
            return False

        # Role match
        if "*" not in rule.roles and identity.role not in rule.roles:
            return False

        # Environment match
        if "*" not in rule.environments and identity.environment not in rule.environments:
            return False

        # Trust level bounds
        if rule.trust_level_min is not None and identity.trust_level < rule.trust_level_min:
            return False
        if rule.trust_level_max is not None and identity.trust_level > rule.trust_level_max:
            return False

        return True

    def _check_constraints(
        self,
        constraints: ConstraintConfig,
        tool: str,
        arguments: dict,
    ) -> list[tuple[bool, str, str]]:
        """
        Run all configured constraint checkers.
        Returns list of (passed, reason, constraint_name) tuples.
        """
        results: list[tuple[bool, str, str]] = []

        # Path constraint
        if constraints.path is not None:
            path_val = arguments.get("path")
            if path_val is not None and isinstance(path_val, str):
                passed, reason = check_path_safety(path_val, constraints.path)
                results.append((passed, reason, "path"))

        # SQL constraint
        if constraints.sql is not None:
            query_val = arguments.get("query")
            if query_val is not None and isinstance(query_val, str):
                passed, reason = check_sql_safety(query_val, constraints.sql)
                results.append((passed, reason, "sql"))

        # URL constraint
        if constraints.url is not None:
            url_val = arguments.get("url")
            if url_val is not None and isinstance(url_val, str):
                passed, reason = check_url_safety(url_val, constraints.url)
                results.append((passed, reason, "url"))

        # Argument pattern constraint
        if constraints.arguments is not None:
            passed, reason = check_argument_patterns(arguments, constraints.arguments)
            results.append((passed, reason, "arguments"))

        return results
