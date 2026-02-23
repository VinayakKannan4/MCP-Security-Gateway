"""
Tool argument schema validation (step 3 of the pipeline).
Validates tool arguments against tool_schemas defined in the policy YAML.
"""

import re
from typing import Any

from gateway.models.policy import PolicyConfig, ToolPropertySchema, ToolSchema


class SchemaValidationError(Exception):
    def __init__(self, violations: list[str]) -> None:
        self.violations = violations
        super().__init__(f"Schema validation failed: {'; '.join(violations)}")


def validate_tool_args(
    tool: str,
    arguments: dict[str, Any],
    policy: PolicyConfig,
) -> list[str]:
    """
    Validate tool arguments against the tool schema in the policy.
    Returns a list of violation strings (empty = valid).
    """
    schema = policy.tool_schemas.get(tool)
    if schema is None:
        # No schema defined for this tool — skip validation
        return []

    return _validate_against_schema(arguments, schema)


def _validate_against_schema(
    arguments: dict[str, Any],
    schema: ToolSchema,
) -> list[str]:
    violations: list[str] = []

    # Check required fields
    for field in schema.required:
        if field not in arguments:
            violations.append(f"Missing required field: '{field}'")

    # Check property constraints
    for field_name, prop_schema in schema.properties.items():
        if field_name not in arguments:
            continue  # Not present, skip (required check above handles missing required fields)

        value = arguments[field_name]
        field_violations = _validate_property(field_name, value, prop_schema)
        violations.extend(field_violations)

    return violations


def _validate_property(
    field_name: str,
    value: Any,
    schema: ToolPropertySchema,
) -> list[str]:
    violations: list[str] = []

    # Type check
    type_map = {
        "string": str,
        "integer": int,
        "number": (int, float),
        "boolean": bool,
        "array": list,
        "object": dict,
    }
    expected_type = type_map.get(schema.type)
    if expected_type and not isinstance(value, expected_type):
        violations.append(
            f"Field '{field_name}' expected type '{schema.type}', "
            f"got {type(value).__name__}"
        )
        return violations  # Skip further checks if type is wrong

    if isinstance(value, str):
        if schema.max_length is not None and len(value) > schema.max_length:
            violations.append(
                f"Field '{field_name}' length {len(value)} exceeds maxLength {schema.max_length}"
            )
        if schema.min_length is not None and len(value) < schema.min_length:
            violations.append(
                f"Field '{field_name}' length {len(value)} below minLength {schema.min_length}"
            )
        if schema.pattern is not None and not re.fullmatch(schema.pattern, value):
            violations.append(
                f"Field '{field_name}' value does not match required pattern: {schema.pattern}"
            )

    if isinstance(value, (int, float)):
        if schema.minimum is not None and value < schema.minimum:
            violations.append(
                f"Field '{field_name}' value {value} below minimum {schema.minimum}"
            )
        if schema.maximum is not None and value > schema.maximum:
            violations.append(
                f"Field '{field_name}' value {value} above maximum {schema.maximum}"
            )

    if schema.enum is not None and value not in schema.enum:
        violations.append(
            f"Field '{field_name}' value '{value}' not in allowed enum: {schema.enum}"
        )

    return violations
