from enum import Enum
from typing import Any
from pydantic import BaseModel, Field


class DecisionEnum(str, Enum):
    ALLOW = "ALLOW"
    DENY = "DENY"
    APPROVAL_REQUIRED = "APPROVAL_REQUIRED"
    SANITIZE_AND_ALLOW = "SANITIZE_AND_ALLOW"


class PathConstraintConfig(BaseModel):
    allowed_prefixes: list[str] = Field(default_factory=list)
    denied_patterns: list[str] = Field(default_factory=list)
    max_depth: int | None = None
    normalize: bool = True


class SqlConstraintConfig(BaseModel):
    allowed_statements: list[str] = Field(default_factory=list)
    denied_keywords: list[str] = Field(default_factory=list)
    max_rows_hint: int | None = None


class UrlConstraintConfig(BaseModel):
    allowed_domains: list[str] = Field(default_factory=list)
    denied_domains: list[str] = Field(default_factory=list)
    require_https: bool = False
    block_private_ips: bool = False


class ArgumentPatternConstraint(BaseModel):
    field: str  # argument field name, or "*" for all
    pattern: str  # Python regex
    label: str  # label for audit log


class ArgumentConstraintConfig(BaseModel):
    denied_patterns: list[ArgumentPatternConstraint] = Field(default_factory=list)
    max_arg_length: int | None = None


class ConstraintConfig(BaseModel):
    path: PathConstraintConfig | None = None
    sql: SqlConstraintConfig | None = None
    url: UrlConstraintConfig | None = None
    arguments: ArgumentConstraintConfig | None = None


class PolicyRule(BaseModel):
    name: str
    description: str = ""
    priority: int = 0
    tools: list[str]  # glob patterns
    roles: list[str]  # exact role names or "*"
    environments: list[str]  # "dev", "staging", "prod", or "*"
    decision: DecisionEnum
    trust_level_min: int | None = None
    trust_level_max: int | None = None
    constraints: ConstraintConfig = Field(default_factory=ConstraintConfig)


class GlobalDenyArgumentPattern(BaseModel):
    pattern: str
    label: str


class GlobalDenyConfig(BaseModel):
    tools: list[str] = Field(default_factory=list)
    argument_patterns: list[GlobalDenyArgumentPattern] = Field(default_factory=list)


class ToolPropertySchema(BaseModel):
    type: str
    pattern: str | None = None
    max_length: int | None = Field(default=None, alias="maxLength")
    min_length: int | None = Field(default=None, alias="minLength")
    minimum: float | None = None
    maximum: float | None = None
    enum: list[Any] | None = None

    model_config = {"populate_by_name": True}


class ToolSchema(BaseModel):
    required: list[str] = Field(default_factory=list)
    properties: dict[str, ToolPropertySchema] = Field(default_factory=dict)


class RoleDefinition(BaseModel):
    trust_level: int
    description: str = ""


class PolicyConfig(BaseModel):
    version: str = "1.0"
    name: str
    description: str = ""
    environment: str = "*"
    global_deny: GlobalDenyConfig = Field(default_factory=GlobalDenyConfig)
    tool_schemas: dict[str, ToolSchema] = Field(default_factory=dict)
    roles: dict[str, RoleDefinition] = Field(default_factory=dict)
    rules: list[PolicyRule] = Field(default_factory=list)


class PolicyDecision(BaseModel):
    decision: DecisionEnum
    matched_rule: str
    rationale: str
    requires_approval: bool = False
    constraints_applied: list[str] = Field(default_factory=list)
