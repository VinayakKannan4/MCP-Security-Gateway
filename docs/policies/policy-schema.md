# Policy Schema Reference

YAML policy files live in the `policies/` directory and are loaded at gateway startup. The default policy is `policies/default.yaml`. Environment-specific overrides can be placed in `policies/dev.yaml`, `policies/staging.yaml`, etc.

---

## Top-Level Structure

```yaml
version: "1.0"          # Required. Schema version.
name: string            # Required. Human-readable policy name.
description: string     # Optional. What this policy covers.
environment: string     # Optional. "*" = all environments. Or "dev", "staging", "prod".

global_deny:            # Optional. Checked before all rules. Cannot be bypassed by role.
  tools: [...]
  argument_patterns: [...]

tool_schemas:           # Optional. Argument schemas for schema validation (step 3).
  tool_name:
    required: [...]
    properties:
      field_name:
        type: string
        ...

roles:                  # Optional. Role definitions with trust levels.
  role_name:
    trust_level: int    # 0=UNTRUSTED, 1=LOW, 2=MEDIUM, 3=HIGH, 4=ADMIN

rules:                  # Required. List of policy rules.
  - name: string
    ...
```

---

## `global_deny`

Applied before rule evaluation. Any request matching a global deny is immediately rejected regardless of caller role.

```yaml
global_deny:
  tools:
    - "shell.*"         # Glob patterns for tool names
    - "exec.*"

  argument_patterns:
    - pattern: "ignore (prior|previous|all) instructions"
      label: "PROMPT_INJECTION"
    - pattern: "\\.\\./\\.\\.+"
      label: "PATH_TRAVERSAL"
    - pattern: "curl.+\\|.+bash"
      label: "SHELL_INJECTION"
```

**Fields**:
- `tools`: List of glob patterns matched against `tool_call.tool`. `*` matches any characters within a segment, `**` matches across segments.
- `argument_patterns`: List of regex patterns. Each argument value (string-coerced) is checked against all patterns. Match → hard DENY.
  - `pattern`: Python regex string
  - `label`: Risk label to attach to the audit event

---

## `tool_schemas`

Defines the expected argument schema for each tool. Used in step 3 (schema validation). Requests with missing required fields or invalid types are rejected before any LLM call.

```yaml
tool_schemas:
  fs.read:
    required: ["path"]
    properties:
      path:
        type: string
        pattern: "^[a-zA-Z0-9/_.-]+$"   # Regex pattern for value
        maxLength: 512

  fs.write:
    required: ["path", "content"]
    properties:
      path:
        type: string
        maxLength: 512
      content:
        type: string
        maxLength: 1048576    # 1MB

  sql.query:
    required: ["query"]
    properties:
      query:
        type: string
        maxLength: 4096
```

**Supported property validators**:
- `type`: `"string"`, `"integer"`, `"number"`, `"boolean"`, `"array"`, `"object"`
- `pattern`: Regex that the string value must match
- `maxLength`: Maximum string length
- `minLength`: Minimum string length
- `minimum` / `maximum`: Numeric bounds
- `enum`: List of allowed values

---

## `roles`

```yaml
roles:
  analyst:
    trust_level: 2
    description: "Read-only data analyst"
  developer:
    trust_level: 3
    description: "Read + limited write developer"
  admin:
    trust_level: 4
    description: "Full access administrator"
```

Trust levels: `0=UNTRUSTED`, `1=LOW`, `2=MEDIUM`, `3=HIGH`, `4=ADMIN`.

---

## Policy Rules

Rules are evaluated in **descending priority order**. The first matching rule wins.

```yaml
rules:
  - name: string               # Required. Unique rule identifier.
    description: string        # Optional. Human-readable description.
    priority: int              # Required. Higher = evaluated first. Default: 0.
    tools: [string]            # Required. Glob patterns for tool names.
    roles: [string]            # Required. Role names. "*" = all roles.
    environments: [string]     # Required. Environment names. "*" = all.
    decision: DecisionEnum     # Required. ALLOW | DENY | APPROVAL_REQUIRED
    require_approval: bool     # Deprecated. Use decision: APPROVAL_REQUIRED instead.
    trust_level_max: int       # Optional. Rule only applies to callers with trust_level <= this.
    trust_level_min: int       # Optional. Rule only applies to callers with trust_level >= this.
    constraints:               # Optional. Tool-specific constraint config.
      path: ...
      sql: ...
      url: ...
      arguments: ...
```

### Decision Values

| Value | Meaning |
|-------|---------|
| `ALLOW` | Request proceeds to execution |
| `DENY` | Request blocked immediately |
| `APPROVAL_REQUIRED` | Approval token issued; execution paused until approved |
| `SANITIZE_AND_ALLOW` | Arguments sanitized; then proceeds to execution |

---

## Constraints

Constraints are rule-level checks applied when a rule matches. If any constraint fails, the rule is skipped and the next rule is evaluated.

### `path` Constraint

```yaml
constraints:
  path:
    allowed_prefixes:
      - "/data/"
      - "/reports/"
    denied_patterns:
      - "\\.\\."         # Block path traversal
      - "~"              # Block home directory shortcuts
      - "/etc/"
      - "/proc/"
      - "/sys/"
    max_depth: 10        # Optional. Max directory depth.
    normalize: true      # Optional. Normalize path before checking (default: true).
```

**Applies to tools**: Any tool with a `path` argument.
**Behavior**: The `path` argument value must start with one of `allowed_prefixes` AND must not match any `denied_patterns`.

### `sql` Constraint

```yaml
constraints:
  sql:
    allowed_statements:
      - "SELECT"          # Whitelist of allowed statement types
    denied_keywords:
      - "INSERT"
      - "UPDATE"
      - "DELETE"
      - "DROP"
      - "ALTER"
      - "CREATE"
      - "TRUNCATE"
      - "EXEC"
      - "EXECUTE"
      - "UNION"           # Block UNION-based exfil
      - "INTO OUTFILE"    # Block file-based exfil
    max_rows_hint: 10000  # Optional. Not enforced, but passed to audit log as intent.
```

**Applies to tools**: Any tool with a `query` argument.
**Behavior**: The SQL statement must start with an allowed statement type AND must not contain any denied keywords (case-insensitive).

### `url` Constraint

```yaml
constraints:
  url:
    allowed_domains:
      - "*.internal.company.com"
      - "api.approved-vendor.com"
    denied_domains:
      - "*.ngrok.io"
      - "requestbin.*"
    require_https: true    # Optional. Block http:// URLs.
    block_private_ips: true # Optional. Block RFC-1918 addresses (SSRF protection).
```

**Applies to tools**: Any tool with a `url` argument.
**Behavior**: Parsed URL domain must match an `allowed_domains` glob AND not match any `denied_domains` glob.

### `arguments` Constraint

```yaml
constraints:
  arguments:
    denied_patterns:
      - field: "content"
        pattern: "ignore.*(prior|previous) instructions"
        label: "PROMPT_INJECTION"
      - field: "*"           # Apply to all string fields
        pattern: "\\$\\{.*\\}"  # Block template injection
        label: "TEMPLATE_INJECTION"
    max_arg_length: 65536    # Optional. Max total serialized arg length.
```

**Applies to**: All tools.
**Behavior**: Each pattern is checked against the specified field (or all fields if `"*"`). Match → constraint fails → rule is skipped.

---

## Rule Evaluation Algorithm

```
1. Check global_deny.tools (glob match on tool name) → immediate DENY if matches
2. Check global_deny.argument_patterns (regex match on all string arg values) → immediate DENY if matches
3. Sort rules by priority (descending)
4. For each rule:
   a. Check tools (glob match) → skip if no match
   b. Check roles (exact match or "*") → skip if no match
   c. Check environments (exact match or "*") → skip if no match
   d. Check trust_level_min/max if specified → skip if out of range
   e. Run constraint checkers (path, sql, url, arguments) → skip rule if any constraint fails
   f. MATCH FOUND → return PolicyDecision(decision=rule.decision, matched_rule=rule.name)
5. No rule matched → return PolicyDecision(decision=DENY, matched_rule="catch-all-deny")
```

---

## Common Policy Patterns

### Deny-by-Default

Place this as the last rule (lowest priority):

```yaml
- name: "deny-all-default"
  priority: 0
  tools: ["*"]
  roles: ["*"]
  environments: ["*"]
  decision: DENY
```

### Allowlist by Role with Path Restriction

```yaml
- name: "allow-fs-read-analysts"
  priority: 90
  tools: ["fs.read"]
  roles: ["analyst", "developer"]
  environments: ["*"]
  decision: ALLOW
  constraints:
    path:
      allowed_prefixes: ["/data/", "/reports/"]
      denied_patterns: ["\\.\\.", "/etc/", "/proc/"]
```

### Require Approval for Production Writes

```yaml
- name: "require-approval-prod-writes"
  priority: 80
  tools: ["fs.write"]
  roles: ["developer", "admin"]
  environments: ["prod"]
  decision: APPROVAL_REQUIRED
  constraints:
    path:
      allowed_prefixes: ["/data/output/"]
```

### SQL Read-Only for Analysts

```yaml
- name: "allow-sql-readonly-analysts"
  priority: 70
  tools: ["sql.query"]
  roles: ["analyst", "developer"]
  environments: ["*"]
  decision: ALLOW
  constraints:
    sql:
      allowed_statements: ["SELECT"]
      denied_keywords: ["INSERT", "UPDATE", "DELETE", "DROP", "ALTER",
                        "CREATE", "TRUNCATE", "UNION", "INTO OUTFILE"]
```

---

## Testing a Policy Change

After modifying a policy YAML, run:

```bash
# Validate the YAML loads without error
uv run python -c "from gateway.policy.loader import load_policy; load_policy('policies/default.yaml'); print('OK')"

# Run policy unit tests
uv run pytest tests/unit/test_policy_engine.py -v

# Run all security scenarios to verify no regressions
uv run pytest -m scenario -v
```
