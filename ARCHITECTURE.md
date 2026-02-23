# Architecture — MCP Security Gateway

## Overview

MCP Security Gateway is a policy-aware, multi-agent proxy that sits between an AI agent client and any MCP (Model Context Protocol) server. Every tool call passes through the gateway before reaching the upstream MCP server. The gateway can allow, deny, sanitize, or require human approval for each call.

```
Agent Client
     │
     │  POST /v1/gateway/invoke
     ▼
┌─────────────────────────────────────────────────┐
│              MCP Security Gateway               │
│                                                 │
│  ┌──────────────────────────────────────────┐   │
│  │         Enforcement Pipeline             │   │
│  │  1. validate_ingress                     │   │
│  │  2. resolve_identity                     │   │
│  │  3. validate_schema                      │   │
│  │  4. classify_risk  ◄── LLM (advisory)   │   │
│  │  5. evaluate_policy ◄── DETERMINISTIC   │   │ ← AUTHORITATIVE
│  │  6. sanitize_arguments                   │   │
│  │  7. check_approval                       │   │
│  │  8. execute                              │   │
│  │  9. write_audit   ◄── ALWAYS RUNS       │   │
│  │  10. build_response                      │   │
│  └──────────────────────────────────────────┘   │
│                                                 │
│  ┌──────────┐  ┌──────────┐  ┌──────────────┐  │
│  │ Postgres │  │  Redis   │  │ OTel Traces  │  │
│  │ (audit)  │  │(approvals│  │              │  │
│  └──────────┘  └──────────┘  └──────────────┘  │
└─────────────────────────────────────────────────┘
     │
     │  (if ALLOW)
     ▼
MCP Server (filesystem-mcp, database-mcp, etc.)
```

---

## Three-Layer Enforcement Model

The critical design choice is that **LLMs are advisory, not authoritative**.

```
┌──────────────────────────────────────────────────────────┐
│  Layer 1: Deterministic Policy Engine (AUTHORITATIVE)    │
│  • YAML-defined rules: allowlists, denylists, RBAC       │
│  • Constraint checkers: path safety, SQL safety, URLs    │
│  • Tool argument schema validation                       │
│  • Environment rules (dev/staging/prod)                  │
│  • Final decision: ALLOW / DENY / APPROVAL_REQUIRED      │
└──────────────────────────────────────────────────────────┘
         ▲
         │ informs (cannot override)
┌──────────────────────────────────────────────────────────┐
│  Layer 2: LLM-Assisted Risk Analysis (ADVISORY)          │
│  • Prompt injection detection                            │
│  • Semantic risk classification                          │
│  • Suspicious intent detection                           │
│  • Policy decision explanation                           │
│  • Output: RiskAssessment (labels + score) → audit only  │
└──────────────────────────────────────────────────────────┘
         ▲
         │ escalates to
┌──────────────────────────────────────────────────────────┐
│  Layer 3: Human Approval Workflow                        │
│  • Triggered for: HIGH_WRITE_ACTION, HIGH_DESTRUCTIVE    │
│  • Token-based: cryptographically random, Redis TTL      │
│  • Single-use approval tokens                            │
│  • All approvals logged with approver identity           │
└──────────────────────────────────────────────────────────┘
```

**Why this matters**: If the LLM misclassifies a prompt injection as safe, the deterministic engine's hard DENY still blocks execution. The LLM can only *escalate* risk (by flagging additional concerns), never *de-escalate* a hard policy deny.

---

## Agent Roles

| Agent | Makes LLM calls? | Input | Output | Can override policy? |
|-------|-----------------|-------|--------|---------------------|
| `CoordinatorAgent` | No | MCPRequest + pipeline state | Routing decisions | N/A |
| `RiskClassifierAgent` | Yes (if heuristics insufficient) | Tool name + sanitized args preview | `RiskAssessment` | No |
| `PolicyReasonerAgent` | Yes | `PolicyDecision` + context | Human-readable explanation | No |
| `ArgumentGuardAgent` | Yes (if deterministic phase ambiguous) | Tool arguments | Sanitized args + `RedactionFlag[]` | No |
| `AuditSummarizerAgent` | Yes | `AuditEvent` | Narrative prose | No |
| `RedTeamAttackerAgent` | Yes | Scenario type | Adversarial `MCPRequest[]` | N/A (test only) |

---

## Request Lifecycle (Detailed)

### Step 1: Validate Ingress
Parse the raw HTTP request body into `MCPRequest`. Reject malformed envelopes immediately with a 422 before any processing.

### Step 2: Resolve Identity
Look up `CallerIdentity` from the `api_keys` table using the provided API key (bcrypt comparison). Attach: `caller_id`, `role`, `trust_level`, `environment`. Reject unknown or inactive keys with 401.

### Step 3: Validate Schema
Check tool arguments against the tool schema defined in the policy YAML (`tool_schemas` section). Reject requests with missing required fields or invalid argument types before any LLM call.

### Step 4: Classify Risk (LLM Advisory)
1. Run deterministic regex heuristics against raw arguments:
   - Prompt injection patterns (e.g., "ignore prior instructions")
   - Path traversal patterns (`../`, `%2e%2e%2f`)
   - Shell injection patterns (`curl | bash`, `;rm -rf`)
   - PII patterns (email, SSN, credit card)
2. If heuristic score < 0.8, invoke `RiskClassifierAgent` (LLM call)
3. Merge scores: take max of heuristic and LLM scores
4. Result is advisory — attached to audit log only

### Step 5: Evaluate Policy (AUTHORITATIVE)
`PolicyEngine.evaluate()` runs deterministically:
1. Check `global_deny` patterns → hard DENY (cannot be bypassed)
2. Match rules in descending priority order
3. Run constraint checkers for the matched rule
4. Return `PolicyDecision` with matched rule name and rationale

**This is the final, authoritative decision.** LLM outputs from step 4 cannot change it.

### Step 6: Sanitize Arguments
If decision is not DENY:
1. Deterministic sanitizer: regex-based PII redaction, path normalization, secret pattern stripping
2. If deterministic phase flags ambiguity: `ArgumentGuardAgent` (LLM) inspects semantics
3. Returns sanitized args + `RedactionFlag[]` (each flag records what was changed and why)

### Step 7: Check Approval
If decision is `APPROVAL_REQUIRED`:
1. `ApprovalManager.issue_token()` creates a cryptographically random token
2. Token stored in Redis with TTL + Postgres for durability
3. Notifier triggered (webhook/Slack stub)
4. Gateway returns `APPROVAL_REQUIRED` response immediately
5. Calling agent polls `GET /v1/approvals/{token}` until status changes
6. Human reviews in dashboard, approves or denies
7. On re-submission with approved token, pipeline proceeds to step 8

### Step 8: Execute
If decision is ALLOW or SANITIZE_AND_ALLOW:
`MCPExecutor.forward(mcp_server, tool, sanitized_args)` makes an HTTP call to the upstream MCP server with a configurable per-tool timeout.

### Step 9: Write Audit (ALWAYS RUNS)
`AuditLogger.write(AuditEvent)` persists to Postgres regardless of whether the request was allowed, denied, or errored. This is the immutable forensic record. Raw args are never stored — only their SHA-256 hash.

### Step 10: Build Response
`GatewayResponse` is assembled with: decision, tool output (if allowed), sanitized args, approval token (if required), policy explanation, risk labels, and latency.

---

## Data Flow: What Each Layer Sees

| Layer | Sees | Does NOT see |
|-------|------|-------------|
| Schema Validator | Raw args | Caller identity, policy rules |
| Risk Classifier (LLM) | Tool name, sanitized args preview, context | Caller ID, API key, policy rule names |
| Policy Engine | Full request, caller identity, policy config | LLM reasoning |
| Argument Guard (LLM) | Tool arguments | Caller identity, policy decisions |
| Audit Logger | Everything (hashed where sensitive) | Nothing hidden — this is the complete record |
| Response to Caller | Decision, result (if allowed), explanation | Internal rule names, other callers' data |

---

## Policy Rule Evaluation Algorithm

```
for rule in sorted(policy.rules, key=lambda r: -r.priority):
    if tool_matches(request.tool_call.tool, rule.tools) and
       role_matches(identity.role, rule.roles) and
       environment_matches(identity.environment, rule.environments):

        constraint_results = run_constraints(rule.constraints, request.tool_call)

        if all(constraint_results):
            return PolicyDecision(decision=rule.decision, matched_rule=rule.name)
        else:
            # Constraint failed for this rule → continue to next rule
            continue

# No rule matched
return PolicyDecision(decision=DENY, matched_rule="catch-all-deny")
```

`global_deny` is checked before this loop and produces an immediate hard DENY.

---

## Threat Model

### What the Gateway Defends Against

| Threat | Defense |
|--------|---------|
| Prompt injection via tool arguments | Global deny patterns (deterministic) + LLM injection detection |
| Indirect prompt injection via retrieved content | ArgumentGuardAgent inspects context passed to tool calls |
| Privilege escalation (low-trust caller using high-privilege tool) | RBAC rules in policy engine |
| Data exfiltration via wildcard file reads | Path constraint checker with allowlist |
| SQL mutation via query tool | SQL constraint checker (allowlist of SELECT only) |
| Shell command injection | Global deny patterns for shell chaining characters |
| Path traversal | Path safety checker, normalized and checked against allowed prefixes |
| Unauthorized writes | Approval workflow for all write operations from non-admin roles |
| Audit log tampering | Append-only by convention; raw args are hashed, not stored |

### Known Limitations

- **Post-execution inspection**: The gateway inspects inputs, not outputs. A malicious MCP server returning harmful data post-execution is not covered by this version.
- **LLM risk detection is probabilistic**: Novel prompt injection techniques may evade LLM detection. The deterministic layer provides a hard floor.
- **Side-channel attacks on approval tokens**: Tokens are cryptographically random and TTL-bound, but physical access to Redis is out of scope.
- **Policy misconfiguration**: A poorly written policy YAML can create gaps. The default policy is deny-by-default as a safety net.

---

## Why No LangChain

1. **Determinism**: LangChain abstractions can obscure when and how LLM calls are made. We need to know exactly what is sent to the LLM and when.
2. **Auditability**: Direct API calls make it trivial to log exact prompts and responses for the audit trail.
3. **OSS credibility**: Minimal dependencies are easier for security reviewers to audit.
4. **Attack surface**: LangChain has had security vulnerabilities. Removing it from the dependency tree reduces exposure.
5. **Simplicity**: Our orchestration logic (10 pipeline steps) is clear Python. A framework doesn't add value here.
