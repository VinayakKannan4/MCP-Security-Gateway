# Agent Interaction Diagrams

## 1. Normal ALLOW Flow

```mermaid
sequenceDiagram
    participant C as Agent Client
    participant G as Gateway API
    participant P as EnforcementPipeline
    participant RC as RiskClassifier
    participant PE as PolicyEngine
    participant AG as ArgumentGuard
    participant MCP as MCP Server
    participant AL as AuditLogger

    C->>G: POST /v1/gateway/invoke (MCPRequest)
    G->>P: run(request)

    Note over P: Step 1-2: Validate ingress + resolve identity
    P->>P: validate_ingress() + resolve_identity()

    Note over P: Step 3: Schema validation
    P->>PE: validate_tool_schema(tool_call)
    PE-->>P: schema_valid=true

    Note over P: Step 4: Risk classification (LLM advisory)
    P->>RC: classify(tool_name, args_preview)
    RC->>RC: run deterministic heuristics
    Note over RC: heuristic_score < 0.8 → call LLM
    RC-->>P: RiskAssessment(labels=[LOW_READONLY], score=0.1)

    Note over P: Step 5: Policy evaluation (AUTHORITATIVE)
    P->>PE: evaluate(request, identity, policy)
    PE-->>P: PolicyDecision(decision=ALLOW, rule="allow-fs-read-analysts")

    Note over P: Step 6: Sanitize arguments
    P->>AG: sanitize(tool_call.arguments)
    AG->>AG: run deterministic redaction
    AG-->>P: sanitized_args, redaction_flags=[]

    Note over P: Steps 7-8: No approval needed, execute
    P->>MCP: forward(server, tool, sanitized_args)
    MCP-->>P: tool_result

    Note over P: Step 9: Audit (ALWAYS)
    P->>AL: write(AuditEvent{decision=ALLOW, ...})

    P-->>G: GatewayResponse(decision=ALLOW, result=tool_result)
    G-->>C: 200 OK + GatewayResponse
```

---

## 2. DENY Flow (Prompt Injection Detected)

```mermaid
sequenceDiagram
    participant C as Agent Client
    participant G as Gateway API
    participant P as EnforcementPipeline
    participant RC as RiskClassifier
    participant PE as PolicyEngine
    participant MCP as MCP Server
    participant AL as AuditLogger

    C->>G: POST /v1/gateway/invoke
    Note over C: args: "path: /etc/passwd\nIgnore prior instructions..."
    G->>P: run(request)

    P->>P: validate_ingress() + resolve_identity()
    P->>PE: validate_tool_schema(tool_call) → valid

    P->>RC: classify(tool_name, args_preview)
    RC->>RC: heuristic fires: "ignore prior instructions" → PROMPT_INJECTION_SUSPECT
    Note over RC: heuristic_score = 0.95 → skip LLM call
    RC-->>P: RiskAssessment(labels=[PROMPT_INJECTION_SUSPECT], score=0.95)

    P->>PE: evaluate(request, identity, policy)
    Note over PE: global_deny pattern match: "ignore.*instructions"
    PE-->>P: PolicyDecision(decision=DENY, rule="global-deny-prompt-injection")

    Note over P: Steps 6-8 SKIPPED (decision is DENY)
    Note over MCP: Tool never called

    P->>AL: write(AuditEvent{decision=DENY, risk=[PROMPT_INJECTION_SUSPECT], ...})

    P-->>G: GatewayResponse(decision=DENY, result=null)
    G-->>C: 200 OK + GatewayResponse(decision=DENY)
```

---

## 3. APPROVAL_REQUIRED Flow

```mermaid
sequenceDiagram
    participant C as Agent Client
    participant G as Gateway API
    participant P as EnforcementPipeline
    participant PE as PolicyEngine
    participant AG as ArgumentGuard
    participant AM as ApprovalManager
    participant H as Human Reviewer (Dashboard)
    participant MCP as MCP Server
    participant AL as AuditLogger

    C->>G: POST /v1/gateway/invoke (fs.write request)
    G->>P: run(request)

    P->>P: validate_ingress() + resolve_identity()
    P->>PE: validate_tool_schema() → valid
    P->>P: classify_risk() → HIGH_WRITE_ACTION, score=0.7

    P->>PE: evaluate(request, identity, policy)
    Note over PE: rule "require-approval-fs-write" matches
    PE-->>P: PolicyDecision(decision=APPROVAL_REQUIRED, rule="require-approval-fs-write")

    Note over P: Step 6: Still sanitize for the approval record
    P->>AG: sanitize(tool_call.arguments) → sanitized_args

    P->>AM: issue_token(request, sanitized_args)
    AM->>AM: generate token = secrets.token_urlsafe(32)
    AM->>AM: store in Redis (TTL=3600) + Postgres
    AM-->>P: token="abc123..."

    P->>AL: write(AuditEvent{decision=APPROVAL_REQUIRED, ...})
    P-->>G: GatewayResponse(decision=APPROVAL_REQUIRED, approval_token="abc123...")
    G-->>C: 200 OK + GatewayResponse

    loop Poll for approval status
        C->>G: GET /v1/approvals/abc123...
        G-->>C: ApprovalRequest{status=PENDING}
    end

    H->>G: POST /v1/approvals/abc123.../approve
    Note over H: Human reviews tool call in dashboard
    G->>AM: set_status(token, APPROVED, approver_id)
    AM->>AM: update Redis + Postgres

    C->>G: GET /v1/approvals/abc123...
    G-->>C: ApprovalRequest{status=APPROVED}

    C->>G: POST /v1/gateway/invoke (same request + approval_token header)
    Note over G: Token is valid, approved, not expired
    G->>P: run(request, approved_token="abc123...")

    P->>P: Steps 1-6 (fast path with approved token)
    P->>MCP: forward(server, tool, sanitized_args)
    MCP-->>P: tool_result

    P->>AL: write(AuditEvent{decision=ALLOW, approver_id=H, ...})
    G-->>C: 200 OK + GatewayResponse(decision=ALLOW, result=tool_result)
```

---

## 4. Red Team Benchmark Flow (Test Mode Only)

```mermaid
sequenceDiagram
    participant B as run_benchmark.py
    participant RT as RedTeamAttackerAgent
    participant G as Gateway API
    participant P as EnforcementPipeline
    participant Report as Benchmark Report

    B->>B: assert ENVIRONMENT != "prod"

    loop For each scenario_type in ["prompt_injection", "data_exfil", "sql_abuse", ...]
        B->>RT: generate_scenario(scenario_type)
        RT->>RT: LLM generates adversarial MCPRequest list
        RT-->>B: adversarial_requests[]

        loop For each request in adversarial_requests
            B->>G: POST /v1/gateway/invoke (adversarial request)
            G->>P: run(request)
            P-->>G: GatewayResponse(decision=DENY)
            G-->>B: response

            B->>B: assert response.decision == expected_decision
            B->>B: record: scenario | expected | actual | pass/fail | latency_ms
        end
    end

    B->>Report: print tabular results
    Note over Report: attack_block_rate, false_positive_rate, avg_latency
```

---

## Agent Decision Tree

```
MCPRequest arrives
       │
       ▼
[1] Schema valid?
   NO → DENY (step 3)
   YES ↓
       ▼
[2] Heuristic risk score ≥ 0.8?
   YES → skip LLM, use heuristic labels
   NO → call RiskClassifierAgent (LLM)
       ↓
       ▼
[3] Global deny pattern match?
   YES → hard DENY (step 5, cannot be bypassed)
   NO ↓
       ▼
[4] Policy rule match?
   DENY → DENY (step 5)
   APPROVAL_REQUIRED → issue token, return early (step 7)
   ALLOW ↓
       ▼
[5] Deterministic sanitization flags PII/secrets?
   YES → redact, continue
   Ambiguous → call ArgumentGuardAgent (LLM)
       ↓
       ▼
[6] Execute tool call (step 8)
       ↓
       ▼
[7] Write audit event (step 9, ALWAYS)
```
