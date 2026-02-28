"""ArgumentGuardAgent — step 6 of the enforcement pipeline.

Two-phase sanitization:
  1. Deterministic redaction (always runs): regex-based PII/secret/path removal
  2. LLM review (only if deterministic phase flagged something): catches edge cases

Output: sanitized args dict + list of RedactionFlags (each records what changed and why).
Model: llama-3.1-8b-instant (Groq free tier, 14,400 RPD — fast and sufficient for pattern tasks).
"""

from __future__ import annotations

import hashlib
import json
import logging
import re
from typing import Any, ClassVar

from pydantic import BaseModel

from gateway.agents.base import BaseAgent
from gateway.config import Settings
from gateway.models.audit import RedactionFlag
from gateway.models.mcp import ToolCall

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Deterministic redaction patterns
# (pattern, replacement, reason_code)
# ---------------------------------------------------------------------------

_REDACTION_RULES: list[tuple[str, str, str]] = [
    # Email addresses
    (
        r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b",
        "[REDACTED_EMAIL]",
        "PII_EMAIL",
    ),
    # SSN  XXX-XX-XXXX
    (
        r"\b\d{3}-\d{2}-\d{4}\b",
        "[REDACTED_SSN]",
        "PII_SSN",
    ),
    # Credit card — 16 digit runs (with optional spaces/dashes)
    (
        r"\b(?:\d{4}[\s\-]?){3}\d{4}\b",
        "[REDACTED_CC]",
        "PII_CC",
    ),
    # API keys / tokens / bearer tokens
    (
        r"(?i)\b(?:sk-|Bearer\s+|api[_\-]?key[_\-]?[=:]?\s*)[A-Za-z0-9_\-]{10,}",
        "[REDACTED_SECRET]",
        "SECRET_TOKEN",
    ),
    # Path traversal sequences — normalize away
    (
        r"(?:\.\.\/|\.\.\\|%2e%2e%2f|%2e%2e\/|\.\.%2f|%252e%252e)",
        "",
        "PATH_TRAVERSAL",
    ),
]


class ArgumentGuardAgent(BaseAgent):
    SYSTEM_PROMPT: ClassVar[str] = """You are a security argument inspector for an MCP gateway.
You inspect tool call arguments for PII, secrets, or dangerous patterns that automated redaction may have missed.

The arguments you receive have already had obvious PII replaced with [REDACTED_*] placeholders.
Your job is to identify any remaining fields that still contain sensitive data.

You MUST respond using ONLY this XML tag:
<redaction_flags>[{"field": "field_name", "reason": "reason_code", "original_hash": "sha256_hex_of_current_value"}]</redaction_flags>

reason_code must be one of: PII_EMAIL, PII_SSN, PII_CC, SECRET_TOKEN, PATH_TRAVERSAL, SENSITIVE_DATA

If no additional redaction is needed, respond with:
<redaction_flags>[]</redaction_flags>

Rules:
- Never fabricate data not present in the arguments
- Only flag fields that clearly contain sensitive data
- Do NOT re-flag fields that already show [REDACTED_*] placeholders
- Do NOT expose or repeat the sensitive values in your response"""

    def __init__(self, settings: Settings) -> None:
        super().__init__(settings)
        self._model = settings.argument_guard_model

    async def sanitize(
        self,
        tool_call: ToolCall,
    ) -> tuple[dict[str, Any], list[RedactionFlag]]:
        """Sanitize tool call arguments.

        Phase 1: deterministic regex redaction (always runs).
        Phase 2: LLM review (only if phase 1 flagged anything).
        Returns: (sanitized_args, flags)
        """
        sanitized, flags = self._deterministic_sanitize(tool_call.arguments)

        if self._needs_llm_review(flags, tool_call):
            prompt = self._build_prompt(tool_call, sanitized)
            raw = await self._call(self.SYSTEM_PROMPT, prompt)
            llm_flags = self._parse_llm_flags(raw)
            sanitized, flags = self._apply_llm_flags(sanitized, flags, llm_flags)

        return sanitized, flags

    def _deterministic_sanitize(
        self,
        args: dict[str, Any],
    ) -> tuple[dict[str, Any], list[RedactionFlag]]:
        """Regex-based redaction over all string values in args (recursive)."""
        flags: list[RedactionFlag] = []
        result = self._redact_dict(args, flags)
        return result, flags

    def _redact_dict(self, obj: dict[str, Any], flags: list[RedactionFlag]) -> dict[str, Any]:
        return {k: self._redact_value(k, v, flags) for k, v in obj.items()}

    def _redact_value(self, key: str, value: Any, flags: list[RedactionFlag]) -> Any:
        if isinstance(value, str):
            return self._redact_string(key, value, flags)
        if isinstance(value, dict):
            return self._redact_dict(value, flags)
        if isinstance(value, list):
            return [self._redact_value(key, item, flags) for item in value]
        return value

    def _redact_string(self, field: str, value: str, flags: list[RedactionFlag]) -> str:
        current = value
        for pattern, replacement, reason in _REDACTION_RULES:
            if re.search(pattern, current):
                original_hash = hashlib.sha256(current.encode()).hexdigest()
                current = re.sub(pattern, replacement, current)
                flags.append(
                    RedactionFlag(
                        field=field,
                        reason=reason,
                        original_hash=original_hash,
                    )
                )
                # Stop after first matching rule for this field to avoid double-flagging
                break
        return current

    def _needs_llm_review(self, flags: list[RedactionFlag], tool_call: ToolCall) -> bool:
        """LLM review is triggered when deterministic phase found something ambiguous."""
        return len(flags) > 0

    def _build_prompt(self, tool_call: ToolCall, sanitized: dict[str, Any]) -> str:
        return (
            f"Tool: {tool_call.tool}\n"
            f"Server: {tool_call.server}\n"
            f"Arguments (partially sanitized):\n{json.dumps(sanitized, default=str, indent=2)}"
        )

    def _parse_llm_flags(self, raw: str) -> list[dict[str, Any]]:
        """Extract <redaction_flags> JSON array from LLM response."""
        tag_content = self._extract_tag(raw, "redaction_flags")
        if not tag_content:
            return []
        try:
            parsed = json.loads(tag_content)
            if isinstance(parsed, list):
                return [item for item in parsed if isinstance(item, dict)]
        except json.JSONDecodeError:
            logger.debug("Failed to parse redaction_flags JSON: %r", tag_content)
        return []

    def _apply_llm_flags(
        self,
        sanitized: dict[str, Any],
        existing_flags: list[RedactionFlag],
        llm_flags: list[dict[str, Any]],
    ) -> tuple[dict[str, Any], list[RedactionFlag]]:
        """Apply LLM-suggested redactions on top of deterministic ones."""
        result = dict(sanitized)
        result_flags = list(existing_flags)

        for flag_data in llm_flags:
            field = flag_data.get("field", "")
            reason = str(flag_data.get("reason", "SENSITIVE_DATA"))

            if field not in result:
                continue

            val = result[field]
            if not isinstance(val, str) or val.startswith("[REDACTED_"):
                continue

            original_hash = hashlib.sha256(val.encode()).hexdigest()
            result[field] = "[REDACTED_SENSITIVE]"
            result_flags.append(
                RedactionFlag(
                    field=field,
                    reason=reason,
                    original_hash=original_hash,
                )
            )

        return result, result_flags

    def parse_response(self, raw: str) -> BaseModel:
        """Satisfy abstract method; actual parsing is done in _parse_llm_flags."""

        class _Flags(BaseModel):
            flags: list[dict[str, Any]]

        return _Flags(flags=self._parse_llm_flags(raw))
