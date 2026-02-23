"""
Deterministic constraint checkers for the policy engine.

All functions are pure (no I/O, no LLM calls, no side effects).
Each returns (passed: bool, reason: str).
"""

import posixpath
import re
from urllib.parse import urlparse
import ipaddress

from gateway.models.policy import (
    ArgumentConstraintConfig,
    PathConstraintConfig,
    SqlConstraintConfig,
    UrlConstraintConfig,
)


def check_path_safety(path: str, config: PathConstraintConfig) -> tuple[bool, str]:
    """Check that a file path is safe according to the constraint config."""
    # Normalize the path to resolve any . or .. components
    normalized = posixpath.normpath(path) if config.normalize else path

    # Block path traversal after normalization
    if ".." in normalized.split("/"):
        return False, f"Path traversal detected in: {normalized}"

    # Check denied patterns
    for pattern in config.denied_patterns:
        if re.search(pattern, normalized):
            return False, f"Path matches denied pattern '{pattern}': {normalized}"

    # Check allowed prefixes
    if config.allowed_prefixes:
        if not any(normalized.startswith(prefix) for prefix in config.allowed_prefixes):
            allowed = ", ".join(config.allowed_prefixes)
            return False, f"Path '{normalized}' not under allowed prefixes: {allowed}"

    # Check max depth
    if config.max_depth is not None:
        depth = len([p for p in normalized.split("/") if p])
        if depth > config.max_depth:
            return False, f"Path depth {depth} exceeds max depth {config.max_depth}"

    return True, "path constraint passed"


def check_sql_safety(query: str, config: SqlConstraintConfig) -> tuple[bool, str]:
    """Check that a SQL query is safe according to the constraint config."""
    # Normalize whitespace for comparison
    normalized = " ".join(query.upper().split())

    # Check denied keywords (case-insensitive, word-boundary aware)
    for keyword in config.denied_keywords:
        # Use word boundary to avoid false positives (e.g. "SELECTIVITY" is not "SELECT")
        pattern = r"\b" + re.escape(keyword.upper()) + r"\b"
        if re.search(pattern, normalized):
            return False, f"SQL contains denied keyword: {keyword}"

    # Check allowed statement types
    if config.allowed_statements:
        # Check that the query starts with an allowed statement
        first_word = normalized.split()[0] if normalized.split() else ""
        if first_word not in [s.upper() for s in config.allowed_statements]:
            allowed = ", ".join(config.allowed_statements)
            return False, f"SQL statement type '{first_word}' not in allowed list: {allowed}"

    return True, "sql constraint passed"


def check_url_safety(url: str, config: UrlConstraintConfig) -> tuple[bool, str]:
    """Check that a URL is safe according to the constraint config."""
    try:
        parsed = urlparse(url)
    except Exception as e:
        return False, f"Invalid URL: {e}"

    # Require HTTPS
    if config.require_https and parsed.scheme != "https":
        return False, f"URL must use HTTPS, got: {parsed.scheme}"

    hostname = parsed.hostname or ""

    # Block private IP ranges (SSRF protection)
    if config.block_private_ips and hostname:
        try:
            ip = ipaddress.ip_address(hostname)
            if ip.is_private or ip.is_loopback or ip.is_link_local:
                return False, f"URL targets private/loopback IP: {hostname}"
        except ValueError:
            pass  # Not an IP address, continue with domain checks

    # Check denied domains
    for denied in config.denied_domains:
        if _glob_match(hostname, denied):
            return False, f"URL domain '{hostname}' matches denied pattern: {denied}"

    # Check allowed domains
    if config.allowed_domains:
        if not any(_glob_match(hostname, allowed) for allowed in config.allowed_domains):
            allowed = ", ".join(config.allowed_domains)
            return False, f"URL domain '{hostname}' not in allowed list: {allowed}"

    return True, "url constraint passed"


def check_argument_patterns(
    arguments: dict,
    config: ArgumentConstraintConfig,
) -> tuple[bool, str]:
    """Check tool arguments against denied regex patterns."""
    if config.max_arg_length is not None:
        import json
        serialized = json.dumps(arguments)
        if len(serialized) > config.max_arg_length:
            return False, (
                f"Arguments length {len(serialized)} exceeds max {config.max_arg_length}"
            )

    for pattern_config in config.denied_patterns:
        fields_to_check: list[tuple[str, str]] = []

        if pattern_config.field == "*":
            # Check all string values recursively
            fields_to_check = _extract_string_fields(arguments)
        else:
            val = arguments.get(pattern_config.field)
            if isinstance(val, str):
                fields_to_check = [(pattern_config.field, val)]

        for field_name, value in fields_to_check:
            if re.search(pattern_config.pattern, value, re.IGNORECASE):
                return False, (
                    f"Argument '{field_name}' matches denied pattern "
                    f"({pattern_config.label}): {pattern_config.pattern}"
                )

    return True, "argument constraint passed"


def check_global_deny_patterns(
    arguments: dict,
    patterns: list,  # list[GlobalDenyArgumentPattern]
) -> tuple[bool, str]:
    """Check arguments against global deny argument patterns."""
    string_fields = _extract_string_fields(arguments)
    for pattern_config in patterns:
        for field_name, value in string_fields:
            if re.search(pattern_config.pattern, value, re.IGNORECASE):
                return False, (
                    f"Argument '{field_name}' matches global deny pattern "
                    f"({pattern_config.label}): {pattern_config.pattern}"
                )
    return True, "no global deny patterns matched"


def _glob_match(hostname: str, pattern: str) -> bool:
    """Simple glob matching for domain patterns. Supports leading *. wildcard."""
    if pattern.startswith("*."):
        suffix = pattern[2:]
        return hostname == suffix or hostname.endswith("." + suffix)
    elif pattern.endswith(".*"):
        prefix = pattern[:-2]
        return hostname == prefix or hostname.startswith(prefix + ".")
    else:
        return hostname == pattern


def _extract_string_fields(
    obj: object,
    prefix: str = "",
) -> list[tuple[str, str]]:
    """Recursively extract all string field name-value pairs from a dict."""
    results: list[tuple[str, str]] = []
    if isinstance(obj, dict):
        for key, value in obj.items():
            full_key = f"{prefix}.{key}" if prefix else key
            results.extend(_extract_string_fields(value, full_key))
    elif isinstance(obj, list):
        for i, item in enumerate(obj):
            results.extend(_extract_string_fields(item, f"{prefix}[{i}]"))
    elif isinstance(obj, str):
        results.append((prefix, obj))
    return results
