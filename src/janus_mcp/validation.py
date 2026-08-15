"""Strict input validation, shared by all tools.

Every model-supplied string is validated before any other code sees it.
Failures raise ToolError with a message that is safe to show the model.
"""

from __future__ import annotations

import re

from mcp.server.fastmcp.exceptions import ToolError

# DNS-1123 subdomain: dot-separated labels. Node names on managed clusters
# (EKS/GKE) routinely contain dots, e.g. ip-10-1-2-3.us-west-2.compute.internal.
_LABEL = r"[a-z0-9]([-a-z0-9]*[a-z0-9])?"
_DNS1123 = re.compile(rf"^{_LABEL}(\.{_LABEL})*$")
# Kubernetes selector syntax: keys (with optional dns-prefix/), =, ==, !=,
# "in (a,b)", "notin (a,b)", existence (!key), comma separation.
_SELECTOR_CHARS = re.compile(r"^[A-Za-z0-9\-_./=!,() ]*$")
# field selectors are restricted to explicit field=value terms so a tool can
# allowlist which fields the model may filter on (see validate_field_selector).
_FIELD_TERM = re.compile(r"^([A-Za-z0-9.]+?)(?:==|!=|=)([A-Za-z0-9\-_.]*)$")
_MAX_NAME_LEN = 253
_MAX_SELECTOR_LEN = 512
_MAX_GREP_LEN = 256
_REASON_CHARS = re.compile(r"^[\w\-.,:;()'\"/ ]*$")


def validate_name(value: str, what: str = "name") -> str:
    if not isinstance(value, str) or not value:
        raise ToolError(f"invalid {what}: must be a non-empty string")
    if len(value) > _MAX_NAME_LEN:
        raise ToolError(f"invalid {what}: longer than {_MAX_NAME_LEN} characters")
    if not _DNS1123.match(value):
        raise ToolError(
            f"invalid {what}: must be a DNS-1123 name (lowercase alphanumeric, '-' and '.')"
        )
    return value


def validate_field_selector(
    value: str | None, allowed_fields: frozenset[str] | set[str], what: str = "field_selector"
) -> str | None:
    """Field selectors are an API-server-side filter and therefore a potential
    membership oracle: filtering on a field whose value the redaction pipeline
    masks (e.g. spec.nodeName) would let the model confirm masked values by
    enumeration. Only explicitly allowlisted fields may be referenced."""
    if value is None:
        return None
    if len(value) > _MAX_SELECTOR_LEN:
        raise ToolError(f"invalid {what}: longer than {_MAX_SELECTOR_LEN} characters")
    for term in value.split(","):
        match = _FIELD_TERM.match(term.strip())
        if not match:
            raise ToolError(
                f"invalid {what}: each term must be 'field=value', 'field==value', "
                "or 'field!=value'"
            )
        field = match.group(1)
        if field not in allowed_fields:
            raise ToolError(
                f"invalid {what}: field '{field}' is not filterable "
                f"(allowed: {', '.join(sorted(allowed_fields))})"
            )
    return value


def validate_selector(value: str | None, what: str = "selector") -> str | None:
    if value is None:
        return None
    if len(value) > _MAX_SELECTOR_LEN:
        raise ToolError(f"invalid {what}: longer than {_MAX_SELECTOR_LEN} characters")
    if not _SELECTOR_CHARS.match(value):
        raise ToolError(f"invalid {what}: contains characters outside selector syntax")
    return value


def validate_grep(value: str | None) -> str | None:
    if value is None:
        return None
    if len(value) > _MAX_GREP_LEN:
        raise ToolError(f"invalid grep: longer than {_MAX_GREP_LEN} characters")
    return value


def validate_reason(value: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ToolError("a non-empty reason is required for write operations")
    value = value.strip()
    if len(value) > 200:
        raise ToolError("invalid reason: longer than 200 characters")
    if "\n" in value or "\r" in value or not _REASON_CHARS.match(value):
        raise ToolError("invalid reason: contains unsupported characters")
    return value


def validate_bounds(value: int, low: int, high: int, what: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool):
        raise ToolError(f"invalid {what}: must be an integer")
    if value < low or value > high:
        raise ToolError(f"invalid {what}: must be between {low} and {high}")
    return value
