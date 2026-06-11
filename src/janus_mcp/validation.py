"""Strict input validation, shared by all tools.

Every model-supplied string is validated before any other code sees it.
Failures raise ToolError with a message that is safe to show the model.
"""

from __future__ import annotations

import re

from mcp.server.fastmcp.exceptions import ToolError

_DNS1123 = re.compile(r"^[a-z0-9]([-a-z0-9]*[a-z0-9])?$")
# Kubernetes selector syntax: keys (with optional dns-prefix/), =, ==, !=,
# "in (a,b)", "notin (a,b)", existence (!key), comma separation.
_SELECTOR_CHARS = re.compile(r"^[A-Za-z0-9\-_./=!,() ]*$")
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
            f"invalid {what}: must be a DNS-1123 label (lowercase alphanumeric and '-')"
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
