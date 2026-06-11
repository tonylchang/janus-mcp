"""Layer 2 — pattern + entropy scrubbing of free text.

Applied to every model-visible string that can carry workload- or
operator-authored content: log lines, event messages, condition messages, and
(belt-and-braces) the rendered output of the structural layer. Replacement
tokens are typed so the model can still reason about *what kind* of value was
present without seeing it.
"""

from __future__ import annotations

import ipaddress
import math
import re
from dataclasses import dataclass, field
from re import Match

from ..config import RedactionSettings


@dataclass
class RedactionStats:
    counts: dict[str, int] = field(default_factory=dict)

    def add(self, name: str, n: int = 1) -> None:
        if n:
            self.counts[name] = self.counts.get(name, 0) + n

    @property
    def total(self) -> int:
        return sum(self.counts.values())


def _typed(name: str) -> str:
    return f"[REDACTED:{name}]"


# Ordered most-specific first. Each entry: (name, compiled pattern, replacement).
# Replacement may reference groups (e.g. keep the credential *key*, mask the value).
_PATTERNS: list[tuple[str, re.Pattern[str], str]] = [
    (
        "pem",
        re.compile(
            r"-----BEGIN [A-Z0-9 ]*(?:PRIVATE KEY|CERTIFICATE)-----"
            r".*?"
            r"-----END [A-Z0-9 ]*(?:PRIVATE KEY|CERTIFICATE)-----",
            re.DOTALL,
        ),
        _typed("pem"),
    ),
    (
        "jwt",
        re.compile(r"\beyJ[\w-]{8,}\.[\w-]{8,}\.[\w-]{4,}"),
        _typed("jwt"),
    ),
    (
        "aws-key",
        re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"),
        _typed("aws-key"),
    ),
    (
        "gcp-key",
        re.compile(r"\bAIza[0-9A-Za-z_\-]{30,}\b"),
        _typed("gcp-key"),
    ),
    (
        "github-token",
        re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,})\b"),
        _typed("github-token"),
    ),
    (
        "slack-token",
        re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}\b"),
        _typed("slack-token"),
    ),
    (
        "basic-auth-url",
        re.compile(r"([a-zA-Z][a-zA-Z0-9+.-]*://[^/\s:@]+):[^@/\s]+@"),
        r"\1:[REDACTED]@",
    ),
    (
        "bearer",
        re.compile(r"(?i)\b(bearer)[ \t]+([A-Za-z0-9_\-.~+/=]{8,})"),
        r"\1 " + _typed("bearer"),
    ),
    (
        "key-value-credential",
        # The optional quote after the key covers JSON-shaped log lines
        # ("password": "..."), not just shell-shaped ones (password=...).
        # Whitespace is same-line only ([ \t], not \s): a bare YAML map key like
        # "secret:" at end of line must not swallow the next line's key.
        re.compile(
            r"(?i)\b(password|passwd|pwd|secret|token|api[_-]?key|access[_-]?key"
            r"|authorization|auth|bearer|credentials?)\b[\"']?([ \t]*[:=][ \t]*)(\S+)"
        ),
        r"\1\2[REDACTED]",
    ),
]

# Shapes that look high-entropy but are diagnostic identifiers, never secrets.
_ENTROPY_EXEMPT = re.compile(
    r"sha(?:1|256|512):[a-fA-F0-9]+"  # image/content digests
    r"|\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b"  # UUID
    r"|\b[0-9A-HJKMNP-TV-Z]{26}\b"  # ULID
    r"|\[REDACTED"  # our own replacement tokens
)

_ENTROPY_MIN_LEN = 20
# Leading/trailing punctuation that should not count toward a token's entropy.
_TOKEN_TRIM = "\"'`,;:()[]{}<>"  # noqa: S105 (not a credential)

_IPV4 = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")


def _shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    probs = [s.count(c) / len(s) for c in set(s)]
    return -sum(p * math.log2(p) for p in probs)


# Narrowly RFC1918 + loopback + link-local + unspecified — NOT the full IANA
# special-purpose list (which would exempt e.g. documentation ranges; anything
# not provably internal gets masked).
_INTERNAL_NETWORKS = [
    ipaddress.ip_network(net)
    for net in (
        "10.0.0.0/8",
        "172.16.0.0/12",
        "192.168.0.0/16",
        "127.0.0.0/8",
        "169.254.0.0/16",
        "0.0.0.0/32",
        "::1/128",
        "fc00::/7",
        "fe80::/10",
    )
]


def _is_public_ip(text: str) -> bool:
    try:
        ip = ipaddress.ip_address(text)
    except ValueError:
        return False
    return not any(ip in net for net in _INTERNAL_NETWORKS)


def _mask_public_ips(text: str, stats: RedactionStats) -> str:
    def sub(m: Match[str]) -> str:
        if _is_public_ip(m.group(0)):
            stats.add("ip", 1)
            return _typed("ip")
        return m.group(0)

    return _IPV4.sub(sub, text)


def _entropy_pass(text: str, threshold: float, stats: RedactionStats) -> str:
    out: list[str] = []
    for token in text.split(" "):
        core = token.strip(_TOKEN_TRIM)
        if (
            len(core) >= _ENTROPY_MIN_LEN
            and not _ENTROPY_EXEMPT.search(core)
            and _shannon_entropy(core) > threshold
        ):
            stats.add("high-entropy", 1)
            out.append(token.replace(core, _typed("high-entropy")))
        else:
            out.append(token)
    return " ".join(out)


def scrub_text(text: str, settings: RedactionSettings, stats: RedactionStats) -> str:
    """Run the full pattern + entropy pass over free text.

    Newlines are preserved; the entropy pass runs per line so that tokens never
    span line boundaries.
    """
    for name, pattern, replacement in _PATTERNS:
        text, n = pattern.subn(replacement, text)
        stats.add(name, n)
    if settings.mask_external_ips:
        text = _mask_public_ips(text, stats)
    lines = [_entropy_pass(line, settings.entropy_threshold, stats) for line in text.split("\n")]
    return "\n".join(lines)
