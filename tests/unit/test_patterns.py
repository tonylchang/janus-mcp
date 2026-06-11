"""Layer 2 scrubber: every pattern class gets positive AND negative cases.

Negative cases matter as much as positive ones — over-redaction silently
destroys diagnostic value.
"""

from __future__ import annotations

import json

import pytest
from hypothesis import given
from hypothesis import settings as hyp_settings
from hypothesis import strategies as st

import support
from janus_mcp.config import RedactionSettings
from janus_mcp.redaction import RedactionStats, scrub_text

RS = RedactionSettings()


def scrub(text: str, rs: RedactionSettings = RS) -> str:
    return scrub_text(text, rs, RedactionStats())


# ---- positive cases: secrets must be replaced with typed tokens -------------


@pytest.mark.parametrize(
    ("text", "token", "gone"),
    [
        (f"key id {support.CANARY_AWS_KEY} resolved", "[REDACTED:aws-key]", support.CANARY_AWS_KEY),
        ("temp creds ASIAIOSFODNN7EXAMPLE", "[REDACTED:aws-key]", "ASIAIOSFODNN7EXAMPLE"),
        (f"jwt: {support.CANARY_JWT}", "[REDACTED:jwt]", support.CANARY_JWT),
        (f"gcp {support.CANARY_GCP_KEY}", "[REDACTED:gcp-key]", support.CANARY_GCP_KEY),
        (f"gh {support.CANARY_GITHUB}", "[REDACTED:github-token]", support.CANARY_GITHUB),
        ("slack xoxb-1234567890-abcdefghijklmnop", "[REDACTED:slack-token]", "xoxb-1234567890"),
        (
            "url postgres://payments:S3cr3tPw!@db.prod.svc:5432/payments",
            "payments:[REDACTED]@",
            "S3cr3tPw!",
        ),
        ("password=Tr0ub4dor&3-canary", "password=[REDACTED]", "Tr0ub4dor"),
        ("api_key: sk-aaaa1111bbbb2222", "api_key: [REDACTED]", "sk-aaaa1111bbbb2222"),
        ("Authorization: Bearer abcdef123456789", "[REDACTED]", "abcdef123456789"),
    ],
)
def test_pattern_redacts(text: str, token: str, gone: str) -> None:
    out = scrub(text)
    assert token in out
    assert gone not in out


def test_pem_block_redacted() -> None:
    pem = (
        "-----BEGIN RSA PRIVATE KEY-----\n"
        "MIIEowIBAAKCAQEAcanary0123456789\nMoreKeyMaterialHere\n"
        "-----END RSA PRIVATE KEY-----"
    )
    out = scrub(f"dumping key\n{pem}\ndone")
    assert "[REDACTED:pem]" in out
    assert "MIIEowIBAAKCAQEA" not in out


def test_high_entropy_token_redacted() -> None:
    out = scrub(f"session nonce {support.CANARY_HIGH_ENTROPY} issued")
    assert support.CANARY_HIGH_ENTROPY not in out
    assert "[REDACTED:high-entropy]" in out


def test_public_ip_masked_by_default() -> None:
    out = scrub("upstream at 203.0.113.99 unreachable")
    assert "203.0.113.99" not in out
    assert "[REDACTED:ip]" in out


def test_private_ips_kept() -> None:
    text = "dial tcp 10.244.1.5:8080 from 192.168.0.4 and 172.20.3.9"
    assert scrub(text) == text


def test_ip_masking_can_be_disabled() -> None:
    rs = RedactionSettings(mask_external_ips=False)
    text = "upstream at 203.0.113.99 unreachable"
    assert scrub(text, rs) == text


# ---- negative cases: diagnostic identifiers must survive --------------------


@pytest.mark.parametrize(
    "text",
    [
        "pulled registry.local/payments-api"
        "@sha256:9b6f1e0a4c1d2e3f45567890abcdef0123456789abcdef0123456789abcdef01",
        "request id 550e8400-e29b-41d4-a716-446655440000 served",
        "Back-off restarting failed container payments-api",
        'pq: password authentication failed for user "payments"',
        "Liveness probe failed: connection refused",
        "pod payments-api-7f9c6d4b-xkq2p in CrashLoopBackOff",
        "image registry.local/payments-api:2.4.1 already present",
    ],
)
def test_diagnostics_survive(text: str) -> None:
    assert scrub(text) == text


def test_key_value_keeps_key_name() -> None:
    out = scrub("password=hunter2")
    assert out.startswith("password=")
    assert "hunter2" not in out


def test_newlines_preserved() -> None:
    text = "line one\nline two password=x\nline three"
    out = scrub(text)
    assert len(out.split("\n")) == 3


# ---- canary property test ----------------------------------------------------


_CANARY_BEARING = [
    support.CANARY_AWS_KEY,
    support.CANARY_JWT,
    f"password={support.CANARY_PASSWORD}",
    support.CANARY_GCP_KEY,
    support.CANARY_GITHUB,
    support.CANARY_HIGH_ENTROPY,
]

_CANARY_CORE = {
    support.CANARY_AWS_KEY: support.CANARY_AWS_KEY,
    support.CANARY_JWT: support.CANARY_JWT,
    f"password={support.CANARY_PASSWORD}": support.CANARY_PASSWORD,
    support.CANARY_GCP_KEY: support.CANARY_GCP_KEY,
    support.CANARY_GITHUB: support.CANARY_GITHUB,
    support.CANARY_HIGH_ENTROPY: support.CANARY_HIGH_ENTROPY,
}


@hyp_settings(max_examples=200)
@given(
    prefix=st.text(
        alphabet=st.characters(blacklist_categories=("Cs",), blacklist_characters="\x00"),
        max_size=40,
    ),
    suffix=st.text(
        alphabet=st.characters(blacklist_categories=("Cs",), blacklist_characters="\x00"),
        max_size=40,
    ),
    canary=st.sampled_from(_CANARY_BEARING),
)
def test_canary_never_survives_in_free_text(prefix: str, suffix: str, canary: str) -> None:
    # Whitespace padding keeps the canary a distinct token, as it would be in
    # real log/event text; gluing arbitrary chars onto a credential changes the
    # credential itself, which is not the threat model.
    text = f"{prefix} {canary} {suffix}"
    out = scrub_text(text, RS, RedactionStats())
    assert _CANARY_CORE[canary] not in out


def test_canary_in_json_structure_never_survives() -> None:
    blob = json.dumps(
        {
            "level": "debug",
            "msg": "loaded credentials",
            "aws": support.CANARY_AWS_KEY,
            "jwt": support.CANARY_JWT,
            "nested": {"password": support.CANARY_PASSWORD},
        }
    )
    out = scrub(blob)
    for canary in (support.CANARY_AWS_KEY, support.CANARY_JWT, support.CANARY_PASSWORD):
        assert canary not in out
