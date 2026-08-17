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
        # env-dump style: the keyword is a SUFFIX of the key — the single most
        # common real-world leak shape in pod logs
        ("POSTGRES_PASSWORD=hunter2", "POSTGRES_PASSWORD=[REDACTED]", "hunter2"),
        ("MYAPP_TOKEN: tk-9f8e7d6c", "MYAPP_TOKEN: [REDACTED]", "tk-9f8e7d6c"),
        (
            "spring.datasource.password=pg123secret",
            "spring.datasource.password=[REDACTED]",
            "pg123secret",
        ),
        # quoted values with spaces must be redacted in full, not to the first space
        (
            'admin password: "correct horse battery staple" set',
            "password: [REDACTED]",
            "correct horse",
        ),
        ("DB_SECRET='multi word secret here'", "DB_SECRET=[REDACTED]", "multi word"),
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


# ---- entropy pass: shapes the absolute threshold could never catch ----------


def test_hex_secret_caught_by_entropy() -> None:
    # A 64-char hex HMAC tops out at 4 bits/char — mathematically below the
    # 4.5 default, so it needs the charset-scaled threshold to be caught.
    secret = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    out = scrub(f"loaded signing key {secret} from disk")
    assert secret not in out
    assert "[REDACTED:high-entropy]" in out


def test_short_random_token_caught_by_entropy() -> None:
    # 20 distinct mixed-case chars: entropy log2(20)=4.32, unreachable under a
    # flat 4.5 threshold — needs the length-scaled cap.
    token = "Zx9Qw2Ke7Rt4Yu1Vb3Nm"
    out = scrub(f"issued nonce {token} to client")
    assert token not in out
    assert "[REDACTED:high-entropy]" in out


def test_unrecognized_key_random_value_masks_value_only() -> None:
    out = scrub("blob=Zx9Qw2Ke7Rt4Yu1Vb3NmPl uploaded")
    assert out.startswith("blob=")
    assert "Zx9Qw2Ke7Rt4Yu1Vb3NmPl" not in out


@pytest.mark.parametrize(
    "text",
    [
        # DNS-1123-shaped: every generated Kubernetes name looks high-entropy
        "replicaset payments-api-7f9c6d4b has 3 replicas",
        # slash-joined forms our own tool output uses
        "deleted pod prod/payments-api-7f9c6d4b-xkq2p successfully",
        "created job billing-export-manual-20260817041500 in prod",
        # key=<short-id>: the label must not be judged as part of the blob
        "approval_id=1a2b3c4d granted by operator",
        # pure numbers are ids/timestamps, never judged as secrets
        "span 16999999999999999999 finished",
    ],
)
def test_entropy_negative_cases_survive(text: str) -> None:
    assert scrub(text) == text


# ---- node names in free text -------------------------------------------------


@pytest.mark.parametrize(
    ("text", "gone"),
    [
        (
            "Successfully assigned prod/payments-api-7f9c6d4b-xkq2p "
            "to ip-10-1-2-3.us-west-2.compute.internal",
            "ip-10-1-2-3",
        ),
        ("kubelet on worker-3.ec2.internal reported OOM", "worker-3.ec2.internal"),
        ("gke-prod-default-pool-1a2b3c4d-x9yz became NotReady", "gke-prod-default-pool"),
        ("drained aks-nodepool1-12345678-vmss000002", "aks-nodepool1"),
    ],
)
def test_node_names_masked_in_free_text(text: str, gone: str) -> None:
    """mask_node_names covers scheduler/kubelet event text and logs, not just
    structural fields — the same names must not leak through free text."""
    out = scrub(text)
    assert gone not in out
    assert "[MASKED:node]" in out


def test_node_names_kept_in_text_when_masking_disabled() -> None:
    rs = RedactionSettings(mask_node_names=False)
    text = "node ip-10-1-2-3.us-west-2.compute.internal cordoned"
    assert scrub(text, rs) == text


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


@pytest.mark.parametrize(
    "address",
    [
        "2607:f8b0:4004:c07::6a",  # compressed
        "2001:db8:85a3:8d3:1319:8a2e:370:7348",  # full 8-group
        "2001:db8::",  # trailing ::
        "::ffff:203.0.113.9",  # IPv4-mapped, masked as one unit
    ],
)
def test_public_ipv6_masked(address: str) -> None:
    out = scrub(f"connected to {address} port 443")
    assert address not in out
    assert "[REDACTED:ip]" in out


def test_internal_ipv6_kept() -> None:
    text = "listening on ::1 and fe80::1 and fd12:3456::1"
    assert scrub(text) == text


def test_ipv6_masked_inside_url_brackets() -> None:
    out = scrub("dial https://[2607:f8b0::1]:8443/healthz failed")
    assert "2607:f8b0::1" not in out
    assert "[[REDACTED:ip]]:8443" in out


@pytest.mark.parametrize(
    "text",
    [
        "event at 12:30:45 acknowledged",  # clock time
        "mac 3d:f2:c9:a6:b3:4f detected",  # MAC address (6 hex groups, no ::)
        "restarting in 00:05 (backoff)",
    ],
)
def test_ipv6_lookalikes_survive(text: str) -> None:
    assert scrub(text) == text


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


@pytest.mark.parametrize(
    "text",
    [
        # keyword must sit immediately before the separator, not mid-identifier
        "tokenizer=fast mode enabled",
        "authors=smith reviewed the change",
        "secrets_manager_region=us-east-1",  # keyword 'secret' not adjacent to '='
    ],
)
def test_keyword_lookalike_keys_survive(text: str) -> None:
    assert scrub(text) == text


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
