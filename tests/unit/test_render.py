"""Layer 3 output shaping: envelope, truncation, tables, event dedup."""

from __future__ import annotations

from datetime import UTC, datetime

import support
from janus_mcp.config import LimitsSettings, RedactionSettings
from janus_mcp.redaction import (
    RedactionStats,
    dedupe_events,
    envelope,
    render_event_lines,
    render_pod_table,
)
from janus_mcp.redaction.render import _format_age

NOW = datetime(2026, 6, 10, 8, 5, 0, tzinfo=UTC)
LIMITS = LimitsSettings()


def test_envelope_header_shape() -> None:
    stats = RedactionStats()
    stats.add("jwt", 3)
    out = envelope("get_logs", "body line", LIMITS, stats=stats, ns="prod", pod="x")
    header, body = out.split("\n", 1)
    assert header == "[janus-mcp] ok=true tool=get_logs ns=prod pod=x truncated=false redactions=3"
    assert body == "body line"


def test_envelope_truncates_on_line_boundary() -> None:
    limits = LimitsSettings(result_max_bytes=1024)
    body = "\n".join(f"line {i} " + "x" * 80 for i in range(100))
    out = envelope("get_logs", body, limits)
    assert "truncated=true" in out.split("\n")[0]
    assert len(out.encode()) < 1024 + 200  # header allowance
    assert out.endswith("retry]")
    # no partial line: every kept line is intact
    for line in out.split("\n")[1:-1]:
        assert line.startswith("line ")


def test_pod_table_matches_walkthrough_shape() -> None:
    pods = [
        support.load_fixture("pod.json"),
    ]
    table = render_pod_table(pods, now=NOW)
    lines = table.split("\n")
    assert lines[0].split() == ["NAME", "READY", "STATUS", "RESTARTS", "AGE", "LAST_STATE"]
    row = lines[1]
    assert "payments-api-7f9c6d4b-xkq2p" in row
    assert "0/1" in row
    assert "CrashLoopBackOff" in row
    assert "17" in row
    assert "3d2h" in row
    assert "Error: exit 1 (3m ago)" in row


def test_event_dedupe_collapses_identical_tuples() -> None:
    events = support.load_fixture("events.json")
    deduped, original = dedupe_events(events)
    assert original == 5
    assert len(deduped) == 4  # the two BackOff events collapse
    backoff = next(e for e in deduped if e["reason"] == "BackOff")
    assert backoff["_janus_count"] == 17  # 9 + 8
    rendered = render_event_lines(deduped, now=NOW)
    assert "×17" in rendered


def test_format_age() -> None:
    assert _format_age("2026-06-10T08:04:30Z", NOW) == "30s"
    assert _format_age("2026-06-10T08:01:00Z", NOW) == "4m"
    assert _format_age("2026-06-10T05:05:00Z", NOW) == "3h"
    assert _format_age("2026-06-07T06:00:00Z", NOW) == "3d2h"
    assert _format_age("2026-05-10T08:00:00Z", NOW) == "31d"
    assert _format_age(None, NOW) == "?"


def test_scrubbed_fixture_log_keeps_diagnostic_signal() -> None:
    """The walkthrough invariant: the FATAL line survives, credentials do not."""
    from janus_mcp.redaction import scrub_text

    stats = RedactionStats()
    out = scrub_text(str(support.load_fixture("pod.log")), RedactionSettings(), stats)
    assert 'FATAL pq: password authentication failed for user "payments"' in out
    assert "postgres://payments:[REDACTED]@db.prod.svc:5432/payments" in out
    assert "Bearer [REDACTED:jwt]" in out
    for canary in (
        support.CANARY_AWS_KEY,
        support.CANARY_JWT,
        support.CANARY_DB_PASSWORD,
        support.CANARY_GCP_KEY,
        support.CANARY_GITHUB,
        support.CANARY_HIGH_ENTROPY,
    ):
        assert canary not in out
    # diagnostic identifiers survive
    assert "550e8400-e29b-41d4-a716-446655440000" in out
    assert "sha256:9b6f1e0a4c1d2e3f45567890abcdef0123456789abcdef0123456789abcdef01" in out
