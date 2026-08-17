"""Golden-file tests: fixture -> full redaction pipeline -> expected output,
byte-for-byte. Regenerate with UPDATE_GOLDENS=1 after reviewing the diff —
the review IS the security control.
"""

from __future__ import annotations

import os
from datetime import UTC, datetime
from pathlib import Path

import pytest

import support
from janus_mcp.config import RedactionSettings
from janus_mcp.redaction import (
    RedactionStats,
    dedupe_events,
    render_event_lines,
    render_pod_table,
    render_resource_table,
    render_usage_table,
    render_yaml,
    sanitize_object,
    scrub_text,
    unified_yaml_diff,
)

GOLDENS = Path(__file__).parent / "goldens"
NOW = datetime(2026, 6, 10, 8, 5, 0, tzinfo=UTC)
RS = RedactionSettings()


def pipeline_describe(kind: str, fixture: str) -> str:
    stats = RedactionStats()
    sanitized = sanitize_object(kind, support.load_fixture(fixture), RS, stats)
    return scrub_text(render_yaml(sanitized), RS, stats)


def pipeline_pods() -> str:
    stats = RedactionStats()
    sanitized = [sanitize_object("Pod", p, RS, stats) for p in support.load_fixture("pods.json")]
    return scrub_text(render_pod_table(sanitized, now=NOW), RS, stats)


def pipeline_events() -> str:
    stats = RedactionStats()
    deduped, _ = dedupe_events(support.load_fixture("events.json"))
    for event in deduped:
        event["message"] = scrub_text(str(event.get("message", "")), RS, stats)
    return scrub_text(render_event_lines(deduped, now=NOW), RS, stats)


def pipeline_logs() -> str:
    stats = RedactionStats()
    return scrub_text(str(support.load_fixture("pod.log")), RS, stats)


def pipeline_list(kind: str, fixture: str) -> str:
    stats = RedactionStats()
    objs = support.load_fixture(fixture)
    if not isinstance(objs, list):
        objs = [objs]
    sanitized = [sanitize_object(kind, o, RS, stats) for o in objs]
    return scrub_text(render_resource_table(kind, sanitized, now=NOW), RS, stats)


def pipeline_usage() -> str:
    stats = RedactionStats()
    table = render_usage_table(
        support.load_fixture("pod_metrics.json"), support.load_fixture("pods.json")
    )
    return scrub_text(table, RS, stats)


def pipeline_rollout_diff() -> str:
    """The template diff shown by get_rollout_status / on rollout_undo approval
    cards: both sides sanitized BEFORE diffing, then scrubbed."""
    stats = RedactionStats()
    current, previous = support.load_fixture("replicasets.json")

    def sanitized_template(rs: dict) -> dict:
        template = dict(rs["spec"]["template"])
        meta = dict(template.get("metadata") or {})
        meta["labels"] = {
            k: v for k, v in (meta.get("labels") or {}).items() if k != "pod-template-hash"
        }
        template["metadata"] = meta
        shell = {"kind": "ReplicaSet", "spec": {"template": template}}
        out = sanitize_object("ReplicaSet", shell, RS, stats)
        return out["spec"]["template"]

    diff = unified_yaml_diff(
        sanitized_template(previous), sanitized_template(current), "revision-13", "revision-14"
    )
    return scrub_text(diff, RS, stats)


CASES = {
    "describe_pod.txt": lambda: pipeline_describe("Pod", "pod.json"),
    "describe_deployment.txt": lambda: pipeline_describe("Deployment", "deployment.json"),
    "describe_configmap.txt": lambda: pipeline_describe("ConfigMap", "configmap.json"),
    "describe_service.txt": lambda: pipeline_describe("Service", "service.json"),
    "describe_node.txt": lambda: pipeline_describe("Node", "node.json"),
    "describe_cronjob.txt": lambda: pipeline_describe("CronJob", "cronjob.json"),
    "get_pods.txt": pipeline_pods,
    "get_events.txt": pipeline_events,
    "get_logs.txt": pipeline_logs,
    "list_resources_deployments.txt": lambda: pipeline_list("Deployment", "deployment.json"),
    "list_resources_cronjobs.txt": lambda: pipeline_list("CronJob", "cronjob.json"),
    "list_resources_replicasets.txt": lambda: pipeline_list("ReplicaSet", "replicasets.json"),
    "resource_usage.txt": pipeline_usage,
    "rollout_diff.txt": pipeline_rollout_diff,
}


@pytest.mark.parametrize("name", sorted(CASES))
def test_golden(name: str) -> None:
    actual = CASES[name]()
    path = GOLDENS / name
    if os.environ.get("UPDATE_GOLDENS"):
        GOLDENS.mkdir(exist_ok=True)
        path.write_text(actual)
        pytest.skip(f"updated golden {name}")
    expected = path.read_text()
    assert actual == expected, f"golden mismatch for {name}; review and UPDATE_GOLDENS=1"


@pytest.mark.parametrize("name", sorted(CASES))
def test_golden_contains_no_canary(name: str) -> None:
    """Defense in depth: even a wrongly-updated golden must never hold a canary."""
    content = (GOLDENS / name).read_text() if (GOLDENS / name).exists() else CASES[name]()
    for canary in support.ALL_CANARIES:
        assert canary not in content
