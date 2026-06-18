"""Kubernetes client policy-facing behavior that can be tested without a cluster."""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any

import pytest

from janus_mcp.kube import KubeClient

READ_ALLOWED = {
    ("prod", "pods", "list", None),
    ("prod", "pods", "get", None),
    ("prod", "events", "list", None),
    ("prod", "pods/log", "get", None),
    ("prod", "services", "get", None),
    ("prod", "configmaps", "get", None),
    ("prod", "persistentvolumeclaims", "get", None),
    ("prod", "persistentvolumeclaims", "list", None),
    ("prod", "deployments", "get", "apps"),
    ("prod", "deployments", "list", "apps"),
    ("prod", "replicasets", "get", "apps"),
    ("prod", "replicasets", "list", "apps"),
    ("prod", "statefulsets", "get", "apps"),
    ("prod", "daemonsets", "get", "apps"),
    ("prod", "jobs", "get", "batch"),
    ("prod", "cronjobs", "get", "batch"),
    ("prod", "ingresses", "get", "networking.k8s.io"),
    ("prod", "horizontalpodautoscalers", "get", "autoscaling"),
    ("prod", "horizontalpodautoscalers", "list", "autoscaling"),
}


def _client_with_ssar(allowed: set[tuple[str | None, str, str, str | None]]):
    client = object.__new__(KubeClient)

    def fake_ssar(**attrs: Any) -> bool:
        key = (
            attrs.get("namespace"),
            attrs["resource"],
            attrs["verb"],
            attrs.get("group"),
        )
        return key in allowed

    client._ssar = fake_ssar  # type: ignore[method-assign]
    return client


def test_self_check_read_only_permissions_and_secret_warning() -> None:
    allowed = READ_ALLOWED | {
        ("prod", "secrets", "get", None),
    }
    client = _client_with_ssar(allowed)

    missing, overprivileged = client.self_check(["prod"], [])

    assert missing == []
    assert any("read Secrets in prod" in warning for warning in overprivileged)


def test_self_check_write_tool_permissions_are_specific() -> None:
    allowed = READ_ALLOWED | {
        ("prod", "deployments", "patch", "apps"),
        ("prod", "deployments/scale", "get", "apps"),
    }
    client = _client_with_ssar(allowed)

    missing, overprivileged = client.self_check(
        ["prod"], ["rollout_restart", "scale_deployment", "pause_rollout"]
    )

    assert "patch statefulsets in prod" in missing
    assert "patch daemonsets in prod" in missing
    assert "patch deployments/scale in prod" in missing
    assert "get statefulsets/scale in prod" in missing
    assert "patch statefulsets/scale in prod" in missing
    assert "patch deployments in prod" not in missing
    assert overprivileged == []


@pytest.mark.anyio
async def test_bounded_list_follows_continue_tokens_and_reports_partial() -> None:
    client = object.__new__(KubeClient)
    calls: list[dict[str, Any]] = []

    async def fake_call(what, fn, *args, **kwargs):
        calls.append(kwargs)
        if kwargs.get("_continue") == "next":
            return SimpleNamespace(
                items=[{"name": "c"}, {"name": "d"}],
                metadata=SimpleNamespace(_continue=""),
            )
        return SimpleNamespace(
            items=[{"name": "a"}, {"name": "b"}],
            metadata=SimpleNamespace(_continue="next"),
        )

    client._call = fake_call  # type: ignore[method-assign]
    client._to_dict = lambda item: item  # type: ignore[method-assign]
    page = await client._list_bounded("objects", lambda: None, limit=3)
    assert [item["name"] for item in page] == ["a", "b", "c"]
    assert page.partial is True
    assert calls[1]["_continue"] == "next"


@pytest.mark.anyio
async def test_bounded_list_reports_complete_result() -> None:
    client = object.__new__(KubeClient)

    async def fake_call(what, fn, *args, **kwargs):
        return SimpleNamespace(
            items=[{"name": "a"}, {"name": "b"}],
            metadata=SimpleNamespace(_continue=""),
        )

    client._call = fake_call  # type: ignore[method-assign]
    client._to_dict = lambda item: item  # type: ignore[method-assign]
    page = await client._list_bounded("objects", lambda: None, limit=3)
    assert len(page) == 2
    assert page.partial is False
