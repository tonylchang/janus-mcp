"""Kubernetes client policy-facing behavior that can be tested without a cluster."""

from __future__ import annotations

from typing import Any

from janus_mcp.kube import KubeClient


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
    allowed = {
        ("prod", "pods", "list", None),
        ("prod", "events", "list", None),
        ("prod", "pods/log", "get", None),
        ("prod", "secrets", "get", None),
    }
    client = _client_with_ssar(allowed)

    missing, overprivileged = client.self_check(["prod"], [])

    assert missing == []
    assert any("read Secrets in prod" in warning for warning in overprivileged)


def test_self_check_write_tool_permissions_are_specific() -> None:
    allowed = {
        ("prod", "pods", "list", None),
        ("prod", "events", "list", None),
        ("prod", "pods/log", "get", None),
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
