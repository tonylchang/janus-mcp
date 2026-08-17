"""The keystone leak test (§6.3): record every JSON-RPC frame of a full
scripted session — all tools, an approval round-trip, a decline, an error —
then grep the capture for canaries and kubeconfig material.

Zero hits or the build fails. This converts invariant #1 ("credentials stay in
server memory") from a promise into a regression test.
"""

from __future__ import annotations

import pytest
from capture import capture_session
from mcp import types
from pydantic import AnyUrl

import support
from janus_mcp.server import build_server
from support import FakeKube, make_audit, make_settings

pytestmark = pytest.mark.anyio


async def _accept(context, params):
    return types.ElicitResult(action="accept", content={"confirm": True})


async def _decline(context, params):
    return types.ElicitResult(action="decline")


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


async def test_full_session_leaks_nothing(tmp_path) -> None:
    settings = make_settings(tmp_path)
    kube = FakeKube()
    server = build_server(settings, kube, make_audit(settings))
    frames: list[str] = []

    async with capture_session(server, frames, elicitation_callback=_accept) as client:
        await client.list_tools()
        await client.call_tool("get_pods", {"namespace": "prod"})
        await client.call_tool(
            "get_events",
            {"namespace": "prod", "involved_object": "payments-api-7f9c6d4b-xkq2p"},
        )
        await client.call_tool(
            "describe_resource",
            {"kind": "Deployment", "name": "payments-api", "namespace": "prod"},
        )
        await client.call_tool(
            "describe_resource",
            {"kind": "ConfigMap", "name": "payments-config", "namespace": "prod"},
        )
        await client.call_tool(
            "get_logs",
            {
                "namespace": "prod",
                "pod": "payments-api-7f9c6d4b-xkq2p",
                "previous": True,
                "tail_lines": 100,
            },
        )
        await client.call_tool("get_cluster_summary", {})
        await client.list_resources()
        await client.read_resource(AnyUrl("cluster://summary"))
        await client.list_prompts()
        await client.get_prompt("diagnose_namespace", {"namespace": "prod"})
        await client.call_tool("list_namespaces", {})
        # the expanded read surface — lists, usage, rollout history + diff
        for kind in ("Deployment", "ReplicaSet", "CronJob", "Service", "ConfigMap"):
            await client.call_tool("list_resources", {"kind": kind, "namespace": "prod"})
        await client.call_tool("get_resource_usage", {"namespace": "prod"})
        await client.call_tool("get_rollout_status", {"name": "payments-api", "namespace": "prod"})
        await client.call_tool(
            "describe_resource",
            {"kind": "CronJob", "name": "billing-export", "namespace": "prod"},
        )
        # approved writes across the whole write surface
        await client.call_tool(
            "scale_deployment",
            {"name": "payments-api", "namespace": "prod", "replicas": 4},
        )
        await client.call_tool(
            "delete_pod",
            {
                "name": "payments-api-7f9c6d4b-xkq2p",
                "namespace": "prod",
                "reason": "wedged instance",
            },
        )
        await client.call_tool(
            "rollout_undo",
            {"name": "payments-api", "namespace": "prod", "reason": "bad release"},
        )
        await client.call_tool(
            "set_cronjob_suspend",
            {
                "name": "billing-export",
                "namespace": "prod",
                "suspend": True,
                "reason": "incident",
            },
        )
        await client.call_tool(
            "trigger_cronjob",
            {"name": "billing-export", "namespace": "prod", "reason": "manual rerun"},
        )
        # an error path: out-of-scope namespace
        error_result = await client.call_tool("get_pods", {"namespace": "kube-system"})
        assert error_result.isError
        # a policy refusal: Secret kind
        secret_result = await client.call_tool(
            "describe_resource",
            {"kind": "Secret", "name": "db-credentials", "namespace": "prod"},
        )
        assert secret_result.isError

    capture = "\n".join(frames)
    assert len(frames) > 20  # the capture actually saw the session

    leaks = [canary for canary in support.ALL_CANARIES if canary in capture]
    assert not leaks, f"CREDENTIAL LEAK across MCP boundary: {leaks}"

    # kubeconfig field names must never appear either (they would imply the
    # config itself was serialized into a frame)
    for marker in (
        "certificate-authority-data",
        "client-key-data",
        "client-certificate-data",
    ):
        assert marker not in capture, f"kubeconfig material in MCP frames: {marker}"


async def test_cluster_scoped_session_leaks_nothing(tmp_path) -> None:
    """Node describe + cordon under cluster scope, frame-captured."""
    settings = make_settings(
        tmp_path,
        scope={
            "allowed_namespaces": ["prod", "staging"],
            "denied_namespaces": ["kube-system"],
            "allow_cluster_scoped": True,
        },
    )
    kube = FakeKube()
    server = build_server(settings, kube, make_audit(settings))
    frames: list[str] = []

    async with capture_session(server, frames, elicitation_callback=_accept) as client:
        await client.call_tool(
            "describe_resource", {"kind": "Node", "name": "ip-10-0-1-23.ec2.internal"}
        )
        result = await client.call_tool(
            "cordon_node",
            {"name": "ip-10-0-1-23.ec2.internal", "unschedulable": True, "reason": "bad disk"},
        )
        assert not result.isError

    assert kube.node_unschedulable is True
    capture = "\n".join(frames)
    leaks = [canary for canary in support.ALL_CANARIES if canary in capture]
    assert not leaks, f"CREDENTIAL LEAK across MCP boundary: {leaks}"


async def test_declined_write_changes_nothing_and_leaks_nothing(tmp_path) -> None:
    settings = make_settings(tmp_path)
    kube = FakeKube()
    server = build_server(settings, kube, make_audit(settings))
    frames: list[str] = []

    async with capture_session(server, frames, elicitation_callback=_decline) as client:
        result = await client.call_tool(
            "rollout_restart",
            {
                "kind": "Deployment",
                "name": "payments-api",
                "namespace": "prod",
                "reason": "test decline path",
            },
        )
        text = result.content[0].text
        assert not result.isError
        assert "Denied by operator" in text
        assert "No change was made" in text

    assert kube.calls_for("rollout_restart") == []
    capture = "\n".join(frames)
    leaks = [canary for canary in support.ALL_CANARIES if canary in capture]
    assert not leaks
