"""Integration tests against a real kind cluster.

Skipped unless JANUS_KIND_TEST=1. Setup:

    kind create cluster --name janus-test
    JANUS_KIND_TEST=1 uv run pytest tests/integration -m integration

The manifests plant canary credentials in a Secret, a ConfigMap, and a
crash-looping pod's stdout; the assertions mirror the unit-level canary
contract against a live API server. (Run under the restricted ServiceAccount
from rbac/ to also catch RBAC drift; defaults to the kind admin context.)
"""

from __future__ import annotations

import os
import shutil
import subprocess
import time
from pathlib import Path

import anyio
import pytest

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(
        not os.environ.get("JANUS_KIND_TEST"),
        reason="set JANUS_KIND_TEST=1 with a running kind cluster (see module docstring)",
    ),
    pytest.mark.anyio,
]

MANIFESTS = Path(__file__).parent / "manifests" / "janus-it.yaml"
CONTEXT = os.environ.get("JANUS_KIND_CONTEXT", "kind-janus-test")


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


@pytest.fixture(scope="module")
def cluster_fixtures() -> None:
    kubectl = shutil.which("kubectl")
    if kubectl is None:
        pytest.skip("kubectl not available")
    subprocess.run(
        [kubectl, "--context", CONTEXT, "apply", "-f", str(MANIFESTS)],
        check=True,
        capture_output=True,
    )
    # give the canary pod a moment to schedule and emit logs
    time.sleep(5)


async def test_live_read_tools_and_canary_absence(tmp_path, cluster_fixtures) -> None:
    from mcp.shared.memory import create_connected_server_and_client_session as connect

    from janus_mcp.kube import KubeClient
    from janus_mcp.server import build_server
    from support import ALL_CANARIES, make_audit, make_settings

    settings = make_settings(
        tmp_path,
        context=CONTEXT,
        scope={"allowed_namespaces": ["janus-it"], "denied_namespaces": ["kube-system"]},
    )
    kube = KubeClient(settings)
    server = build_server(settings, kube, make_audit(settings))

    async with connect(server) as client:
        # the canary pod must eventually appear in scope
        with anyio.fail_after(120):
            while True:
                pods = await client.call_tool("get_pods", {"namespace": "janus-it"})
                assert not pods.isError, pods.content[0].text
                if "janus-it-crashloop" in pods.content[0].text:
                    break
                await anyio.sleep(3)

        outputs = [pods.content[0].text]
        for tool, args in [
            ("list_namespaces", {}),
            ("get_events", {"namespace": "janus-it", "only_warnings": False}),
            (
                "describe_resource",
                {"kind": "ConfigMap", "name": "janus-it-config", "namespace": "janus-it"},
            ),
            (
                "describe_resource",
                {"kind": "Pod", "name": "janus-it-crashloop", "namespace": "janus-it"},
            ),
            ("get_cluster_summary", {}),
        ]:
            result = await client.call_tool(tool, args)
            assert not result.isError, f"{tool} failed: {result.content[0].text}"
            outputs.append(result.content[0].text)

        # logs may need a few retries while the container starts
        with anyio.fail_after(120):
            while True:
                logs = await client.call_tool(
                    "get_logs", {"namespace": "janus-it", "pod": "janus-it-crashloop"}
                )
                if not logs.isError and "FATAL boom" in logs.content[0].text:
                    outputs.append(logs.content[0].text)
                    break
                await anyio.sleep(3)

        secret = await client.call_tool(
            "describe_resource",
            {"kind": "Secret", "name": "janus-canary", "namespace": "janus-it"},
        )
        assert secret.isError
        outputs.append(secret.content[0].text)

    blob = "\n".join(outputs)
    leaks = [c for c in ALL_CANARIES if c in blob]
    assert not leaks, f"canaries crossed the MCP boundary: {leaks}"
    assert "[REDACTED:aws-key]" in blob
    assert "[REDACTED:jwt]" in blob


async def test_live_write_path_scale_and_restart(tmp_path, cluster_fixtures) -> None:
    """Exercises the real Scale subresource: the readiness read for the approval
    card, the resourceVersion-bound patch, and the restart annotation patch."""
    from mcp import types
    from mcp.shared.memory import create_connected_server_and_client_session as connect

    from janus_mcp.kube import KubeClient
    from janus_mcp.server import build_server
    from support import make_audit, make_settings

    settings = make_settings(
        tmp_path,
        context=CONTEXT,
        scope={"allowed_namespaces": ["janus-it"], "denied_namespaces": ["kube-system"]},
    )
    kube = KubeClient(settings)
    server = build_server(settings, kube, make_audit(settings))

    cards: list[str] = []

    async def approve(context, params):
        cards.append(params.message)
        return types.ElicitResult(action="accept", content={"confirm": True})

    async with connect(server, elicitation_callback=approve) as client:
        result = await client.call_tool(
            "scale_deployment",
            {"name": "janus-it-web", "namespace": "janus-it", "replicas": 2},
        )
        assert not result.isError, result.content[0].text
        assert "from 1 to 2" in result.content[0].text
        # the card showed real readiness (N/1 ready), never a fabricated total
        assert cards and "/1 ready" in cards[0]

        restart = await client.call_tool(
            "rollout_restart",
            {
                "kind": "Deployment",
                "name": "janus-it-web",
                "namespace": "janus-it",
                "reason": "integration test",
            },
        )
        assert not restart.isError, restart.content[0].text
        assert "restart requested" in restart.content[0].text

        # Scale back so the fixture is reusable on repeat runs. The restart above
        # leaves the Deployment actively reconciling, so the RV-bound patch may
        # 409 — that is the bait-and-switch guard failing safe; only the typed
        # conflict error is acceptable, and a retry (fresh read, fresh approval)
        # must eventually succeed.
        with anyio.fail_after(60):
            while True:
                back = await client.call_tool(
                    "scale_deployment",
                    {"name": "janus-it-web", "namespace": "janus-it", "replicas": 1},
                )
                if not back.isError:
                    break
                assert "conflict" in back.content[0].text, back.content[0].text
                await anyio.sleep(2)


async def test_live_expanded_surface(tmp_path, cluster_fixtures) -> None:
    """The new read tools plus CronJob and delete_pod writes against a real
    API server: listing, rollout history (the restart in the previous test
    guarantees >= 2 revisions), metrics absence handled as a typed error,
    UID-bound pod deletion, and CronJob suspend/trigger."""
    from mcp import types
    from mcp.shared.memory import create_connected_server_and_client_session as connect

    from janus_mcp.kube import KubeClient
    from janus_mcp.server import build_server
    from support import ALL_CANARIES, make_audit, make_settings

    settings = make_settings(
        tmp_path,
        context=CONTEXT,
        scope={"allowed_namespaces": ["janus-it"], "denied_namespaces": ["kube-system"]},
    )
    kube = KubeClient(settings)
    server = build_server(settings, kube, make_audit(settings))

    async def approve(context, params):
        return types.ElicitResult(action="accept", content={"confirm": True})

    outputs: list[str] = []
    async with connect(server, elicitation_callback=approve) as client:
        for kind in ("Deployment", "ReplicaSet", "CronJob"):
            result = await client.call_tool(
                "list_resources", {"kind": kind, "namespace": "janus-it"}
            )
            assert not result.isError, result.content[0].text
            outputs.append(result.content[0].text)
        assert "janus-it-web" in outputs[0]
        assert "janus-it-cron" in outputs[2]

        rollout = await client.call_tool(
            "get_rollout_status", {"name": "janus-it-web", "namespace": "janus-it"}
        )
        assert not rollout.isError, rollout.content[0].text
        assert "REVISIONS" in rollout.content[0].text
        outputs.append(rollout.content[0].text)

        # kind has no metrics-server: the failure must be typed and helpful
        usage = await client.call_tool("get_resource_usage", {"namespace": "janus-it"})
        assert usage.isError
        assert "metrics API unavailable" in usage.content[0].text

        # describe the CronJob: the planted identity annotation must be gone
        cron = await client.call_tool(
            "describe_resource",
            {"kind": "CronJob", "name": "janus-it-cron", "namespace": "janus-it"},
        )
        assert not cron.isError, cron.content[0].text
        assert "role-arn" not in cron.content[0].text
        outputs.append(cron.content[0].text)

        # suspend, trigger, resume the CronJob
        for suspend in (True, False):
            result = await client.call_tool(
                "set_cronjob_suspend",
                {
                    "name": "janus-it-cron",
                    "namespace": "janus-it",
                    "suspend": suspend,
                    "reason": "integration test",
                },
            )
            assert not result.isError, result.content[0].text
        trigger = await client.call_tool(
            "trigger_cronjob",
            {"name": "janus-it-cron", "namespace": "janus-it", "reason": "integration test"},
        )
        assert not trigger.isError, trigger.content[0].text
        assert "created Job janus-it-cron-manual-" in trigger.content[0].text

        # delete a managed pod of the deployment (UID-bound); the RS recreates it
        pods = await client.call_tool("get_pods", {"namespace": "janus-it"})
        web_pod = next(
            line.split()[0]
            for line in pods.content[0].text.splitlines()
            if line.startswith("janus-it-web-")
        )
        deleted = await client.call_tool(
            "delete_pod",
            {"name": web_pod, "namespace": "janus-it", "reason": "integration test"},
        )
        assert not deleted.isError, deleted.content[0].text
        assert "deletion requested" in deleted.content[0].text

    blob = "\n".join(outputs)
    leaks = [c for c in ALL_CANARIES if c in blob]
    assert not leaks, f"canaries crossed the MCP boundary: {leaks}"
