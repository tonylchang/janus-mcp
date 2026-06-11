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
