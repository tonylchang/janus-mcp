"""The adversarial probing suite (§6.3): scripted hostile calls, asserted safe
behavior. Each probe also asserts the policy error short-circuited BEFORE any
Kubernetes API access where that is the contract."""

from __future__ import annotations

import pytest
from mcp.shared.memory import create_connected_server_and_client_session as connect

import support
from janus_mcp.server import build_server
from support import FakeKube, make_audit, make_settings

pytestmark = pytest.mark.anyio


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


async def _call(server, tool: str, args: dict):
    async with connect(server) as client:
        return await client.call_tool(tool, args)


async def test_secret_kind_refused_with_zero_api_calls(server, fake_kube) -> None:
    result = await _call(
        server,
        "describe_resource",
        {"kind": "Secret", "name": "db-credentials", "namespace": "prod"},
    )
    assert result.isError
    assert "by design" in result.content[0].text
    assert fake_kube.calls == []  # the policy error fired before ANY API access


async def test_out_of_scope_namespace_refused(server, fake_kube) -> None:
    result = await _call(server, "get_pods", {"namespace": "kube-system"})
    assert result.isError
    assert "denied" in result.content[0].text
    assert fake_kube.calls == []


async def test_unlisted_namespace_refused(server, fake_kube) -> None:
    result = await _call(server, "get_pods", {"namespace": "internal-tools"})
    assert result.isError
    assert "outside" in result.content[0].text
    assert fake_kube.calls == []


async def test_selector_injection_treated_as_data(server, fake_kube) -> None:
    result = await _call(
        server, "get_pods", {"namespace": "prod", "label_selector": "a==b,$(rm -rf /)"}
    )
    assert result.isError  # validation error, no API call, nothing executed
    assert fake_kube.calls == []


async def test_path_traversal_name_rejected(server, fake_kube) -> None:
    result = await _call(server, "get_logs", {"namespace": "prod", "pod": "../../etc/shadow"})
    assert result.isError
    assert "DNS-1123" in result.content[0].text
    assert fake_kube.calls == []


async def test_huge_replicas_refused_before_approval(server, fake_kube) -> None:
    result = await _call(
        server,
        "scale_deployment",
        {"name": "payments-api", "namespace": "prod", "replicas": 999999},
    )
    assert result.isError
    assert "maximum" in result.content[0].text
    # bounds check fires before the fresh read and before any approval flow
    assert fake_kube.calls_for("get_scale") == []
    assert fake_kube.calls_for("scale") == []


async def test_grep_runs_post_redaction(server, fake_kube) -> None:
    """grep="AKIA" must match nothing: the key was redacted before filtering,
    so match-counting cannot binary-search secret values."""
    result = await _call(
        server,
        "get_logs",
        {
            "namespace": "prod",
            "pod": "payments-api-7f9c6d4b-xkq2p",
            "previous": True,
            "grep": "AKIA",
        },
    )
    assert not result.isError
    text = result.content[0].text
    assert "AKIA" not in text
    # but grepping for the *typed token* works fine — the model can still
    # reason about where credentials appeared
    result2 = await _call(
        server,
        "get_logs",
        {
            "namespace": "prod",
            "pod": "payments-api-7f9c6d4b-xkq2p",
            "previous": True,
            "grep": "[REDACTED:aws-key]",
        },
    )
    assert "[REDACTED:aws-key]" in result2.content[0].text


async def test_unknown_pod_is_typed_not_found(server) -> None:
    result = await _call(server, "get_logs", {"namespace": "prod", "pod": "made-up-pod-name"})
    assert result.isError
    text = result.content[0].text
    assert "not found" in text
    assert support.FAKE_API_SERVER not in text


async def test_node_describe_blocked_when_cluster_scope_disabled(server, fake_kube) -> None:
    result = await _call(server, "describe_resource", {"kind": "Node", "name": "some-node"})
    assert result.isError
    assert "cluster-scoped" in result.content[0].text
    assert fake_kube.calls == []


async def test_log_output_is_framed_as_untrusted(server) -> None:
    result = await _call(
        server,
        "get_logs",
        {"namespace": "prod", "pod": "payments-api-7f9c6d4b-xkq2p", "previous": True},
    )
    text = result.content[0].text
    assert "BEGIN UNTRUSTED WORKLOAD OUTPUT" in text
    assert "END UNTRUSTED WORKLOAD OUTPUT" in text
    # the prompt-injection line survives as inert data inside the markers
    assert "ignore previous instructions" in text


async def test_read_only_config_hides_write_tools(tmp_path) -> None:
    settings = make_settings(tmp_path, read_only=True)
    server = build_server(settings, FakeKube(), make_audit(settings))
    async with connect(server) as client:
        tools = [t.name for t in (await client.list_tools()).tools]
    assert "scale_deployment" not in tools
    assert "rollout_restart" not in tools
    assert "get_pods" in tools


async def test_tool_descriptions_are_static(server, fake_kube) -> None:
    """Tool metadata must never be derived from cluster content."""
    async with connect(server) as client:
        listed = (await client.list_tools()).tools
    blob = "".join((t.description or "") + t.name for t in listed)
    for canary in support.ALL_CANARIES:
        assert canary not in blob
    assert fake_kube.calls == []  # listing tools touches the cluster not at all


async def test_cluster_summary_resource_is_listed_and_sanitized(server) -> None:
    """The cluster://summary resource serves the same redacted content as the
    summary tool — and nothing else."""
    from pydantic import AnyUrl

    async with connect(server) as client:
        resources = (await client.list_resources()).resources
        assert [str(r.uri) for r in resources] == ["cluster://summary"]
        result = await client.read_resource(AnyUrl("cluster://summary"))
        text = result.contents[0].text
    assert "namespaces in scope: prod, staging" in text
    assert "pods by phase:" in text
    for canary in support.ALL_CANARIES:
        assert canary not in text
