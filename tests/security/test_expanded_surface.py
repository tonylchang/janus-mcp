"""Functional + adversarial coverage for the expanded tool surface:
list_resources, get_resource_usage, get_rollout_status, and the five
approval-gated writes (delete_pod, rollout_undo, set_cronjob_suspend,
trigger_cronjob, cordon_node)."""

from __future__ import annotations

import pytest
from mcp import types
from mcp.shared.memory import create_connected_server_and_client_session as connect

import support
from janus_mcp.server import build_server
from support import FakeKube, make_audit, make_settings

pytestmark = pytest.mark.anyio


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


def _accept_recorder(cards: list[str]):
    async def callback(context, params):
        cards.append(params.message)
        return types.ElicitResult(action="accept", content={"confirm": True})

    return callback


async def _call(server, tool: str, args: dict):
    async with connect(server) as client:
        return await client.call_tool(tool, args)


# ---- list_resources ----------------------------------------------------------


async def test_list_resources_renders_status_and_leaks_nothing(server, fake_kube) -> None:
    for kind, expect in [
        ("Deployment", "0/2 ready"),
        ("CronJob", "0 3 * * *"),
        ("ReplicaSet", "payments-api-7f9c6d4b"),
    ]:
        result = await _call(server, "list_resources", {"kind": kind, "namespace": "prod"})
        assert not result.isError, result.content[0].text
        text = result.content[0].text
        assert expect in text
        for canary in support.ALL_CANARIES:
            assert canary not in text


async def test_list_resources_secret_kind_rejected(server, fake_kube) -> None:
    result = await _call(server, "list_resources", {"kind": "Secret", "namespace": "prod"})
    assert result.isError  # not in the schema literal; rejected before any API call
    assert fake_kube.calls == []


async def test_list_resources_out_of_scope_refused(server, fake_kube) -> None:
    result = await _call(
        server, "list_resources", {"kind": "Deployment", "namespace": "kube-system"}
    )
    assert result.isError
    assert fake_kube.calls == []


# ---- get_resource_usage ------------------------------------------------------


async def test_resource_usage_reports_pods(server, fake_kube) -> None:
    result = await _call(server, "get_resource_usage", {"namespace": "prod"})
    assert not result.isError, result.content[0].text
    text = result.content[0].text
    assert "payments-api-7f9c6d4b-xkq2p" in text
    assert "236m" in text
    assert "128Mi" in text  # 131072Ki normalized
    for canary in support.ALL_CANARIES:
        assert canary not in text


async def test_resource_usage_out_of_scope_refused(server, fake_kube) -> None:
    result = await _call(server, "get_resource_usage", {"namespace": "kube-system"})
    assert result.isError
    assert fake_kube.calls == []


# ---- get_rollout_status ------------------------------------------------------


async def test_rollout_status_shows_revisions_and_sanitized_diff(server, fake_kube) -> None:
    result = await _call(
        server, "get_rollout_status", {"name": "payments-api", "namespace": "prod"}
    )
    assert not result.isError, result.content[0].text
    text = result.content[0].text
    assert "REVISIONS" in text
    assert "payments-api-7f9c6d4b" in text and "payments-api-5d8e7f6a" in text
    # the diff surfaces the actual change (image bump), with credentials masked
    assert "-    image: registry.local/payments-api:2.4.0" in text
    assert "+    image: registry.local/payments-api:2.4.1" in text
    assert "[REDACTED:env-value]" in text
    for canary in support.ALL_CANARIES:
        assert canary not in text


# ---- delete_pod --------------------------------------------------------------


async def test_delete_pod_approved_binds_uid(tmp_path) -> None:
    settings = make_settings(tmp_path)
    kube = FakeKube()
    server = build_server(settings, kube, make_audit(settings))
    cards: list[str] = []
    async with connect(server, elicitation_callback=_accept_recorder(cards)) as client:
        result = await client.call_tool(
            "delete_pod",
            {
                "name": "payments-api-7f9c6d4b-xkq2p",
                "namespace": "prod",
                "reason": "wedged after node reboot",
            },
        )
    assert not result.isError, result.content[0].text
    assert "deletion requested" in result.content[0].text
    # the card told the human what controls the pod
    assert "ReplicaSet/payments-api-7f9c6d4b" in cards[0]
    # the delete carried the UID observed at approval time
    fixture_uid = support.load_fixture("pod.json")["metadata"]["uid"]
    assert kube.deleted_pods == [("prod", "payments-api-7f9c6d4b-xkq2p", fixture_uid)]


async def test_delete_pod_replaced_instance_conflicts(tmp_path) -> None:
    """If the pod is replaced (same name, new UID) between approval-request and
    execution, the UID precondition must abort the delete."""
    settings = make_settings(tmp_path)
    kube = FakeKube()
    real_get_object = kube.get_object

    async def stale_get_object(kind, name, namespace):
        obj = await real_get_object(kind, name, namespace)
        if kind == "Pod":
            obj = dict(obj)
            obj["metadata"] = dict(obj["metadata"], uid="a-different-uid-after-replacement")
        return obj

    kube.get_object = stale_get_object  # type: ignore[method-assign]
    server = build_server(settings, kube, make_audit(settings))
    async with connect(server, elicitation_callback=_accept_recorder([])) as client:
        result = await client.call_tool(
            "delete_pod",
            {
                "name": "payments-api-7f9c6d4b-xkq2p",
                "namespace": "prod",
                "reason": "kick stuck pod",
            },
        )
    assert result.isError
    assert "conflict" in result.content[0].text
    assert kube.deleted_pods == []


async def test_delete_bare_pod_refused_before_approval(tmp_path) -> None:
    settings = make_settings(tmp_path)  # allow_bare_pod_deletion defaults to False
    kube = FakeKube()
    real_get_object = kube.get_object

    async def bare_get_object(kind, name, namespace):
        obj = await real_get_object(kind, name, namespace)
        if kind == "Pod":
            obj = dict(obj)
            obj["metadata"] = {k: v for k, v in obj["metadata"].items() if k != "ownerReferences"}
        return obj

    kube.get_object = bare_get_object  # type: ignore[method-assign]
    server = build_server(settings, kube, make_audit(settings))
    cards: list[str] = []
    async with connect(server, elicitation_callback=_accept_recorder(cards)) as client:
        result = await client.call_tool(
            "delete_pod",
            {"name": "payments-api-7f9c6d4b-xkq2p", "namespace": "prod", "reason": "cleanup"},
        )
    assert result.isError
    assert "bare-pod deletion is disabled" in result.content[0].text
    assert cards == []  # refused BEFORE any approval was requested
    assert kube.deleted_pods == []


# ---- rollout_undo ------------------------------------------------------------


async def test_rollout_undo_approved_patches_previous_template(tmp_path) -> None:
    settings = make_settings(tmp_path)
    kube = FakeKube()
    server = build_server(settings, kube, make_audit(settings))
    cards: list[str] = []
    async with connect(server, elicitation_callback=_accept_recorder(cards)) as client:
        result = await client.call_tool(
            "rollout_undo",
            {"name": "payments-api", "namespace": "prod", "reason": "2.4.1 crashloops"},
        )
    assert not result.isError, result.content[0].text
    assert "revision 13" in result.content[0].text
    # the human saw the sanitized diff: image change visible, credentials not
    assert "registry.local/payments-api:2.4.0" in cards[0]
    assert support.CANARY_PASSWORD not in cards[0]
    calls = kube.calls_for("patch_deployment_template")
    assert len(calls) == 1
    template = calls[0]["template"]
    containers = template["spec"]["containers"]
    assert containers[0]["image"] == "registry.local/payments-api:2.4.0"
    # ReplicaSet plumbing must not ride into the deployment template
    assert "pod-template-hash" not in (template["metadata"].get("labels") or {})
    assert calls[0]["expected_resource_version"] == "991100"


async def test_rollout_undo_without_history_refused(tmp_path) -> None:
    settings = make_settings(tmp_path)
    kube = FakeKube()
    real_list = kube.list_replica_sets

    async def single_rs(namespace, label_selector):
        return (await real_list(namespace, label_selector))[:1]

    kube.list_replica_sets = single_rs  # type: ignore[method-assign]
    server = build_server(settings, kube, make_audit(settings))
    async with connect(server, elicitation_callback=_accept_recorder([])) as client:
        result = await client.call_tool(
            "rollout_undo", {"name": "payments-api", "namespace": "prod", "reason": "revert"}
        )
    assert result.isError
    assert "no previous revision" in result.content[0].text
    assert kube.calls_for("patch_deployment_template") == []


# ---- CronJob tools -----------------------------------------------------------


async def test_cronjob_suspend_and_noop(tmp_path) -> None:
    settings = make_settings(tmp_path)
    kube = FakeKube()
    server = build_server(settings, kube, make_audit(settings))
    cards: list[str] = []
    async with connect(server, elicitation_callback=_accept_recorder(cards)) as client:
        result = await client.call_tool(
            "set_cronjob_suspend",
            {
                "name": "billing-export",
                "namespace": "prod",
                "suspend": True,
                "reason": "pausing exports during incident",
            },
        )
        assert not result.isError, result.content[0].text
        assert "now suspended" in result.content[0].text
        assert kube.cronjob_suspended is True
        assert "0 3 * * *" in cards[0]

        # already-suspended: a no-op that never requests approval
        again = await client.call_tool(
            "set_cronjob_suspend",
            {
                "name": "billing-export",
                "namespace": "prod",
                "suspend": True,
                "reason": "double-check",
            },
        )
        assert not again.isError
        assert "no change needed" in again.content[0].text
        assert len(cards) == 1


async def test_trigger_cronjob_creates_named_job(tmp_path) -> None:
    settings = make_settings(tmp_path)
    kube = FakeKube()
    server = build_server(settings, kube, make_audit(settings))
    cards: list[str] = []
    async with connect(server, elicitation_callback=_accept_recorder(cards)) as client:
        result = await client.call_tool(
            "trigger_cronjob",
            {"name": "billing-export", "namespace": "prod", "reason": "rerun failed export"},
        )
    assert not result.isError, result.content[0].text
    assert "created Job billing-export-manual-" in result.content[0].text
    assert "registry.local/billing-export:1.2.0" in cards[0]
    calls = kube.calls_for("create_job_from_cronjob")
    assert len(calls) == 1
    assert calls[0]["job_name"].startswith("billing-export-manual-")


# ---- cordon_node -------------------------------------------------------------


async def test_cordon_requires_cluster_scope(server, fake_kube) -> None:
    result = await _call(
        server,
        "cordon_node",
        {"name": "ip-10-0-1-23.ec2.internal", "unschedulable": True, "reason": "bad disk"},
    )
    assert result.isError
    assert "cluster-scoped" in result.content[0].text
    assert fake_kube.calls == []


async def test_cordon_and_uncordon_with_cluster_scope(tmp_path) -> None:
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
    cards: list[str] = []
    async with connect(server, elicitation_callback=_accept_recorder(cards)) as client:
        result = await client.call_tool(
            "cordon_node",
            {"name": "ip-10-0-1-23.ec2.internal", "unschedulable": True, "reason": "bad disk"},
        )
        assert not result.isError, result.content[0].text
        assert "cordoned" in result.content[0].text
        assert kube.node_unschedulable is True
        assert "Ready=" in cards[0]

        # no-op path: already cordoned
        again = await client.call_tool(
            "cordon_node",
            {"name": "ip-10-0-1-23.ec2.internal", "unschedulable": True, "reason": "again"},
        )
        assert "no change needed" in again.content[0].text
        assert len(cards) == 1


# ---- registration gating -----------------------------------------------------


async def test_new_write_tools_absent_unless_enabled(tmp_path) -> None:
    settings = make_settings(
        tmp_path,
        write_tools={"enabled": ["rollout_restart"], "approval_timeout_seconds": 1},
    )
    server = build_server(settings, FakeKube(), make_audit(settings))
    async with connect(server) as client:
        tools = [t.name for t in (await client.list_tools()).tools]
    for name in (
        "delete_pod",
        "rollout_undo",
        "set_cronjob_suspend",
        "trigger_cronjob",
        "cordon_node",
    ):
        assert name not in tools
    assert "rollout_restart" in tools
