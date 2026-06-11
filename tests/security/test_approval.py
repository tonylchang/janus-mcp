"""Approval-gate behavior end-to-end: elicitation accept/decline/cancel/timeout,
the out-of-band fallback, bait-and-switch resistance, and stale-state conflicts."""

from __future__ import annotations

import anyio
import pytest
from mcp import types
from mcp.shared.memory import create_connected_server_and_client_session as connect

from janus_mcp.policy import ApprovalStore
from janus_mcp.server import build_server
from support import FakeKube, make_audit, make_settings

pytestmark = pytest.mark.anyio


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


def _responder(action: str, confirm: bool | None = None):
    async def callback(context, params):
        content = {"confirm": confirm} if confirm is not None else None
        return types.ElicitResult(action=action, content=content)

    return callback


SCALE_ARGS = {"name": "payments-api", "namespace": "prod", "replicas": 4}


async def test_elicitation_accept_executes(tmp_path) -> None:
    settings = make_settings(tmp_path)
    kube = FakeKube()
    server = build_server(settings, kube, make_audit(settings))
    async with connect(server, elicitation_callback=_responder("accept", True)) as client:
        result = await client.call_tool("scale_deployment", SCALE_ARGS)
    assert not result.isError
    assert "scaled Deployment prod/payments-api from 2 to 4" in result.content[0].text
    assert len(kube.calls_for("scale")) == 1
    # the patch carried the resourceVersion observed at approval time
    assert kube.calls_for("scale")[0]["expected_resource_version"] == "12345"


async def test_elicitation_accept_without_confirm_is_denied(tmp_path) -> None:
    settings = make_settings(tmp_path)
    kube = FakeKube()
    server = build_server(settings, kube, make_audit(settings))
    async with connect(server, elicitation_callback=_responder("accept", False)) as client:
        result = await client.call_tool("scale_deployment", SCALE_ARGS)
    assert "Denied by operator" in result.content[0].text
    assert kube.calls_for("scale") == []


@pytest.mark.parametrize("action", ["decline", "cancel"])
async def test_elicitation_decline_and_cancel_are_noops(tmp_path, action: str) -> None:
    settings = make_settings(tmp_path)
    kube = FakeKube()
    server = build_server(settings, kube, make_audit(settings))
    async with connect(server, elicitation_callback=_responder(action)) as client:
        result = await client.call_tool("scale_deployment", SCALE_ARGS)
    assert "Denied by operator" in result.content[0].text
    assert "No change was made" in result.content[0].text
    assert kube.calls_for("scale") == []


async def test_elicitation_timeout_is_denied(tmp_path) -> None:
    settings = make_settings(tmp_path)  # approval_timeout_seconds=0.5

    async def answers_too_late(context, params):
        # Well past the server's 0.5s approval timeout. (Kept short because the
        # client SDK processes incoming requests inline in its receive loop, so
        # the tool result is only read after this callback returns.)
        await anyio.sleep(3)
        return types.ElicitResult(action="accept", content={"confirm": True})

    kube = FakeKube()
    server = build_server(settings, kube, make_audit(settings))
    async with connect(server, elicitation_callback=answers_too_late) as client:
        with anyio.fail_after(15):
            result = await client.call_tool("scale_deployment", SCALE_ARGS)
    assert "Denied by operator" in result.content[0].text
    assert "timed out" in result.content[0].text
    assert kube.calls_for("scale") == []


# ---- out-of-band fallback (client without elicitation support) ---------------


async def test_oob_flow_pending_then_approved(tmp_path) -> None:
    settings = make_settings(tmp_path)
    kube = FakeKube()
    server = build_server(settings, kube, make_audit(settings))
    store = ApprovalStore(settings.approvals_dir, ttl_seconds=300)

    # no elicitation_callback => client does not advertise the capability
    async with connect(server) as client:
        first = await client.call_tool("scale_deployment", SCALE_ARGS)
        text = first.content[0].text
        assert "status=pending" in text
        assert "No change was made" in text
        approval_id = text.split("approval_id=")[1].split()[0]
        assert kube.calls_for("scale") == []

        # retry while still pending: still no mutation
        second = await client.call_tool("scale_deployment", SCALE_ARGS)
        assert "status=pending" in second.content[0].text
        assert kube.calls_for("scale") == []

        # the human approves out-of-band (CLI path uses the same store call)
        assert store.approve(approval_id) is not None

        third = await client.call_tool("scale_deployment", SCALE_ARGS)
        assert not third.isError
        assert "scaled Deployment prod/payments-api" in third.content[0].text
        assert len(kube.calls_for("scale")) == 1

        # approval was burned: the same args go back to pending, not execution
        fourth = await client.call_tool("scale_deployment", SCALE_ARGS)
        assert "status=pending" in fourth.content[0].text
        assert len(kube.calls_for("scale")) == 1


async def test_oob_bait_and_switch_rejected(tmp_path) -> None:
    """Approval for replicas=4 must not authorize replicas=1."""
    settings = make_settings(tmp_path)
    kube = FakeKube()
    server = build_server(settings, kube, make_audit(settings))
    store = ApprovalStore(settings.approvals_dir, ttl_seconds=300)

    async with connect(server) as client:
        first = await client.call_tool("scale_deployment", SCALE_ARGS)
        approval_id = first.content[0].text.split("approval_id=")[1].split()[0]
        store.approve(approval_id)

        switched = dict(SCALE_ARGS, replicas=1)
        result = await client.call_tool("scale_deployment", switched)
        # args hash mismatch -> a NEW pending approval, never execution
        assert "status=pending" in result.content[0].text
        new_id = result.content[0].text.split("approval_id=")[1].split()[0]
        assert new_id != approval_id
        assert kube.calls_for("scale") == []


async def test_stale_resource_version_conflicts_safely(tmp_path) -> None:
    """If the object changes between the fresh read and the patch, the write
    aborts with a typed conflict instead of retrying blindly."""
    settings = make_settings(tmp_path)
    kube = FakeKube()
    server = build_server(settings, kube, make_audit(settings))

    real_get_scale = kube.get_scale

    async def stale_get_scale(kind, name, namespace):
        info = await real_get_scale(kind, name, namespace)
        # simulate a concurrent writer bumping the resourceVersion after our read
        kube.scale_state = type(info)(
            kind=info.kind,
            name=info.name,
            namespace=info.namespace,
            replicas=info.replicas,
            ready_replicas=info.ready_replicas,
            resource_version=str(int(info.resource_version) + 7),
        )
        return info

    kube.get_scale = stale_get_scale  # type: ignore[method-assign]
    async with connect(server, elicitation_callback=_responder("accept", True)) as client:
        result = await client.call_tool("scale_deployment", SCALE_ARGS)
    assert result.isError
    assert "conflict" in result.content[0].text


async def test_rollout_restart_approved_path(tmp_path) -> None:
    settings = make_settings(tmp_path)
    kube = FakeKube()
    server = build_server(settings, kube, make_audit(settings))
    async with connect(server, elicitation_callback=_responder("accept", True)) as client:
        result = await client.call_tool(
            "rollout_restart",
            {
                "kind": "Deployment",
                "name": "payments-api",
                "namespace": "prod",
                "reason": "DB credentials rotated; pick up fixed secret",
            },
        )
    assert not result.isError
    assert "restart requested for Deployment prod/payments-api" in result.content[0].text
    calls = kube.calls_for("rollout_restart")
    assert len(calls) == 1
    assert calls[0]["reason"] == "DB credentials rotated; pick up fixed secret"
