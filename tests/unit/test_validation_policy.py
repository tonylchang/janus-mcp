"""Input validation, ScopeGuard, RateLimiter, ApprovalGate policy checks,
and the file-based ApprovalStore."""

from __future__ import annotations

import pytest
from mcp.server.fastmcp.exceptions import ToolError

from janus_mcp.policy import ApprovalGate, ApprovalStore, RateLimiter, ScopeGuard
from janus_mcp.validation import (
    validate_bounds,
    validate_field_selector,
    validate_name,
    validate_reason,
    validate_selector,
)
from support import make_settings

# ---- validation --------------------------------------------------------------


@pytest.mark.parametrize(
    "bad",
    ["../etc", "UPPER", "a" * 300, "", "a_b", "a b", "x/../y", "$(rm)", ".a", "a.", "a..b", "A.b"],
)
def test_bad_names_rejected(bad: str) -> None:
    with pytest.raises(ToolError):
        validate_name(bad)


@pytest.mark.parametrize(
    "good",
    [
        "prod",
        "payments-api-7f9c6d4b-xkq2p",
        "a",
        "x1",
        # dotted Node names are routine on managed clusters (EKS/GKE)
        "ip-10-1-2-3.us-west-2.compute.internal",
        "gke-cluster-default-pool-1a2b3c4d-x9yz.c.project.internal",
    ],
)
def test_good_names_accepted(good: str) -> None:
    assert validate_name(good) == good


def test_field_selector_allowlist_enforced() -> None:
    allowed = {"metadata.name", "status.phase"}
    assert validate_field_selector(None, allowed) is None
    assert (
        validate_field_selector("status.phase=Running,metadata.name!=x", allowed)
        == "status.phase=Running,metadata.name!=x"
    )
    # a selector on a masked field is a membership oracle — refused
    with pytest.raises(ToolError, match="not filterable"):
        validate_field_selector("spec.nodeName=ip-10-0-1-23.ec2.internal", allowed)
    with pytest.raises(ToolError, match="term"):
        validate_field_selector("status.phase", allowed)  # bare field, no operator
    with pytest.raises(ToolError):
        validate_field_selector("x" * 600, allowed)


def test_selector_charset_enforced() -> None:
    assert validate_selector("app=payments,env in (prod, staging)") is not None
    with pytest.raises(ToolError):
        validate_selector("a==b,$(rm -rf /)")
    with pytest.raises(ToolError):
        validate_selector("x" * 600)


def test_reason_validation() -> None:
    assert validate_reason("  DB creds rotated  ") == "DB creds rotated"
    with pytest.raises(ToolError):
        validate_reason("")
    with pytest.raises(ToolError):
        validate_reason("x" * 201)
    with pytest.raises(ToolError):
        validate_reason("line\nbreak")


def test_bounds() -> None:
    assert validate_bounds(5, 1, 10, "n") == 5
    with pytest.raises(ToolError):
        validate_bounds(11, 1, 10, "n")
    with pytest.raises(ToolError):
        validate_bounds(True, 0, 10, "n")  # bools are not acceptable integers


# ---- scope -------------------------------------------------------------------


def test_scope_deny_wins(tmp_path) -> None:
    settings = make_settings(
        tmp_path,
        scope={
            "allowed_namespaces": ["prod", "kube-system"],
            "denied_namespaces": ["kube-system"],
        },
    )
    guard = ScopeGuard(settings.scope)
    guard.check_namespace("prod")
    with pytest.raises(ToolError, match="denied"):
        guard.check_namespace("kube-system")
    assert guard.namespaces() == ["prod"]


def test_scope_outside_allowlist(tmp_path) -> None:
    guard = ScopeGuard(make_settings(tmp_path).scope)
    with pytest.raises(ToolError, match="outside"):
        guard.check_namespace("internal-tools")


def test_cluster_scoped_disabled_by_default(tmp_path) -> None:
    guard = ScopeGuard(make_settings(tmp_path).scope)
    with pytest.raises(ToolError):
        guard.check_cluster_scoped()


# ---- rate limiting -----------------------------------------------------------


def test_rate_limiter_exhausts_and_reports() -> None:
    limiter = RateLimiter({"get_logs": 2}, default=100)
    limiter.acquire("get_logs")
    limiter.acquire("get_logs")
    with pytest.raises(ToolError, match="rate limit"):
        limiter.acquire("get_logs")
    # other tools have their own buckets
    limiter.acquire("get_pods")


def test_per_tool_denial_does_not_drain_global_bucket() -> None:
    """A client retry-looping one throttled tool must not starve every other
    tool by draining the shared global bucket with denied attempts."""
    limiter = RateLimiter({"get_logs": 1}, default=30)  # global bucket: 60
    limiter.acquire("get_logs")
    for _ in range(100):
        with pytest.raises(ToolError):
            limiter.acquire("get_logs")
    limiter.acquire("get_pods")  # still works: denials consumed no global tokens


# ---- approval gate policy checks --------------------------------------------


def _gate(tmp_path, **overrides):
    settings = make_settings(tmp_path, **overrides)
    store = ApprovalStore(settings.approvals_dir, ttl_seconds=300)
    return ApprovalGate(settings.write_tools, settings.read_only, store), store


def test_read_only_blocks_writes(tmp_path) -> None:
    gate, _ = _gate(tmp_path, read_only=True)
    with pytest.raises(ToolError, match="read-only"):
        gate.check_enabled("scale_deployment")


def test_disabled_tool_blocked(tmp_path) -> None:
    gate, _ = _gate(
        tmp_path, write_tools={"enabled": ["rollout_restart"], "approval_timeout_seconds": 1}
    )
    gate.check_enabled("rollout_restart")
    with pytest.raises(ToolError, match="not enabled"):
        gate.check_enabled("scale_deployment")


def test_replica_bounds_policy(tmp_path) -> None:
    gate, _ = _gate(tmp_path)
    gate.check_replica_bounds(5)
    with pytest.raises(ToolError, match="zero"):
        gate.check_replica_bounds(0)
    with pytest.raises(ToolError, match="maximum"):
        gate.check_replica_bounds(999999)


def test_scale_to_zero_opt_in(tmp_path) -> None:
    gate, _ = _gate(
        tmp_path,
        write_tools={
            "enabled": ["scale_deployment"],
            "allow_scale_to_zero": True,
            "approval_timeout_seconds": 1,
        },
    )
    gate.check_replica_bounds(0)


# ---- approval store ----------------------------------------------------------


def test_store_binds_args_hash(tmp_path) -> None:
    _, store = _gate(tmp_path)
    args_a = {"name": "x", "replicas": 4}
    approval_id = store.create(
        "scale_deployment", args_a, "Scale x to 4", {"resource_version": "7"}
    )
    store.approve(approval_id)
    # bait-and-switch: approval for A must not authorize B
    status, _, _ = store.consume("scale_deployment", {"name": "x", "replicas": 0})
    assert status == "none"
    status, matched, state = store.consume("scale_deployment", args_a)
    assert status == "approved"
    assert matched == approval_id
    # the live-state snapshot bound at creation time comes back with the approval
    assert state == {"resource_version": "7"}
    # burned on use
    status, _, _ = store.consume("scale_deployment", args_a)
    assert status == "none"


def test_store_pending_then_approved(tmp_path) -> None:
    _, store = _gate(tmp_path)
    args = {"name": "y"}
    approval_id = store.create("rollout_restart", args, "restart y")
    status, matched, _ = store.consume("rollout_restart", args)
    assert status == "pending"
    assert matched == approval_id
    assert store.approve(approval_id) is not None
    status, _, _ = store.consume("rollout_restart", args)
    assert status == "approved"


def test_store_expiry(tmp_path) -> None:
    settings = make_settings(tmp_path)
    store = ApprovalStore(settings.approvals_dir, ttl_seconds=-1)  # already expired
    approval_id = store.create("rollout_restart", {"n": 1}, "restart")
    assert store.approve(approval_id) is None
    assert store.list_pending() == []


def test_approve_unknown_id(tmp_path) -> None:
    _, store = _gate(tmp_path)
    assert store.approve("doesnotexist") is None


def test_consume_burn_is_atomic_under_races(tmp_path) -> None:
    """Two consumers observing the same approved record must not BOTH be
    authorized: unlink() succeeds exactly once, the loser gets 'none'."""
    _, store = _gate(tmp_path)
    args = {"name": "x", "replicas": 4}
    approval_id = store.create("scale_deployment", args, "Scale x to 4")
    store.approve(approval_id)

    # Freeze a stale record listing, simulating a second consumer that read
    # the directory before the first one burned the file.
    stale_records = store.list_pending()
    store.list_pending = lambda: [dict(r) for r in stale_records]  # type: ignore[method-assign]

    first, _, _ = store.consume("scale_deployment", args)
    second, _, _ = store.consume("scale_deployment", args)
    assert first == "approved"
    assert second == "none"  # lost the race -> no authorization
