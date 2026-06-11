"""Server-side policy: scope, rate limiting, and the human-approval gate.

These checks are authoritative regardless of what the kubeconfig's RBAC would
allow and regardless of client behavior. The server is the enforcement point;
client-side confirmation UI is welcome defense-in-depth, nothing more.
"""

from __future__ import annotations

import hashlib
import json
import secrets
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import anyio
from mcp import types
from mcp.server.fastmcp import Context
from mcp.server.fastmcp.exceptions import ToolError
from pydantic import BaseModel

from .config import ScopeSettings, WriteToolsSettings


class ScopeGuard:
    """Namespace and cluster-scope policy. Deny wins over allow."""

    def __init__(self, scope: ScopeSettings):
        self._scope = scope

    def check_namespace(self, namespace: str) -> None:
        if namespace in self._scope.denied_namespaces:
            raise ToolError(f"namespace '{namespace}' is denied by operator policy")
        if namespace not in self._scope.allowed_namespaces:
            raise ToolError(f"namespace '{namespace}' is outside the operator-configured scope")

    def check_cluster_scoped(self) -> None:
        if not self._scope.allow_cluster_scoped:
            raise ToolError("cluster-scoped resources are disabled by operator policy")

    def namespaces(self) -> list[str]:
        return [
            ns for ns in self._scope.allowed_namespaces if ns not in self._scope.denied_namespaces
        ]


class _TokenBucket:
    def __init__(self, per_minute: int):
        self.capacity = float(per_minute)
        self.tokens = float(per_minute)
        self.rate = per_minute / 60.0
        self.updated = time.monotonic()

    def try_acquire(self) -> bool:
        now = time.monotonic()
        self.tokens = min(self.capacity, self.tokens + (now - self.updated) * self.rate)
        self.updated = now
        if self.tokens >= 1.0:
            self.tokens -= 1.0
            return True
        return False


class RateLimiter:
    """Per-tool token buckets plus a global bucket; protects the API server and
    bounds any exfiltration bandwidth to a trickle."""

    def __init__(self, rates: dict[str, int], default: int):
        self._rates = rates
        self._default = default
        self._buckets: dict[str, _TokenBucket] = {}
        self._global = _TokenBucket(max(60, default * 2))

    def acquire(self, tool: str) -> None:
        if tool not in self._buckets:
            self._buckets[tool] = _TokenBucket(self._rates.get(tool, self._default))
        if not self._global.try_acquire() or not self._buckets[tool].try_acquire():
            raise ToolError(f"rate limit exceeded for '{tool}'; wait a moment and narrow the query")


def _args_hash(tool: str, args: dict[str, Any]) -> str:
    canonical = json.dumps({"tool": tool, "args": args}, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode()).hexdigest()


@dataclass
class Decision:
    approved: bool
    via: str
    pending_id: str | None = None
    detail: str = ""


class ApprovalStore:
    """File-based pending approvals for the out-of-band fallback flow.

    The approval record binds a hash of the exact tool arguments to the ID, so
    approval granted for one set of arguments can never authorize another
    (bait-and-switch prevention). Approved records are burned on first use.
    """

    def __init__(self, directory: Path, ttl_seconds: float):
        self._dir = directory
        self._ttl = ttl_seconds

    def _path(self, approval_id: str) -> Path:
        return self._dir / f"{approval_id}.json"

    def _load(self, path: Path) -> dict[str, Any] | None:
        try:
            record: dict[str, Any] = json.loads(path.read_text())
        except (OSError, ValueError):
            return None
        if not isinstance(record, dict):
            return None
        if record.get("expires_at", 0) < time.time():
            path.unlink(missing_ok=True)
            return None
        return record

    def create(self, tool: str, args: dict[str, Any], action: str) -> str:
        self._dir.mkdir(parents=True, exist_ok=True)
        approval_id = secrets.token_hex(4)
        record = {
            "id": approval_id,
            "tool": tool,
            "args_hash": _args_hash(tool, args),
            "action": action,
            "created_at": time.time(),
            "expires_at": time.time() + self._ttl,
            "approved": False,
        }
        self._path(approval_id).write_text(json.dumps(record, indent=2))
        return approval_id

    def approve(self, approval_id: str) -> dict[str, Any] | None:
        """Mark a pending record approved (called by the CLI, never by the model)."""
        path = self._path(approval_id)
        record = self._load(path)
        if record is None:
            return None
        record["approved"] = True
        path.write_text(json.dumps(record, indent=2))
        return record

    def list_pending(self) -> list[dict[str, Any]]:
        if not self._dir.is_dir():
            return []
        records = [self._load(p) for p in sorted(self._dir.glob("*.json"))]
        return [r for r in records if r is not None]

    def consume(self, tool: str, args: dict[str, Any]) -> tuple[str, str | None]:
        """Look up the approval state for this exact (tool, args) pair.

        Returns one of ("approved", id) — record found and burned;
        ("pending", id) — a matching unapproved record exists;
        ("none", None) — no matching record.
        """
        wanted = _args_hash(tool, args)
        for record in self.list_pending():
            if record.get("tool") == tool and record.get("args_hash") == wanted:
                if record.get("approved"):
                    self._path(record["id"]).unlink(missing_ok=True)  # burn on use
                    return "approved", record["id"]
                return "pending", record["id"]
        return "none", None


class ApprovalSchema(BaseModel):
    confirm: bool


class ApprovalGate:
    """Human approval for write tools.

    A model-supplied parameter is never accepted as consent: approval arrives
    either via MCP elicitation (rendered by the client, answered by the human)
    or via the out-of-band CLI (`janus-mcp approve <id>`). There is no code
    path that mutates the cluster without one of those two signals.
    """

    def __init__(
        self,
        write_settings: WriteToolsSettings,
        read_only: bool,
        store: ApprovalStore,
    ):
        self._settings = write_settings
        self._read_only = read_only
        self._store = store

    def check_enabled(self, tool: str) -> None:
        if self._read_only:
            raise ToolError("server is in read-only mode; write operations are disabled")
        if tool not in self._settings.enabled:
            raise ToolError(f"write tool '{tool}' is not enabled in the server configuration")

    def check_replica_bounds(self, replicas: int) -> None:
        if replicas == 0 and not self._settings.allow_scale_to_zero:
            raise ToolError("scaling to zero is disabled by operator policy")
        if replicas < 0 or replicas > self._settings.max_replicas:
            raise ToolError(
                f"replicas must be between 0 and the operator-configured maximum "
                f"({self._settings.max_replicas})"
            )

    def _client_supports_elicitation(self, ctx: Context) -> bool:  # type: ignore[type-arg]
        try:
            return bool(
                ctx.session.check_client_capability(
                    types.ClientCapabilities(elicitation=types.ElicitationCapability())
                )
            )
        except Exception:
            return False

    async def request_approval(
        self,
        ctx: Context,  # type: ignore[type-arg]
        tool: str,
        args: dict[str, Any],
        action: str,
        live_state: str,
    ) -> Decision:
        message = (
            f"⚠ Cluster write requested\n{action}\nLive state: {live_state}\nApprove this change?"
        )
        if self._client_supports_elicitation(ctx):
            result: Any = None
            with anyio.move_on_after(self._settings.approval_timeout_seconds):
                result = await ctx.elicit(message=message, schema=ApprovalSchema)
            if result is None:
                return Decision(approved=False, via="elicitation", detail="approval timed out")
            approved = result.action == "accept" and bool(
                getattr(result, "data", None) and result.data.confirm
            )
            detail = "approved by operator" if approved else f"operator response: {result.action}"
            return Decision(approved=approved, via="elicitation", detail=detail)

        # Out-of-band fallback: the client cannot render an approval prompt, so
        # the request is parked and the human approves via `janus-mcp approve <id>`.
        state, approval_id = self._store.consume(tool, args)
        if state == "approved":
            return Decision(approved=True, via="oob-cli", pending_id=approval_id)
        if state == "pending":
            return Decision(
                approved=False,
                via="oob-pending",
                pending_id=approval_id,
                detail="awaiting operator approval",
            )
        approval_id = self._store.create(tool, args, action)
        return Decision(
            approved=False,
            via="oob-created",
            pending_id=approval_id,
            detail="awaiting operator approval",
        )
