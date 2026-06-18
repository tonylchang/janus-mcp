"""Command-line entry point.

``janus-mcp serve``           — run the MCP server on stdio (default command)
``janus-mcp approve <id>``    — approve a pending write (out-of-band channel)
``janus-mcp approvals``       — list pending write approvals

The approve/approvals commands are the out-of-band human-approval channel for
MCP clients that do not support elicitation. They run in a separate process
and communicate with the server through the approvals directory; the model has
no tool that can reach them.
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import sys
from pathlib import Path
from typing import Any

import structlog
import yaml

from .audit import AuditLog
from .config import Settings, load_settings
from .policy import APPROVAL_STORE_TTL_FACTOR, ApprovalStore, ScopeGuard

log = structlog.get_logger("janus_mcp.cli")


def _configure_logging() -> None:
    # stderr only: stdout belongs to the MCP stdio transport.
    structlog.configure(
        logger_factory=structlog.PrintLoggerFactory(file=sys.stderr),
    )


def _store(settings: Settings) -> ApprovalStore:
    return ApprovalStore(
        settings.approvals_dir,
        ttl_seconds=settings.write_tools.approval_timeout_seconds * APPROVAL_STORE_TTL_FACTOR,
    )


def serve(settings: Settings, strict: bool) -> int:
    from .kube import KubeClient
    from .server import build_server

    kube = KubeClient(settings)  # loads the kubeconfig HERE, pinned context

    in_scope = ScopeGuard(settings.scope).namespaces()
    enabled_write_tools = [] if settings.read_only else settings.write_tools.enabled
    missing, overprivileged = kube.self_check(in_scope, enabled_write_tools)
    for warning in overprivileged:
        log.warning("overprivileged_credentials", detail=warning)
    if missing:
        for item in missing:
            log.error("missing_permission", detail=item)
        print(
            "janus-mcp: the configured credentials are missing permissions: " + "; ".join(missing),
            file=sys.stderr,
        )
        return 1
    if overprivileged and strict:
        print(
            "janus-mcp: --strict refused start: credentials are over-privileged "
            "(can access Secrets). Use the least-privilege manifests in rbac/.",
            file=sys.stderr,
        )
        return 1

    audit = AuditLog(settings.audit_log)
    audit.write(
        "server_start",
        context=settings.context,
        read_only=settings.read_only,
        write_tools=settings.write_tools.enabled,
        namespaces=settings.scope.allowed_namespaces,
    )
    server = build_server(settings, kube, audit)
    server.run(transport="stdio")
    return 0


def approve(settings: Settings, approval_id: str) -> int:
    record = _store(settings).approve(approval_id)
    if record is None:
        print(f"no pending approval with id '{approval_id}' (expired or unknown)")
        return 1
    print(f"approved: {record['action']}")
    print("The assistant must now re-issue the tool call with the same arguments.")
    return 0


def list_approvals(settings: Settings) -> int:
    records = _store(settings).list_pending()
    if not records:
        print("no pending approvals")
        return 0
    for record in records:
        state = "APPROVED (awaiting pickup)" if record.get("approved") else "PENDING"
        print(f"{record['id']}  {state}  {record['action']}")
        print(f"  live state: {record.get('live_state', 'unavailable')}")
    return 0


def _exec_auth_status(settings: Settings) -> dict[str, Any]:
    configured = settings.kubeconfig
    if configured is None:
        configured = Path(os.environ.get("KUBECONFIG", "~/.kube/config").split(os.pathsep)[0])
    path = configured.expanduser()
    try:
        raw = yaml.safe_load(path.read_text())
        contexts = {item["name"]: item["context"] for item in raw.get("contexts", [])}
        users = {item["name"]: item["user"] for item in raw.get("users", [])}
        user_name = contexts[settings.context]["user"]
        command = str((users[user_name].get("exec") or {}).get("command", ""))
    except (OSError, KeyError, TypeError, ValueError):
        return {"configured": False}
    if not command:
        return {"configured": False}
    available = (
        Path(command).is_file()
        if Path(command).is_absolute()
        else shutil.which(command) is not None
    )
    return {
        "configured": True,
        "command": Path(command).name,
        "available": available,
    }


def _state_path_status(path: Path, *, directory: bool) -> dict[str, Any]:
    target = path if directory else path.parent
    probe = target
    while not probe.exists() and probe != probe.parent:
        probe = probe.parent
    exists = target.exists()
    mode = (target.stat().st_mode & 0o777) if exists else None
    return {
        "path": str(path),
        "exists": exists,
        "writable": os.access(probe, os.W_OK),
        "private": mode is None or mode & 0o077 == 0,
        "mode": f"{mode:03o}" if mode is not None else None,
    }


def doctor(
    settings: Settings,
    strict: bool,
    json_output: bool,
    kube: Any | None = None,
) -> int:
    """Run safe local configuration, RBAC, and filesystem diagnostics."""
    if kube is None:
        from .kube import KubeClient

        kube = KubeClient(settings)
    in_scope = ScopeGuard(settings.scope).namespaces()
    enabled_write_tools = [] if settings.read_only else settings.write_tools.enabled
    missing, overprivileged = kube.self_check(in_scope, enabled_write_tools)
    exec_auth = _exec_auth_status(settings)
    state_paths = {
        "audit": _state_path_status(settings.audit_log, directory=False),
        "approvals": _state_path_status(settings.approvals_dir, directory=True),
    }
    unsafe_paths = [name for name, status in state_paths.items() if not status["private"]]
    unavailable_plugin = exec_auth.get("configured") and not exec_auth.get("available")
    report = {
        "ok": not missing
        and not unavailable_plugin
        and not (strict and (overprivileged or unsafe_paths)),
        "context": settings.context,
        "namespaces": in_scope,
        "read_only": settings.read_only,
        "write_tools": enabled_write_tools,
        "missing_permissions": missing,
        "overprivilege_warnings": overprivileged,
        "exec_auth": exec_auth,
        "state_paths": state_paths,
    }
    if json_output:
        print(json.dumps(report, indent=2, sort_keys=True))
    else:
        print(f"context: {settings.context}")
        print(f"namespaces: {', '.join(in_scope)}")
        print(f"mode: {'read-only' if settings.read_only else 'bounded writes'}")
        print(f"RBAC: {'ok' if not missing else 'missing permissions'}")
        for item in missing:
            print(f"  missing: {item}")
        for warning in overprivileged:
            print(f"  warning: {warning}")
        if exec_auth.get("configured"):
            state = "available" if exec_auth.get("available") else "NOT FOUND"
            print(f"exec auth plugin: {exec_auth['command']} ({state})")
        for name, status in state_paths.items():
            privacy = "private" if status["private"] else f"mode {status['mode']}"
            writable = "writable" if status["writable"] else "NOT WRITABLE"
            print(f"{name} state: {privacy}, {writable}")
        print(f"doctor: {'ok' if report['ok'] else 'problems found'}")
    return 0 if report["ok"] else 1


def main(argv: list[str] | None = None) -> int:
    _configure_logging()
    parser = argparse.ArgumentParser(prog="janus-mcp")
    parser.add_argument("--config", type=Path, default=None, help="path to config.yaml")
    sub = parser.add_subparsers(dest="command")

    serve_parser = sub.add_parser("serve", help="run the MCP server on stdio (default)")
    serve_parser.add_argument("--config", type=Path, default=None)
    serve_parser.add_argument("--kubeconfig", type=Path, default=None)
    serve_parser.add_argument(
        "--strict",
        action="store_true",
        help="refuse to start if credentials are over-privileged (can access Secrets)",
    )

    approve_parser = sub.add_parser("approve", help="approve a pending write operation")
    approve_parser.add_argument("approval_id")
    approve_parser.add_argument("--config", type=Path, default=None)

    approvals_parser = sub.add_parser("approvals", help="list pending write approvals")
    approvals_parser.add_argument("--config", type=Path, default=None)

    doctor_parser = sub.add_parser("doctor", help="validate context, RBAC, auth, and state paths")
    doctor_parser.add_argument("--config", type=Path, default=None)
    doctor_parser.add_argument("--strict", action="store_true")
    doctor_parser.add_argument("--json", action="store_true", dest="json_output")

    args = parser.parse_args(argv)

    try:
        settings = load_settings(args.config)
    except FileNotFoundError:
        print(
            "janus-mcp: no config file found. Create ~/.config/janus-mcp/config.yaml "
            "(see examples/config.yaml) or pass --config.",
            file=sys.stderr,
        )
        return 1

    if args.command == "approve":
        return approve(settings, args.approval_id)
    if args.command == "approvals":
        return list_approvals(settings)
    if args.command == "doctor":
        return doctor(settings, strict=args.strict, json_output=args.json_output)

    if getattr(args, "kubeconfig", None):
        settings = settings.model_copy(update={"kubeconfig": args.kubeconfig.expanduser()})
    return serve(settings, strict=getattr(args, "strict", False))


if __name__ == "__main__":
    sys.exit(main())
