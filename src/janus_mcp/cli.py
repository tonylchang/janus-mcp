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
import sys
from pathlib import Path

import structlog

from .audit import AuditLog
from .config import Settings, load_settings
from .policy import ApprovalStore

log = structlog.get_logger("janus_mcp.cli")


def _configure_logging() -> None:
    # stderr only: stdout belongs to the MCP stdio transport.
    structlog.configure(
        logger_factory=structlog.PrintLoggerFactory(file=sys.stderr),
    )


def _store(settings: Settings) -> ApprovalStore:
    return ApprovalStore(
        settings.approvals_dir,
        ttl_seconds=settings.write_tools.approval_timeout_seconds * 2.5,
    )


def serve(settings: Settings, strict: bool) -> int:
    from .kube import KubeClient
    from .server import build_server

    kube = KubeClient(settings)  # loads the kubeconfig HERE, pinned context

    in_scope = [
        ns for ns in settings.scope.allowed_namespaces if ns not in settings.scope.denied_namespaces
    ]
    missing, overprivileged = kube.self_check(in_scope, settings.writes_enabled())
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
    return 0


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

    if getattr(args, "kubeconfig", None):
        settings = settings.model_copy(update={"kubeconfig": args.kubeconfig.expanduser()})
    return serve(settings, strict=getattr(args, "strict", False))


if __name__ == "__main__":
    sys.exit(main())
