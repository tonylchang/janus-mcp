"""Shared test support: canary secrets, fixtures, FakeKube, settings factory.

Canaries are planted throughout the fixtures. The contract of the entire test
suite is simple: no canary value may ever appear in anything the model sees.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from janus_mcp.audit import AuditLog
from janus_mcp.config import Settings
from janus_mcp.kube import KubeError, ScaleInfo

FIXTURES = Path(__file__).parent / "fixtures"

# Values that must never cross the MCP boundary, in any frame, ever.
CANARY_AWS_KEY = "AKIAIOSFODNN7CANARY1"
CANARY_JWT = "eyJhbGciOiJIUzI1NiJ9.eyJjYW5hcnkiOnRydWV9.czNjcjN0LXNpZ25hdHVyZQ"
CANARY_PASSWORD = "Tr0ub4dor&3-canary"
CANARY_DB_PASSWORD = "S3cr3tPw!"
CANARY_ENV_VALUE = "super-secret-env-canary-value"
CANARY_CM_VALUE = "postgres://app:CanaryCmPw99@db.prod.svc:5432/app"
CANARY_LAST_APPLIED = "last-applied-canary-XYZZY"
CANARY_GCP_KEY = "AIzaCanaryCanaryCanaryCanaryCanary123"
CANARY_GITHUB = "ghp_canaryCanaryCanary1234567890"
CANARY_HIGH_ENTROPY = "9fX2kQ7vR1mZ8pL3wN5tY0uB6cD4eF7g"

# Fake kubeconfig material held by FakeKube; invariant #1 says these can never
# be serialized into an MCP frame.
FAKE_API_SERVER = "https://10.93.77.2:6443"
FAKE_BEARER_TOKEN = "kubeconfig-token-canary-9f8e7d6c5b4a"
FAKE_CA_DATA = "LS0tLS1CRUdJTkNBTkFSWUNBREFUQS0tLS0t"

ALL_CANARIES = [
    CANARY_AWS_KEY,
    CANARY_JWT,
    CANARY_PASSWORD,
    CANARY_DB_PASSWORD,
    CANARY_ENV_VALUE,
    CANARY_CM_VALUE,
    CANARY_LAST_APPLIED,
    CANARY_GCP_KEY,
    CANARY_GITHUB,
    CANARY_HIGH_ENTROPY,
    FAKE_API_SERVER,
    FAKE_BEARER_TOKEN,
    FAKE_CA_DATA,
]


def load_fixture(name: str) -> Any:
    path = FIXTURES / name
    if name.endswith(".json"):
        return json.loads(path.read_text())
    return path.read_text()


def make_settings(tmp_path: Path, **overrides: Any) -> Settings:
    base: dict[str, Any] = {
        "context": "limited-sa@test-cluster",
        "scope": {
            "allowed_namespaces": ["prod", "staging"],
            "denied_namespaces": ["kube-system", "kube-node-lease"],
            "allow_cluster_scoped": False,
        },
        "read_only": False,
        "write_tools": {
            "enabled": [
                "rollout_restart",
                "scale_deployment",
                "delete_pod",
                "rollout_undo",
                "set_cronjob_suspend",
                "trigger_cronjob",
                "cordon_node",
            ],
            "max_replicas": 20,
            "allow_scale_to_zero": False,
            "approval_timeout_seconds": 0.5,
        },
        "limits": {
            # generous so tests never trip rate limits unless they mean to
            "rate_per_minute": {"default": 10000, "get_logs": 10000, "write": 10000},
        },
        "audit_log": str(tmp_path / "audit.jsonl"),
        "approvals_dir": str(tmp_path / "approvals"),
    }
    base.update(overrides)
    return Settings.model_validate(base)


def make_audit(settings: Settings) -> AuditLog:
    return AuditLog(settings.audit_log)


class FakeKube:
    """In-memory KubeApi double. Records every call so tests can assert that
    policy errors short-circuit before any API access."""

    def __init__(self) -> None:
        self.calls: list[tuple[str, dict[str, Any]]] = []
        # Mimics credential material the real client would hold in memory.
        self.api_server_url = FAKE_API_SERVER
        self.bearer_token = FAKE_BEARER_TOKEN
        self.ca_data = FAKE_CA_DATA
        self.scale_state = ScaleInfo(
            kind="Deployment",
            name="payments-api",
            namespace="prod",
            replicas=2,
            status_replicas=2,
            resource_version="12345",
        )
        self.cronjob_suspended = False
        self.node_unschedulable = False
        self.deleted_pods: list[tuple[str, str, str]] = []

    def _record(self, method: str, **kwargs: Any) -> None:
        self.calls.append((method, kwargs))

    async def list_namespaces(self, label_selector: str | None = None) -> list[dict[str, Any]]:
        self._record("list_namespaces", label_selector=label_selector)
        namespaces = list(load_fixture("namespaces.json"))
        if label_selector:
            # naive k=v[,k=v] matching, enough to prove pass-through
            wanted = dict(term.split("=", 1) for term in label_selector.split(","))
            namespaces = [
                ns
                for ns in namespaces
                if all((ns["metadata"].get("labels") or {}).get(k) == v for k, v in wanted.items())
            ]
        return namespaces

    async def get_namespace(self, name: str) -> dict[str, Any]:
        self._record("get_namespace", name=name)
        for ns in load_fixture("namespaces.json"):
            if ns["metadata"]["name"] == name:
                return dict(ns)
        raise KubeError(f"not found: namespace {name}")

    async def list_pods(
        self,
        namespace: str,
        label_selector: str | None,
        field_selector: str | None,
        limit: int,
    ) -> list[dict[str, Any]]:
        self._record(
            "list_pods",
            namespace=namespace,
            label_selector=label_selector,
            field_selector=field_selector,
            limit=limit,
        )
        if namespace != "prod":
            return []
        return list(load_fixture("pods.json"))

    async def list_events(
        self, namespace: str, field_selector: str | None, limit: int
    ) -> list[dict[str, Any]]:
        self._record("list_events", namespace=namespace, field_selector=field_selector, limit=limit)
        if namespace != "prod":
            return []
        events = list(load_fixture("events.json"))
        if field_selector and "involvedObject.name=" in field_selector:
            wanted = next(
                part.split("=", 1)[1]
                for part in field_selector.split(",")
                if part.startswith("involvedObject.name=")
            )
            events = [e for e in events if e["involvedObject"]["name"] == wanted]
        if field_selector and "type=Warning" in field_selector:
            events = [e for e in events if e.get("type") == "Warning"]
        return events[:limit]

    async def get_object(self, kind: str, name: str, namespace: str | None) -> dict[str, Any]:
        self._record("get_object", kind=kind, name=name, namespace=namespace)
        fixture_by_kind = {
            "Pod": "pod.json",
            "Deployment": "deployment.json",
            "ConfigMap": "configmap.json",
            "Service": "service.json",
            "CronJob": "cronjob.json",
            "Node": "node.json",
        }
        if kind not in fixture_by_kind:
            raise KubeError(f"not found: {kind} {name}")
        obj = load_fixture(fixture_by_kind[kind])
        if kind == "CronJob":
            obj = dict(obj)
            obj["spec"] = dict(obj["spec"], suspend=self.cronjob_suspended)
        if kind == "Node":
            obj = dict(obj)
            obj["spec"] = dict(obj.get("spec") or {}, unschedulable=self.node_unschedulable)
        if name != obj["metadata"]["name"]:
            raise KubeError(f"not found: {kind} {namespace}/{name}")
        return dict(obj)

    async def read_pod_log(
        self,
        pod: str,
        namespace: str,
        container: str | None,
        tail_lines: int,
        since_seconds: int | None,
        previous: bool,
    ) -> str:
        self._record(
            "read_pod_log",
            pod=pod,
            namespace=namespace,
            container=container,
            tail_lines=tail_lines,
            since_seconds=since_seconds,
            previous=previous,
        )
        known = {p["metadata"]["name"] for p in load_fixture("pods.json")}
        if namespace != "prod" or pod not in known:
            raise KubeError(f"not found: logs of pod {namespace}/{pod}")
        text = str(load_fixture("pod.log"))
        return "\n".join(text.splitlines()[-tail_lines:])

    async def list_deployments(self, namespace: str) -> list[dict[str, Any]]:
        self._record("list_deployments", namespace=namespace)
        if namespace != "prod":
            return []
        return [load_fixture("deployment.json")]

    async def list_nodes(self) -> list[dict[str, Any]]:
        self._record("list_nodes")
        return [load_fixture("node.json")]

    async def list_objects(
        self, kind: str, namespace: str, label_selector: str | None, limit: int
    ) -> list[dict[str, Any]]:
        self._record(
            "list_objects",
            kind=kind,
            namespace=namespace,
            label_selector=label_selector,
            limit=limit,
        )
        if namespace != "prod":
            return []
        if kind == "ReplicaSet":
            return [dict(rs) for rs in load_fixture("replicasets.json")]
        fixture_by_kind = {
            "Deployment": "deployment.json",
            "Service": "service.json",
            "ConfigMap": "configmap.json",
            "CronJob": "cronjob.json",
        }
        if kind not in fixture_by_kind:
            return []
        return [dict(load_fixture(fixture_by_kind[kind]))]

    async def list_replica_sets(
        self, namespace: str, label_selector: str | None
    ) -> list[dict[str, Any]]:
        self._record("list_replica_sets", namespace=namespace, label_selector=label_selector)
        if namespace != "prod":
            return []
        return [dict(rs) for rs in load_fixture("replicasets.json")]

    async def list_pod_metrics(self, namespace: str) -> list[dict[str, Any]]:
        self._record("list_pod_metrics", namespace=namespace)
        if namespace != "prod":
            return []
        return [dict(m) for m in load_fixture("pod_metrics.json")]

    async def list_node_metrics(self) -> list[dict[str, Any]]:
        self._record("list_node_metrics")
        return [
            {
                "metadata": {"name": "ip-10-0-1-23.ec2.internal"},
                "usage": {"cpu": "2", "memory": "8Gi"},
            }
        ]

    async def server_version(self) -> str:
        self._record("server_version")
        return "1.31"

    async def get_scale(self, kind: str, name: str, namespace: str) -> ScaleInfo:
        self._record("get_scale", kind=kind, name=name, namespace=namespace)
        if name != self.scale_state.name or namespace != self.scale_state.namespace:
            raise KubeError(f"not found: {kind} {namespace}/{name}")
        return self.scale_state

    async def scale(
        self, kind: str, name: str, namespace: str, replicas: int, expected_resource_version: str
    ) -> ScaleInfo:
        self._record(
            "scale",
            kind=kind,
            name=name,
            namespace=namespace,
            replicas=replicas,
            expected_resource_version=expected_resource_version,
        )
        if expected_resource_version != self.scale_state.resource_version:
            raise KubeError(f"conflict: {kind} {namespace}/{name} changed; re-read and retry")
        self.scale_state = ScaleInfo(
            kind=kind,
            name=name,
            namespace=namespace,
            replicas=replicas,
            status_replicas=self.scale_state.status_replicas,
            resource_version=str(int(expected_resource_version) + 1),
        )
        return self.scale_state

    async def rollout_restart(
        self,
        kind: str,
        name: str,
        namespace: str,
        reason: str,
        expected_resource_version: str,
    ) -> dict[str, Any]:
        self._record(
            "rollout_restart",
            kind=kind,
            name=name,
            namespace=namespace,
            reason=reason,
            expected_resource_version=expected_resource_version,
        )
        result = dict(load_fixture("deployment.json"))
        if expected_resource_version != result["metadata"]["resourceVersion"]:
            raise KubeError(
                f"conflict: {kind} {namespace}/{name} changed since it was read; re-read and retry"
            )
        result["metadata"] = dict(result["metadata"])
        result["metadata"]["generation"] = 15
        return result

    async def delete_pod(self, name: str, namespace: str, expected_uid: str) -> None:
        self._record("delete_pod", name=name, namespace=namespace, expected_uid=expected_uid)
        pod = load_fixture("pod.json")
        if name != pod["metadata"]["name"] or namespace != "prod":
            raise KubeError(f"not found: pod {namespace}/{name}")
        if expected_uid != pod["metadata"]["uid"]:
            raise KubeError(
                f"conflict: pod {namespace}/{name} changed since it was read; re-read and retry"
            )
        self.deleted_pods.append((namespace, name, expected_uid))

    async def patch_deployment_template(
        self,
        name: str,
        namespace: str,
        template: dict[str, Any],
        expected_resource_version: str,
        reason: str,
    ) -> dict[str, Any]:
        self._record(
            "patch_deployment_template",
            name=name,
            namespace=namespace,
            template=template,
            expected_resource_version=expected_resource_version,
            reason=reason,
        )
        dep = dict(load_fixture("deployment.json"))
        if expected_resource_version != dep["metadata"]["resourceVersion"]:
            raise KubeError(
                f"conflict: Deployment {namespace}/{name} changed since it was read; "
                "re-read and retry"
            )
        dep["metadata"] = dict(dep["metadata"], generation=15)
        return dep

    async def set_cronjob_suspend(
        self, name: str, namespace: str, suspend: bool, expected_resource_version: str
    ) -> dict[str, Any]:
        self._record(
            "set_cronjob_suspend",
            name=name,
            namespace=namespace,
            suspend=suspend,
            expected_resource_version=expected_resource_version,
        )
        cronjob = dict(load_fixture("cronjob.json"))
        if expected_resource_version != cronjob["metadata"]["resourceVersion"]:
            raise KubeError(
                f"conflict: CronJob {namespace}/{name} changed since it was read; re-read and retry"
            )
        self.cronjob_suspended = suspend
        cronjob["spec"] = dict(cronjob["spec"], suspend=suspend)
        return cronjob

    async def create_job_from_cronjob(
        self,
        cronjob_name: str,
        namespace: str,
        job_name: str,
        reason: str,
        job_template: dict[str, Any],
    ) -> dict[str, Any]:
        self._record(
            "create_job_from_cronjob",
            cronjob_name=cronjob_name,
            namespace=namespace,
            job_name=job_name,
            reason=reason,
            job_template=job_template,
        )
        cronjob = load_fixture("cronjob.json")
        if cronjob_name != cronjob["metadata"]["name"] or namespace != "prod":
            raise KubeError(f"not found: CronJob {namespace}/{cronjob_name}")
        return {"kind": "Job", "metadata": {"name": job_name, "namespace": namespace}}

    async def set_node_unschedulable(
        self, name: str, desired: bool, expected_resource_version: str
    ) -> dict[str, Any]:
        self._record(
            "set_node_unschedulable",
            name=name,
            desired=desired,
            expected_resource_version=expected_resource_version,
        )
        node = dict(load_fixture("node.json"))
        if expected_resource_version != node["metadata"]["resourceVersion"]:
            raise KubeError(f"conflict: Node {name} changed since it was read; re-read and retry")
        self.node_unschedulable = desired
        node["spec"] = dict(node.get("spec") or {}, unschedulable=desired)
        return node

    def calls_for(self, method: str) -> list[dict[str, Any]]:
        return [kwargs for name, kwargs in self.calls if name == method]
