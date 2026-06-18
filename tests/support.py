"""Shared test support: canary secrets, fixtures, FakeKube, settings factory.

Canaries are planted throughout the fixtures. The contract of the entire test
suite is simple: no canary value may ever appear in anything the model sees.
"""

from __future__ import annotations

import copy
import json
from pathlib import Path
from typing import Any

from janus_mcp.audit import AuditLog
from janus_mcp.config import Settings
from janus_mcp.kube import KubeError, KubePage, ScaleInfo

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
                "pause_rollout",
                "resume_rollout",
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
            ready_replicas=2,
            resource_version="12345",
            uid="deployment-payments-api",
        )
        self.deployment = load_fixture("deployment.json")

    def _record(self, method: str, **kwargs: Any) -> None:
        self.calls.append((method, kwargs))

    async def list_namespaces(self) -> KubePage:
        self._record("list_namespaces")
        return KubePage(list(load_fixture("namespaces.json")))

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
    ) -> KubePage:
        self._record(
            "list_pods",
            namespace=namespace,
            label_selector=label_selector,
            field_selector=field_selector,
            limit=limit,
        )
        if namespace != "prod":
            return KubePage([])
        pods = list(load_fixture("pods.json"))
        return KubePage(pods[:limit], partial=len(pods) > limit)

    async def list_events(self, namespace: str, field_selector: str | None, limit: int) -> KubePage:
        self._record("list_events", namespace=namespace, field_selector=field_selector, limit=limit)
        if namespace != "prod":
            return KubePage([])
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
        return KubePage(events[:limit], partial=len(events) > limit)

    async def get_object(self, kind: str, name: str, namespace: str | None) -> dict[str, Any]:
        self._record("get_object", kind=kind, name=name, namespace=namespace)
        fixture_by_kind = {
            "Pod": "pod.json",
            "ConfigMap": "configmap.json",
            "Service": "service.json",
            "Node": "node.json",
        }
        if kind == "Deployment":
            obj = copy.deepcopy(self.deployment)
        elif kind in fixture_by_kind:
            obj = load_fixture(fixture_by_kind[kind])
        else:
            raise KubeError(f"not found: {kind} {name}")
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

    async def list_deployments(self, namespace: str) -> KubePage:
        self._record("list_deployments", namespace=namespace)
        if namespace != "prod":
            return KubePage([])
        return KubePage([load_fixture("deployment.json")])

    async def list_replica_sets(self, namespace: str, limit: int) -> KubePage:
        self._record("list_replica_sets", namespace=namespace, limit=limit)
        if namespace != "prod":
            return KubePage([])
        deployment = load_fixture("deployment.json")
        replicasets = []
        for revision in (12, 13, 14):
            replicasets.append(
                {
                    "kind": "ReplicaSet",
                    "metadata": {
                        "name": f"payments-api-r{revision}",
                        "namespace": namespace,
                        "creationTimestamp": f"2026-06-{revision - 5:02d}T08:00:00Z",
                        "annotations": {"deployment.kubernetes.io/revision": str(revision)},
                        "ownerReferences": [
                            {
                                "kind": "Deployment",
                                "name": deployment["metadata"]["name"],
                                "uid": deployment["metadata"]["uid"],
                                "controller": True,
                            }
                        ],
                    },
                    "spec": {"replicas": 2},
                    "status": {"replicas": 2, "readyReplicas": 2},
                }
            )
        return KubePage(replicasets[:limit], partial=len(replicasets) > limit)

    async def list_hpas(self, namespace: str, limit: int) -> KubePage:
        self._record("list_hpas", namespace=namespace, limit=limit)
        if namespace != "prod":
            return KubePage([])
        return KubePage(
            [
                {
                    "metadata": {"name": "payments-api"},
                    "spec": {"minReplicas": 2, "maxReplicas": 10},
                    "status": {"currentReplicas": 2, "desiredReplicas": 3},
                }
            ]
        )

    async def list_pvcs(self, namespace: str, limit: int) -> KubePage:
        self._record("list_pvcs", namespace=namespace, limit=limit)
        if namespace != "prod":
            return KubePage([])
        return KubePage(
            [
                {
                    "metadata": {"name": "payments-data"},
                    "spec": {"storageClassName": "standard"},
                    "status": {"phase": "Bound", "capacity": {"storage": "10Gi"}},
                }
            ]
        )

    async def list_nodes(self) -> KubePage:
        self._record("list_nodes")
        return KubePage([load_fixture("node.json")])

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
            ready_replicas=self.scale_state.ready_replicas,
            resource_version=str(int(expected_resource_version) + 1),
            uid=self.scale_state.uid,
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
        if expected_resource_version != self.deployment["metadata"]["resourceVersion"]:
            raise KubeError(f"conflict: {kind} {namespace}/{name} changed; re-read and retry")
        result = copy.deepcopy(self.deployment)
        result["metadata"] = dict(result["metadata"])
        result["metadata"]["generation"] = 15
        result["metadata"]["resourceVersion"] = str(int(expected_resource_version) + 1)
        self.deployment = copy.deepcopy(result)
        return result

    async def set_deployment_paused(
        self,
        name: str,
        namespace: str,
        paused: bool,
        expected_resource_version: str,
    ) -> dict[str, Any]:
        self._record(
            "set_deployment_paused",
            name=name,
            namespace=namespace,
            paused=paused,
            expected_resource_version=expected_resource_version,
        )
        meta = self.deployment["metadata"]
        if name != meta["name"] or namespace != meta["namespace"]:
            raise KubeError(f"not found: Deployment {namespace}/{name}")
        if expected_resource_version != meta["resourceVersion"]:
            raise KubeError("conflict: Deployment changed since it was read; re-read and retry")
        self.deployment = copy.deepcopy(self.deployment)
        self.deployment.setdefault("spec", {})["paused"] = paused
        self.deployment["metadata"] = dict(self.deployment["metadata"])
        self.deployment["metadata"]["resourceVersion"] = str(int(expected_resource_version) + 1)
        return copy.deepcopy(self.deployment)

    def calls_for(self, method: str) -> list[dict[str, Any]]:
        return [kwargs for name, kwargs in self.calls if name == method]
