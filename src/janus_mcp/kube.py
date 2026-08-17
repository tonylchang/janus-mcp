"""Kubernetes access layer — the only module that imports the kubernetes client.

The kubeconfig is loaded here, in-process, pinned to the configured context.
Credential material lives in this process's memory and nowhere else.

Two rules keep this module honest:

* ``Secret`` and other credential-bearing kinds are absent from the kind
  registry, so they are never fetched — there is nothing to redact.
* Exceptions are mapped to typed, generic messages. Raw client exceptions
  (urllib3 errors in particular) embed the API server URL and must never
  reach the model; full details go to the server's own stderr log only.
"""

from __future__ import annotations

import functools
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, Protocol

import anyio.to_thread
import structlog

from .config import Settings

log = structlog.get_logger("janus_mcp.kube")

# Kinds the server refuses to fetch under any circumstances. describe_resource
# checks this list explicitly so the model gets a clear policy error, but the
# real guarantee is structural: these kinds have no registry entry.
BLOCKED_KINDS = frozenset(
    {"Secret", "ServiceAccount", "CertificateSigningRequest", "TokenReview", "SecretList"}
)

# kind -> namespaced? Readable kinds for describe_resource. Note what is absent.
KIND_REGISTRY: dict[str, bool] = {
    "Pod": True,
    "Deployment": True,
    "ReplicaSet": True,
    "StatefulSet": True,
    "DaemonSet": True,
    "Job": True,
    "CronJob": True,
    "Service": True,
    "Ingress": True,
    "ConfigMap": True,
    "PersistentVolumeClaim": True,
    "HorizontalPodAutoscaler": True,
    "Endpoints": True,
    "ResourceQuota": True,
    "LimitRange": True,
    "PodDisruptionBudget": True,
    "Node": False,
}

# Namespaced kinds list_resources may enumerate. Pod is deliberately absent —
# get_pods is the richer, purpose-built lister.
LISTABLE_KINDS = frozenset(k for k, namespaced in KIND_REGISTRY.items() if namespaced) - {"Pod"}

RESTART_ANNOTATION = "kubectl.kubernetes.io/restartedAt"
REASON_ANNOTATION = "janus-mcp.io/restart-reason"


class KubeError(Exception):
    """Carries a message that is safe to surface to the model."""

    def __init__(self, safe_message: str):
        super().__init__(safe_message)
        self.safe_message = safe_message


@dataclass
class ScaleInfo:
    kind: str
    name: str
    namespace: str
    replicas: int
    # The Scale subresource's status.replicas is the observed TOTAL replica
    # count — it says nothing about readiness (V1ScaleStatus has no
    # readyReplicas). Never present this as "ready" to a human approver.
    status_replicas: int
    resource_version: str

    def summary(self) -> str:
        return (
            f"{self.kind} {self.namespace}/{self.name}: "
            f"{self.replicas} desired, {self.status_replicas} observed"
        )


class KubeApi(Protocol):
    """The surface server.py programs against; tests substitute a fake."""

    async def list_namespaces(self) -> list[dict[str, Any]]: ...
    async def get_namespace(self, name: str) -> dict[str, Any]: ...
    async def list_pods(
        self,
        namespace: str,
        label_selector: str | None,
        field_selector: str | None,
        limit: int,
    ) -> list[dict[str, Any]]: ...
    async def list_events(
        self, namespace: str, field_selector: str | None, limit: int
    ) -> list[dict[str, Any]]: ...
    async def get_object(self, kind: str, name: str, namespace: str | None) -> dict[str, Any]: ...
    async def read_pod_log(
        self,
        pod: str,
        namespace: str,
        container: str | None,
        tail_lines: int,
        since_seconds: int | None,
        previous: bool,
    ) -> str: ...
    async def list_deployments(self, namespace: str) -> list[dict[str, Any]]: ...
    async def list_nodes(self) -> list[dict[str, Any]]: ...
    async def list_objects(
        self, kind: str, namespace: str, label_selector: str | None, limit: int
    ) -> list[dict[str, Any]]: ...
    async def list_replica_sets(
        self, namespace: str, label_selector: str | None
    ) -> list[dict[str, Any]]: ...
    async def list_pod_metrics(self, namespace: str) -> list[dict[str, Any]]: ...
    async def list_node_metrics(self) -> list[dict[str, Any]]: ...
    async def server_version(self) -> str: ...
    async def get_scale(self, kind: str, name: str, namespace: str) -> ScaleInfo: ...
    async def scale(
        self, kind: str, name: str, namespace: str, replicas: int, expected_resource_version: str
    ) -> ScaleInfo: ...
    async def rollout_restart(
        self, kind: str, name: str, namespace: str, reason: str
    ) -> dict[str, Any]: ...
    async def delete_pod(self, name: str, namespace: str, expected_uid: str) -> None: ...
    async def patch_deployment_template(
        self,
        name: str,
        namespace: str,
        template: dict[str, Any],
        expected_resource_version: str,
        reason: str,
    ) -> dict[str, Any]: ...
    async def set_cronjob_suspend(
        self, name: str, namespace: str, suspend: bool, expected_resource_version: str
    ) -> dict[str, Any]: ...
    async def create_job_from_cronjob(
        self, cronjob_name: str, namespace: str, job_name: str, reason: str
    ) -> dict[str, Any]: ...
    async def set_node_unschedulable(
        self, name: str, desired: bool, expected_resource_version: str
    ) -> dict[str, Any]: ...


def _map_api_error(exc: Exception, what: str) -> KubeError:
    from kubernetes.client.exceptions import ApiException

    if isinstance(exc, ApiException):
        if exc.status == 404:
            return KubeError(f"not found: {what}")
        if exc.status == 403:
            return KubeError(f"RBAC denied: the server's credentials cannot access {what}")
        if exc.status == 409:
            return KubeError(f"conflict: {what} changed since it was read; re-read and retry")
        return KubeError(f"Kubernetes API error (HTTP {exc.status}) accessing {what}")
    # Connection-level errors embed the API server URL in their message — never
    # forward them. Log locally, return a generic message.
    log.warning("kubernetes_request_failed", what=what, error_type=type(exc).__name__)
    return KubeError(f"Kubernetes API request failed ({type(exc).__name__}) accessing {what}")


class KubeClient:
    """Real client. Loads the kubeconfig once, pinned to the configured context."""

    def __init__(self, settings: Settings):
        from kubernetes import client, config

        kubeconfig = str(settings.kubeconfig) if settings.kubeconfig else None
        try:
            config.load_kube_config(config_file=kubeconfig, context=settings.context)
        except config.config_exception.ConfigException as exc:
            raise SystemExit(
                f"janus-mcp: cannot load kubeconfig context '{settings.context}': {exc}\n"
                "The server refuses to start on any context other than the pinned one."
            ) from exc

        self._timeout = settings.limits.api_timeout_seconds
        self._api_client = client.ApiClient()
        self._core = client.CoreV1Api(self._api_client)
        self._apps = client.AppsV1Api(self._api_client)
        self._batch = client.BatchV1Api(self._api_client)
        self._networking = client.NetworkingV1Api(self._api_client)
        self._autoscaling = client.AutoscalingV2Api(self._api_client)
        self._policy = client.PolicyV1Api(self._api_client)
        self._custom = client.CustomObjectsApi(self._api_client)
        self._authz = client.AuthorizationV1Api(self._api_client)
        self._version = client.VersionApi(self._api_client)

        self._readers: dict[str, Callable[..., Any]] = {
            "Pod": self._core.read_namespaced_pod,
            "Deployment": self._apps.read_namespaced_deployment,
            "ReplicaSet": self._apps.read_namespaced_replica_set,
            "StatefulSet": self._apps.read_namespaced_stateful_set,
            "DaemonSet": self._apps.read_namespaced_daemon_set,
            "Job": self._batch.read_namespaced_job,
            "CronJob": self._batch.read_namespaced_cron_job,
            "Service": self._core.read_namespaced_service,
            "Ingress": self._networking.read_namespaced_ingress,
            "ConfigMap": self._core.read_namespaced_config_map,
            "PersistentVolumeClaim": self._core.read_namespaced_persistent_volume_claim,
            "HorizontalPodAutoscaler": (
                self._autoscaling.read_namespaced_horizontal_pod_autoscaler
            ),
            "Endpoints": self._core.read_namespaced_endpoints,
            "ResourceQuota": self._core.read_namespaced_resource_quota,
            "LimitRange": self._core.read_namespaced_limit_range,
            "PodDisruptionBudget": self._policy.read_namespaced_pod_disruption_budget,
            "Node": self._core.read_node,
        }
        self._listers: dict[str, Callable[..., Any]] = {
            "Deployment": self._apps.list_namespaced_deployment,
            "ReplicaSet": self._apps.list_namespaced_replica_set,
            "StatefulSet": self._apps.list_namespaced_stateful_set,
            "DaemonSet": self._apps.list_namespaced_daemon_set,
            "Job": self._batch.list_namespaced_job,
            "CronJob": self._batch.list_namespaced_cron_job,
            "Service": self._core.list_namespaced_service,
            "Ingress": self._networking.list_namespaced_ingress,
            "ConfigMap": self._core.list_namespaced_config_map,
            "PersistentVolumeClaim": self._core.list_namespaced_persistent_volume_claim,
            "HorizontalPodAutoscaler": (
                self._autoscaling.list_namespaced_horizontal_pod_autoscaler
            ),
            "Endpoints": self._core.list_namespaced_endpoints,
            "ResourceQuota": self._core.list_namespaced_resource_quota,
            "LimitRange": self._core.list_namespaced_limit_range,
            "PodDisruptionBudget": self._policy.list_namespaced_pod_disruption_budget,
        }

    def _to_dict(self, obj: Any) -> dict[str, Any]:
        data = self._api_client.sanitize_for_serialization(obj)
        return data if isinstance(data, dict) else {"value": data}

    async def _call(self, what: str, fn: Callable[..., Any], /, *args: Any, **kwargs: Any) -> Any:
        kwargs.setdefault("_request_timeout", self._timeout)
        try:
            return await anyio.to_thread.run_sync(functools.partial(fn, *args, **kwargs))
        except Exception as exc:
            raise _map_api_error(exc, what) from None

    async def list_namespaces(self) -> list[dict[str, Any]]:
        result = await self._call("namespaces", self._core.list_namespace)
        return [self._to_dict(item) for item in result.items]

    async def get_namespace(self, name: str) -> dict[str, Any]:
        result = await self._call(f"namespace {name}", self._core.read_namespace, name)
        return self._to_dict(result)

    async def list_pods(
        self,
        namespace: str,
        label_selector: str | None,
        field_selector: str | None,
        limit: int,
    ) -> list[dict[str, Any]]:
        kwargs: dict[str, Any] = {"limit": limit}
        if label_selector:
            kwargs["label_selector"] = label_selector
        if field_selector:
            kwargs["field_selector"] = field_selector
        result = await self._call(
            f"pods in {namespace}", self._core.list_namespaced_pod, namespace, **kwargs
        )
        return [self._to_dict(item) for item in result.items]

    async def list_events(
        self, namespace: str, field_selector: str | None, limit: int
    ) -> list[dict[str, Any]]:
        kwargs: dict[str, Any] = {"limit": limit}
        if field_selector:
            kwargs["field_selector"] = field_selector
        result = await self._call(
            f"events in {namespace}", self._core.list_namespaced_event, namespace, **kwargs
        )
        return [self._to_dict(item) for item in result.items]

    async def get_object(self, kind: str, name: str, namespace: str | None) -> dict[str, Any]:
        reader = self._readers.get(kind)
        if reader is None:
            raise KubeError(f"kind '{kind}' is not retrievable")
        what = f"{kind} {namespace + '/' if namespace else ''}{name}"
        if KIND_REGISTRY.get(kind, True):
            result = await self._call(what, reader, name, namespace)
        else:
            result = await self._call(what, reader, name)
        data = self._to_dict(result)
        data.setdefault("kind", kind)
        return data

    async def read_pod_log(
        self,
        pod: str,
        namespace: str,
        container: str | None,
        tail_lines: int,
        since_seconds: int | None,
        previous: bool,
    ) -> str:
        kwargs: dict[str, Any] = {
            "tail_lines": tail_lines,
            "previous": previous,
            "timestamps": True,
        }
        if container:
            kwargs["container"] = container
        if since_seconds:
            kwargs["since_seconds"] = since_seconds
        result = await self._call(
            f"logs of pod {namespace}/{pod}",
            self._core.read_namespaced_pod_log,
            pod,
            namespace,
            **kwargs,
        )
        return str(result)

    async def list_deployments(self, namespace: str) -> list[dict[str, Any]]:
        result = await self._call(
            f"deployments in {namespace}", self._apps.list_namespaced_deployment, namespace
        )
        return [self._to_dict(item) for item in result.items]

    async def list_nodes(self) -> list[dict[str, Any]]:
        result = await self._call("nodes", self._core.list_node)
        return [self._to_dict(item) for item in result.items]

    async def list_objects(
        self, kind: str, namespace: str, label_selector: str | None, limit: int
    ) -> list[dict[str, Any]]:
        lister = self._listers.get(kind)
        if lister is None:
            raise KubeError(f"kind '{kind}' is not listable")
        kwargs: dict[str, Any] = {"limit": limit}
        if label_selector:
            kwargs["label_selector"] = label_selector
        result = await self._call(f"{kind} list in {namespace}", lister, namespace, **kwargs)
        items = []
        for item in result.items:
            data = self._to_dict(item)
            data.setdefault("kind", kind)
            items.append(data)
        return items

    async def list_replica_sets(
        self, namespace: str, label_selector: str | None
    ) -> list[dict[str, Any]]:
        return await self.list_objects("ReplicaSet", namespace, label_selector, 50)

    async def list_pod_metrics(self, namespace: str) -> list[dict[str, Any]]:
        try:
            result = await self._call(
                f"pod metrics in {namespace}",
                self._custom.list_namespaced_custom_object,
                "metrics.k8s.io",
                "v1beta1",
                namespace,
                "pods",
            )
        except KubeError as exc:
            if "not found" in exc.safe_message:
                raise KubeError(
                    "metrics API unavailable (is metrics-server installed in the cluster?)"
                ) from None
            raise
        items = result.get("items", []) if isinstance(result, dict) else []
        return [dict(item) for item in items]

    async def list_node_metrics(self) -> list[dict[str, Any]]:
        try:
            result = await self._call(
                "node metrics",
                self._custom.list_cluster_custom_object,
                "metrics.k8s.io",
                "v1beta1",
                "nodes",
            )
        except KubeError as exc:
            if "not found" in exc.safe_message:
                raise KubeError(
                    "metrics API unavailable (is metrics-server installed in the cluster?)"
                ) from None
            raise
        items = result.get("items", []) if isinstance(result, dict) else []
        return [dict(item) for item in items]

    async def server_version(self) -> str:
        info = await self._call("server version", self._version.get_code)
        major = "".join(c for c in str(info.major) if c.isdigit()) or "?"
        minor = "".join(c for c in str(info.minor) if c.isdigit()) or "?"
        return f"{major}.{minor}"

    def _scale_apis(self, kind: str) -> tuple[Callable[..., Any], Callable[..., Any]]:
        if kind == "Deployment":
            return (
                self._apps.read_namespaced_deployment_scale,
                self._apps.patch_namespaced_deployment_scale,
            )
        if kind == "StatefulSet":
            return (
                self._apps.read_namespaced_stateful_set_scale,
                self._apps.patch_namespaced_stateful_set_scale,
            )
        raise KubeError(f"kind '{kind}' is not scalable")

    async def get_scale(self, kind: str, name: str, namespace: str) -> ScaleInfo:
        read_scale, _ = self._scale_apis(kind)
        what = f"{kind} {namespace}/{name}"
        scale = await self._call(what, read_scale, name, namespace)
        return ScaleInfo(
            kind=kind,
            name=name,
            namespace=namespace,
            replicas=scale.spec.replicas or 0,
            status_replicas=scale.status.replicas or 0,
            resource_version=scale.metadata.resource_version,
        )

    async def scale(
        self, kind: str, name: str, namespace: str, replicas: int, expected_resource_version: str
    ) -> ScaleInfo:
        _, patch_scale = self._scale_apis(kind)
        what = f"{kind} {namespace}/{name}"
        # Carrying the observed resourceVersion makes the patch abort with 409
        # if the object changed since the approval card was rendered.
        body = {
            "metadata": {"resourceVersion": expected_resource_version},
            "spec": {"replicas": replicas},
        }
        scale = await self._call(what, patch_scale, name, namespace, body)
        return ScaleInfo(
            kind=kind,
            name=name,
            namespace=namespace,
            replicas=scale.spec.replicas or 0,
            status_replicas=scale.status.replicas or 0,
            resource_version=scale.metadata.resource_version,
        )

    async def rollout_restart(
        self, kind: str, name: str, namespace: str, reason: str
    ) -> dict[str, Any]:
        patchers: dict[str, Callable[..., Any]] = {
            "Deployment": self._apps.patch_namespaced_deployment,
            "StatefulSet": self._apps.patch_namespaced_stateful_set,
            "DaemonSet": self._apps.patch_namespaced_daemon_set,
        }
        patcher = patchers.get(kind)
        if patcher is None:
            raise KubeError(f"kind '{kind}' does not support rollout restart")
        now = datetime.now(UTC).isoformat()
        body = {
            "spec": {
                "template": {
                    "metadata": {
                        "annotations": {RESTART_ANNOTATION: now, REASON_ANNOTATION: reason}
                    }
                }
            }
        }
        what = f"{kind} {namespace}/{name}"
        result = await self._call(what, patcher, name, namespace, body)
        return dict(self._to_dict(result))

    async def delete_pod(self, name: str, namespace: str, expected_uid: str) -> None:
        from kubernetes import client

        # The UID precondition binds the delete to the exact pod instance the
        # approval referred to: a same-name replacement pod aborts with 409.
        body = client.V1DeleteOptions(preconditions=client.V1Preconditions(uid=expected_uid))
        await self._call(
            f"pod {namespace}/{name}",
            self._core.delete_namespaced_pod,
            name,
            namespace,
            body=body,
        )

    async def patch_deployment_template(
        self,
        name: str,
        namespace: str,
        template: dict[str, Any],
        expected_resource_version: str,
        reason: str,
    ) -> dict[str, Any]:
        annotations = dict(((template.get("metadata") or {}).get("annotations")) or {})
        annotations[REASON_ANNOTATION] = reason
        template = dict(template)
        template["metadata"] = dict(template.get("metadata") or {})
        template["metadata"]["annotations"] = annotations
        body = {
            "metadata": {"resourceVersion": expected_resource_version},
            "spec": {"template": template},
        }
        what = f"Deployment {namespace}/{name}"
        result = await self._call(
            what, self._apps.patch_namespaced_deployment, name, namespace, body
        )
        return dict(self._to_dict(result))

    async def set_cronjob_suspend(
        self, name: str, namespace: str, suspend: bool, expected_resource_version: str
    ) -> dict[str, Any]:
        body = {
            "metadata": {"resourceVersion": expected_resource_version},
            "spec": {"suspend": suspend},
        }
        what = f"CronJob {namespace}/{name}"
        result = await self._call(
            what, self._batch.patch_namespaced_cron_job, name, namespace, body
        )
        return dict(self._to_dict(result))

    async def create_job_from_cronjob(
        self, cronjob_name: str, namespace: str, job_name: str, reason: str
    ) -> dict[str, Any]:
        cronjob = await self.get_object("CronJob", cronjob_name, namespace)
        job_template = (cronjob.get("spec") or {}).get("jobTemplate") or {}
        template_meta = job_template.get("metadata") or {}
        job = {
            "apiVersion": "batch/v1",
            "kind": "Job",
            "metadata": {
                "name": job_name,
                "namespace": namespace,
                "labels": dict(template_meta.get("labels") or {}),
                "annotations": {
                    **dict(template_meta.get("annotations") or {}),
                    "janus-mcp.io/triggered-from": f"cronjob/{cronjob_name}",
                    REASON_ANNOTATION: reason,
                },
            },
            "spec": job_template.get("spec") or {},
        }
        what = f"Job {namespace}/{job_name}"
        result = await self._call(what, self._batch.create_namespaced_job, namespace, job)
        return dict(self._to_dict(result))

    async def set_node_unschedulable(
        self, name: str, desired: bool, expected_resource_version: str
    ) -> dict[str, Any]:
        body = {
            "metadata": {"resourceVersion": expected_resource_version},
            "spec": {"unschedulable": desired},
        }
        result = await self._call(f"Node {name}", self._core.patch_node, name, body)
        return dict(self._to_dict(result))

    # ---- startup self-check -------------------------------------------------

    def _ssar(self, **attrs: Any) -> bool:
        from kubernetes import client

        review = client.V1SelfSubjectAccessReview(
            spec=client.V1SelfSubjectAccessReviewSpec(
                resource_attributes=client.V1ResourceAttributes(**attrs)
            )
        )
        try:
            result = self._authz.create_self_subject_access_review(
                review, _request_timeout=self._timeout
            )
            return bool(result.status and result.status.allowed)
        except Exception as exc:
            log.warning("ssar_failed", error_type=type(exc).__name__)
            return False

    def self_check(
        self, namespaces: list[str], writes_enabled: bool
    ) -> tuple[list[str], list[str]]:
        """Returns (missing capabilities, over-privilege warnings)."""
        missing: list[str] = []
        overprivileged: list[str] = []
        read_probes = [("pods", "list"), ("events", "list"), ("pods/log", "get")]
        for ns in namespaces:
            for resource, verb in read_probes:
                if not self._ssar(namespace=ns, resource=resource, verb=verb):
                    missing.append(f"{verb} {resource} in {ns}")
            if writes_enabled and not self._ssar(
                namespace=ns, group="apps", resource="deployments", verb="patch"
            ):
                missing.append(f"patch deployments in {ns}")
            if self._ssar(namespace=ns, resource="secrets", verb="get"):
                overprivileged.append(
                    f"credentials can read Secrets in {ns} — janus-mcp never will, but a "
                    "least-privilege ServiceAccount is strongly recommended (see rbac/)"
                )
        if self._ssar(resource="secrets", verb="list"):
            overprivileged.append(
                "credentials can list Secrets cluster-wide — use the shipped rbac/ manifests"
            )
        return missing, overprivileged
