"""Layer 1 — structural, schema-aware redaction.

Operates on parsed Kubernetes objects (camelCase dicts, as produced by the
client's ``sanitize_for_serialization``) *before* any rendering. Deterministic
field rules per kind, with a conservative summary-only default for kinds
without explicit rules.

The kind blocklist (Secret et al.) lives at the fetch layer in ``kube.py`` —
objects of those kinds are never requested, so they can never reach this code.
"""

from __future__ import annotations

import copy
import fnmatch
from typing import Any

from ..config import RedactionSettings
from .patterns import RedactionStats

ENV_VALUE_TOKEN = "[REDACTED:env-value]"  # noqa: S105 (replacement token, not a credential)
MASKED_NODE = "[MASKED:node]"
MASKED_IP = "[REDACTED:ip]"

# Dropped unconditionally: embeds the entire previously-applied object,
# including env values and ConfigMap data.
_ALWAYS_DROP_ANNOTATIONS = frozenset(
    {
        "kubectl.kubernetes.io/last-applied-configuration",
        "kapp.k14s.io/original",
        "banzaicloud.com/last-applied",
    }
)

_SENSITIVE_ANNOTATION_GLOBS = (
    "*credential*",
    "*secret*",
    "*token*",
    "*auth*",
    "*password*",
    "*apikey*",
    "*api-key*",
    "iam.amazonaws.com/*",
    "eks.amazonaws.com/role-arn",
    "iam.gke.io/*",
    "azure.workload.identity/*",
    "vault.hashicorp.com/*",
)

_NODE_CLOUD_LABEL_GLOBS = (
    "*.amazonaws.com/*",
    "*.eks.amazonaws.com/*",
    "*.eksctl.io/*",
    "cloud.google.com/*",
    "*.gke.io/*",
    "*.azure.com/*",
    "kubernetes.azure.com/*",
)

_POD_TEMPLATE_KINDS = {
    "Deployment",
    "ReplicaSet",
    "StatefulSet",
    "DaemonSet",
    "Job",
}


def _filter_annotations(
    annotations: dict[str, Any] | None, settings: RedactionSettings, stats: RedactionStats
) -> dict[str, Any]:
    if not annotations:
        return {}
    out: dict[str, Any] = {}
    for key, value in annotations.items():
        if key in _ALWAYS_DROP_ANNOTATIONS:
            stats.add("annotation", 1)
            continue
        if key in settings.annotation_allowlist:
            out[key] = value
            continue
        if any(fnmatch.fnmatch(key.lower(), glob) for glob in _SENSITIVE_ANNOTATION_GLOBS):
            stats.add("annotation", 1)
            continue
        out[key] = value
    return out


def _clean_metadata(
    obj: dict[str, Any], settings: RedactionSettings, stats: RedactionStats
) -> None:
    meta = obj.get("metadata")
    if not isinstance(meta, dict):
        return
    for key in ("managedFields", "uid", "resourceVersion", "selfLink", "generateName"):
        meta.pop(key, None)
    annotations = _filter_annotations(meta.get("annotations"), settings, stats)
    if annotations:
        meta["annotations"] = annotations
    else:
        meta.pop("annotations", None)
    owners = meta.get("ownerReferences")
    if isinstance(owners, list):
        meta["ownerReferences"] = [
            {k: o.get(k) for k in ("kind", "name") if k in o} for o in owners
        ]


def _render_value_from(value_from: dict[str, Any]) -> str:
    if "secretKeyRef" in value_from:
        ref = value_from["secretKeyRef"]
        return f"secretKeyRef({ref.get('name')}/{ref.get('key')})"
    if "configMapKeyRef" in value_from:
        ref = value_from["configMapKeyRef"]
        return f"configMapKeyRef({ref.get('name')}/{ref.get('key')})"
    if "fieldRef" in value_from:
        return f"fieldRef({value_from['fieldRef'].get('fieldPath')})"
    if "resourceFieldRef" in value_from:
        return f"resourceFieldRef({value_from['resourceFieldRef'].get('resource')})"
    return "valueFrom(?)"


def _sanitize_container(
    container: dict[str, Any], settings: RedactionSettings, stats: RedactionStats
) -> None:
    env = container.get("env")
    if isinstance(env, list):
        for entry in env:
            if "value" in entry:
                entry["value"] = ENV_VALUE_TOKEN
                stats.add("env-value", 1)
            if "valueFrom" in entry:
                entry["valueFrom"] = _render_value_from(entry["valueFrom"])
    env_from = container.get("envFrom")
    if isinstance(env_from, list):
        rendered = []
        for entry in env_from:
            if "secretRef" in entry:
                rendered.append(f"secretRef({entry['secretRef'].get('name')})")
            elif "configMapRef" in entry:
                rendered.append(f"configMapRef({entry['configMapRef'].get('name')})")
        container["envFrom"] = rendered


def _sanitize_volumes(
    spec: dict[str, Any], settings: RedactionSettings, stats: RedactionStats
) -> None:
    volumes = spec.get("volumes")
    if not isinstance(volumes, list):
        return
    for vol in volumes:
        if "secret" in vol and isinstance(vol["secret"], dict):
            vol["secret"] = {"secretName": vol["secret"].get("secretName")}
        if "projected" in vol and isinstance(vol["projected"], dict):
            sources = vol["projected"].get("sources") or []
            names: list[str] = []
            for src in sources:
                for src_kind in ("secret", "configMap", "serviceAccountToken"):
                    if src_kind in src:
                        name = (src[src_kind] or {}).get("name", src_kind)
                        names.append(f"{src_kind}({name})")
            vol["projected"] = {"sources": names}


def _sanitize_pod_spec(
    spec: dict[str, Any], settings: RedactionSettings, stats: RedactionStats
) -> None:
    for section in ("containers", "initContainers", "ephemeralContainers"):
        containers = spec.get(section)
        if isinstance(containers, list):
            for container in containers:
                _sanitize_container(container, settings, stats)
    _sanitize_volumes(spec, settings, stats)
    pull_secrets = spec.get("imagePullSecrets")
    if isinstance(pull_secrets, list):
        spec["imagePullSecrets"] = [s.get("name") for s in pull_secrets]
    if settings.mask_node_names and "nodeName" in spec:
        spec["nodeName"] = MASKED_NODE


def _sanitize_pod_status(
    status: dict[str, Any], settings: RedactionSettings, stats: RedactionStats
) -> None:
    if settings.mask_node_names:
        for key in ("hostIP", "nominatedNodeName"):
            if key in status:
                status[key] = MASKED_NODE
        if "hostIPs" in status:
            status["hostIPs"] = MASKED_NODE
    for cs_section in ("containerStatuses", "initContainerStatuses"):
        statuses = status.get(cs_section)
        if isinstance(statuses, list):
            for cs in statuses:
                cs.pop("containerID", None)


def _sanitize_pod(
    obj: dict[str, Any], settings: RedactionSettings, stats: RedactionStats
) -> dict[str, Any]:
    if isinstance(obj.get("spec"), dict):
        _sanitize_pod_spec(obj["spec"], settings, stats)
    if isinstance(obj.get("status"), dict):
        _sanitize_pod_status(obj["status"], settings, stats)
    return obj


def _sanitize_workload(
    obj: dict[str, Any], settings: RedactionSettings, stats: RedactionStats
) -> dict[str, Any]:
    template = (obj.get("spec") or {}).get("template")
    if isinstance(template, dict):
        meta = template.get("metadata")
        if isinstance(meta, dict) and "annotations" in meta:
            filtered = _filter_annotations(meta.get("annotations"), settings, stats)
            if filtered:
                meta["annotations"] = filtered
            else:
                meta.pop("annotations", None)
        if isinstance(template.get("spec"), dict):
            _sanitize_pod_spec(template["spec"], settings, stats)
    return obj


def _sanitize_cronjob(
    obj: dict[str, Any], settings: RedactionSettings, stats: RedactionStats
) -> dict[str, Any]:
    job_template = (obj.get("spec") or {}).get("jobTemplate")
    if isinstance(job_template, dict):
        _sanitize_workload(job_template, settings, stats)
    return obj


def _sanitize_configmap(
    obj: dict[str, Any], settings: RedactionSettings, stats: RedactionStats
) -> dict[str, Any]:
    for section in ("data", "binaryData"):
        data = obj.get(section)
        if not isinstance(data, dict):
            continue
        masked: dict[str, Any] = {}
        for key, value in data.items():
            size = len(value) if isinstance(value, str | bytes) else 0
            if settings.configmap_values == "allowlist" and key in settings.configmap_key_allowlist:
                masked[key] = value
            else:
                masked[key] = f"[MASKED:{size} bytes]"
                stats.add("configmap-value", 1)
        obj[section] = masked
    return obj


def _sanitize_service(
    obj: dict[str, Any], settings: RedactionSettings, stats: RedactionStats
) -> dict[str, Any]:
    spec = obj.get("spec")
    if isinstance(spec, dict) and settings.mask_external_ips:
        if spec.get("externalIPs"):
            spec["externalIPs"] = [MASKED_IP for _ in spec["externalIPs"]]
            stats.add("ip", len(spec["externalIPs"]))
    status = obj.get("status")
    if isinstance(status, dict) and settings.mask_external_ips:
        ingress = (status.get("loadBalancer") or {}).get("ingress")
        if isinstance(ingress, list):
            for entry in ingress:
                if "ip" in entry:
                    entry["ip"] = MASKED_IP
                    stats.add("ip", 1)
    return obj


def _sanitize_node(
    obj: dict[str, Any], settings: RedactionSettings, stats: RedactionStats
) -> dict[str, Any]:
    spec = obj.get("spec")
    if isinstance(spec, dict) and "providerID" in spec:
        spec["providerID"] = "[MASKED:provider-id]"
        stats.add("node-field", 1)
    meta = obj.get("metadata")
    if isinstance(meta, dict) and isinstance(meta.get("labels"), dict):
        labels = {}
        for key, value in meta["labels"].items():
            if any(fnmatch.fnmatch(key, glob) for glob in _NODE_CLOUD_LABEL_GLOBS):
                labels[key] = "[MASKED]"
                stats.add("node-field", 1)
            else:
                labels[key] = value
        meta["labels"] = labels
    status = obj.get("status")
    if isinstance(status, dict):
        addresses = status.get("addresses")
        if isinstance(addresses, list):
            for addr in addresses:
                addr_type = addr.get("type", "")
                if addr_type in ("ExternalIP", "ExternalDNS") and settings.mask_external_ips:
                    addr["address"] = MASKED_IP
                    stats.add("ip", 1)
                elif settings.mask_node_names and addr_type in ("Hostname", "InternalDNS"):
                    addr["address"] = MASKED_NODE
        node_info = status.get("nodeInfo")
        if isinstance(node_info, dict):
            for key in ("machineID", "systemUUID", "bootID"):
                node_info.pop(key, None)
    return obj


def _sanitize_default(
    obj: dict[str, Any], settings: RedactionSettings, stats: RedactionStats
) -> dict[str, Any]:
    """Conservative fallback for kinds without explicit rules: summary fields only."""
    meta = obj.get("metadata") or {}
    return {
        "kind": obj.get("kind"),
        "metadata": {"name": meta.get("name"), "namespace": meta.get("namespace")},
        "status": {
            "conditions": (obj.get("status") or {}).get("conditions"),
        },
    }


def sanitize_object(
    kind: str,
    obj: dict[str, Any],
    settings: RedactionSettings,
    stats: RedactionStats,
) -> dict[str, Any]:
    """Apply per-kind structural rules. Returns a new dict; the input is not mutated."""
    obj = copy.deepcopy(obj)
    _clean_metadata(obj, settings, stats)

    if kind == "Pod":
        return _sanitize_pod(obj, settings, stats)
    if kind in _POD_TEMPLATE_KINDS:
        return _sanitize_workload(obj, settings, stats)
    if kind == "CronJob":
        return _sanitize_cronjob(obj, settings, stats)
    if kind == "ConfigMap":
        return _sanitize_configmap(obj, settings, stats)
    if kind in ("Service", "Ingress"):
        return _sanitize_service(obj, settings, stats)
    if kind == "Node":
        return _sanitize_node(obj, settings, stats)
    if kind in ("PersistentVolumeClaim", "HorizontalPodAutoscaler", "Namespace"):
        return obj
    return _sanitize_default(obj, settings, stats)
