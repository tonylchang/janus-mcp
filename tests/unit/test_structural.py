"""Layer 1 structural rules, per kind."""

from __future__ import annotations

import json

import support
from janus_mcp.config import RedactionSettings
from janus_mcp.redaction import RedactionStats, sanitize_object

RS = RedactionSettings()


def sanitize(kind: str, fixture: str, rs: RedactionSettings = RS) -> dict:
    return sanitize_object(kind, support.load_fixture(fixture), rs, RedactionStats())


def test_last_applied_annotation_always_dropped() -> None:
    out = sanitize("Pod", "pod.json")
    blob = json.dumps(out)
    assert "last-applied" not in blob
    assert support.CANARY_LAST_APPLIED not in blob


def test_managed_fields_and_uids_dropped() -> None:
    out = sanitize("Pod", "pod.json")
    blob = json.dumps(out)
    assert "managedFields" not in blob
    assert "uid" not in json.dumps(out["metadata"].get("ownerReferences", []))
    assert "uid" not in out["metadata"]


def test_env_values_masked_names_kept() -> None:
    out = sanitize("Pod", "pod.json")
    env = out["spec"]["containers"][0]["env"]
    by_name = {e["name"]: e for e in env}
    assert by_name["DB_PASSWORD"]["value"] == "[REDACTED:env-value]"
    assert by_name["API_TOKEN"]["value"] == "[REDACTED:env-value]"
    assert support.CANARY_PASSWORD not in json.dumps(out)
    assert support.CANARY_ENV_VALUE not in json.dumps(out)
    # names are diagnostic gold and must survive
    assert set(by_name) == {"DB_USER", "DB_PASSWORD", "API_TOKEN", "DB_URL", "POD_NAME"}


def test_value_from_rendered_as_reference() -> None:
    out = sanitize("Pod", "pod.json")
    env = {e["name"]: e for e in out["spec"]["containers"][0]["env"]}
    assert env["DB_URL"]["valueFrom"] == "secretKeyRef(db-credentials/url)"
    assert env["POD_NAME"]["valueFrom"] == "fieldRef(metadata.name)"


def test_env_from_rendered_as_references() -> None:
    out = sanitize("Pod", "pod.json")
    assert out["spec"]["containers"][0]["envFrom"] == [
        "secretRef(payments-env)",
        "configMapRef(payments-config)",
    ]


def test_secret_and_projected_volumes_reduced_to_names() -> None:
    out = sanitize("Pod", "pod.json")
    volumes = {v["name"]: v for v in out["spec"]["volumes"]}
    assert volumes["db-creds"]["secret"] == {"secretName": "db-credentials"}
    assert volumes["sa-token"]["projected"] == {
        "sources": ["serviceAccountToken(serviceAccountToken)", "configMap(ca-bundle)"]
    }


def test_node_name_and_host_ip_masked() -> None:
    out = sanitize("Pod", "pod.json")
    assert out["spec"]["nodeName"] == "[MASKED:node]"
    assert out["status"]["hostIP"] == "[MASKED:node]"
    assert "ip-10-0-1-23" not in json.dumps(out)


def test_node_name_kept_when_masking_disabled() -> None:
    rs = RedactionSettings(mask_node_names=False)
    out = sanitize("Pod", "pod.json", rs)
    assert out["spec"]["nodeName"] == "ip-10-0-1-23.ec2.internal"


def test_sensitive_pod_annotations_dropped_benign_kept() -> None:
    out = sanitize("Pod", "pod.json")
    annotations = out["metadata"]["annotations"]
    assert "vault.hashicorp.com/agent-inject-token" not in annotations
    assert annotations["prometheus.io/scrape"] == "true"


def test_workload_template_sanitized() -> None:
    out = sanitize("Deployment", "deployment.json")
    blob = json.dumps(out)
    assert support.CANARY_PASSWORD not in blob
    assert support.CANARY_LAST_APPLIED not in blob
    assert "iam.amazonaws.com/role" not in blob
    env = {e["name"]: e for e in out["spec"]["template"]["spec"]["containers"][0]["env"]}
    assert env["DB_PASSWORD"]["value"] == "[REDACTED:env-value]"
    # the restartedAt annotation is operational, not sensitive
    template_annotations = out["spec"]["template"]["metadata"]["annotations"]
    assert "kubectl.kubernetes.io/restartedAt" in template_annotations
    assert "vault.hashicorp.com/agent-inject-secret-db" not in template_annotations


def test_configmap_values_masked_keys_and_sizes_shown() -> None:
    out = sanitize("ConfigMap", "configmap.json")
    blob = json.dumps(out)
    assert support.CANARY_CM_VALUE not in blob
    assert "CanaryCmPw99" not in blob
    assert set(out["data"]) == {"database.url", "log_level", "feature_flags"}
    assert out["data"]["database.url"].startswith("[MASKED:")
    assert "bytes" in out["data"]["log_level"]
    assert out["binaryData"]["keystore.p12"].startswith("[MASKED:")


def test_configmap_key_allowlist() -> None:
    rs = RedactionSettings(configmap_values="allowlist", configmap_key_allowlist=["log_level"])
    out = sanitize("ConfigMap", "configmap.json", rs)
    assert out["data"]["log_level"] == "info"
    assert support.CANARY_CM_VALUE not in json.dumps(out)


def test_service_credential_annotations_dropped() -> None:
    out = sanitize("Service", "service.json")
    annotations = out["metadata"]["annotations"]
    assert "my-vendor.io/api-key" not in annotations
    assert annotations["prometheus.io/port"] == "9100"
    assert out["spec"]["externalIPs"] == ["[REDACTED:ip]"]
    assert out["status"]["loadBalancer"]["ingress"][0]["ip"] == "[REDACTED:ip]"


def test_node_masking() -> None:
    out = sanitize("Node", "node.json")
    blob = json.dumps(out)
    assert out["spec"]["providerID"] == "[MASKED:provider-id]"
    assert "i-0abc123def456789a" not in blob
    addresses = {a["type"]: a["address"] for a in out["status"]["addresses"]}
    assert addresses["ExternalIP"] == "[REDACTED:ip]"
    assert addresses["Hostname"] == "[MASKED:node]"
    assert addresses["InternalIP"] == "10.0.1.23"
    assert out["metadata"]["labels"]["eks.amazonaws.com/nodegroup"] == "[MASKED]"
    assert out["metadata"]["labels"]["kubernetes.io/os"] == "linux"
    node_info = out["status"]["nodeInfo"]
    assert "machineID" not in node_info
    assert "systemUUID" not in node_info
    assert node_info["kubeletVersion"].startswith("v1.31")


def test_unknown_kind_conservative_summary() -> None:
    obj = {
        "kind": "Mystery",
        "metadata": {"name": "x", "namespace": "prod", "annotations": {"a": "b"}},
        "spec": {"dangerous": "stuff"},
        "status": {"conditions": [{"type": "Ready"}]},
    }
    out = sanitize_object("Mystery", obj, RS, RedactionStats())
    assert "spec" not in out
    assert out["metadata"] == {"name": "x", "namespace": "prod"}


def test_input_not_mutated() -> None:
    original = support.load_fixture("pod.json")
    snapshot = json.dumps(original, sort_keys=True)
    sanitize_object("Pod", original, RS, RedactionStats())
    assert json.dumps(original, sort_keys=True) == snapshot
