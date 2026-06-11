"""Configuration loading and validation.

The config file is the operator's authoritative policy: scope, write gating,
limits, and redaction tuning. Unknown fields are rejected so a typo in a
security-relevant key (e.g. ``read_onyl``) fails loudly instead of silently
falling back to a default.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field

DEFAULT_CONFIG_PATH = Path("~/.config/janus-mcp/config.yaml")


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class ScopeSettings(StrictModel):
    allowed_namespaces: list[str] = Field(min_length=1)
    denied_namespaces: list[str] = Field(default_factory=lambda: ["kube-system", "kube-node-lease"])
    allow_cluster_scoped: bool = False


class RatePerMinute(StrictModel):
    default: int = Field(default=30, ge=1)
    get_logs: int = Field(default=5, ge=1)
    write: int = Field(default=3, ge=1)


class LimitsSettings(StrictModel):
    log_tail_max: int = Field(default=500, ge=1, le=5000)
    result_max_bytes: int = Field(default=65536, ge=1024)
    rate_per_minute: RatePerMinute = Field(default_factory=RatePerMinute)
    api_timeout_seconds: float = Field(default=10.0, gt=0)
    tool_budget_seconds: float = Field(default=30.0, gt=0)


class WriteToolsSettings(StrictModel):
    enabled: list[str] = Field(default_factory=list)
    max_replicas: int = Field(default=20, ge=1)
    allow_scale_to_zero: bool = False
    approval_timeout_seconds: float = Field(default=120.0, gt=0)


class RedactionSettings(StrictModel):
    mask_node_names: bool = True
    mask_external_ips: bool = True
    entropy_threshold: float = Field(default=4.5, gt=0)
    configmap_values: Literal["mask", "allowlist"] = "mask"
    configmap_key_allowlist: list[str] = Field(default_factory=list)
    annotation_allowlist: list[str] = Field(default_factory=list)
    namespace_label_allowlist: list[str] = Field(default_factory=list)


class Settings(StrictModel):
    # The server refuses to start on any kubeconfig context other than this one.
    context: str = Field(min_length=1)
    kubeconfig: Path | None = None
    scope: ScopeSettings
    read_only: bool = False
    write_tools: WriteToolsSettings = Field(default_factory=WriteToolsSettings)
    limits: LimitsSettings = Field(default_factory=LimitsSettings)
    redaction: RedactionSettings = Field(default_factory=RedactionSettings)
    audit_log: Path = Path("~/.local/state/janus-mcp/audit.jsonl")
    approvals_dir: Path = Path("~/.local/state/janus-mcp/approvals")

    def writes_enabled(self) -> bool:
        return bool(self.write_tools.enabled) and not self.read_only


def load_settings(path: Path | str | None = None) -> Settings:
    """Load settings from YAML. Path resolution: explicit arg > $JANUS_MCP_CONFIG > default."""
    if path is None:
        path = os.environ.get("JANUS_MCP_CONFIG", str(DEFAULT_CONFIG_PATH))
    resolved = Path(path).expanduser()
    raw = yaml.safe_load(resolved.read_text())
    if not isinstance(raw, dict):
        raise ValueError(f"config file {resolved} must contain a YAML mapping")
    settings = Settings.model_validate(raw)
    settings = settings.model_copy(
        update={
            "kubeconfig": settings.kubeconfig.expanduser() if settings.kubeconfig else None,
            "audit_log": settings.audit_log.expanduser(),
            "approvals_dir": settings.approvals_dir.expanduser(),
        }
    )
    return settings
