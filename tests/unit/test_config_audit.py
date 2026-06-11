"""Config loading (strictness, context pinning) and the audit log."""

from __future__ import annotations

import json

import pytest
import yaml
from pydantic import ValidationError

from janus_mcp.audit import AuditLog
from janus_mcp.config import Settings, load_settings
from support import make_settings


def test_example_config_parses() -> None:
    from pathlib import Path

    example = Path(__file__).parents[2] / "examples" / "config.yaml"
    settings = Settings.model_validate(yaml.safe_load(example.read_text()))
    assert settings.context
    assert settings.scope.allowed_namespaces


def test_unknown_field_rejected(tmp_path) -> None:
    config = {
        "context": "x",
        "scope": {"allowed_namespaces": ["prod"]},
        "read_onyl": True,  # typo in a security-relevant key must fail loudly
    }
    path = tmp_path / "config.yaml"
    path.write_text(yaml.safe_dump(config))
    with pytest.raises(ValidationError):
        load_settings(path)


def test_context_required(tmp_path) -> None:
    path = tmp_path / "config.yaml"
    path.write_text(yaml.safe_dump({"scope": {"allowed_namespaces": ["prod"]}}))
    with pytest.raises(ValidationError):
        load_settings(path)


def test_writes_enabled_logic(tmp_path) -> None:
    assert make_settings(tmp_path).writes_enabled()
    assert not make_settings(tmp_path, read_only=True).writes_enabled()
    assert not make_settings(
        tmp_path, write_tools={"enabled": [], "approval_timeout_seconds": 1}
    ).writes_enabled()


def test_audit_records_are_json_lines(tmp_path) -> None:
    audit = AuditLog(tmp_path / "audit.jsonl")
    audit.log_call("get_pods", namespace="prod", items=4, redactions=2)
    audit.log_denied("scale_deployment", via="elicitation", name="x")
    lines = (tmp_path / "audit.jsonl").read_text().strip().split("\n")
    assert len(lines) == 2
    first, second = (json.loads(line) for line in lines)
    assert first["event"] == "tool_call"
    assert first["tool"] == "get_pods"
    assert first["redactions"] == 2
    assert "ts" in first
    assert second["event"] == "write_denied"


def test_audit_rotation(tmp_path) -> None:
    path = tmp_path / "audit.jsonl"
    audit = AuditLog(path, max_bytes=512, backups=2)
    for i in range(50):
        audit.log_call("get_pods", namespace="prod", i=i)
    assert path.exists()
    assert path.with_suffix(".jsonl.1").exists()
    # backup count is bounded
    assert not path.with_suffix(".jsonl.3").exists()
