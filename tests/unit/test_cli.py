"""CLI behavior that does not require a live Kubernetes cluster."""

from __future__ import annotations

import json

import yaml

from janus_mcp import cli
from janus_mcp.policy import ApprovalStore
from support import make_settings


def test_cli_approvals_and_approve_commands(tmp_path, capsys) -> None:
    settings = make_settings(tmp_path)
    store = ApprovalStore(settings.approvals_dir, ttl_seconds=300)
    approval_id = store.create("rollout_restart", {"name": "payments-api"}, "restart payments-api")

    assert cli.list_approvals(settings) == 0
    listed = capsys.readouterr().out
    assert approval_id in listed
    assert "PENDING" in listed

    assert cli.approve(settings, approval_id) == 0
    approved = capsys.readouterr().out
    assert "approved: restart payments-api" in approved

    assert cli.approve(settings, "missing") == 1
    missing = capsys.readouterr().out
    assert "no pending approval" in missing


def test_cli_main_kubeconfig_override(tmp_path, monkeypatch) -> None:
    config_path = tmp_path / "config.yaml"
    kubeconfig_path = tmp_path / "override.kubeconfig"
    config_path.write_text(
        yaml.safe_dump(
            {
                "context": "limited-sa@test-cluster",
                "scope": {"allowed_namespaces": ["prod"]},
            }
        )
    )
    kubeconfig_path.write_text("apiVersion: v1\nkind: Config\n")
    captured = {}

    def fake_serve(settings, strict: bool) -> int:
        captured["kubeconfig"] = settings.kubeconfig
        captured["strict"] = strict
        return 0

    monkeypatch.setattr(cli, "serve", fake_serve)

    result = cli.main(
        [
            "serve",
            "--config",
            str(config_path),
            "--kubeconfig",
            str(kubeconfig_path),
            "--strict",
        ]
    )

    assert result == 0
    assert captured["kubeconfig"] == kubeconfig_path
    assert captured["strict"] is True


def test_doctor_json_reports_safe_capabilities(tmp_path, capsys) -> None:
    class HealthyKube:
        def self_check(self, namespaces, write_tools):
            assert namespaces == ["prod", "staging"]
            return [], []

    settings = make_settings(tmp_path)
    assert cli.doctor(settings, strict=True, json_output=True, kube=HealthyKube()) == 0
    report = json.loads(capsys.readouterr().out)
    assert report["ok"] is True
    assert report["context"] == "limited-sa@test-cluster"
    assert report["missing_permissions"] == []


def test_doctor_strict_rejects_overprivileged_credentials(tmp_path, capsys) -> None:
    class OverprivilegedKube:
        def self_check(self, namespaces, write_tools):
            return [], ["credentials can read Secrets in prod"]

    settings = make_settings(tmp_path)
    assert (
        cli.doctor(
            settings,
            strict=True,
            json_output=False,
            kube=OverprivilegedKube(),
        )
        == 1
    )
    assert "problems found" in capsys.readouterr().out
