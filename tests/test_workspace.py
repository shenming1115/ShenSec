import json

import pytest
from typer.testing import CliRunner

from shensec import AuditResult, ScanResult, evaluate_gate
from shensec.auth import AuthConfig
from shensec.cli import app
from shensec.project import ProjectConfig, load_project, project_toml
from shensec.workspace import Workspace


def config(**kwargs):
    return ProjectConfig(name="Daily app", targets=["https://example.com/api/me"], **kwargs)


def report(**kwargs):
    audit = AuditResult(results=[ScanResult(target_url="https://example.com/api/me", status_code=200, response_time_ms=1, **kwargs)])
    audit.gate = evaluate_gate(audit)
    return audit


def test_project_toml_roundtrip_preserves_auth_references(tmp_path):
    project = config(auth=AuthConfig(bearer_env="APP_TOKEN", header_env={"X-API-Key": "APP_KEY"}, headers={"Accept": "application/json"}, origins=["https://example.com"], verify_url="https://example.com/me"))
    path = tmp_path / "shensec.toml"
    path.write_text(project_toml(project), encoding="utf-8")
    assert load_project(path) == project


def test_workspace_survives_restart_and_keeps_projects_and_baselines_separate(tmp_path):
    store = Workspace(tmp_path)
    one = store.save_project(config())
    two = store.save_project(config())
    run_id = store.save_run(one, config(), report())
    store.set_baseline(one, run_id)
    restarted = Workspace(tmp_path)
    assert len(restarted.list_projects()) == 2
    assert restarted.load_project(one).name == "Daily app"
    assert restarted.list_runs(one)[0]["id"] == run_id
    assert restarted.list_runs(two) == []
    assert restarted.baseline(one).results[0].status == "complete"
    assert restarted.baseline(two) is None
    with pytest.raises(ValueError, match="not found"):
        restarted.load_run(two, run_id)
    with pytest.raises(ValueError):
        restarted.set_baseline(two, run_id)


@pytest.mark.parametrize("metadata", [{"error": "Network failure"}, {"warnings": ["OPTIONS failed"]}, {"cancelled": True}])
def test_incomplete_or_cancelled_run_cannot_be_accepted_as_baseline(tmp_path, metadata):
    store = Workspace(tmp_path)
    project = store.save_project(config())
    run_id = store.save_run(project, config(), report(**metadata))
    with pytest.raises(ValueError, match="complete"):
        store.set_baseline(project, run_id)


def test_read_only_listing_does_not_create_workspace(tmp_path):
    store = Workspace(tmp_path / "absent")
    assert store.list_projects() == []
    with pytest.raises(ValueError):
        store.load_project("missing")
    assert not store.root.exists()


def test_cli_project_config_history_and_baseline_flow(tmp_path, monkeypatch):
    import shensec.cli as module
    runner = CliRunner()
    path, root = tmp_path / "shensec.toml", tmp_path / "workspace"
    result = runner.invoke(app, ["init", "--target", "https://example.com/api/me", "--bearer-env", "APP_TOKEN", "-o", str(path)])
    assert result.exit_code == 0, result.output
    assert "APP_TOKEN" in path.read_text()
    assert runner.invoke(app, ["init", "--target", "https://example.com", "-o", str(path)]).exit_code == 2
    imported = runner.invoke(app, ["project", "import", str(path), "--workspace", str(root)])
    assert imported.exit_code == 0, imported.output
    project_id = imported.stdout.strip()
    monkeypatch.setenv("APP_TOKEN", "not-to-be-saved-private-token")
    def fake_scan(targets, *args, **kwargs):
        assert kwargs["auth"].credentials["Authorization"] == "Bearer not-to-be-saved-private-token"
        return report()
    monkeypatch.setattr(module, "scan_many", fake_scan)
    result = runner.invoke(app, ["audit", "--project", project_id, "--workspace", str(root), "--format", "json"])
    assert result.exit_code == 0, result.output
    assert json.loads(result.stdout)["gate"]["outcome"] == "passed"
    history = runner.invoke(app, ["history", project_id, "--workspace", str(root)])
    run_id = json.loads(history.stdout)[0]["id"]
    assert runner.invoke(app, ["baseline", project_id, run_id, "--workspace", str(root)]).exit_code == 0
    exported = runner.invoke(app, ["history", project_id, "--workspace", str(root), "--run", run_id, "--format", "html"])
    assert exported.exit_code == 0
    assert "ShenSec Audit Report" in exported.stdout
    assert b"not-to-be-saved-private-token" not in (root / "workspace.sqlite3").read_bytes()


def test_missing_auth_variable_fails_before_scan_without_leaking_secrets(tmp_path, monkeypatch):
    import shensec.cli as module
    monkeypatch.delenv("MISSING_SHENSEC_TOKEN", raising=False)
    monkeypatch.setattr(module, "scan_many", lambda *args, **kwargs: pytest.fail("Unexpected scan"))
    path = tmp_path / "project.toml"
    path.write_text(project_toml(config(auth=AuthConfig(bearer_env="MISSING_SHENSEC_TOKEN"))))
    result = CliRunner().invoke(app, ["audit", "--config", str(path)])
    assert result.exit_code == 2
    assert "missing or empty" in result.stderr
