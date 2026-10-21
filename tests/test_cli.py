import pytest
from typer.testing import CliRunner
from shensec.cli import app
import sys

import builtins
import json
from shensec.models import AuditResult, ScanResult, Finding, Severity

runner = CliRunner()

def test_cli_gui_no_dependency(monkeypatch):
    """
    Test GUI launch fails gracefully when PySide6 is not present.
    We simulate this by mocking the import statement to raise ImportError.
    """
    original_import = builtins.__import__

    def mock_import(name, *args, **kwargs):
        if "gui.app" in name or name == "shensec.gui.app":
            raise ImportError("No module named 'shensec.gui.app'")
        return original_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", mock_import)

    result = runner.invoke(app, ["gui"])
    # It might actually fail or just return the exit code 1
    assert result.exit_code == 1
    assert "Failed to load GUI" in result.stdout
    assert "pip install shensec[gui]" in result.stdout

def test_cli_help():
    """Test the CLI help command."""
    result = runner.invoke(app, ["--help"])
    assert result.exit_code == 0
    assert "ShenSec" in result.stdout
    assert "scan" in result.stdout
    assert "gui" in result.stdout


def sample_scan(**kwargs):
    return ScanResult(target_url="https://example.com/", status_code=200, response_time_ms=2, **kwargs)


def test_scan_json_stdout_is_parseable_and_jwt_updates_summary(monkeypatch):
    import shensec.cli as module
    monkeypatch.setattr(module, "scan_target", lambda *args, **kwargs: sample_scan())
    result = runner.invoke(app, ["scan", "https://example.com", "--jwt", "malformed", "--format", "json", "--fail-on", "HIGH"])
    assert result.exit_code == 1
    data = json.loads(result.stdout)
    assert data["risk_rating"] == "CRITICAL"
    assert data["severity_counts"]["CRITICAL"] == 1
    assert "Scanning" in result.stderr


def test_scan_error_exits_two_and_keeps_json_report(monkeypatch):
    import shensec.cli as module
    monkeypatch.setattr(module, "scan_target", lambda *args, **kwargs: sample_scan(error="TLS verification failed"))
    result = runner.invoke(app, ["scan", "https://example.com", "--format", "json"])
    assert result.exit_code == 2
    assert json.loads(result.stdout)["status"] == "error"


def test_audit_reads_targets_and_only_new_gate_can_pass_existing_findings(tmp_path, monkeypatch):
    import shensec.cli as module
    issue = Finding(rule_id="R1", title="Existing issue", description="Evidence", severity=Severity.HIGH)
    baseline = AuditResult(results=[sample_scan(findings=[issue])])
    baseline_path = tmp_path / "baseline.json"
    baseline_path.write_text(baseline.model_dump_json())
    targets = tmp_path / "targets.txt"
    targets.write_text("# test\nhttps://example.com\nhttps://EXAMPLE.com:443/\n", encoding="utf-8-sig")
    seen = []
    def fake_scan(urls, *args, **kwargs):
        seen.extend(urls)
        return AuditResult(results=[sample_scan(findings=[issue])])
    monkeypatch.setattr(module, "scan_many", fake_scan)
    result = runner.invoke(app, ["audit", "--targets", str(targets), "--baseline", str(baseline_path), "--only-new", "--format", "json"])
    assert result.exit_code == 0, result.output
    assert seen == ["https://example.com/"]
    data = json.loads(result.stdout)
    assert data["gate"]["outcome"] == "passed"
    assert len(data["comparison"]["existing"]) == 1


@pytest.mark.parametrize("args", [[], ["https://example.com", "--only-new"], ["ftp://example.com"], ["https://example.com", "--workers", "17"]])
def test_audit_invalid_inputs_fail_before_scanning(monkeypatch, args):
    import shensec.cli as module
    monkeypatch.setattr(module, "scan_many", lambda *args, **kwargs: pytest.fail("Unexpected scan"))
    assert runner.invoke(app, ["audit", *args]).exit_code == 2


def test_audit_refuses_to_overwrite_baseline(tmp_path, monkeypatch):
    import shensec.cli as module
    monkeypatch.setattr(module, "scan_many", lambda *args, **kwargs: pytest.fail("Unexpected scan"))
    path = tmp_path / "baseline.json"
    path.write_text("preserve this")
    result = runner.invoke(app, ["audit", "https://example.com", "--baseline", str(path), "--output", str(path)])
    assert result.exit_code == 2
    assert path.read_text() == "preserve this"


def test_jwt_token_file_exports_without_the_token(tmp_path):
    token = "eyJhbGciOiJub25lIn0.eyJzdWIiOiIxMjMifQ.signature"
    path = tmp_path / "token.txt"
    path.write_text(token)
    result = runner.invoke(app, ["jwt", "--token-file", str(path), "--format", "json", "--fail-on", "critical"])
    assert result.exit_code == 1
    assert token not in result.output
    data = json.loads(result.stdout)
    assert data["scan_kind"] == "jwt"
    assert data["status"] == "complete"


def test_output_write_failure_has_exit_two(monkeypatch, tmp_path):
    import shensec.cli as module
    monkeypatch.setattr(module, "scan_target", lambda *args, **kwargs: sample_scan())
    result = runner.invoke(app, ["scan", "https://example.com", "-o", str(tmp_path / "missing" / "report.json")])
    assert result.exit_code == 2
    assert "Error:" in result.stderr
