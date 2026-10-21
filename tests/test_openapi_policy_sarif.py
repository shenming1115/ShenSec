from datetime import date
import json

import httpx
import pytest
from typer.testing import CliRunner

from shensec import AuditResult, Finding, ScanResult, Severity, compare_audits, evaluate_gate
from shensec.cli import app
from shensec.openapi import import_openapi
from shensec.policy import RuleException, apply_exceptions
from shensec.project import load_project
from shensec.reporting.formatters import generate_report

URL = "https://example.com/api/me"


def spec_file(tmp_path, paths, **kwargs):
    path = tmp_path / "api.json"
    doc = {"openapi": "3.1.0", "info": {"title": "Test API"}, "paths": paths, **kwargs}
    path.write_text(json.dumps(doc), encoding="utf-8")
    return path


def test_openapi_bindings_encoding_local_refs_and_mutators_skipped(tmp_path):
    path = spec_file(tmp_path, {
        "/users/{id}": {"parameters": [{"$ref": "#/components/parameters/id"}], "get": {"parameters": [{"name": "page", "in": "query", "required": True, "schema": {"default": 1}}]}, "delete": {}},
        "/health": {"get": {}, "head": {}},
        "/missing/{id}": {"get": {}},
        "/external": {"$ref": "https://untrusted.invalid/other.json"},
    }, components={"parameters": {"id": {"name": "id", "in": "path", "required": True, "schema": {"type": "string"}}}}, servers=[{"url": "https://ignored.invalid"}])
    result = import_openapi(path, "https://example.com/v1", {"path.id": "a/b c"})
    assert result.config.targets == ["https://example.com/v1/users/a%2Fb%20c?page=1", "https://example.com/v1/health"]
    assert len(result.skipped) == 4
    assert all(p.method == "GET" for p in result.config.requests)


def test_openapi_operation_parameter_overrides_path_parameter(tmp_path):
    path = spec_file(tmp_path, {"/search": {"parameters": [{"name": "q", "in": "query", "required": True}], "get": {"parameters": [{"name": "q", "in": "query", "required": False}]}}})
    assert import_openapi(path, "https://example.com").config.targets == ["https://example.com/search"]


def test_openapi_security_requirement_cannot_silently_become_anonymous(tmp_path):
    path = spec_file(tmp_path, {"/me": {"get": {}}}, security=[{"bearerAuth": []}])
    assert import_openapi(path, "https://example.com").config.auth.required
    path = spec_file(tmp_path, {"/me": {"get": {"security": []}}}, security=[{"bearerAuth": []}])
    assert not import_openapi(path, "https://example.com").config.auth.required


@pytest.mark.parametrize("paths", [
    {"/users/{id}": {"get": {"parameters": [{"name": "id", "in": "path", "required": True}]}}},
    {"/data": {"get": {"parameters": [{"name": "X-Tenant", "in": "header", "required": True}]}}},
    {"/cycle": {"$ref": "#/paths/~1cycle"}},
    {"//external.example/": {"get": {}}},
    {"/data": {"post": {}}},
])
def test_openapi_unready_operations_are_not_silently_scanned(tmp_path, paths):
    with pytest.raises(ValueError, match="No ready"):
        import_openapi(spec_file(tmp_path, paths), "https://example.com")


def test_openapi_cli_creates_config_offline_and_does_not_overwrite(tmp_path):
    path = spec_file(tmp_path, {"/health": {"get": {}}, "/mutate": {"post": {}}})
    output = tmp_path / "project.toml"
    args = ["import-openapi", str(path), "--server", "https://example.com", "-o", str(output)]
    result = CliRunner().invoke(app, args)
    assert result.exit_code == 0, result.output
    assert "Skipped: POST" in result.stderr
    assert load_project(output).targets == ["https://example.com/health"]
    assert CliRunner().invoke(app, args).exit_code == 2


def audit_fixture(**kwargs):
    return AuditResult(results=[ScanResult(target_url=URL, status_code=200, response_time_ms=1, checks=["headers"], findings=[Finding(rule_id="SEC-HDR-001", title="Missing HSTS", description="Observed configuration", severity=Severity.HIGH)], **kwargs)])


def exception(**kwargs):
    return RuleException(rule_id="SEC-HDR-001", target=URL, reason="TLS edge deployment scheduled", expires="2099-12-31", **kwargs)


def test_exception_keeps_raw_risk_and_evidence_but_waives_gate():
    audit = audit_fixture()
    apply_exceptions(audit, [exception()])
    assert evaluate_gate(audit).outcome == "passed"
    assert audit.risk_rating == Severity.HIGH
    assert audit.severity_counts["HIGH"] == 1
    assert "TLS edge deployment" in audit.results[0].findings[0].suppression
    for fmt in ("html", "markdown", "json", "sarif"):
        assert "TLS edge deployment" in generate_report(audit, fmt)


def test_expired_exception_reenters_only_new_gate():
    before = audit_fixture()
    rule = exception()
    apply_exceptions(before, [rule], today=date(2099, 12, 30))
    current = audit_fixture()
    apply_exceptions(current, [rule], today=date(2100, 1, 1))
    current.comparison = compare_audits(current, before)
    assert len(current.comparison.regressed) == 1
    assert evaluate_gate(current, only_new=True).outcome == "failed"


def test_exception_scope_is_case_sensitive_and_execution_errors_cannot_pass():
    audit = audit_fixture(error="Not authenticated")
    apply_exceptions(audit, [exception()])
    assert evaluate_gate(audit).exit_code == 2
    audit = audit_fixture()
    rule = exception().model_copy(update={"target": "https://example.com/api/ME"})
    apply_exceptions(audit, [rule])
    assert evaluate_gate(audit).outcome == "failed"


def test_selected_url_exception_does_not_broaden_query_metacharacters():
    from shensec.policy import literal_target_pattern
    audit = audit_fixture()
    target = "https://example.com/search?q[]=a*b"
    audit.results[0].target_url = target
    rule = exception().model_copy(update={"target": literal_target_pattern(target)})
    apply_exceptions(audit, [rule])
    assert audit.results[0].findings[0].suppression
    audit.results[0].target_url = "https://example.com/search?q[]=ab"
    apply_exceptions(audit, [rule])
    assert audit.results[0].findings[0].suppression is None


def test_sarif_has_stable_identity_rules_baseline_and_suppression():
    audit = audit_fixture()
    audit.comparison = compare_audits(audit, audit_fixture())
    apply_exceptions(audit, [exception()])
    data = json.loads(generate_report(audit, "sarif"))
    assert data["version"] == "2.1.0"
    run = data["runs"][0]
    assert run["tool"]["driver"]["rules"][0]["id"] == "SEC-HDR-001"
    finding = run["results"][0]
    assert finding["ruleIndex"] == 0
    assert finding["level"] == "error"
    assert finding["baselineState"] == "unchanged"
    assert finding["partialFingerprints"]["primaryLocationLineHash"]
    assert finding["suppressions"][0]["status"] == "accepted"
    assert "physicalLocation" not in finding["locations"][0]
    failed = json.loads(generate_report(audit_fixture(error="Controlled error"), "sarif"))
    assert failed["runs"][0]["invocations"][0]["executionSuccessful"] is False


def test_cli_sarif_anchors_to_actual_target_declaration(tmp_path, monkeypatch):
    import shensec.cli as cli
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(cli, "scan_many", lambda *args, **kwargs: audit_fixture())
    manifest = tmp_path / "targets.txt"
    manifest.write_text(f"# Targets\n{URL}\n", encoding="utf-8")
    result = CliRunner().invoke(app, ["audit", URL, "-f", "sarif", "--sarif-source", "targets.txt"])
    assert result.exit_code == 1, result.output
    data = json.loads(result.stdout)
    physical = data["runs"][0]["results"][0]["locations"][0]["physicalLocation"]
    assert physical["artifactLocation"]["uri"] == "targets.txt"
    assert physical["region"]["startLine"] == 2
    manifest.write_text("https://different.example/", encoding="utf-8")
    bad = CliRunner().invoke(app, ["audit", URL, "-f", "sarif", "--sarif-source", "targets.txt"])
    assert bad.exit_code == 2
    assert "must contain each target" in bad.stderr


def test_project_cli_applies_request_network_and_exceptions(tmp_path, monkeypatch):
    from shensec import NetworkPolicy, ProjectConfig, RequestSpec
    from shensec.project import project_toml
    import shensec.cli as cli
    config = ProjectConfig(targets=[URL], requests=[RequestSpec(url=URL, method="HEAD")], network=NetworkPolicy(requests_per_second=2), exceptions=[exception()], check_cors=True)
    path = tmp_path / "project.toml"
    path.write_text(project_toml(config), encoding="utf-8")
    def scan(*args, **kwargs):
        assert kwargs["requests"][0].method == "HEAD"
        assert kwargs["network"].requests_per_second == 2
        assert kwargs["check_cors"] is True
        return audit_fixture()
    monkeypatch.setattr(cli, "scan_many", scan)
    result = CliRunner().invoke(app, ["audit", "-c", str(path), "-f", "json"])
    assert result.exit_code == 0, result.output
    assert json.loads(result.stdout)["gate"]["outcome"] == "passed"


def test_report_conversion_is_offline_and_preserves_input(tmp_path, monkeypatch):
    import shensec.cli as cli
    monkeypatch.setattr(cli, "scan_many", lambda *args, **kwargs: pytest.fail("Must not rescan"))
    path = tmp_path / "recorded.json"
    path.write_text(audit_fixture().model_dump_json(), encoding="utf-8")
    result = CliRunner().invoke(app, ["report", str(path), "-f", "sarif"])
    assert result.exit_code == 0, result.output
    assert json.loads(result.stdout)["version"] == "2.1.0"
    assert CliRunner().invoke(app, ["report", str(path), "-o", str(path)]).exit_code == 2
