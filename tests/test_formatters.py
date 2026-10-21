from shensec.models import AuditResult, ScanResult, Finding, Severity
from shensec.audit import compare_audits, evaluate_gate
import json
from shensec.reporting.formatters import generate_report

def get_mock_result():
    return ScanResult(
        target_url="https://example.com",
        status_code=200,
        response_time_ms=120.5,
        findings=[
            Finding(
                rule_id="TEST-001",
                title="A test finding",
                description="Test description.",
                severity=Severity.HIGH,
                recommendation="Fix it."
            )
        ],
        risk_rating=Severity.HIGH,
        severity_counts={"CRITICAL": 0, "HIGH": 1, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    )

def test_json_formatter():
    result = get_mock_result()
    output = generate_report(result, "json")
    assert '"target_url": "https://example.com"' in output
    assert '"rule_id": "TEST-001"' in output
    assert '"risk_rating": "HIGH"' in output
    assert '"CRITICAL": 0' in output
    assert '"HIGH": 1' in output

def test_markdown_formatter():
    result = get_mock_result()
    output = generate_report(result, "markdown")
    assert "# ShenSec Security Scan Report" in output
    assert "**Target URL**: https://example.com" in output
    assert "**Overall Risk Rating**: **HIGH**" in output
    assert "HIGH: 1" in output
    assert "### 1. A test finding (HIGH)" in output


def test_html_escapes_all_target_controlled_fields():
    payload = '<script>alert("report injection")</script>'
    result = ScanResult(
        target_url=payload, final_url=payload, status_code=200, response_time_ms=1,
        error=payload, warnings=[payload], redirect_chain=[payload],
        findings=[Finding(rule_id=payload, title=payload, description=payload,
                          severity=Severity.HIGH, recommendation=payload, evidence=payload, location=payload)],
    )
    for report in (result, AuditResult(results=[result])):
        output = generate_report(report, "html")
        assert payload not in output
        assert "&lt;script&gt;" in output
        assert 'Content-Security-Policy' in output
        assert 'src="http' not in output


def test_markdown_does_not_emit_active_html_or_injected_links():
    result = get_mock_result()
    result.findings[0].description = '<img src=x onerror=alert(1)> [click](javascript:alert(1))'
    output = generate_report(result, "markdown")
    assert "<img" not in output
    assert "\\[click\\]\\(javascript:" in output


def test_batch_reports_contain_comparison_and_policy_decision():
    baseline = AuditResult(results=[get_mock_result()])
    current = AuditResult(results=[get_mock_result()])
    current.results[0].findings.clear()
    current.comparison = compare_audits(current, baseline)
    current.gate = evaluate_gate(current, only_new=True)
    assert json.loads(generate_report(current, "json"))["gate"]["outcome"] == "passed"
    assert "Resolved: 1" in generate_report(current, "markdown")
    html = generate_report(current, "html")
    assert "Resolved · 1" in html
    assert "Security regression report" in html

def test_html_formatter():
    result = get_mock_result()
    output = generate_report(result, "html")
    assert "<title>ShenSec Audit Report</title>" in output
    assert "https://example.com" in output
    assert "A test finding" in output
    assert "HIGH: 1" in output
