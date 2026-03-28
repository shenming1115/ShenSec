from shensec.models import ScanResult, Finding, Severity
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

def test_markdown_formatter():
    result = get_mock_result()
    output = generate_report(result, "markdown")
    assert "# ShenSec Security Scan Report" in output
    assert "**Target URL**: https://example.com" in output
    assert "**Overall Risk Rating**: **HIGH**" in output
    assert "HIGH: 1" in output
    assert "### 1. A test finding (HIGH)" in output

def test_html_formatter():
    result = get_mock_result()
    output = generate_report(result, "html")
    assert "<title>ShenSec Audit Report</title>" in output
    assert "https://example.com" in output
    assert "A test finding" in output
    assert "HIGH: 1" in output