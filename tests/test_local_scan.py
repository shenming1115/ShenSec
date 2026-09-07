"""Exercise real loopback HTTP requests and the report pipeline."""

import importlib.util
import json
from pathlib import Path

from shensec import Severity, generate_report


def test_local_scan_and_reports(monkeypatch):
    monkeypatch.setenv("NO_PROXY", "127.0.0.1,localhost")
    example = Path(__file__).resolve().parents[1] / "examples" / "local_scan.py"
    spec = importlib.util.spec_from_file_location("local_scan", example)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    result = module.scan_example()

    assert result.status_code == 200
    assert result.risk_rating == Severity.HIGH
    assert sum(result.severity_counts.values()) == len(result.findings)
    rules = {finding.rule_id for finding in result.findings}
    assert {"SEC-CORS-STAR", "SEC-COOKIE-001", "SEC-SRV-INFO"} <= rules
    assert "SEC-SCAN-ERR" not in rules
    assert "SEC-HTTP-METHODS" not in rules
    assert json.loads(generate_report(result, "json"))["status_code"] == 200
    assert "SEC-COOKIE-001" in generate_report(result, "markdown")
    assert "<title>ShenSec Audit Report</title>" in generate_report(result, "html")
