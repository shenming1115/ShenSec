import json
from threading import Barrier, Lock

import pytest

from shensec import (
    AuditResult, Finding, ScanResult, Severity, compare_audits,
    evaluate_gate, load_baseline, scan_many,
)
from shensec.targets import parse_targets


def finding(rule="R1", severity=Severity.HIGH, location=None, evidence="first observation"):
    return Finding(rule_id=rule, title=rule, description="Observation", severity=severity, location=location, evidence=evidence)


def scan(findings=(), target="https://example.com/", **kwargs):
    return ScanResult(target_url=target, status_code=200, response_time_ms=1, findings=list(findings), **kwargs)


def test_summary_stays_consistent_after_api_mutations_and_json_roundtrip():
    result = scan([finding()], risk_rating="INFO", severity_counts={})
    result.findings.append(finding("R2", Severity.CRITICAL))
    assert result.risk_rating == Severity.CRITICAL
    assert result.severity_counts["CRITICAL"] == 1
    restored = ScanResult.model_validate_json(result.model_dump_json())
    assert restored.severity_counts == result.severity_counts
    restored.findings.clear()
    assert restored.risk_rating == Severity.INFO
    assert sum(restored.severity_counts.values()) == 0


def test_comparison_tracks_new_existing_fixed_and_severity_regressions():
    before = AuditResult(results=[scan([
        finding("existing"), finding("fixed"), finding("regression", Severity.LOW),
    ])])
    after = AuditResult(results=[scan([
        finding("existing", evidence="changed timestamp"), finding("new"), finding("regression"),
    ])])
    after.comparison = compare_audits(after, before)
    assert [r.finding.rule_id for r in after.comparison.new] == ["new"]
    assert [r.finding.rule_id for r in after.comparison.existing] == ["existing"]
    assert [r.finding.rule_id for r in after.comparison.resolved] == ["fixed"]
    assert [r.finding.rule_id for r in after.comparison.regressed] == ["regression"]
    assert after.comparison.regressed[0].previous_severity == Severity.LOW
    gate = evaluate_gate(after, Severity.HIGH, only_new=True)
    assert {r.finding.rule_id for r in gate.violations} == {"new", "regression"}
    assert gate.exit_code == 1


def test_existing_high_does_not_block_only_new_but_blocks_full_gate():
    before = AuditResult(results=[scan([finding()])])
    after = AuditResult(results=[scan([finding()])])
    after.comparison = compare_audits(after, before)
    assert evaluate_gate(after, only_new=True).exit_code == 0
    assert evaluate_gate(after).exit_code == 1


@pytest.mark.parametrize("mode", ["removed", "failed", "partial", "skipped"])
def test_incomplete_coverage_never_claims_a_baseline_issue_is_fixed(mode):
    before = AuditResult(results=[scan([finding("SEC-HTTP-METHODS")], checks=["http-methods"])])
    if mode == "removed":
        current = scan(target="https://other.example/")
    elif mode == "failed":
        current = scan(error="Connection refused")
    elif mode == "partial":
        current = scan(warnings=["OPTIONS failed"])
    else:
        current = scan(checks=["headers"])
    after = AuditResult(results=[current])
    after.comparison = compare_audits(after, before)
    assert not after.comparison.resolved
    assert len(after.comparison.unverified) == 1
    assert evaluate_gate(after, only_new=True).exit_code == 2


def test_different_cookies_are_not_collapsed_into_one_baseline_issue():
    before = AuditResult(results=[scan([finding("SEC-COOKIE-001", location="cookie:first")])])
    after = AuditResult(results=[scan([
        finding("SEC-COOKIE-001", location="cookie:first"),
        finding("SEC-COOKIE-001", location="cookie:second"),
    ])])
    comparison = compare_audits(after, before)
    assert len(comparison.existing) == 1
    assert len(comparison.new) == 1


def test_fully_rechecked_rule_is_resolved():
    before = AuditResult(results=[scan([finding("SEC-HTTP-METHODS")])])
    after = AuditResult(results=[scan(checks=["http-methods"])])
    assert len(compare_audits(after, before).resolved) == 1


def test_only_new_requires_a_baseline():
    with pytest.raises(ValueError, match="requires"):
        evaluate_gate(AuditResult(results=[scan()]), only_new=True)


def test_batch_has_bounded_parallelism_deduplicates_and_preserves_order(monkeypatch):
    import shensec.audit as module
    barrier, lock = Barrier(2), Lock()
    active = peak = 0
    calls = []

    def fake_scan(url, *args, **kwargs):
        nonlocal active, peak
        with lock:
            active += 1
            peak = max(active, peak)
            calls.append(url)
        if url in ("https://a.example/", "https://b.example/"):
            barrier.wait(timeout=5)
        with lock:
            active -= 1
        return scan(target=url)

    monkeypatch.setattr(module, "scan_target", fake_scan)
    result = scan_many(["https://a.example", "https://b.example", "https://a.example/", "https://c.example"], workers=2)
    assert peak == 2
    assert len(calls) == 3
    assert [r.target_url for r in result.results] == ["https://a.example/", "https://b.example/", "https://c.example/"]


@pytest.mark.parametrize("workers", [0, 17])
def test_invalid_workers_rejected(workers):
    with pytest.raises(ValueError, match="Workers"):
        scan_many(["https://example.com"], workers=workers)


@pytest.mark.parametrize("target", ["example.com", "file:///etc/passwd", "ftp://example.com", "https://user:secret@example.com", "https://example.com:bad"])
def test_target_list_rejects_unsupported_or_credentialed_urls(target):
    with pytest.raises(ValueError):
        parse_targets([target])


def test_target_file_comments_bom_and_url_normalization():
    assert parse_targets(["# internal services", "", "HTTPS://Example.com:443/#overview", "https://example.com/"]) == ["https://example.com/"]


def test_url_normalization_preserves_encoded_slashes_and_query_values():
    assert parse_targets(["https://example.com/a%2Fb?value=c%2Fd"]) == ["https://example.com/a%2Fb?value=c%2Fd"]


def test_load_baseline_recomputes_untrusted_summary_and_accepts_single_scan(tmp_path):
    path = tmp_path / "baseline.json"
    data = scan([finding()]).model_dump(mode="json")
    data["risk_rating"] = "INFO"
    data["severity_counts"] = {"HIGH": 0}
    path.write_text(json.dumps(data), encoding="utf-8-sig")
    restored = load_baseline(path)
    assert restored.risk_rating == Severity.HIGH
    assert restored.severity_counts["HIGH"] == 1


@pytest.mark.parametrize("data", [[], {}, {"schema_version": 2, "results": []}, {"schema_version": 1, "results": []}])
def test_malformed_baselines_rejected(tmp_path, data):
    path = tmp_path / "baseline.json"
    path.write_text(json.dumps(data))
    with pytest.raises(ValueError, match="Cannot load baseline"):
        load_baseline(path)


def test_duplicate_baseline_targets_rejected(tmp_path):
    path = tmp_path / "duplicate.json"
    path.write_text(AuditResult(results=[scan(), scan(target="https://EXAMPLE.com:443")]).model_dump_json())
    with pytest.raises(ValueError, match="Duplicate target"):
        load_baseline(path)
