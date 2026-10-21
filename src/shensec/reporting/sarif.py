"""SARIF 2.1.0 for remote observations; optional reviewed source anchors for CI."""

import json
from hashlib import sha256
from pathlib import Path
from urllib.parse import quote

from .. import __version__
from ..models import AuditResult, FindingRecord, ScanResult, SEVERITY_RANK


def format_sarif(result: ScanResult | AuditResult, *, source: str | None = None, source_lines: dict[str, int] | None = None) -> str:
    audit = result if isinstance(result, AuditResult) else AuditResult(results=[result])
    findings = [f for scan in audit.results for f in scan.findings]
    descriptors = {}
    for finding in findings:
        descriptors.setdefault(finding.rule_id, {
            "id": finding.rule_id, "shortDescription": {"text": finding.title},
            "fullDescription": {"text": finding.description},
            "help": {"text": finding.recommendation or "Review the observed response in context."},
            "properties": {"tags": ["security", "web-configuration"]},
        })
    rules = list(descriptors.values())
    rule_index = {rule["id"]: index for index, rule in enumerate(rules)}
    states = {}
    if audit.comparison:
        for category, state in (("new", "new"), ("existing", "unchanged"), ("regressed", "updated")):
            states.update({r.fingerprint: state for r in getattr(audit.comparison, category)})
    entries = []
    for scan in audit.results:
        for finding in scan.findings:
            record = FindingRecord(target_url=scan.target_url, finding=finding)
            identity = sha256(f"{scan.request_method} {record.fingerprint}".encode()).hexdigest()[:24]
            location = {"logicalLocations": [{"fullyQualifiedName": f"{scan.request_method} {scan.target_url}", "kind": "resource"}]}
            if source:
                location["physicalLocation"] = {
                    "artifactLocation": {"uri": quote(source.replace('\\', '/'), safe='/'), "uriBaseId": "%SRCROOT%"},
                    "region": {"startLine": (source_lines or {}).get(scan.target_url, 1)},
                }
            entry = {
                "ruleId": finding.rule_id, "ruleIndex": rule_index[finding.rule_id],
                "level": "error" if SEVERITY_RANK[finding.severity] >= 3 else "warning" if SEVERITY_RANK[finding.severity] >= 1 else "note",
                "message": {"text": f"{finding.title}: {scan.request_method} {scan.target_url}\n{finding.description}\n{finding.recommendation or ''}"},
                "locations": [location], "partialFingerprints": {"primaryLocationLineHash": identity},
                "properties": {"severity": finding.severity.value, "target": scan.target_url, "evidence": finding.evidence or ""},
            }
            if record.fingerprint in states:
                entry["baselineState"] = states[record.fingerprint]
            if finding.suppression:
                entry["suppressions"] = [{"kind": "external", "status": "accepted", "justification": finding.suppression}]
            entries.append(entry)
    run = {
        "tool": {"driver": {"name": "ShenSec", "version": __version__, "informationUri": "https://github.com/shenming1115/ShenSec", "rules": rules}},
        "automationDetails": {"id": "shensec/web-configuration/"},
        "invocations": [{"executionSuccessful": not audit.cancelled and not audit.failed_targets and not (audit.gate and audit.gate.outcome == "error")}],
        "results": entries,
    }
    if source:
        run["originalUriBaseIds"] = {"%SRCROOT%": {"uri": Path.cwd().as_uri().rstrip('/') + '/'}}
    run["properties"] = {"permissionChecks": len(audit.permissions), "permissionViolations": sum(r.outcome == "failed" for r in audit.permissions), "sessions": [session.model_dump(mode="json") for session in audit.sessions]}
    return json.dumps({"$schema": "https://docs.oasis-open.org/sarif/sarif/v2.1.0/os/schemas/sarif-schema-2.1.0.json", "version": "2.1.0", "runs": [run]}, ensure_ascii=False, indent=2)
