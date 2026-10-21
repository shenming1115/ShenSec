"""Offline, escaped reports for individual inspections and batch audits."""

from html import escape
from pathlib import Path
import re

from jinja2 import Environment, FileSystemLoader, select_autoescape

from ..models import AuditResult, Finding, ScanResult, SEVERITY_RANK
from .sarif import format_sarif


def sorted_findings(findings: list[Finding]) -> list[Finding]:
    return sorted(findings, key=lambda f: (-SEVERITY_RANK[f.severity], f.rule_id, f.title))


def _md(value: object) -> str:
    # Escape HTML first so target-controlled text cannot introduce active markup.
    value = escape(str(value), quote=True)
    return re.sub(r"([\\`*_{}\[\]()#+!|])", r"\\\1", value).replace("\n", " ").replace("\r", " ")


def format_json(result: ScanResult | AuditResult) -> str:
    return result.model_dump_json(indent=4)


def _finding_markdown(finding: Finding, number: int) -> str:
    lines = [
        f"### {number}. {_md(finding.title)} ({finding.severity.value})",
        f"- **Rule ID**: {_md(finding.rule_id)}",
        f"- **Description**: {_md(finding.description)}",
    ]
    if finding.location:
        lines.append(f"- **Location**: {_md(finding.location)}")
    if finding.evidence:
        lines.append(f"- **Evidence**: {_md(finding.evidence)}")
    if finding.recommendation:
        lines.append(f"- **Recommendation**: {_md(finding.recommendation)}")
    if finding.suppression:
        lines.append(f"- **Accepted exception**: {_md(finding.suppression)}")
    return "\n".join(lines)


def _scan_markdown(result: ScanResult) -> str:
    lines = [
        f"**Target URL**: {_md(result.target_url)}",
        f"**Scan Status**: {result.status.upper()}",
        f"**Status Code**: {result.status_code}",
        f"**Response Time**: {result.response_time_ms} ms",
        f"**Overall Risk Rating**: **{result.risk_rating.value}**",
        f"**Method**: {result.request_method} | **Authentication**: {result.authentication} | **Requests**: {result.request_count} | **Retries**: {result.retry_count}",
    ]
    if result.final_url:
        lines.append(f"**Final URL**: {_md(result.final_url)}")
    if result.redirect_chain:
        lines.append(f"**Redirects**: {_md(' -> '.join(result.redirect_chain))}")
    if result.error:
        lines.append(f"**Execution Error**: {_md(result.error)}")
    for warning in result.warnings:
        lines.append(f"**Warning**: {_md(warning)}")
    lines.extend(f"- {severity}: {count}" for severity, count in reversed(result.severity_counts.items()))
    lines.extend(["", "## Detailed Findings", ""])
    lines.extend(_finding_markdown(finding, i) + "\n" for i, finding in enumerate(sorted_findings(result.findings), 1))
    if not result.findings:
        lines.append("No findings from the completed checks. This is not a guarantee of application security.")
    return "\n".join(lines)


def format_markdown(result: ScanResult | AuditResult) -> str:
    if isinstance(result, ScanResult):
        return "# ShenSec Security Scan Report\n\n" + _scan_markdown(result) + "\n"
    lines = [
        "# ShenSec Security Audit Report", "",
        f"**Created**: {result.created_at.isoformat()}",
        f"**Targets**: {len(result.results)} | **Incomplete**: {result.failed_targets}",
        f"**Overall Risk Rating**: **{result.risk_rating.value}**", "",
        f"**Duration**: {result.duration_ms} ms | **Cancelled**: {result.cancelled}", "",
    ]
    if result.gate:
        gate = result.gate
        lines.extend([
            f"**Gate**: {gate.outcome.upper()} | **Threshold**: {gate.threshold.value if gate.threshold else 'disabled'}",
            f"**Only new / regressed**: {gate.only_new} | **Violations**: {len(gate.violations)}", "",
        ])
        lines.extend(f"- **Execution / coverage error**: {_md(error)}" for error in gate.errors)
    if result.comparison:
        comparison = result.comparison
        lines.extend(["", "## Baseline Comparison", ""])
        for name in ("new", "regressed", "existing", "resolved", "unverified"):
            records = getattr(comparison, name)
            lines.append(f"### {name.title()}: {len(records)}")
            for record in records:
                severity = f"{record.previous_severity.value} -> {record.finding.severity.value}" if record.previous_severity else record.finding.severity.value
                lines.append(f"- [{severity}] {_md(record.target_url)} — {_md(record.finding.rule_id)}: {_md(record.finding.title)}")
                if record.change_reason:
                    lines.append(f"  - {_md(record.change_reason)}")
        lines.append(f"**Added targets**: {len(comparison.added_targets)} | **Removed targets**: {len(comparison.removed_targets)}")
        lines.extend(f"- Removed target: {_md(target)}" for target in comparison.removed_targets)
        lines.extend(f"- Authentication context changed: {_md(target)}" for target in comparison.context_changed_targets)
    if result.sessions:
        lines.extend(["", "## Session activity", "", "| Identity | Mode | State | Logins | Refreshes | Renewals |", "| --- | --- | --- | --- | --- | --- |"])
        for session in result.sessions:
            lines.append(f"| {_md(session.scope + ': ' + session.profile)} | {session.mode} | {session.state} | {session.logins} | {session.refreshes} | {session.renewals} |")
    if result.permissions:
        lines.extend(["", "## Role permission comparison", "", "| Expectation | Role | Expected | Observed | HTTP | Outcome |", "| --- | --- | --- | --- | --- | --- |"])
        for observation in result.permissions:
            lines.append(f"| {_md(observation.title)} | {_md(observation.role)} | {observation.expected} | {observation.observed} | {observation.status_code} | {observation.outcome} |")
        for observation in result.permissions:
            if observation.outcome in {"failed", "error", "cancelled"}:
                lines.append(f"\n{_md(observation.target_url)}: {_md(observation.detail)}\n")
    for i, scan in enumerate(result.results, 1):
        lines.extend(["", "---", "", f"## Target {i}: {_md(scan.target_url)}", "", _scan_markdown(scan)])
    return "\n".join(lines) + "\n"


def format_html(result: ScanResult | AuditResult) -> str:
    env = Environment(
        loader=FileSystemLoader(Path(__file__).resolve().parents[1] / "templates"),
        autoescape=select_autoescape(["html", "xml"]),
    )
    env.filters["by_severity"] = sorted_findings
    template = env.get_template("audit.html" if isinstance(result, AuditResult) else "report.html")
    return template.render(result=result)


def generate_report(result: ScanResult | AuditResult, format_type: str) -> str:
    formatters = {"json": format_json, "markdown": format_markdown, "html": format_html, "sarif": format_sarif}
    try:
        formatter = formatters[format_type.lower()]
    except KeyError as exc:
        raise ValueError(f"Unsupported format: {format_type}") from exc
    return formatter(result)
