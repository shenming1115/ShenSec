import json
import os
from jinja2 import Environment, FileSystemLoader
from ..models import ScanResult

MARKDOWN_TEMPLATE = """# ShenSec Security Scan Report

**Target URL**: {target_url}
**Status Code**: {status_code}
**Response Time**: {response_time_ms} ms

## Security Risk Analysis
**Overall Risk Rating**: **{risk_rating}**
- CRITICAL: {cnt_critical}
- HIGH: {cnt_high}
- MEDIUM: {cnt_medium}
- LOW: {cnt_low}
- INFO: {cnt_info}

## Findings Summary
Total Issues Found: {total_issues}

## Detailed Findings

{findings_markdown}
"""

def format_json(result: ScanResult) -> str:
    # Serialize the Pydantic model directly to JSON
    return result.model_dump_json(indent=4)

def format_markdown(result: ScanResult) -> str:
    findings_md = ""
    for idx, finding in enumerate(result.findings, 1):
        findings_md += f"### {idx}. {finding.title} ({finding.severity.value})\n"
        findings_md += f"- **Rule ID**: {finding.rule_id}\n"
        findings_md += f"- **Description**: {finding.description}\n"
        if finding.recommendation:
            findings_md += f"- **Recommendation**: {finding.recommendation}\n\n"
            
    if not result.findings:
        findings_md = "No issues detected. Good job!\n"

    return MARKDOWN_TEMPLATE.format(
        target_url=result.target_url,
        status_code=result.status_code,
        response_time_ms=result.response_time_ms,
        risk_rating=result.risk_rating.value,
        cnt_critical=result.severity_counts.get("CRITICAL", 0),
        cnt_high=result.severity_counts.get("HIGH", 0),
        cnt_medium=result.severity_counts.get("MEDIUM", 0),
        cnt_low=result.severity_counts.get("LOW", 0),
        cnt_info=result.severity_counts.get("INFO", 0),
        total_issues=len(result.findings),
        findings_markdown=findings_md
    )

def format_html(result: ScanResult) -> str:
    templates_dir = os.path.join(os.path.dirname(__file__), "..", "templates")
    env = Environment(loader=FileSystemLoader(templates_dir))
    template = env.get_template("report.html")
    return template.render(result=result)

def generate_report(result: ScanResult, format_type: str) -> str:
    if format_type.lower() == "json":
        return format_json(result)
    elif format_type.lower() == "markdown":
        return format_markdown(result)
    elif format_type.lower() == "html":
        return format_html(result)
    else:
        raise ValueError(f"Unsupported format: {format_type}")