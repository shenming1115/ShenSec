"""Shared, serializable audit results. Summaries are derived from findings."""

from datetime import datetime, timezone
from enum import Enum
from hashlib import sha256
import json
from typing import Literal

from pydantic import BaseModel, Field, computed_field

class Severity(str, Enum):
    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

SEVERITY_RANK = {severity: rank for rank, severity in enumerate(Severity)}


def highest_severity(findings: list["Finding"]) -> Severity:
    return max((f.severity for f in findings), key=SEVERITY_RANK.get, default=Severity.INFO)


def count_severities(findings: list["Finding"]) -> dict[str, int]:
    counts = {severity.value: 0 for severity in Severity}
    for finding in findings:
        counts[finding.severity.value] += 1
    return counts


class Finding(BaseModel):
    rule_id: str
    title: str
    description: str
    severity: Severity
    recommendation: str | None = None
    location: str | None = None
    evidence: str | None = None
    suppression: str | None = None

    @computed_field
    @property
    def fingerprint(self) -> str:
        # Evidence and severity can change without changing the identity of an issue.
        identity = json.dumps([self.rule_id, self.location or self.title], ensure_ascii=True)
        return sha256(identity.encode()).hexdigest()[:24]

class ScanResult(BaseModel):
    target_url: str
    status_code: int
    response_time_ms: float
    findings: list[Finding] = Field(default_factory=list)
    scan_kind: Literal["http", "jwt"] = "http"
    final_url: str | None = None
    redirect_chain: list[str] = Field(default_factory=list)
    error: str | None = None
    warnings: list[str] = Field(default_factory=list)
    checks: list[str] = Field(default_factory=list)
    auth_context: str | None = None
    authentication: Literal["none", "applied"] = "none"
    cancelled: bool = False
    request_count: int = 0
    retry_count: int = 0
    request_method: str = "GET"
    request_context: str | None = None

    @computed_field
    @property
    def status(self) -> Literal["complete", "partial", "error", "cancelled"]:
        if self.cancelled:
            return "cancelled"
        if self.error or (self.scan_kind == "http" and self.status_code == 0):
            return "error"
        return "partial" if self.warnings else "complete"

    @computed_field
    @property
    def risk_rating(self) -> Severity:
        return highest_severity(self.findings)

    @computed_field
    @property
    def severity_counts(self) -> dict[str, int]:
        return count_severities(self.findings)


class FindingRecord(BaseModel):
    target_url: str
    finding: Finding
    previous_severity: Severity | None = None
    change_reason: str | None = None

    @computed_field
    @property
    def fingerprint(self) -> str:
        identity = json.dumps([self.target_url, self.finding.fingerprint])
        return sha256(identity.encode()).hexdigest()[:24]


class Comparison(BaseModel):
    new: list[FindingRecord] = Field(default_factory=list)
    existing: list[FindingRecord] = Field(default_factory=list)
    resolved: list[FindingRecord] = Field(default_factory=list)
    regressed: list[FindingRecord] = Field(default_factory=list)
    unverified: list[FindingRecord] = Field(default_factory=list)
    added_targets: list[str] = Field(default_factory=list)
    removed_targets: list[str] = Field(default_factory=list)
    context_changed_targets: list[str] = Field(default_factory=list)


class GateResult(BaseModel):
    threshold: Severity | None = None
    only_new: bool = False
    outcome: Literal["passed", "failed", "error"]
    violations: list[FindingRecord] = Field(default_factory=list)
    errors: list[str] = Field(default_factory=list)

    @property
    def exit_code(self) -> int:
        return {"passed": 0, "failed": 1, "error": 2}[self.outcome]


class SessionState(BaseModel):
    profile: str
    scope: Literal["primary", "role"] = "primary"
    mode: Literal["automatic", "static", "anonymous"]
    state: Literal["pending", "ready", "error"]
    logins: int = 0
    refreshes: int = 0
    renewals: int = 0
    requests: int = 0


class PermissionResult(BaseModel):
    case_id: str
    title: str
    target_url: str
    method: str = "GET"
    role: str
    expected: Literal["allow", "deny"]
    observed: Literal["allowed", "denied", "unverified"] = "unverified"
    outcome: Literal["passed", "failed", "error", "cancelled"] = "error"
    status_code: int = 0
    detail: str = ""
    duration_ms: float = 0


class AuditResult(BaseModel):
    schema_version: Literal[1] = 1
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    results: list[ScanResult] = Field(min_length=1)
    comparison: Comparison | None = None
    gate: GateResult | None = None
    duration_ms: float = 0.0
    cancelled: bool = False
    sessions: list[SessionState] = Field(default_factory=list)
    permissions: list[PermissionResult] = Field(default_factory=list)
    access_context: str | None = None

    @computed_field
    @property
    def severity_counts(self) -> dict[str, int]:
        return count_severities([f for result in self.results for f in result.findings])

    @computed_field
    @property
    def risk_rating(self) -> Severity:
        return highest_severity([f for result in self.results for f in result.findings])

    @computed_field
    @property
    def failed_targets(self) -> int:
        return sum(result.status != "complete" for result in self.results)

