"""Expiring, scoped rule exceptions that retain the original evidence."""

from datetime import date
from fnmatch import fnmatchcase

from pydantic import BaseModel, ConfigDict, Field, field_validator

from .models import AuditResult


def literal_target_pattern(url: str) -> str:
    """A GUI acceptance is scoped to this exact URL, including query metacharacters."""
    return ''.join({'[': '[[]', '*': '[*]', '?': '[?]'}.get(char, char) for char in url)


class RuleException(BaseModel):
    model_config = ConfigDict(extra="forbid")
    rule_id: str = Field(pattern=r"^SEC-[A-Z0-9-]+$")
    target: str = Field(min_length=1, max_length=4096)
    reason: str = Field(min_length=8, max_length=1000)
    expires: date

    @field_validator("reason")
    @classmethod
    def meaningful_reason(cls, value):
        value = value.strip()
        if len(value) < 8:
            raise ValueError("Give a reason of at least 8 non-padding characters.")
        return value


def apply_exceptions(audit: AuditResult, exceptions: list[RuleException], *, today: date | None = None):
    today = today or date.today()
    for result in audit.results:
        for finding in result.findings:
            finding.suppression = None
            if finding.rule_id == "SEC-SCAN-ERR":
                continue
            for exception in exceptions:
                if exception.expires >= today and exception.rule_id == finding.rule_id and fnmatchcase(result.target_url, exception.target):
                    finding.suppression = f"{exception.reason} (expires {exception.expires.isoformat()})"
                    break
