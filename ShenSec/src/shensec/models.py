from enum import Enum
from pydantic import BaseModel, Field
from typing import List, Optional

class Severity(str, Enum):
    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

class Finding(BaseModel):
    rule_id: str
    title: str
    description: str
    severity: Severity
    recommendation: Optional[str] = None

class ScanResult(BaseModel):
    target_url: str
    status_code: int
    response_time_ms: float
    findings: List[Finding] = Field(default_factory=list)
    risk_rating: Severity = Severity.INFO
    severity_counts: dict[str, int] = Field(default_factory=dict)

