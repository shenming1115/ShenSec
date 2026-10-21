"""
ShenSec: repeatable security configuration audits and regression analysis.
"""

__version__ = "0.5.0b1"

from .api import (
    scan_target, analyze_response, analyze_jwt, inspect_jwt, generate_report,
    scan_many, compare_audits, evaluate_gate, load_baseline,
    ScanResult, AuditResult, Comparison, GateResult, Finding, Severity,
    audit_project, AuthConfig, resolve_auth, ProjectConfig, load_project, Workspace,
    RequestSpec, NetworkPolicy, RuleException, import_openapi,
    LoginConfig, RoleConfig, PermissionCase, SessionState, PermissionResult,
)

__all__ = [
    "scan_target",
    "analyze_response",
    "analyze_jwt",
    "generate_report",
    "ScanResult",
    "Finding",
    "Severity",
    "inspect_jwt",
    "scan_many",
    "compare_audits",
    "evaluate_gate",
    "load_baseline",
    "AuditResult",
    "Comparison",
    "GateResult",
    "audit_project", "AuthConfig", "resolve_auth", "ProjectConfig", "load_project", "Workspace",
    "__version__", "RequestSpec", "NetworkPolicy", "RuleException", "import_openapi",
    "LoginConfig", "RoleConfig", "PermissionCase", "SessionState", "PermissionResult",
]
