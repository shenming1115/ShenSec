"""
Public API for ShenSec.
Provides easy access to core scanning and reporting functionalities.
"""
from .scanner.core import scan_target, analyze_response
from .scanner.jwt import analyze_jwt, inspect_jwt
from .audit import audit_project, scan_many, compare_audits, evaluate_gate, load_baseline
from .auth import AuthConfig, resolve_auth
from .project import ProjectConfig, load_project
from .workspace import Workspace
from .reporting.formatters import generate_report
from .models import AuditResult, Comparison, GateResult, ScanResult, Finding, Severity
from .requests import RequestSpec
from .network import NetworkPolicy
from .policy import RuleException
from .openapi import import_openapi
from .login_config import LoginConfig
from .access import RoleConfig, PermissionCase
from .models import SessionState, PermissionResult

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
    "RequestSpec", "NetworkPolicy", "RuleException", "import_openapi",
    "LoginConfig", "RoleConfig", "PermissionCase", "SessionState", "PermissionResult",
]
