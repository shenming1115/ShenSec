"""
ShenSec: A Python Package for Web Security Auditing and Result Analysis.
"""

from .api import scan_target, analyze_response, analyze_jwt, generate_report, ScanResult, Finding, Severity

__version__ = "0.2.0"

__all__ = [
    "scan_target",
    "analyze_response",
    "analyze_jwt",
    "generate_report",
    "ScanResult",
    "Finding",
    "Severity",
    "__version__"
]