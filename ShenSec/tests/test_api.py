import pytest
from shensec.api import scan_target, analyze_response, analyze_jwt, generate_report, ScanResult, Finding, Severity

def test_api_exports():
    """Test that all expected functions and classes are exported by the API."""
    assert scan_target is not None
    assert analyze_response is not None
    assert analyze_jwt is not None
    assert generate_report is not None
    assert ScanResult is not None
    assert Finding is not None
    assert Severity is not None

def test_shensec_init_exports():
    """Test that __init__.py exports the proper API correctly."""
    import shensec
    assert hasattr(shensec, 'scan_target')
    assert hasattr(shensec, 'analyze_response')
    assert hasattr(shensec, 'analyze_jwt')
    assert hasattr(shensec, 'generate_report')
    assert hasattr(shensec, 'ScanResult')
    assert hasattr(shensec, 'Finding')
    assert hasattr(shensec, 'Severity')
