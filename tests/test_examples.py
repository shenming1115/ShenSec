import pytest
import os
import sys

def test_basic_usage_import():
    """Test that the example file doesn't have any import errors."""
    example_path = os.path.join(os.path.dirname(__file__), "..", "examples")
    sys.path.insert(0, example_path)
    
    try:
        import basic_usage
        assert callable(basic_usage.main)
    finally:
        sys.path.pop(0)

def test_imports_match_readme():
    """Test that imports mentioned in README are valid."""
    from shensec import scan_target, analyze_response, analyze_jwt, generate_report
    assert callable(scan_target)
    assert callable(analyze_response)
    assert callable(analyze_jwt)
    assert callable(generate_report)
