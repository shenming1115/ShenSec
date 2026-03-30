import pytest
from typer.testing import CliRunner
from shensec.cli import app
import sys

import builtins

runner = CliRunner()

def test_cli_gui_no_dependency(monkeypatch):
    """
    Test GUI launch fails gracefully when PySide6 is not present.
    We simulate this by mocking the import statement to raise ImportError.
    """
    original_import = builtins.__import__

    def mock_import(name, *args, **kwargs):
        if "gui.app" in name or name == "shensec.gui.app":
            raise ImportError("No module named 'shensec.gui.app'")
        return original_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", mock_import)

    result = runner.invoke(app, ["gui"])
    # It might actually fail or just return the exit code 1
    assert result.exit_code == 1
    assert "Failed to load GUI" in result.stdout
    assert "pip install shensec[gui]" in result.stdout

def test_cli_help():
    """Test the CLI help command."""
    result = runner.invoke(app, ["--help"])
    assert result.exit_code == 0
    assert "ShenSec" in result.stdout
    assert "scan" in result.stdout
    assert "gui" in result.stdout
