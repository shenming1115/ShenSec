"""Standalone desktop entry point. No shell, package manager or console required."""

import argparse
import json
import os
from pathlib import Path
import sys


def self_test(output: Path):
    """Exercise the shipped Qt runtime, login transport, storage and report assets."""
    from tempfile import TemporaryDirectory
    from .gui.app import run_gui
    from .identity_demo import demo_workspace
    from .reporting.formatters import generate_report
    from .workspace import Workspace
    from . import __version__

    output.mkdir(parents=True, exist_ok=True)
    with TemporaryDirectory(prefix="shensec-check-") as root:
        with demo_workspace(root) as (workspace, project, before, current):
            assert before.gate.outcome == "failed"
            assert current.gate.outcome == "passed"
            assert len(current.permissions) == 8
            assert all(item.outcome == "passed" for item in current.permissions)
            app, window = run_gui(test_mode=True, workspace=Workspace(root))
            window.show()
            window.workbench.result_tabs.setCurrentWidget(window.workbench.access_results)
            app.processEvents()
            assert window.workbench.history.count() == 2
            assert window.grab().save(str(output / "desktop.png"))
            for kind, suffix in (("html", "html"), ("json", "json"), ("markdown", "md"), ("sarif", "sarif")):
                (output / f"audit.{suffix}").write_text(generate_report(current, kind), encoding="utf-8")
            window.close()
            app.processEvents()
            from . import desktop
            result = {"version": __version__, "frozen": bool(getattr(sys, "frozen", False)),
                      "module": desktop.__file__, "permissions": 8, "history_runs": 2,
                      "gate": current.gate.outcome, "renewals": sum(s.renewals for s in current.sessions)}
            (output / "result.json").write_text(json.dumps(result, indent=2), encoding="utf-8")
    return 0


def main(argv=None):
    parser = argparse.ArgumentParser(description="ShenSec desktop workbench")
    parser.add_argument("--workspace", type=Path, help="Use another local workspace folder")
    parser.add_argument("--self-test", type=Path, metavar="OUTPUT", help="Run the isolated release verification and write reports")
    args = parser.parse_args(argv)
    try:
        if args.self_test:
            return self_test(args.self_test.resolve())
        from .gui.app import run_gui
        run_gui(workspace=args.workspace)
        return 0
    except Exception as exc:
        # A windowed executable has no stderr. Record only the exception type and
        # code locations: raw exception strings may contain credentials/URLs.
        import traceback
        root = args.workspace or Path(os.environ.get("SHENSEC_HOME", str(Path.home() / ".shensec")))
        message = "ShenSec could not start. Try a writable workspace and see the startup log."
        try:
            root.mkdir(parents=True, exist_ok=True)
            locations = [f"{Path(frame.filename).name}:{frame.lineno} in {frame.name}" for frame in traceback.extract_tb(exc.__traceback__)]
            (root / "startup-error.log").write_text(type(exc).__name__ + "\n" + "\n".join(locations), encoding="utf-8")
            message += f"\n\n{root / 'startup-error.log'}"
        except OSError:
            pass
        if args.self_test:
            args.self_test.mkdir(parents=True, exist_ok=True)
            detail = str(exc) if isinstance(exc, ImportError) else "See startup-error.log for code locations."
            (args.self_test / "error.json").write_text(json.dumps({"type": type(exc).__name__, "detail": detail}), encoding="utf-8")
            return 1
        try:
            from PySide6.QtWidgets import QApplication, QMessageBox
            app = QApplication.instance() or QApplication([])
            QMessageBox.critical(None, "ShenSec startup", message)
        except Exception:
            if sys.platform == "win32":
                import ctypes
                ctypes.windll.user32.MessageBoxW(None, message, "ShenSec startup", 0x10)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
