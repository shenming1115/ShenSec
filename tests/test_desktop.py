"""Exercise demo lifecycle through the actual desktop action and event loop."""
import os
from pathlib import Path
from time import monotonic

import pytest
pytest.importorskip("PySide6")
from PySide6.QtCore import QEventLoop, QTimer
from shensec.gui.app import run_gui


def pump_until(app, predicate, timeout=20):
    deadline = monotonic() + timeout
    while not predicate() and monotonic() < deadline:
        app.processEvents(QEventLoop.AllEvents, 20)
    assert predicate(), "Desktop did not reach the expected state"


def test_demo_action_keeps_history_separate_and_cleans_up(tmp_path):
    saved = os.environ.get("IDENTITY_PASSWORD")
    app, window = run_gui(test_mode=True, workspace=tmp_path)
    window.show()
    ticks = []
    timer = QTimer()
    timer.timeout.connect(lambda: ticks.append(1))
    timer.start(25)
    window.demo_action.trigger()
    pump_until(app, lambda: window.demo_window is not None or window.demo_worker is None)
    assert window.demo_window is not None, window.statusBar().currentMessage()
    demo = window.demo_window
    root = demo.workbench.workspace.root
    assert root != Path(tmp_path)
    assert not window.workbench.workspace.list_projects()
    assert demo.workbench.history.count() == 2
    assert len(ticks) > 3, "Local demo blocked the main event loop"
    assert demo.workbench.audit.gate.outcome == "passed"
    demo.close()
    pump_until(app, lambda: window.demo_worker is None)
    assert not root.exists()
    assert os.environ.get("IDENTITY_PASSWORD") == saved
    assert window.demo_action.isEnabled()
    timer.stop()
    window.close()


def test_close_during_demo_preparation_waits_for_cleanup(tmp_path):
    app, window = run_gui(test_mode=True, workspace=tmp_path)
    window.show()
    window.start_demo()
    worker = window.demo_worker
    finished = []
    worker.finished.connect(lambda: finished.append(True))
    window.close()
    assert window._close_requested
    pump_until(app, lambda: window.demo_worker is None and not window.isVisible())
    assert finished
