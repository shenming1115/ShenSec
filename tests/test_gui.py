import pytest
import sys

pytest.importorskip("PySide6")

@pytest.fixture(scope="session")
def qapp():
    from PySide6.QtWidgets import QApplication
    app = QApplication.instance()
    if app is None:
        app = QApplication(sys.argv)
    return app

def test_gui_initial_state(qapp):
    from shensec.gui.main_window import MainWindow
    window = MainWindow()
    
    assert not window.btn_export_html.isEnabled()
    assert not window.btn_export_json.isEnabled()
    assert not window.btn_export_md.isEnabled()
    assert window.current_result is None

def test_gui_scan_error_clears_result(monkeypatch, qapp):
    from shensec.gui.main_window import MainWindow
    from shensec.models import ScanResult, Severity
    from PySide6.QtWidgets import QMessageBox

    window = MainWindow()

    # Simulate an existing successful state
    window.current_result = ScanResult(
        target_url="http://test.com",
        status_code=200,
        response_time_ms=10.0,
        findings=[],
        risk_rating=Severity.INFO,
        severity_counts={}
    )
    window.btn_export_html.setEnabled(True)
    window.btn_export_json.setEnabled(True)
    window.btn_export_md.setEnabled(True)

    # Prevent GUI popup during test
    monkeypatch.setattr(QMessageBox, "critical", lambda *args, **kwargs: None)  

    window.on_scan_error("Network Failure")

    assert window.current_result is None
    assert not window.btn_export_html.isEnabled()
    assert not window.btn_export_json.isEnabled()
    assert not window.btn_export_md.isEnabled()

def test_gui_start_scan_clears_result(monkeypatch, qapp):
    from shensec.gui.main_window import MainWindow

    class DummySignal:
        def connect(self, slot):
            pass

    class DummyWorker:
        def __init__(self, *args, **kwargs):
            self.finished_signal = DummySignal()
            self.error_signal = DummySignal()
        def start(self):
            pass

    import shensec.gui.main_window as mw
    monkeypatch.setattr(mw, "ScanWorker", DummyWorker)
    
    window = MainWindow()
    window.current_result = "FAKE_OLD_RESULT"  # type: ignore
    window.btn_export_html.setEnabled(True)
    
    window.url_input.setText("https://test.com")
    window.start_url_scan()
    
    assert window.current_result is None
    assert not window.btn_export_html.isEnabled()

def test_gui_app_reusability(qapp):
    from shensec.gui.app import run_gui
    # Run the GUI but in test mode so it doesn't block on app.exec()
    app, window = run_gui(test_mode=True)
    assert window is not None
    assert app is not None

def test_gui_filter_findings(qapp):
    from shensec.gui.main_window import MainWindow
    from shensec.models import Finding, Severity
    
    window = MainWindow()
    findings = [
        Finding(rule_id="R1", title="Title 1", description="Desc 1", severity=Severity.CRITICAL, recommendation="Rec 1"),
        Finding(rule_id="R2", title="Title 2", description="Desc 2", severity=Severity.MEDIUM, recommendation="Rec 2"),
    ]
    window._populate_table(findings)
    assert window.table.rowCount() == 2
    
    window.severity_filter.setCurrentIndex(1) # CRITICAL is at index 1
    window.apply_table_filter()
    
    # We find which row holds CRITICAL to be safe against sorting
    critical_row = 0 if window.table.item(0, 0).text() == "CRITICAL" else 1
    medium_row = 1 - critical_row

    assert not window.table.isRowHidden(critical_row)
    assert window.table.isRowHidden(medium_row)
    
    window.severity_filter.setCurrentIndex(0) # ALL
    window.apply_table_filter()
    assert not window.table.isRowHidden(0)
    assert not window.table.isRowHidden(1)

def test_gui_on_scan_finished(qapp, monkeypatch):
    from shensec.gui.main_window import MainWindow
    from shensec.models import ScanResult, Severity, Finding
    
    window = MainWindow()
    result = ScanResult(
        target_url="http://test.com",
        status_code=200,
        response_time_ms=10.0,
        findings=[Finding(rule_id="R1", title="Title 1", description="Desc", severity=Severity.CRITICAL, recommendation="Rec")],
        risk_rating=Severity.CRITICAL,
        severity_counts={"CRITICAL": 1, "HIGH": 0}
    )
    window.on_scan_finished(result)
    
    assert "Overall Risk: CRITICAL" in window.lbl_risk.text()
    assert "CRITICAL: 1" in window.lbl_counts.text()
    assert window.table.rowCount() == 1
    assert window.btn_export_html.isEnabled()

def test_gui_export_formats(qapp, monkeypatch):
    from shensec.gui.main_window import MainWindow
    from PySide6.QtWidgets import QFileDialog, QMessageBox
    import shensec.gui.main_window as mw
    
    window = MainWindow()
    window.current_result = "FAKE_RESULT"  # type: ignore
    
    mock_file_path = "mock/path/report.ext"
    monkeypatch.setattr(QFileDialog, "getSaveFileName", lambda *args, **kwargs: (mock_file_path, None))
    monkeypatch.setattr(QMessageBox, "information", lambda *args, **kwargs: None)
    
    class MockFile:
        def __init__(self, *args, **kwargs): pass
        def __enter__(self): return self
        def __exit__(self, *args): pass
        def write(self, data): self.data = data
    
    monkeypatch.setattr("builtins.open", MockFile)
    
    written_format = []
    def mock_generate_report(result, fmt):
        written_format.append(fmt)
        return "fake_content"
        
    monkeypatch.setattr(mw, "generate_report", mock_generate_report)
    
    window.export_html()
    assert "html" in written_format
    
    window.export_json()
    assert "json" in written_format
    
    window.export_md()
    assert "markdown" in written_format


def test_gui_search_includes_recommendation_and_reapplies_filter(qapp):
    from shensec.gui.main_window import MainWindow
    from shensec.models import Finding, Severity
    window = MainWindow()
    findings = [
        Finding(rule_id="A", title="First", description="Observation", severity=Severity.HIGH, recommendation="Rotate the signing key", evidence="Header absent"),
        Finding(rule_id="B", title="Second", description="Observation", severity=Severity.LOW),
    ]
    window.search_input.setText("signing key")
    window._populate_table(findings)
    visible = [window.table.item(row, 1).text() for row in range(window.table.rowCount()) if not window.table.isRowHidden(row)]
    assert visible == ["A"]
    window.table.selectRow(0)
    window.show_finding_details()
    assert "Rotate the signing key" in window.finding_details.toPlainText()
    assert "Header absent" in window.finding_details.toPlainText()


def test_gui_jwt_has_summary_and_exportable_result(qapp):
    from shensec.gui.main_window import MainWindow
    from shensec.models import Finding, Severity
    window = MainWindow()
    window.on_jwt_finished([Finding(rule_id="JWT", title="Test", description="Observation", severity=Severity.CRITICAL)])
    assert window.current_result.scan_kind == "jwt"
    assert window.current_result.risk_rating == Severity.CRITICAL
    assert "CRITICAL: 1" in window.lbl_counts.text()
    assert window.btn_export_html.isEnabled()
    assert window.btn_export_json.isEnabled()


def test_gui_failed_scan_is_not_presented_as_clean(qapp):
    from shensec.gui.main_window import MainWindow
    from shensec.models import ScanResult
    window = MainWindow()
    window.on_scan_finished(ScanResult(target_url="https://test/", status_code=0, response_time_ms=1, error="Network failure"))
    assert "ERROR" in window.lbl_risk.text()
    assert "Network failure" in window.lbl_risk.toolTip()

