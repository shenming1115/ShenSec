import sys
from PySide6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QLabel, QLineEdit, QPushButton, QDoubleSpinBox, QTableWidget,
    QTableWidgetItem, QHeaderView, QGroupBox, QMessageBox, QFileDialog, QTabWidget,
    QComboBox, QPlainTextEdit
)
from PySide6.QtCore import Qt, Signal, QUrl, QTimer
from PySide6.QtGui import QColor, QFont, QDesktopServices
from pathlib import Path
from .worker import ScanWorker, JwtWorker
from ..api import ScanResult, generate_report, Severity
from ..models import SEVERITY_RANK
from .workbench import Workbench


class SeverityItem(QTableWidgetItem):
    def __lt__(self, other):
        return SEVERITY_RANK[Severity(self.text())] < SEVERITY_RANK[Severity(other.text())]

class MainWindow(QMainWindow):
    closed = Signal()

    def __init__(self, workspace=None):
        super().__init__()
        self.setWindowTitle("ShenSec — Security Regression Workbench")
        self.resize(1320, 900)
        self.workspace = workspace
        self.demo_worker = self.demo_window = None
        self._close_requested = False

        self.current_result: ScanResult | None = None
        
        self._init_ui()
        toolbar = self.addToolBar("Get started")
        toolbar.setMovable(False)
        self.demo_action = toolbar.addAction("Try local demo", self.start_demo)
        toolbar.addAction("User guide", self.open_guide)
        toolbar.addAction("Open history folder", self.open_history_folder)

    def open_guide(self):
        guide = Path(__file__).resolve().parents[1] / "resources" / "desktop-guide.html"
        QDesktopServices.openUrl(QUrl.fromLocalFile(str(guide)))

    def open_history_folder(self):
        root = self.workbench.workspace.root
        root.mkdir(parents=True, exist_ok=True)
        QDesktopServices.openUrl(QUrl.fromLocalFile(str(root.resolve())))

    def start_demo(self):
        if self.demo_worker is not None:
            if self.demo_window:
                self.demo_window.showNormal()
                self.demo_window.raise_()
                self.demo_window.activateWindow()
            return
        from .demo_worker import DemoWorker
        self.demo_action.setEnabled(False)
        self.statusBar().showMessage("Preparing local demo: login, renew sessions, compare four roles…")
        self.demo_worker = DemoWorker(self)
        self.demo_worker.ready.connect(self._demo_ready)
        self.demo_worker.error.connect(lambda text: self.statusBar().showMessage(text))
        self.demo_worker.finished.connect(self._demo_finished)
        self.demo_worker.start()

    def _demo_ready(self, result):
        if self._close_requested:
            self.demo_worker.stop()
            return
        workspace, _, _, _ = result
        self.demo_window = MainWindow(workspace=workspace)
        self.demo_window.setWindowTitle("ShenSec — Local demo · temporary history")
        self.demo_window.demo_action.setEnabled(False)
        self.demo_window.closed.connect(self.demo_worker.stop)
        self.demo_window.workbench.result_tabs.setCurrentWidget(self.demo_window.workbench.access_results)
        self.demo_window.statusBar().showMessage("Demo only · 4 roles × 2 endpoints · 3 fixed access violations. Select the older run to compare. Closing this window removes demo data.")
        self.demo_window.show()
        self.statusBar().showMessage("Local demo is open in a separate window. Your projects stay in this workspace.")

    def _demo_finished(self):
        worker = self.demo_worker
        self.demo_worker = self.demo_window = None
        worker.deleteLater()
        self.demo_action.setEnabled(True)
        if self._close_requested:
            QTimer.singleShot(0, self.close)

    def _init_ui(self):
        main_widget = QWidget()
        main_layout = QVBoxLayout(main_widget)

        # === Input Area ===
        input_group = QGroupBox("Scan Configuration")
        input_layout = QVBoxLayout(input_group)

        # Tab widget for URL vs JWT scanning
        self.tabs = QTabWidget()
        
        # URL Data
        url_tab = QWidget()
        url_layout = QHBoxLayout(url_tab)
        url_layout.setAlignment(Qt.AlignTop)
        url_layout.addWidget(QLabel("Target URL:"))
        self.url_input = QLineEdit()
        self.url_input.setPlaceholderText("https://example.com")
        url_layout.addWidget(self.url_input)
        url_layout.addWidget(QLabel("Timeout (s):"))
        self.timeout_input = QDoubleSpinBox()
        self.timeout_input.setRange(1.0, 60.0)
        self.timeout_input.setValue(10.0)
        url_layout.addWidget(self.timeout_input)
        
        self.btn_scan = QPushButton("Start Scan")
        self.btn_scan.clicked.connect(self.start_url_scan)
        url_layout.addWidget(self.btn_scan)

        # JWT Data
        jwt_tab = QWidget()
        jwt_layout = QHBoxLayout(jwt_tab)
        jwt_layout.setAlignment(Qt.AlignTop)
        jwt_layout.addWidget(QLabel("JWT Token:"))
        self.jwt_input = QLineEdit()
        self.jwt_input.setPlaceholderText("eyJhbGci...")
        self.jwt_input.setEchoMode(QLineEdit.Password)
        jwt_layout.addWidget(self.jwt_input)

        self.btn_jwt_scan = QPushButton("Analyze JWT")
        self.btn_jwt_scan.clicked.connect(self.start_jwt_scan)
        jwt_layout.addWidget(self.btn_jwt_scan)

        self.tabs.addTab(url_tab, "URL Scanner")
        self.tabs.addTab(jwt_tab, "JWT Analyzer")
        input_layout.addWidget(self.tabs)
        main_layout.addWidget(input_group)

        # === Overview Area ===
        overview_group = QGroupBox("Scan Overview")
        overview_layout = QVBoxLayout(overview_group)
        
        counts_layout = QHBoxLayout()
        self.lbl_risk = QLabel("Overall Risk: N/A")
        font = QFont()
        font.setPointSize(12)
        font.setBold(True)
        self.lbl_risk.setFont(font)
        counts_layout.addWidget(self.lbl_risk)
        counts_layout.addStretch()

        self.lbl_counts = QLabel("CRITICAL: 0 | HIGH: 0 | MEDIUM: 0 | LOW: 0 | INFO: 0")
        counts_layout.addWidget(self.lbl_counts)
        overview_layout.addLayout(counts_layout)
        main_layout.addWidget(overview_group)

        # === Details Area ===
        details_group = QGroupBox("Findings")
        details_layout = QVBoxLayout(details_group)

        # Filter UI
        filter_layout = QHBoxLayout()
        filter_layout.addWidget(QLabel("Filter by Severity:"))
        self.severity_filter = QComboBox()
        self.severity_filter.addItems(["ALL", "CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"])
        self.severity_filter.currentTextChanged.connect(self.apply_table_filter)
        filter_layout.addWidget(self.severity_filter)
        self.search_input = QLineEdit()
        self.search_input.setPlaceholderText("Search rule, title, evidence, or recommended action...")
        self.search_input.textChanged.connect(self.apply_table_filter)
        filter_layout.addWidget(self.search_input)
        filter_layout.addStretch()
        details_layout.addLayout(filter_layout)

        self.table = QTableWidget(0, 4)
        self.table.setHorizontalHeaderLabels(["Severity", "Rule ID", "Title", "Description"])
        self.table.horizontalHeader().setSectionResizeMode(3, QHeaderView.Stretch)
        self.table.setWordWrap(True)
        self.table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.table.setSelectionBehavior(QTableWidget.SelectRows)
        self.table.itemSelectionChanged.connect(self.show_finding_details)
        details_layout.addWidget(self.table)

        self.finding_details = QPlainTextEdit()
        self.finding_details.setReadOnly(True)
        self.finding_details.setPlaceholderText("Select a finding to view its evidence and recommended action.")
        self.finding_details.setMaximumHeight(165)
        details_layout.addWidget(self.finding_details)

        main_layout.addWidget(details_group)

        # === Options Area ===
        options_layout = QHBoxLayout()
        self.btn_export_html = QPushButton("Export HTML")
        self.btn_export_html.setEnabled(False)
        self.btn_export_html.clicked.connect(self.export_html)
        options_layout.addWidget(self.btn_export_html)
        
        self.btn_export_json = QPushButton("Export JSON")
        self.btn_export_json.setEnabled(False)
        self.btn_export_json.clicked.connect(self.export_json)
        options_layout.addWidget(self.btn_export_json)
        
        self.btn_export_md = QPushButton("Export Markdown")
        self.btn_export_md.setEnabled(False)
        self.btn_export_md.clicked.connect(self.export_md)
        options_layout.addWidget(self.btn_export_md)

        options_layout.addStretch()
        main_layout.addLayout(options_layout)

        self.pages = QTabWidget()
        self.workbench = Workbench(self.workspace, self)
        self.pages.addTab(self.workbench, "Project workbench")
        self.pages.addTab(main_widget, "Quick scan && JWT")
        self.setCentralWidget(self.pages)

    def _set_ui_enabled(self, enabled: bool):
        self.btn_scan.setEnabled(enabled)
        self.btn_jwt_scan.setEnabled(enabled)
        self.url_input.setEnabled(enabled)
        self.jwt_input.setEnabled(enabled)
        if self.current_result:
            self.btn_export_html.setEnabled(enabled)
            self.btn_export_json.setEnabled(enabled)
            self.btn_export_md.setEnabled(enabled)

    def start_url_scan(self):
        target = self.url_input.text().strip()
        if not target:
            QMessageBox.warning(self, "Input Error", "Please enter a target URL.")
            return

        self.current_result = None
        self.btn_export_html.setEnabled(False)
        self.btn_export_json.setEnabled(False)
        self.btn_export_md.setEnabled(False)

        self._set_ui_enabled(False)
        QApplication.setOverrideCursor(Qt.WaitCursor)
        self.lbl_risk.setText("Scanning...")
        self.lbl_risk.setStyleSheet("color: blue;")
        self.table.setRowCount(0)

        self.worker = ScanWorker(target_url=target, timeout=self.timeout_input.value())
        self.worker.finished_signal.connect(self.on_scan_finished)
        self.worker.error_signal.connect(self.on_scan_error)
        self.worker.start()

    def start_jwt_scan(self):
        token = self.jwt_input.text().strip()
        if not token:
            QMessageBox.warning(self, "Input Error", "Please enter a JWT token.")
            return

        self.current_result = None
        self.btn_export_html.setEnabled(False)
        self.btn_export_json.setEnabled(False)
        self.btn_export_md.setEnabled(False)

        self._set_ui_enabled(False)
        QApplication.setOverrideCursor(Qt.WaitCursor)
        self.lbl_risk.setText("Analyzing JWT...")
        self.lbl_risk.setStyleSheet("color: blue;")
        self.table.setRowCount(0)

        self.jwt_worker = JwtWorker(token)
        self.jwt_worker.finished_signal.connect(self.on_jwt_finished)
        self.jwt_worker.error_signal.connect(self.on_scan_error)
        self.jwt_worker.start()

    def on_scan_finished(self, result: ScanResult):
        QApplication.restoreOverrideCursor()
        self.current_result = result
        self._populate_overview()
        self._populate_table(result.findings)
        self.btn_export_html.setEnabled(True)
        self.btn_export_json.setEnabled(True)
        self.btn_export_md.setEnabled(True)
        self._set_ui_enabled(True)

    def on_jwt_finished(self, findings):
        QApplication.restoreOverrideCursor()
        self.current_result = ScanResult(
            target_url="local JWT", status_code=0, response_time_ms=0.0,
            scan_kind="jwt", findings=findings, checks=["jwt"],
        )
        self._populate_overview()
        self._populate_table(findings)
        self._set_ui_enabled(True)

    def on_scan_error(self, error_msg: str):
        QApplication.restoreOverrideCursor()
        self.current_result = None
        self.btn_export_html.setEnabled(False)
        self.btn_export_json.setEnabled(False)
        self.btn_export_md.setEnabled(False)
        self.table.setRowCount(0)
        self.finding_details.clear()
        self.lbl_counts.setText("No complete result")
        QMessageBox.critical(self, "Scan Error", f"An error occurred:\n{error_msg}")
        self.lbl_risk.setText("Scan Failed")
        self._set_ui_enabled(True)

    def closeEvent(self, event):
        if self.workbench.is_running():
            self.workbench.worker.finished.connect(self.close)
            self.workbench.cancel()
            event.ignore()
            return
        # Destroying a running QThread can abort the process.
        for name in ("worker", "jwt_worker"):
            worker = getattr(self, name, None)
            if worker is not None and worker.isRunning():
                self.statusBar().showMessage("Wait for the current inspection to finish before closing.")
                event.ignore()
                return
        self.workbench.clear_session()
        if self.demo_worker is not None and self.demo_worker.isRunning():
            self._close_requested = True
            if self.demo_window is not None:
                self.demo_window.close()
            else:
                self.demo_worker.stop()
            event.ignore()
            return
        self.closed.emit()
        event.accept()

    def _populate_overview(self):
        if not self.current_result:
            return

        rating = self.current_result.risk_rating.value
        self.lbl_risk.setText(
            f"Overall Risk: {rating}" if self.current_result.status == "complete"
            else f"Scan {self.current_result.status.upper()} — observed risk: {rating}"
        )
        self.lbl_risk.setToolTip(self.current_result.error or '\n'.join(self.current_result.warnings))
        
        # Dark theme compatible colors for the Risk Label
        color_map = {
            "CRITICAL": "#ff5555",
            "HIGH": "#ffaa00",
            "MEDIUM": "#f0e68c",
            "LOW": "#55ff55",
            "INFO": "#55aaff"
        }
        color = color_map.get(rating, "white")
        # Add a subtle background pill-style look to the label
        self.lbl_risk.setStyleSheet(f"""
            QLabel {{
                color: {color};
                background-color: rgba(255, 255, 255, 0.1);
                padding: 4px 8px;
                border-radius: 4px;
                border: 1px solid {color};
            }}
        """)

        counts = self.current_result.severity_counts
        # Add formatting to counts
        self.lbl_counts.setText(
            f"<span style='color:#ff5555; font-weight:bold;'>CRITICAL: {counts.get('CRITICAL', 0)}</span> &nbsp;|&nbsp; "
            f"<span style='color:#ffaa00; font-weight:bold;'>HIGH: {counts.get('HIGH', 0)}</span> &nbsp;|&nbsp; "
            f"<span style='color:#f0e68c; font-weight:bold;'>MEDIUM: {counts.get('MEDIUM', 0)}</span> &nbsp;|&nbsp; "
            f"<span style='color:#55ff55; font-weight:bold;'>LOW: {counts.get('LOW', 0)}</span> &nbsp;|&nbsp; "
            f"<span style='color:#55aaff; font-weight:bold;'>INFO: {counts.get('INFO', 0)}</span>"
        )

    def _populate_table(self, findings):
        self.finding_details.clear()
        self.table.setSortingEnabled(False)
        self.table.setRowCount(len(findings))
        for row, f in enumerate(findings):
            item_sev = SeverityItem(f.severity.value)
            item_sev.setData(Qt.UserRole, f)
            # Center the severity column just to be fancy
            item_sev.setTextAlignment(Qt.AlignCenter)
            item_id = QTableWidgetItem(f.rule_id)
            item_title = QTableWidgetItem(f.title)
            item_desc = QTableWidgetItem(f.description)

            # Dark theme appropriate typography colors instead of backgrounds
            color_map = {
                Severity.CRITICAL: QColor(255, 85, 85),
                Severity.HIGH: QColor(255, 170, 0),
                Severity.MEDIUM: QColor(240, 230, 140),
                Severity.LOW: QColor(85, 255, 85),
                Severity.INFO: QColor(85, 170, 255),
            }
            fg_color = color_map.get(f.severity)

            if fg_color:
                for item in (item_sev, item_id, item_title, item_desc):
                    item.setForeground(fg_color)
                
                # Make the severity column bold
                font = item_sev.font()
                font.setBold(True)
                item_sev.setFont(font)

            self.table.setItem(row, 0, item_sev)
            self.table.setItem(row, 1, item_id)
            self.table.setItem(row, 2, item_title)
            self.table.setItem(row, 3, item_desc)

        self.table.resizeRowsToContents()
        self.table.setSortingEnabled(True)
        self.apply_table_filter()
        if findings:
            self.table.selectRow(0)
            

    def apply_table_filter(self):
        target_sev = self.severity_filter.currentText().upper()
        query = self.search_input.text().strip().casefold()
        for row in range(self.table.rowCount()):
            item_sev = self.table.item(row, 0)
            if item_sev:
                finding = item_sev.data(Qt.UserRole)
                text = ' '.join(str(value or '') for value in (
                    finding.rule_id, finding.title, finding.description,
                    finding.evidence, finding.recommendation, finding.location,
                )).casefold()
                if (target_sev == "ALL" or item_sev.text().upper() == target_sev) and query in text:
                    self.table.setRowHidden(row, False)
                else:
                    self.table.setRowHidden(row, True)

    def show_finding_details(self):
        row = self.table.currentRow()
        item = self.table.item(row, 0) if row >= 0 else None
        if item is None:
            self.finding_details.clear()
            return
        finding = item.data(Qt.UserRole)
        self.finding_details.setPlainText(
            f"{finding.severity.value} · {finding.rule_id} · {finding.title}\n\n"
            f"{finding.description}\n\n"
            f"Evidence: {finding.evidence or 'Not recorded'}\n"
            f"Location: {finding.location or 'Current target'}\n\n"
            f"Recommended action: {finding.recommendation or 'Review in application context.'}"
        )

    def export_html(self):
        if not self.current_result:
            return
        path, _ = QFileDialog.getSaveFileName(self, "Export HTML Report", "report.html", "HTML Files (*.html)")
        if path:
            report = generate_report(self.current_result, "html")
            with open(path, "w", encoding="utf-8") as f:
                f.write(report)
            QMessageBox.information(self, "Export Successful", f"HTML report exported to:\n{path}")

    def export_json(self):
        if not self.current_result:
            return
        path, _ = QFileDialog.getSaveFileName(self, "Export JSON Report", "report.json", "JSON Files (*.json)")
        if path:
            report = generate_report(self.current_result, "json")
            with open(path, "w", encoding="utf-8") as f:
                f.write(report)
            QMessageBox.information(self, "Export Successful", f"JSON report exported to:\n{path}")

    def export_md(self):
        if not self.current_result:
            return
        path, _ = QFileDialog.getSaveFileName(self, "Export Markdown Report", "report.md", "Markdown Files (*.md)")
        if path:
            report = generate_report(self.current_result, "markdown")
            with open(path, "w", encoding="utf-8") as f:
                f.write(report)
            QMessageBox.information(self, "Export Successful", f"Markdown report exported to:\n{path}")
