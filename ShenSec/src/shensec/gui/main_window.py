import sys
from PySide6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QLabel, QLineEdit, QPushButton, QDoubleSpinBox, QTableWidget,
    QTableWidgetItem, QHeaderView, QGroupBox, QMessageBox, QFileDialog, QTabWidget,
    QComboBox
)
from PySide6.QtCore import Qt
from PySide6.QtGui import QColor, QFont
from .worker import ScanWorker, JwtWorker
from ..api import ScanResult, generate_report, Severity

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("ShenSec - Web Security Auditor")
        self.resize(900, 700)

        self.current_result: ScanResult | None = None
        
        self._init_ui()

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
        filter_layout.addStretch()
        details_layout.addLayout(filter_layout)

        self.table = QTableWidget(0, 4)
        self.table.setHorizontalHeaderLabels(["Severity", "Rule ID", "Title", "Description"])
        self.table.horizontalHeader().setSectionResizeMode(3, QHeaderView.Stretch)
        self.table.setWordWrap(True)
        self.table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.table.setSelectionBehavior(QTableWidget.SelectRows)
        details_layout.addWidget(self.table)

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

        self.setCentralWidget(main_widget)

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
        self.current_result = None # JWT uses a list, not ScanResult. Disable report generation for now.
        self.lbl_risk.setText("JWT Analysis Complete")
        self.lbl_counts.setText(f"Total Findings: {len(findings)}")
        self.btn_export_html.setEnabled(False)
        self.btn_export_json.setEnabled(False)
        self.btn_export_md.setEnabled(False)
        self._populate_table(findings)
        self._set_ui_enabled(True)

    def on_scan_error(self, error_msg: str):
        QApplication.restoreOverrideCursor()
        self.current_result = None
        self.btn_export_html.setEnabled(False)
        self.btn_export_json.setEnabled(False)
        self.btn_export_md.setEnabled(False)
        QMessageBox.critical(self, "Scan Error", f"An error occurred:\n{error_msg}")
        self.lbl_risk.setText("Scan Failed")
        self._set_ui_enabled(True)

    def _populate_overview(self):
        if not self.current_result:
            return

        rating = self.current_result.risk_rating.value
        self.lbl_risk.setText(f"Overall Risk: {rating}")
        
        # Color code the rating
        color_map = {
            "CRITICAL": "red",
            "HIGH": "orange",
            "MEDIUM": "goldenrod",
            "LOW": "green",
            "INFO": "blue"
        }
        color = color_map.get(rating, "black")
        self.lbl_risk.setStyleSheet(f"color: {color};")
        
        counts = self.current_result.severity_counts
        self.lbl_counts.setText(
            f"CRITICAL: {counts.get('CRITICAL', 0)} | "
            f"HIGH: {counts.get('HIGH', 0)} | "
            f"MEDIUM: {counts.get('MEDIUM', 0)} | "
            f"LOW: {counts.get('LOW', 0)} | "
            f"INFO: {counts.get('INFO', 0)}"
        )

    def _populate_table(self, findings):
        self.table.setSortingEnabled(False)
        self.table.setRowCount(len(findings))
        for row, f in enumerate(findings):
            item_sev = QTableWidgetItem(f.severity.value)
            # Useful to sort by severity impact internally if we map it, but text sorting works for now
            item_id = QTableWidgetItem(f.rule_id)
            item_title = QTableWidgetItem(f.title)
            item_desc = QTableWidgetItem(f.description)

            # Optional color-coding for table cells
            color_map = {
                Severity.CRITICAL: QColor(255, 200, 200),
                Severity.HIGH: QColor(255, 228, 181),
                Severity.MEDIUM: QColor(255, 250, 205),
                Severity.LOW: QColor(200, 255, 200),
                Severity.INFO: QColor(200, 200, 255),
            }
            bg_color = color_map.get(f.severity)

            # Use dark text for better readability on light backgrounds (since background colors are very pale/light)
            dark_text_color = QColor(0, 0, 0)

            if bg_color:
                for item in (item_sev, item_id, item_title, item_desc):
                    item.setBackground(bg_color)
                    item.setForeground(dark_text_color)

            self.table.setItem(row, 0, item_sev)
            self.table.setItem(row, 1, item_id)
            self.table.setItem(row, 2, item_title)
            self.table.setItem(row, 3, item_desc)

        self.table.resizeRowsToContents()
        self.table.setSortingEnabled(True)
        if findings:
            self.table.selectRow(0)
            

    def apply_table_filter(self):
        target_sev = self.severity_filter.currentText().upper()
        for row in range(self.table.rowCount()):
            item_sev = self.table.item(row, 0)
            if item_sev:
                if target_sev == "ALL" or item_sev.text().upper() == target_sev:
                    self.table.setRowHidden(row, False)
                else:
                    self.table.setRowHidden(row, True)

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