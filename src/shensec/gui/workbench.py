"""Project-first desktop workflow: configure, audit, review, accept a baseline."""

from pathlib import Path
import sqlite3
import json
from datetime import date, timedelta

from pydantic import ValidationError
from PySide6.QtCore import Qt, QTimer
from PySide6.QtGui import QColor, QKeySequence, QShortcut
from PySide6.QtWidgets import (
    QAbstractItemView, QCheckBox, QComboBox, QDoubleSpinBox, QFileDialog,
    QFormLayout, QHBoxLayout, QHeaderView, QInputDialog, QLabel, QLineEdit, QListWidget,
    QListWidgetItem, QMessageBox, QPlainTextEdit, QProgressBar, QPushButton,
    QScrollArea, QSpinBox, QSplitter, QTableView, QTableWidget,
    QTableWidgetItem, QTabWidget, QVBoxLayout, QWidget,
)

from ..audit import compare_audits, evaluate_gate
from ..auth import AuthConfig, origin, resolve_auth
from ..models import AuditResult, Severity
from ..project import ProjectConfig, load_project, project_toml, validation_message
from ..reporting.formatters import generate_report
from ..targets import parse_targets
from ..workspace import Workspace
from .findings_model import FindingsFilter, FindingsModel
from .worker import AuditWorker, SessionWorker
from .auth_editors import LoginEditor, AccessEditor
from .project_editors import PlanEditor, ExceptionEditor
from ..network import NetworkPolicy
from ..openapi import import_openapi
from ..policy import RuleException, literal_target_pattern
from ..requests import RequestSpec


class Workbench(QWidget):
    CARD_STYLE = "background: #1b2838; color: #c3e9e1; border-radius: 6px; padding: 9px; font-size: 13px; font-weight: 600;"
    def __init__(self, workspace=None, parent=None):
        super().__init__(parent)
        self.workspace = workspace if isinstance(workspace, Workspace) else Workspace(workspace)
        self.project_id = self.run_id = None
        self.baseline_id = None
        self.audit: AuditResult | None = None
        self.worker = None
        self._config = None
        self._session_bearer = self._session_cookie = self._session_scope = None
        self._runtime_auth = None
        self._role_sessions = {}
        self._testing_auth = False
        self._build()
        self.new_project()
        try:
            self.refresh_projects()
            if self.project_list.count():
                self.project_list.setCurrentRow(0)
        except (OSError, sqlite3.Error, ValueError) as exc:
            self.status.setText(f"Workspace could not be read: {exc}")

    def _button(self, text, callback):
        button = QPushButton(text)
        button.clicked.connect(callback)
        return button

    def _build(self):
        root = QHBoxLayout(self)
        sidebar = QWidget()
        sidebar.setMaximumWidth(265)
        sidebar.setMinimumWidth(210)
        side = QVBoxLayout(sidebar)
        brand = QLabel("SHENSEC")
        brand.setStyleSheet("font-size: 23px; font-weight: 800; color: #72dbc6; letter-spacing: 3px;")
        side.addWidget(brand)
        side.addWidget(QLabel("Security, checked again."))
        side.addSpacing(16)
        side.addWidget(QLabel("PROJECTS"))
        self.project_list = QListWidget()
        self.project_list.setMaximumHeight(180)
        self.project_list.currentItemChanged.connect(self.select_project)
        side.addWidget(self.project_list)
        actions = QHBoxLayout()
        self.new_button = self._button("+ New", self.new_project)
        self.import_button = self._button("Import config", self.import_config)
        actions.addWidget(self.new_button)
        actions.addWidget(self.import_button)
        side.addLayout(actions)
        side.addSpacing(16)
        side.addWidget(QLabel("SCAN HISTORY"))
        self.history = QListWidget()
        self.history.currentItemChanged.connect(self.select_history)
        side.addWidget(self.history, 1)
        self.baseline_label = QLabel("No accepted baseline")
        self.baseline_label.setWordWrap(True)
        side.addWidget(self.baseline_label)
        self.baseline_button = self._button("Accept selected run as baseline", self.accept_baseline)
        self.baseline_button.setEnabled(False)
        side.addWidget(self.baseline_button)
        location = QLabel(f"History stays on this device.\n{self.workspace.root}")
        location.setWordWrap(True)
        location.setStyleSheet("color: #8699af; font-size: 10px;")
        side.addWidget(location)
        root.addWidget(sidebar)

        content = QVBoxLayout()
        header = QHBoxLayout()
        self.name = QLineEdit("My project")
        self.name.setPlaceholderText("Project name")
        self.name.setStyleSheet("font-size: 18px; font-weight: 600; padding: 6px;")
        header.addWidget(self.name, 1)
        self.configure_button = QPushButton("Hide configuration")
        self.configure_button.setCheckable(True)
        self.configure_button.setChecked(True)
        header.addWidget(self.configure_button)
        self.save_button = self._button("Save project", self.save_project)
        self.config_button = self._button("Export config", self.export_config)
        header.addWidget(self.save_button)
        header.addWidget(self.config_button)
        content.addLayout(header)
        self.settings = QTabWidget()
        target_tab = QWidget()
        targets_layout = QVBoxLayout(target_tab)
        self.targets = QPlainTextEdit()
        self.targets.setPlaceholderText("Paste one URL per line.\nhttps://your-app.example/\nhttps://your-app.example/api/me\n# Comments and duplicate URLs are handled automatically.")
        targets_layout.addWidget(self.targets)
        row = QHBoxLayout()
        self.target_import = self._button("Import URLs…", self.import_targets)
        row.addWidget(self.target_import)
        row.addWidget(QLabel("Workers"))
        self.workers = QSpinBox()
        self.workers.setRange(1, 16)
        row.addWidget(self.workers)
        row.addWidget(QLabel("Timeout"))
        self.timeout = QDoubleSpinBox()
        self.timeout.setRange(0.1, 120)
        self.timeout.setSuffix(" s")
        row.addWidget(self.timeout)
        row.addWidget(QLabel("Fail on"))
        self.threshold = QComboBox()
        self.threshold.addItems(["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"])
        row.addWidget(self.threshold)
        self.options = QCheckBox("Check OPTIONS")
        row.addWidget(self.options)
        self.cors = QCheckBox("Probe CORS")
        self.cors.setToolTip("Send two GET/HEAD requests with unrelated Origin headers to each eligible target.")
        row.addWidget(self.cors)
        self.cross_origin = QCheckBox("Other-origin redirects")
        row.addWidget(self.cross_origin)
        targets_layout.addLayout(row)
        self.settings.addTab(target_tab, "Targets && policy")

        auth_page = QWidget()
        form = QFormLayout(auth_page)
        self.profile = QLineEdit()
        self.bearer_env = QLineEdit()
        self.bearer_env.setPlaceholderText("Environment variable name, e.g. SHENSEC_TOKEN")
        self.cookie_env = QLineEdit()
        self.cookie_env.setPlaceholderText("Environment variable containing session=…")
        self.header_env = QLineEdit()
        self.header_env.setPlaceholderText("X-API-Key=API_KEY; X-Tenant=TENANT_ID")
        self.origins = QLineEdit()
        self.origins.setPlaceholderText("Default: first target origin. Separate additional origins with commas.")
        self.verify_url = QLineEdit()
        self.verify_url.setPlaceholderText("Optional session health/me URL; default success status is HTTP 200")
        self.verify_header = QLineEdit()
        self.verify_header.setPlaceholderText("Optional success marker, e.g. X-Authenticated=true")
        self.verify_json = QLineEdit()
        self.verify_json.setPlaceholderText('Optional JSON identity, e.g. /role="admin" or /authenticated=true')
        self.session_bearer = QLineEdit()
        self.session_bearer.setEchoMode(QLineEdit.Password)
        self.session_bearer.setPlaceholderText("Paste a token; reused in memory until project switch or app close")
        self.session_cookie = QLineEdit()
        self.session_cookie.setEchoMode(QLineEdit.Password)
        self.session_cookie.setPlaceholderText("Paste session=…; reused in memory, never saved")
        self.require_auth = QCheckBox("Require credentials before sending requests")
        self.clear_credentials = self._button("Clear session credentials", self.clear_session)
        self.allow_http = QCheckBox("Allow credentials over HTTP for an intended development origin")
        for label, widget in (
            ("Profile / role", self.profile), ("Bearer variable", self.bearer_env),
            ("Cookie variable", self.cookie_env), ("Header variables", self.header_env),
            ("Credential origins", self.origins), ("Verify session", self.verify_url),
            ("Success header", self.verify_header), ("Session Bearer", self.session_bearer),
            ("Success JSON assertion", self.verify_json),
            ("Session Cookie", self.session_cookie), ("Development HTTP", self.allow_http),
            ("Authentication", self.require_auth), ("Session memory", self.clear_credentials),
        ):
            form.addRow(label, widget)
        auth_scroll = QScrollArea()
        auth_scroll.setWidgetResizable(True)
        auth_scroll.setWidget(auth_page)
        self.settings.addTab(auth_scroll, "Authentication")
        self.login_editor = LoginEditor()
        self.login_editor.set_config(None)
        self.login_editor.test_button.clicked.connect(self.test_login)
        self.settings.addTab(self.login_editor, "Auto login")
        self.access_editor = AccessEditor(lambda: parse_targets(self.targets.toPlainText().splitlines()), lambda: self.collect_config().auth, primary_session=self.primary_session_values)
        self.settings.addTab(self.access_editor, "Roles && access")
        self.request_editor = PlanEditor()
        self.request_editor.add_button.clicked.connect(self.add_request)
        self.request_editor.import_button.clicked.connect(self.import_api)
        self.settings.addTab(self.request_editor, "API requests")
        network_page = QWidget()
        network_form = QFormLayout(network_page)
        self.rate = QDoubleSpinBox()
        self.rate.setRange(0, 100)
        self.rate.setDecimals(2)
        self.rate.setSpecialValueText("Unlimited")
        self.retries = QSpinBox()
        self.retries.setRange(0, 3)
        self.backoff = QDoubleSpinBox()
        self.backoff.setRange(0, 10)
        self.retry_after = QDoubleSpinBox()
        self.retry_after.setRange(0, 60)
        for label, widget in (("Requests/sec per origin", self.rate), ("Safe request retries", self.retries), ("Backoff (seconds)", self.backoff), ("Maximum retry wait (seconds)", self.retry_after)):
            network_form.addRow(label, widget)
        network_form.addRow(QLabel("Workers share each origin's request budget. Only GET, HEAD and OPTIONS are retried."))
        self.settings.addTab(network_page, "Speed && reliability")
        self.exception_editor = ExceptionEditor()
        self.settings.addTab(self.exception_editor, "Rule exceptions")
        self.settings.setMaximumHeight(360)
        self.settings.setTabText(0, "Targets")
        self.settings.setTabText(1, "Credentials")
        self.configure_button.toggled.connect(self.settings.setVisible)
        self.configure_button.toggled.connect(lambda checked: self.configure_button.setText("Hide configuration" if checked else "Edit configuration"))
        content.addWidget(self.settings)
        self.workflow_buttons = []
        navigation = QHBoxLayout()
        for title, tab in (("1 · Targets", 0), ("2 · Sign in", 2), ("3 · Access expectations", 3)):
            button = self._button(title, lambda checked=False, index=tab: self.edit_step(index))
            navigation.addWidget(button)
            self.workflow_buttons.append(button)
        navigation.addStretch()
        self.test_login_button = self._button("Test sign-in · Ctrl+L", self.test_login)
        navigation.addWidget(self.test_login_button)
        self.session_label = QLabel("Session: not checked")
        self.session_label.setTextFormat(Qt.PlainText)
        self.session_label.setMaximumWidth(280)
        self.session_label.setWordWrap(True)
        navigation.addWidget(self.session_label)
        content.addLayout(navigation)

        controls = QHBoxLayout()
        self.start_button = self._button("Start audit  ·  Ctrl+Enter", self.start_audit)
        self.start_button.setStyleSheet("background: #217b70; color: white; font-weight: 700; padding: 9px 18px;")
        self.cancel_button = self._button("Cancel", self.cancel)
        self.cancel_button.setEnabled(False)
        controls.addWidget(self.start_button)
        controls.addWidget(self.cancel_button)
        controls.addStretch()
        self.export_format = QComboBox()
        self.export_format.addItems(["HTML", "JSON", "Markdown", "SARIF"])
        controls.addWidget(self.export_format)
        self.export_button = self._button("Export report", self.export_report)
        self.export_button.setEnabled(False)
        controls.addWidget(self.export_button)
        content.addLayout(controls)
        self.progress = QProgressBar()
        self.progress.setRange(0, 100)
        self.progress.setValue(0)
        self.progress.setMaximumHeight(16)
        content.addWidget(self.progress)
        self.status = QLabel("Ready")
        self.status.setWordWrap(True)
        self.status.setTextFormat(Qt.PlainText)
        content.addWidget(self.status)
        self.summary = QLabel("Run an audit to review findings and changes.")
        self.summary.setStyleSheet("background: #1b2838; color: #c3e9e1; border-radius: 6px; padding: 12px; font-size: 13px; font-weight: 600;")
        self.summary.setWordWrap(True)
        content.addWidget(self.summary)
        cards = QHBoxLayout()
        self.cards = {}
        for name in ("Gate", "Sessions", "Access", "Changes"):
            card = QLabel(f"{name}\n—")
            card.setTextFormat(Qt.PlainText)
            card.setStyleSheet(self.CARD_STYLE)
            cards.addWidget(card, 1)
            self.cards[name] = card
        content.addLayout(cards)

        filters = QHBoxLayout()
        self.change_filter = QComboBox()
        self.change_filter.addItems(["ALL", "ACTIONABLE", "NEW", "REGRESSED", "EXISTING", "RESOLVED", "UNVERIFIED", "CURRENT", "ERROR", "ACCEPTED"])
        self.severity_filter = QComboBox()
        self.severity_filter.addItems(["ALL", "CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"])
        self.search = QLineEdit()
        self.search.setPlaceholderText("Search targets, findings, evidence, or recommended actions…  Ctrl+F")
        filters.addWidget(self.change_filter)
        filters.addWidget(self.severity_filter)
        filters.addWidget(self.search, 1)
        self.exception_button = self._button("Accept selected finding…", self.accept_finding)
        filters.addWidget(self.exception_button)
        content.addLayout(filters)
        self.filter_timer = QTimer(self)
        self.filter_timer.setSingleShot(True)
        self.filter_timer.setInterval(120)
        self.filter_timer.timeout.connect(self.apply_filters)
        self.search.textChanged.connect(lambda: self.filter_timer.start())
        self.change_filter.currentTextChanged.connect(self.apply_filters)
        self.severity_filter.currentTextChanged.connect(self.apply_filters)
        splitter = QSplitter(Qt.Vertical)
        result_tabs = QTabWidget()
        self.result_tabs = result_tabs
        self.model = FindingsModel(self)
        self.proxy = FindingsFilter(self)
        self.proxy.setSourceModel(self.model)
        self.findings = QTableView()
        self.findings.setModel(self.proxy)
        self.findings.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.findings.setSelectionMode(QAbstractItemView.SingleSelection)
        self.findings.setSortingEnabled(True)
        self.findings.sortByColumn(1, Qt.DescendingOrder)
        self.findings.setWordWrap(False)
        self.findings.verticalHeader().hide()
        self.findings.horizontalHeader().setSectionResizeMode(4, QHeaderView.Stretch)
        self.findings.setColumnWidth(0, 90)
        self.findings.setColumnWidth(1, 80)
        self.findings.setColumnWidth(2, 210)
        self.findings.setColumnWidth(3, 135)
        self.findings.setColumnWidth(5, 175)
        self.findings.selectionModel().selectionChanged.connect(self.show_details)
        result_tabs.addTab(self.findings, "Findings && changes")
        self.target_results = QTableWidget(0, 6)
        self.target_results.setHorizontalHeaderLabels(["Target", "Status", "Auth", "HTTP", "Findings", "Time (ms)"])
        self.target_results.horizontalHeader().setSectionResizeMode(0, QHeaderView.Stretch)
        self.target_results.setEditTriggers(QAbstractItemView.NoEditTriggers)
        result_tabs.addTab(self.target_results, "Target status")
        self.access_results = QTableWidget(0, 1)
        self.access_results.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.access_results.setSelectionBehavior(QAbstractItemView.SelectItems)
        self.access_results.cellClicked.connect(self.show_access_detail)
        result_tabs.addTab(self.access_results, "Permission matrix")
        self.session_results = QTableWidget(0, 6)
        self.session_results.setHorizontalHeaderLabels(["Identity", "Mode", "State", "Logins", "Refreshes", "Renewals"])
        self.session_results.horizontalHeader().setSectionResizeMode(0, QHeaderView.Stretch)
        self.session_results.setEditTriggers(QAbstractItemView.NoEditTriggers)
        result_tabs.addTab(self.session_results, "Sessions")
        splitter.addWidget(result_tabs)
        self.details = QPlainTextEdit()
        self.details.setReadOnly(True)
        self.details.setPlaceholderText("Select a finding to see its full evidence and recommended action.")
        splitter.addWidget(self.details)
        splitter.setStretchFactor(0, 3)
        splitter.setStretchFactor(1, 1)
        content.addWidget(splitter, 1)
        root.addLayout(content, 1)
        for sequence, callback in (("Ctrl+Return", self.start_audit), ("Ctrl+S", self.save_project), ("Ctrl+F", self.search.setFocus), ("Ctrl+L", self.test_login)):
            shortcut = QShortcut(QKeySequence(sequence), self)
            shortcut.activated.connect(callback)

    def _message(self, exc):
        text = validation_message(exc) if isinstance(exc, ValidationError) else str(exc)
        QMessageBox.warning(self, "ShenSec", text)

    def collect_config(self) -> ProjectConfig:
        header_env = {}
        for item in self.header_env.text().split(';'):
            if item.strip():
                key, sep, value = item.partition('=')
                if not sep:
                    raise ValueError("Header variables use Header-Name=ENV_VARIABLE pairs.")
                header_env[key.strip()] = value.strip()
        marker, sep, expected = self.verify_header.text().partition('=')
        if marker and not sep:
            raise ValueError("Success header uses Header-Name=expected-value.")
        pointer, json_sep, json_expected = self.verify_json.text().partition('=')
        if pointer and not json_sep:
            raise ValueError('JSON verification uses /pointer=JSON-value, e.g. /role="admin".')
        previous = self._config.auth if self._config else AuthConfig()
        return ProjectConfig(
            name=self.name.text().strip(), targets=parse_targets(self.targets.toPlainText().splitlines()),
            workers=self.workers.value(), timeout=self.timeout.value(), threshold=self.threshold.currentText(),
            check_options=self.options.isChecked(), allow_cross_origin=self.cross_origin.isChecked(),
            check_cors=self.cors.isChecked(),
            requests=self.request_editor.plans(), exceptions=self.exception_editor.exceptions(),
            roles=self.access_editor.roles, permissions=self.access_editor.cases,
            network=NetworkPolicy(requests_per_second=self.rate.value(), retries=self.retries.value(), backoff=self.backoff.value(), max_retry_after=self.retry_after.value()),
            auth=AuthConfig(
                profile=self.profile.text().strip() or "default", bearer_env=self.bearer_env.text().strip() or None,
                required=self.require_auth.isChecked() or bool(self.session_bearer.text() or self.session_cookie.text() or self._session_bearer or self._session_cookie),
                cookie_env=self.cookie_env.text().strip() or None, header_env=header_env, headers=previous.headers,
                origins=[value.strip() for value in self.origins.text().split(',') if value.strip()],
                allow_http=self.allow_http.isChecked(), verify_url=self.verify_url.text().strip() or None,
                verify_header=marker.strip() or None, verify_value=expected if sep else None,
                verify_status=previous.verify_status,
                login=self.login_editor.config(),
                verify_json_pointer=pointer.strip() or None,
                verify_json_value=json.loads(json_expected) if json_sep else None,
            ),
        )

    def apply_config(self, config: ProjectConfig):
        self.clear_session()
        self._config = config
        self.name.setText(config.name)
        self.targets.setPlainText('\n'.join(config.targets))
        self.workers.setValue(config.workers)
        self.timeout.setValue(config.timeout)
        self.threshold.setCurrentText(config.threshold.value)
        self.options.setChecked(config.check_options)
        self.cors.setChecked(config.check_cors)
        self.cross_origin.setChecked(config.allow_cross_origin)
        self.request_editor.set_plans(config.requests)
        self.exception_editor.set_exceptions(config.exceptions)
        self.login_editor.set_config(config.auth.login)
        self.access_editor.set_config(config.roles, config.permissions)
        self.rate.setValue(config.network.requests_per_second)
        self.retries.setValue(config.network.retries)
        self.backoff.setValue(config.network.backoff)
        self.retry_after.setValue(config.network.max_retry_after)
        auth = config.auth
        for field in ("profile", "bearer_env", "cookie_env", "verify_url"):
            getattr(self, field).setText(getattr(auth, field) or "")
        self.header_env.setText('; '.join(f"{key}={value}" for key, value in auth.header_env.items()))
        self.origins.setText(', '.join(auth.origins))
        self.verify_header.setText(f"{auth.verify_header}={auth.verify_value}" if auth.verify_header else "")
        self.verify_json.setText(f"{auth.verify_json_pointer}={json.dumps(auth.verify_json_value)}" if auth.verify_json_pointer else "")
        self.allow_http.setChecked(auth.allow_http)
        self.require_auth.setChecked(auth.required)
        self.session_bearer.clear()
        self.session_cookie.clear()

    def new_project(self):
        if self.is_running():
            return
        self.project_id = self.run_id = self.audit = self._config = None
        self.project_list.setCurrentRow(-1)
        self.name.setText("My project")
        self.targets.clear()
        self.workers.setValue(4)
        self.timeout.setValue(10)
        self.threshold.setCurrentText("HIGH")
        self.options.setChecked(True)
        self.cors.setChecked(False)
        self.cross_origin.setChecked(False)
        self.request_editor.set_plans([])
        self.exception_editor.set_exceptions([])
        self.login_editor.set_config(None)
        self.access_editor.set_config([], [])
        self.rate.setValue(0)
        self.retries.setValue(1)
        self.backoff.setValue(0.5)
        self.retry_after.setValue(10)
        for field in ("bearer_env", "cookie_env", "header_env", "origins", "verify_url", "verify_header", "verify_json", "session_bearer", "session_cookie"):
            getattr(self, field).clear()
        self.profile.setText("default")
        self.allow_http.setChecked(False)
        self.require_auth.setChecked(False)
        self.clear_session()
        self.history.clear()
        self.baseline_label.setText("No accepted baseline")
        self.baseline_button.setEnabled(False)
        self.export_button.setEnabled(False)
        self.model.beginResetModel()
        self.model.rows = []
        self.model.endResetModel()
        self.target_results.setRowCount(0)
        self.access_results.setRowCount(0)
        self.session_results.setRowCount(0)
        self.session_label.setText("Session: not checked")
        for name, card in self.cards.items():
            card.setText(f"{name}\n—")
            card.setStyleSheet(self.CARD_STYLE)
        self.details.clear()
        self.status.setText("Paste targets, add authentication if needed, then start. Your project is saved with the audit.")
        self.summary.setText("Ready for the first scan")
        self.progress.setValue(0)
        self.configure_button.setChecked(True)

    def refresh_projects(self, selected=None):
        self.project_list.blockSignals(True)
        self.project_list.clear()
        for project in self.workspace.list_projects():
            item = QListWidgetItem(project["name"])
            item.setData(Qt.UserRole, project["id"])
            self.project_list.addItem(item)
            if project["id"] == selected:
                self.project_list.setCurrentItem(item)
        self.project_list.blockSignals(False)

    def save_project(self):
        if self.is_running():
            return
        try:
            config = self.collect_config()
            self.project_id = self.workspace.save_project(config, self.project_id)
            self._config = config
            self.refresh_projects(self.project_id)
            self.status.setText("Project saved. Credential values are not stored.")
            return config
        except (ValueError, OSError, sqlite3.Error) as exc:
            self._message(exc)
            return None

    def select_project(self, item, previous=None):
        if item is None or self.is_running():
            return
        try:
            project_id = item.data(Qt.UserRole)
            self.new_project()
            self.project_id = project_id
            self.apply_config(self.workspace.load_project(project_id))
            self.refresh_projects(project_id)
            self.refresh_history()
            if self.history.count():
                self.history.setCurrentRow(0)
        except (ValueError, OSError, sqlite3.Error) as exc:
            self._message(exc)

    def refresh_history(self, selected=None):
        self.history.blockSignals(True)
        self.history.clear()
        baseline = next((p["baseline_id"] for p in self.workspace.list_projects() if p["id"] == self.project_id), None)
        self.baseline_id = baseline
        self.baseline_label.setText("Baseline accepted · [B] in history" if baseline else "No accepted baseline · gate checks all findings")
        for run in self.workspace.list_runs(self.project_id):
            prefix = "[B] " if run["id"] == baseline else ""
            text = f"{prefix}{run['created_at'][:19].replace('T', ' ')} UTC\n{run['outcome'].upper()} · {run['target_count']} targets · {run['findings']} findings"
            item = QListWidgetItem(text)
            item.setData(Qt.UserRole, run["id"])
            self.history.addItem(item)
            if run["id"] == selected:
                self.history.setCurrentItem(item)
        self.history.blockSignals(False)

    def select_history(self, item, previous=None):
        if item is None or self.is_running():
            return
        try:
            self.run_id = item.data(Qt.UserRole)
            audit = self.workspace.load_run(self.project_id, self.run_id)
            baseline = self.workspace.baseline(self.project_id)
            if baseline and self.run_id != self.baseline_id:
                audit.comparison = compare_audits(audit, baseline)
                audit.gate = evaluate_gate(audit, self.threshold.currentText(), only_new=True)
            self.display_audit(audit)
            self.status.setText("Saved scan loaded. Changes are compared with the accepted baseline when available.")
        except (ValueError, OSError, sqlite3.Error) as exc:
            self._message(exc)

    def start_audit(self):
        if self.is_running():
            return
        try:
            config = self.collect_config()
            scope = (config.auth.profile, tuple(config.auth.origins or [origin(config.targets[0])]), config.auth.bearer_env, config.auth.cookie_env, tuple(sorted(config.auth.header_env.items())))
            bearer, cookie = self.session_bearer.text().strip(), self.session_cookie.text().strip()
            if self._session_scope is not None and scope != self._session_scope:
                self._session_bearer = self._session_cookie = None
            bearer = bearer or self._session_bearer
            cookie = cookie or self._session_cookie
            auth = resolve_auth(config.auth, config.targets, bearer=bearer, cookie=cookie)
            if config.auth.login and self._runtime_auth and self._runtime_auth.config.model_dump_json() == auth.config.model_dump_json():
                auth = self._runtime_auth
            auth.set_environment(self.login_editor.session_inputs())
            self._runtime_auth = auth if config.auth.login else None
            self._session_bearer, self._session_cookie, self._session_scope = bearer, cookie, scope
            self.project_id = self.workspace.save_project(config, self.project_id)
            self._config = config
            baseline = self.workspace.baseline(self.project_id)
            self.refresh_projects(self.project_id)
            self.session_bearer.clear()
            self.session_cookie.clear()
            self.login_editor.clear_inputs()
            values = {name: dict(fields) for name, fields in self.access_editor.session_values.items()}
            self.access_editor.session_values.clear()
            self._testing_auth = False
            self.worker = AuditWorker(config, auth, self.workspace, self.project_id, baseline, parent=self, role_auth=self._role_sessions, role_values=values)
            self.worker.phase_signal.connect(self.on_phase)
            self.worker.progress_signal.connect(self.on_progress)
            self.worker.result_signal.connect(self.on_result)
            self.worker.error_signal.connect(self.on_error)
            self.worker.finished.connect(self.on_thread_finished)
            self.audit = self.run_id = None
            self.model.beginResetModel()
            self.model.rows = []
            self.model.endResetModel()
            self.target_results.setRowCount(0)
            self.access_results.setRowCount(0)
            self.session_results.setRowCount(0)
            for name, card in self.cards.items():
                card.setText(f"{name}\nRunning…")
                card.setStyleSheet(self.CARD_STYLE)
            self.details.clear()
            self.summary.setText("Audit in progress · results will appear when this run finishes")
            self.set_busy(True)
            self.progress.setRange(0, len(config.targets))
            self.progress.setValue(0)
            self.status.setText("Checking credentials and starting audit…")
            self.worker.start()
        except (ValueError, OSError, sqlite3.Error) as exc:
            self._message(exc)

    def is_running(self):
        return self.worker is not None and self.worker.isRunning()

    def clear_session(self):
        self._session_bearer = self._session_cookie = self._session_scope = None
        self.session_bearer.clear()
        self.session_cookie.clear()
        self._runtime_auth = None
        self._role_sessions = {}
        if hasattr(self, "login_editor"):
            self.login_editor.clear_inputs()
            self.access_editor.session_values.clear()
            self.session_label.setText("Session: cleared")

    def edit_step(self, index):
        self.configure_button.setChecked(True)
        self.settings.setCurrentIndex(index)

    def test_login(self):
        if self.is_running():
            return
        try:
            config = self.collect_config()
            if not config.auth.login:
                raise ValueError("Enable automatic login and configure its endpoint/fields first.")
            auth = resolve_auth(config.auth, config.targets)
            if self._runtime_auth and self._runtime_auth.config.model_dump_json() == auth.config.model_dump_json():
                auth = self._runtime_auth
            auth.set_environment(self.login_editor.session_inputs())
            self.login_editor.clear_inputs()
            self._runtime_auth = auth
            self._testing_auth = True
            self.worker = SessionWorker(auth, config, self)
            self.worker.phase_signal.connect(self.on_phase)
            self.worker.result_signal.connect(self.on_login_result)
            self.worker.error_signal.connect(self.on_error)
            self.worker.finished.connect(self.on_thread_finished)
            self.set_busy(True)
            self.status.setText("Testing sign-in without running endpoint or permission checks…")
            self.worker.start()
        except ValueError as exc:
            self._message(exc)

    def primary_session_values(self):
        values = dict(self._runtime_auth.environment) if self._runtime_auth else {}
        values.update(self.login_editor.session_inputs())
        values['__primary_bearer'] = self.session_bearer.text().strip() or self._session_bearer
        values['__primary_cookie'] = self.session_cookie.text().strip() or self._session_cookie
        return values

    def on_login_result(self, auth):
        self._runtime_auth = auth
        self.session_label.setText("Session: ready")
        self.status.setText("Sign-in test passed. This session stays in memory and will be reused or renewed when needed.")

    def on_phase(self, phase, message):
        self.status.setText(message)
        if phase == "authentication":
            self.session_label.setText(message)

    def set_busy(self, busy):
        for widget in (self.project_list, self.history, self.new_button, self.import_button, self.name, self.settings, self.save_button, self.config_button, self.start_button, self.exception_button):
            widget.setEnabled(not busy)
        for button in self.workflow_buttons:
            button.setEnabled(not busy)
        self.test_login_button.setEnabled(not busy)
        self.cancel_button.setEnabled(busy)
        self.export_button.setEnabled(not busy and self.audit is not None)
        self.baseline_button.setEnabled(not busy and self.run_id is not None and self.audit is not None and self.audit.failed_targets == 0 and not self.audit.cancelled)

    def cancel(self):
        if self.worker:
            self.worker.cancel()
            self.cancel_button.setEnabled(False)
            self.status.setText("Stopping new work; waiting for current requests to finish within their timeout…")

    def on_progress(self, completed, total, result):
        self.progress.setValue(completed)
        self.status.setText(f"{completed}/{total} · {result.status.upper()} · {result.target_url}")

    def on_result(self, audit, run_id):
        self.run_id = run_id or None
        self.display_audit(audit)
        self.refresh_history(run_id)
        complete = sum(result.status == "complete" for result in audit.results)
        self.progress.setValue(len(audit.results))
        self.status.setText(f"{'Cancelled' if audit.cancelled else 'Audit saved'} · {complete}/{len(audit.results)} complete · {audit.duration_ms / 1000:.2f} s · Gate {audit.gate.outcome.upper()}")

    def on_error(self, message):
        self.status.setText(f"{'Sign-in test failed' if self._testing_auth else 'Audit could not finish'}: {message}")
        self.session_label.setText("Session: check authentication")
        if self.audit is None:
            self.summary.setText("Audit did not complete · check authentication and connection status")
            for name, card in self.cards.items():
                card.setText(f"{name}\nNot completed")
                card.setStyleSheet(self.CARD_STYLE)

    def on_thread_finished(self):
        worker = self.worker
        self.worker = None
        self._testing_auth = False
        self.set_busy(False)
        if worker:
            worker.deleteLater()

    def display_audit(self, audit):
        self.audit = audit
        self.configure_button.setChecked(False)
        if not self.is_running():
            self.progress.setRange(0, len(audit.results))
            self.progress.setValue(len(audit.results))
        comparison = audit.comparison
        self.summary.setText(
            f"{len(audit.results)} targets    ·    {audit.failed_targets} incomplete    ·    "
            f"Risk {audit.risk_rating.value}    ·    Gate {audit.gate.outcome.upper() if audit.gate else 'N/A'}"
            f"    ·    Auth applied {sum(result.authentication == 'applied' for result in audit.results)}/{len(audit.results)}"
            f"    ·    {sum(f.suppression is not None for r in audit.results for f in r.findings)} accepted    ·    {sum(r.retry_count for r in audit.results)} retries"
            + (f"\nChanges: {len(comparison.new)} new    ·    {len(comparison.regressed)} regressed    ·    {len(comparison.resolved)} fixed    ·    {len(comparison.unverified)} unverified" if comparison else "")
        )
        self.model.set_audit(audit)
        self.render_access(audit)
        passed = sum(r.outcome == "passed" for r in audit.permissions)
        failed = sum(r.outcome == "failed" for r in audit.permissions)
        renewals = sum(s.renewals for s in audit.sessions)
        self.cards["Gate"].setText(f"Gate\n{audit.gate.outcome.upper() if audit.gate else 'NOT EVALUATED'}")
        self.cards["Sessions"].setText(f"Sessions\n{len(audit.sessions)} sessions · {renewals} renewals")
        self.cards["Access"].setText(f"Access\n{passed}/{len(audit.permissions)} expected · {failed} violations" if audit.permissions else "Access\nNo expectations configured")
        self.cards["Changes"].setText(f"Changes\n{len(comparison.new)} new · {len(comparison.resolved)} fixed" if comparison else "Changes\nFirst scan / no baseline")
        gate_color = "#173d35" if audit.gate and audit.gate.outcome == "passed" else "#662e36"
        self.cards["Gate"].setStyleSheet(f"background: {gate_color}; color: #f0f4fa; border-radius: 6px; padding: 9px; font-size: 13px; font-weight: 600;")
        self.cards["Access"].setStyleSheet(f"background: {'#662e36' if failed else '#1b2838'}; color: #f0f4fa; border-radius: 6px; padding: 9px; font-size: 13px; font-weight: 600;")
        self.session_label.setText("Session: complete" if audit.failed_targets == 0 else "Session / coverage: review errors")
        self.details.clear()
        self.target_results.setRowCount(len(audit.results))
        for row, result in enumerate(audit.results):
            for column, value in enumerate((f"{result.request_method} {result.target_url}", result.status.upper(), result.authentication, result.status_code, len(result.findings), result.response_time_ms)):
                item = QTableWidgetItem(str(value))
                item.setToolTip(result.error or '\n'.join(result.warnings))
                self.target_results.setItem(row, column, item)
        if comparison and self.change_filter.currentText() == "ALL":
            self.change_filter.setCurrentText("ACTIONABLE")
        elif comparison is None and self.change_filter.currentText() == "ACTIONABLE":
            self.change_filter.setCurrentText("ALL")
        self.apply_filters()
        self.set_busy(self.is_running())

    def render_access(self, audit):
        roles = list(dict.fromkeys(r.role for r in audit.permissions))
        cases = list(dict.fromkeys(r.case_id for r in audit.permissions))
        self.access_results.setColumnCount(len(roles) + 1)
        self.access_results.setHorizontalHeaderLabels(["Endpoint / expectation"] + roles)
        self.access_results.setRowCount(len(cases))
        indexed = {(r.case_id, r.role): r for r in audit.permissions}
        self.access_results.horizontalHeader().setSectionResizeMode(0, QHeaderView.Stretch)
        colors = {"passed": "#173d35", "failed": "#662e36", "error": "#574621", "cancelled": "#574621"}
        for row, case_id in enumerate(cases):
            first = next(r for r in audit.permissions if r.case_id == case_id)
            item = QTableWidgetItem(f"{first.title}\n{first.method} {first.target_url}")
            item.setToolTip(first.target_url)
            item.setData(Qt.UserRole, first)
            self.access_results.setItem(row, 0, item)
            self.access_results.setRowHeight(row, 50)
            for column, role in enumerate(roles, 1):
                observation = indexed.get((case_id, role))
                if observation is None:
                    continue
                label = observation.observed.upper() if observation.outcome == "passed" else "UNEXPECTED " + ("ALLOW" if observation.observed == "allowed" else "DENY") if observation.outcome == "failed" else "UNVERIFIED"
                item = QTableWidgetItem(f"{label}\nHTTP {observation.status_code} · expect {observation.expected}")
                item.setBackground(QColor(colors[observation.outcome]))
                item.setForeground(QColor("#f0f4fa"))
                item.setToolTip(observation.detail)
                item.setData(Qt.UserRole, observation)
                self.access_results.setItem(row, column, item)
                self.access_results.setColumnWidth(column, 180)
        self.session_results.setRowCount(len(audit.sessions))
        for row, session in enumerate(audit.sessions):
            for column, value in enumerate((f"{session.scope}: {session.profile}", session.mode, session.state, session.logins, session.refreshes, session.renewals)):
                self.session_results.setItem(row, column, QTableWidgetItem(str(value)))
        self.result_tabs.setCurrentWidget(self.access_results if audit.permissions else self.findings)

    def show_access_detail(self, row, column):
        item = self.access_results.item(row, column)
        observation = item.data(Qt.UserRole) if item else None
        if observation:
            self.details.setPlainText(f"{observation.title}\n{observation.method} {observation.target_url}\n\nRole: {observation.role}\nExpected: {observation.expected}\nObserved: {observation.observed}\nOutcome: {observation.outcome.upper()}\nHTTP: {observation.status_code}\nTime: {observation.duration_ms} ms\n\n{observation.detail}\n\nUnexpected access requires reviewing the server's resource/role authorization against the configured assertion.")

    def apply_filters(self):
        self.proxy.update_filters(self.search.text(), self.severity_filter.currentText(), self.change_filter.currentText())

    def show_details(self, *args):
        selected = self.findings.selectionModel().selectedRows()
        if not selected:
            self.details.clear()
            return
        index = self.proxy.mapToSource(selected[0])
        row = self.model.rows[index.row()]
        record, finding = row.record, row.record.finding
        change = f"{record.previous_severity.value} → {finding.severity.value}" if record.previous_severity else row.change
        self.details.setPlainText(
            f"{change} · {finding.severity.value} · {finding.rule_id}\n{record.target_url}\n\n"
            f"{finding.title}\n\nRecommended action: {finding.recommendation or 'Review in context.'}\n\n"
            f"Evidence: {finding.evidence or 'Not recorded'}\nLocation: {finding.location or 'Current target'}\n\n{finding.description}"
            + (f"\n\nAccepted exception: {finding.suppression}" if finding.suppression else "")
            + (f"\n\nChange reason: {record.change_reason}" if record.change_reason else "")
        )

    def add_request(self):
        try:
            targets = parse_targets(self.targets.toPlainText().splitlines())
            value, ok = QInputDialog.getItem(self, "Configure API request", "Target URL", targets, 0, False)
            if ok:
                if value in {p.url for p in self.request_editor.plans()}:
                    raise ValueError("This URL already has a request plan; edit its row.")
                self.request_editor.add(RequestSpec(url=value))
        except ValueError as exc:
            self._message(exc)

    def load_api(self, path, server, bindings=None):
        imported = import_openapi(path, server, bindings)
        existing = self.targets.toPlainText().splitlines()
        plans = {plan.url: plan for plan in imported.config.requests}
        plans.update({plan.url: plan for plan in self.request_editor.plans()})
        merged = parse_targets(existing + imported.config.targets)
        if len(merged) > 1000:
            raise ValueError("Project limit of 1000 targets reached.")
        self.targets.setPlainText('\n'.join(merged))
        self.request_editor.set_plans(list(plans.values()))
        if self.name.text() == "My project":
            self.name.setText(imported.config.name)
        if imported.config.auth.required:
            self.require_auth.setChecked(True)
        self.request_editor.message.setPlainText(f"Imported {len(imported.config.targets)} endpoints. " + '\n'.join(imported.skipped))
        self.request_editor.message.show()
        self.status.setText(f"OpenAPI imported: {len(imported.config.targets)} endpoints; {len(imported.skipped)} skipped. Review the request table before scanning.")

    def import_api(self):
        path, _ = QFileDialog.getOpenFileName(self, "Import OpenAPI", "", "OpenAPI JSON (*.json)")
        if not path:
            return
        server, ok = QInputDialog.getText(self, "API deployment", "Deployment base URL, including any API prefix")
        if not ok:
            return
        params, ok = QInputDialog.getText(self, "Parameter bindings", "Optional bindings: path.id=42; query.page=1")
        if not ok:
            return
        try:
            bindings = {}
            for value in params.split(';'):
                if value.strip():
                    key, sep, binding = value.partition('=')
                    if not sep:
                        raise ValueError("Parameter bindings use name=value.")
                    bindings[key.strip()] = binding.strip()
            self.load_api(path, server, bindings)
        except (OSError, ValueError) as exc:
            self._message(exc)

    def accept_finding(self):
        selected = self.findings.selectionModel().selectedRows()
        if not selected or self.is_running():
            return
        row = self.model.rows[self.proxy.mapToSource(selected[0]).row()]
        if row.change in {"ERROR", "CANCELLED", "UNVERIFIED", "RESOLVED"} or row.record.finding.rule_id == "SEC-SCAN-ERR":
            self._message(ValueError("Select a current finding from a completed check."))
            return
        reason, ok = QInputDialog.getText(self, "Accept finding until expiry", "Reason (at least 8 characters)")
        if not ok:
            return
        expiry, ok = QInputDialog.getText(self, "Exception expiry", "Expiry date (YYYY-MM-DD)", text=(date.today() + timedelta(days=30)).isoformat())
        if not ok:
            return
        try:
            exception = RuleException(rule_id=row.record.finding.rule_id, target=literal_target_pattern(row.record.target_url), reason=reason, expires=expiry)
            if exception.expires < date.today():
                raise ValueError("Choose today or a future expiry date.")
            self.exception_editor.add(exception)
            self.configure_button.setChecked(True)
            self.settings.setCurrentWidget(self.exception_editor)
            self.status.setText("Exception added to project settings. Save and rescan to apply it; the recorded run stays unchanged.")
        except ValueError as exc:
            self._message(exc)

    def accept_baseline(self):
        if not self.project_id or not self.run_id or self.is_running():
            return
        try:
            self.workspace.set_baseline(self.project_id, self.run_id)
            self.refresh_history(self.run_id)
            self.status.setText("Baseline accepted. Future scans will gate new findings and severity increases.")
        except (ValueError, OSError, sqlite3.Error) as exc:
            self._message(exc)

    def import_targets(self):
        path, _ = QFileDialog.getOpenFileName(self, "Import target URLs", "", "Text files (*.txt);;All files (*)")
        if path:
            try:
                lines = self.targets.toPlainText().splitlines() + Path(path).read_text(encoding="utf-8-sig").splitlines()
                self.targets.setPlainText('\n'.join(parse_targets(lines)))
            except (ValueError, OSError) as exc:
                self._message(exc)

    def import_config(self):
        path, _ = QFileDialog.getOpenFileName(self, "Import project", "", "ShenSec projects (*.toml *.json)")
        if path:
            try:
                config = load_project(path)
                self.new_project()
                self.apply_config(config)
                self.status.setText("Configuration imported. Save or start an audit to create a local project.")
            except (ValueError, OSError) as exc:
                self._message(exc)

    def export_config(self):
        try:
            config = self.collect_config()
            path, _ = QFileDialog.getSaveFileName(self, "Export project configuration", "shensec.toml", "TOML (*.toml)")
            if path:
                target = Path(path) if Path(path).suffix else Path(path + ".toml")
                target.write_text(project_toml(config), encoding="utf-8")
                self.status.setText("Configuration exported. Only credential variable names are included.")
        except (ValueError, OSError) as exc:
            self._message(exc)

    def export_report(self):
        if self.audit is None:
            return
        fmt = self.export_format.currentText().lower()
        extension = "md" if fmt == "markdown" else fmt
        path, _ = QFileDialog.getSaveFileName(self, "Export recorded audit", f"shensec-report.{extension}", f"{fmt.upper()} (*.{extension})")
        if path:
            try:
                target = Path(path) if Path(path).suffix else Path(path + "." + extension)
                target.write_text(generate_report(self.audit, fmt), encoding="utf-8")
                self.status.setText(f"Report exported: {path}")
            except (ValueError, OSError) as exc:
                self._message(exc)
