"""Guided login recipes, named role identities and explicit access expectations."""

import json
import re
from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QCheckBox, QComboBox, QDialog, QDialogButtonBox, QFormLayout, QHBoxLayout,
    QInputDialog, QLabel, QLineEdit, QMessageBox, QPlainTextEdit, QPushButton,
    QScrollArea, QSpinBox, QTabWidget, QTableWidget, QTableWidgetItem,
    QVBoxLayout, QWidget, QHeaderView, QAbstractItemView,
)
from ..access import PermissionCase, RoleConfig
from ..auth import AuthConfig
from ..login_config import LoginConfig
from ..project import validation_message
from pydantic import ValidationError


def message(parent, exc):
    QMessageBox.warning(parent, "Check configuration", validation_message(exc) if isinstance(exc, ValidationError) else str(exc))


def references(text):
    values = {}
    for line in text.replace(';', '\n').splitlines():
        if line.strip():
            key, sep, value = line.partition('=')
            if not sep or not key.strip() or not value.strip():
                raise ValueError("Use field=ENV_VARIABLE pairs, one per line.")
            if key.strip() in values:
                raise ValueError("Configure each field only once.")
            values[key.strip()] = value.strip()
    return values


class LoginEditor(QScrollArea):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWidgetResizable(True)
        page = QWidget()
        form = QFormLayout(page)
        self.enabled = QCheckBox("Sign in automatically and keep the session valid")
        form.addRow(self.enabled)
        hint = QLabel("Map account/password fields to variable names. Configure an identity verification URL and success assertion in Credentials, then test sign-in.")
        hint.setWordWrap(True)
        form.addRow(hint)
        self.url = QLineEdit()
        self.url.setPlaceholderText("https://app.example/api/login")
        self.encoding = QComboBox()
        self.encoding.addItems(["json", "form"])
        self.fields = QPlainTextEdit()
        self.fields.setMaximumHeight(75)
        self.fields.setPlaceholderText("username=APP_USERNAME\npassword=APP_PASSWORD")
        self.output = QComboBox()
        self.output.addItems(["JSON Bearer token", "Session cookie"])
        self.token = QLineEdit("/access_token")
        self.refresh_token = QLineEdit("/refresh_token")
        self.expires = QLineEdit("/expires_in")
        self.status = QSpinBox()
        self.status.setRange(200, 399)
        self.status.setValue(200)
        self.refresh_url = QLineEdit()
        self.refresh_encoding = QComboBox()
        self.refresh_encoding.addItems(["form", "json"])
        self.refresh_field = QLineEdit("refresh_token")
        self.refresh_fields = QLineEdit()
        self.refresh_fields.setPlaceholderText("Optional client_id=CLIENT_ID; client_secret=CLIENT_SECRET")
        self.renewals = QSpinBox()
        self.renewals.setRange(0, 20)
        self.renewals.setValue(3)
        self.csrf_url = QLineEdit()
        self.csrf_field = QLineEdit("csrf_token")
        self.csrf_pointer = QLineEdit()
        self.csrf_pointer.setPlaceholderText("Empty: hidden HTML input; or /csrf_token for JSON")
        self.csrf_header = QLineEdit()
        self.csrf_header.setPlaceholderText("Optional X-CSRF-Token; empty submits a form/JSON field")
        for label, widget in (
            ("Login URL", self.url), ("Request format", self.encoding), ("Field → environment", self.fields),
            ("Response type", self.output), ("Access token pointer", self.token), ("Refresh token pointer", self.refresh_token),
            ("Lifetime pointer", self.expires), ("Login success status", self.status), ("Refresh URL", self.refresh_url),
            ("Refresh format", self.refresh_encoding), ("Refresh token field", self.refresh_field), ("Refresh variables", self.refresh_fields),
            ("Renewals per audit", self.renewals), ("CSRF initialization URL", self.csrf_url), ("CSRF field", self.csrf_field),
            ("CSRF JSON pointer", self.csrf_pointer), ("CSRF header", self.csrf_header),
        ):
            form.addRow(label, widget)
        self.account_ref, self.secret_ref = QComboBox(), QComboBox()
        self.account_value, self.secret_value = QLineEdit(), QLineEdit()
        self.secret_value.setEchoMode(QLineEdit.Password)
        self.account_value.setPlaceholderText("Optional account value; memory only")
        self.secret_value.setPlaceholderText("Optional password/secret; memory only")
        for index, (label, combo, value) in enumerate((("Session account", self.account_ref, self.account_value), ("Session secret", self.secret_ref, self.secret_value))):
            row = QWidget()
            layout = QHBoxLayout(row)
            layout.setContentsMargins(0, 0, 0, 0)
            layout.addWidget(combo)
            layout.addWidget(value, 1)
            form.insertRow(5 + index, label, row)
        self.fields.textChanged.connect(self.update_references)
        self.test_button = QPushButton("Test sign-in")
        form.addRow(self.test_button)
        self.setWidget(page)
        self._previous = None

    def set_config(self, config):
        self._previous = config
        self.enabled.setChecked(config is not None)
        config = config or LoginConfig(url="https://app.example/login")
        self.url.setText(config.url if self._previous else "")
        self.encoding.setCurrentText(config.encoding)
        self.fields.setPlainText('\n'.join(f"{k}={v}" for k, v in config.fields_env.items()))
        self.output.setCurrentIndex(0 if config.token_pointer is not None else 1)
        for widget, value in ((self.token, config.token_pointer), (self.refresh_token, config.refresh_pointer), (self.expires, config.expires_pointer), (self.refresh_url, config.refresh_url), (self.refresh_field, config.refresh_field), (self.csrf_url, config.csrf_url), (self.csrf_field, config.csrf_field), (self.csrf_pointer, config.csrf_pointer), (self.csrf_header, config.csrf_header)):
            widget.setText(value or "")
        self.refresh_fields.setText('; '.join(f"{k}={v}" for k, v in config.refresh_fields_env.items()))
        self.refresh_encoding.setCurrentText(config.refresh_encoding)
        self.renewals.setValue(config.max_renewals)
        self.status.setValue(config.success_status)
        self.clear_inputs()
        self.update_references()

    def update_references(self):
        try:
            fields = references(self.fields.toPlainText())
        except ValueError:
            return
        for combo, secret in ((self.account_ref, False), (self.secret_ref, True)):
            old = combo.currentText()
            names = list(dict.fromkeys(fields.values()))
            combo.clear()
            combo.addItems(names)
            preferred = next((v for k, v in fields.items() if (any(part in k.lower() for part in ('pass', 'pwd', 'secret')) == secret)), None)
            combo.setCurrentText(old if old in names else preferred or (names[0] if names else ""))

    def session_inputs(self):
        values = {}
        for combo, value in ((self.account_ref, self.account_value), (self.secret_ref, self.secret_value)):
            if value.text():
                if not combo.currentText():
                    raise ValueError("Map login fields to variable names before entering session values.")
                if combo.currentText() in values:
                    raise ValueError("Account and secret inputs must use different variable names.")
                values[combo.currentText()] = value.text()
        return values

    def clear_inputs(self):
        self.account_value.setText("")
        self.secret_value.setText("")

    def config(self):
        if not self.enabled.isChecked():
            return None
        return LoginConfig(
            url=self.url.text().strip(), encoding=self.encoding.currentText(), fields_env=references(self.fields.toPlainText()),
            token_pointer=(self.token.text().strip() or None) if self.output.currentIndex() == 0 else None,
            refresh_pointer=self.refresh_token.text().strip() or None, expires_pointer=self.expires.text().strip() or None,
            success_status=self.status.value(), refresh_url=self.refresh_url.text().strip() or None,
            refresh_encoding=self.refresh_encoding.currentText(), refresh_field=self.refresh_field.text().strip() or None,
            refresh_fields_env=references(self.refresh_fields.text()), max_renewals=self.renewals.value(),
            refresh_skew=self._previous.refresh_skew if self._previous else 30,
            csrf_url=self.csrf_url.text().strip() or None, csrf_field=self.csrf_field.text().strip(),
            csrf_header=self.csrf_header.text().strip() or None, csrf_pointer=self.csrf_pointer.text().strip() or None,
        )


class RoleDialog(QDialog):
    def __init__(self, role=None, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Role identity")
        self.resize(720, 670)
        layout = QVBoxLayout(self)
        identity = QWidget()
        form = QFormLayout(identity)
        self.name = QLineEdit(role.name if role else "member")
        self.anonymous = QCheckBox("Anonymous — send no login credentials")
        self.anonymous.setChecked(role.anonymous if role else False)
        self.previous = role.auth if role else AuthConfig()
        self.bearer = QLineEdit(self.previous.bearer_env or "")
        self.cookie = QLineEdit(self.previous.cookie_env or "")
        self.session_bearer = QLineEdit()
        self.session_cookie = QLineEdit()
        for widget in (self.session_bearer, self.session_cookie):
            widget.setEchoMode(QLineEdit.Password)
            widget.setPlaceholderText("Optional temporary credential; memory only")
        self.headers = QLineEdit('; '.join(f"{k}={v}" for k, v in self.previous.header_env.items()))
        self.origins = QLineEdit(', '.join(self.previous.origins))
        self.verify = QLineEdit(self.previous.verify_url or "")
        self.marker = QLineEdit(f"{self.previous.verify_header}={self.previous.verify_value}" if self.previous.verify_header else "")
        self.marker.setPlaceholderText("Recommended: X-Role=member, proving this identity")
        self.verify_pointer = QLineEdit(self.previous.verify_json_pointer or "")
        self.verify_value = QLineEdit(json.dumps(self.previous.verify_json_value) if self.previous.verify_json_pointer else "")
        self.verify_pointer.setPlaceholderText("Alternative JSON identity: /role")
        self.verify_value.setPlaceholderText('JSON scalar, e.g. "member"')
        self.http = QCheckBox("Allow HTTP for an intended development origin")
        self.http.setChecked(self.previous.allow_http)
        for label, widget in (("Role name", self.name), ("Anonymous", self.anonymous), ("Bearer variable", self.bearer), ("Cookie variable", self.cookie), ("Session Bearer", self.session_bearer), ("Session Cookie", self.session_cookie), ("Header variables", self.headers), ("Credential origins", self.origins), ("Verify identity URL", self.verify), ("Success header", self.marker), ("Identity JSON pointer", self.verify_pointer), ("Expected JSON value", self.verify_value), ("Development HTTP", self.http)):
            form.addRow(label, widget)
        tabs = QTabWidget()
        tabs.addTab(identity, "Identity & verification")
        self.login = LoginEditor()
        self.login.set_config(self.previous.login)
        self.login.test_button.hide()
        tabs.addTab(self.login, "Automatic login & renewal")
        layout.addWidget(tabs)
        buttons = QDialogButtonBox(QDialogButtonBox.Save | QDialogButtonBox.Cancel)
        buttons.accepted.connect(self.save)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)
        self.value = None
        self.session_values = {}
        self.initial_values = {}

    def save(self):
        try:
            if not re.fullmatch(r"[A-Za-z][A-Za-z0-9_-]{0,39}", self.name.text().strip()):
                raise ValueError("Role names start with a letter and use up to 40 letters, digits, underscores or hyphens.")
            anonymous = self.anonymous.isChecked()
            values = dict(self.initial_values)
            if anonymous:
                auth = AuthConfig()
            else:
                header, sep, value = self.marker.text().partition('=')
                if header and not sep:
                    raise ValueError("Success header uses Header=expected-value.")
                data = self.previous.model_dump()
                namespace = 'SHENSEC_ROLE_' + self.name.text().strip().upper().replace('-', '_')
                if self.session_bearer.text():
                    if not self.bearer.text().strip():
                        self.bearer.setText(namespace + '_TOKEN')
                    values[self.bearer.text().strip()] = self.session_bearer.text()
                if self.session_cookie.text():
                    if not self.cookie.text().strip():
                        self.cookie.setText(namespace + '_COOKIE')
                    values[self.cookie.text().strip()] = self.session_cookie.text()
                data.update(required=True, bearer_env=self.bearer.text().strip() or None, cookie_env=self.cookie.text().strip() or None, header_env=references(self.headers.text()), origins=[v.strip() for v in self.origins.text().split(',') if v.strip()], verify_url=self.verify.text().strip() or None, verify_header=header.strip() or None, verify_value=value if sep else None, allow_http=self.http.isChecked(), login=self.login.config())
                pointer = self.verify_pointer.text().strip() or None
                data.update(verify_json_pointer=pointer, verify_json_value=json.loads(self.verify_value.text()) if pointer else None)
                auth = AuthConfig.model_validate(data)
            self.value = RoleConfig(name=self.name.text().strip(), anonymous=anonymous, auth=auth)
            if not anonymous and auth.login:
                values.update(self.login.session_inputs())
            self.session_values = values if not anonymous else {}
            self.initial_values = {}
            self.login.clear_inputs()
            self.session_bearer.setText("")
            self.session_cookie.setText("")
            self.accept()
        except ValueError as exc:
            message(self, exc)

    def reject(self):
        self.login.clear_inputs()
        self.session_bearer.setText("")
        self.session_cookie.setText("")
        self.session_values = {}
        self.initial_values = {}
        super().reject()


class PermissionDialog(QDialog):
    def __init__(self, roles, targets, case=None, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Access expectation")
        self.resize(720, 570)
        layout = QVBoxLayout(self)
        page = QWidget()
        form = QFormLayout(page)
        self.id = QLineEdit(case.id if case else "access_check")
        self.title = QLineEdit(case.title if case else "Resource access")
        self.url = QComboBox()
        self.url.addItems(targets)
        if case:
            self.url.setCurrentText(case.url)
        self.method = QComboBox()
        self.method.addItems(["GET", "HEAD"])
        self.method.setCurrentText(case.method if case else "GET")
        self.allow = QLineEdit(','.join(map(str, case.allow_status)) if case else "200")
        self.deny = QLineEdit(','.join(map(str, case.deny_status)) if case else "401,403")
        self.header = QLineEdit(case.allow_header or "" if case else "")
        self.header_value = QLineEdit(case.allow_value or "" if case else "")
        self.pointer = QLineEdit(case.json_pointer or "" if case else "")
        self.pointer.setPlaceholderText("Example: /resource/id")
        self.json_value = QLineEdit(json.dumps(case.json_value) if case and case.json_pointer else "")
        self.json_value.setPlaceholderText('JSON scalar: 42, true, or "resource-42"')
        for label, widget in (("Stable check ID", self.id), ("Display name", self.title), ("Target", self.url), ("Method", self.method), ("Allowed statuses", self.allow), ("Denied statuses", self.deny), ("Success header", self.header), ("Expected header value", self.header_value), ("Success JSON pointer", self.pointer), ("Expected JSON value", self.json_value)):
            form.addRow(label, widget)
        self.expectations = {}
        for role in roles:
            combo = QComboBox()
            combo.addItems(["deny", "allow"])
            combo.setCurrentText(case.expectations.get(role.name, "deny") if case else "deny")
            self.expectations[role.name] = combo
            form.addRow(f"{role.name} should", combo)
        hint = QLabel("At least one success assertion is required. Denial is checked only against the selected statuses; redirects and ambiguous responses stay unverified.")
        hint.setWordWrap(True)
        form.addRow(hint)
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setWidget(page)
        layout.addWidget(scroll)
        buttons = QDialogButtonBox(QDialogButtonBox.Save | QDialogButtonBox.Cancel)
        buttons.accepted.connect(self.save)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)
        self.value = None

    def save(self):
        try:
            pointer = self.pointer.text().strip() or None
            self.value = PermissionCase(id=self.id.text().strip(), title=self.title.text().strip(), url=self.url.currentText(), method=self.method.currentText(), expectations={name: widget.currentText() for name, widget in self.expectations.items()}, allow_status=[int(v.strip()) for v in self.allow.text().split(',')], deny_status=[int(v.strip()) for v in self.deny.text().split(',')], allow_header=self.header.text().strip() or None, allow_value=self.header_value.text() if self.header.text().strip() else None, json_pointer=pointer, json_value=json.loads(self.json_value.text()) if pointer else None)
            self.accept()
        except ValueError as exc:
            message(self, exc)


class AccessEditor(QWidget):
    def __init__(self, targets, primary, parent=None, primary_session=None):
        super().__init__(parent)
        self.target_provider, self.primary_provider = targets, primary
        self.primary_session_provider = primary_session or (lambda: {})
        self.roles, self.cases = [], []
        self.session_values = {}
        layout = QVBoxLayout(self)
        self.roles_table = QTableWidget(0, 3)
        self.roles_table.setHorizontalHeaderLabels(["Role", "Credentials", "Identity verification"])
        self.roles_table.horizontalHeader().setSectionResizeMode(2, QHeaderView.Stretch)
        self.roles_table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.roles_table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.roles_table.setMaximumHeight(110)
        layout.addWidget(self.roles_table)
        controls = QHBoxLayout()
        for title, callback in (("+ Role", self.add_role), ("Copy primary…", self.copy_primary), ("Edit role…", self.edit_role), ("Remove role", self.remove_role)):
            button = QPushButton(title)
            button.clicked.connect(callback)
            controls.addWidget(button)
        controls.addStretch()
        layout.addLayout(controls)
        self.cases_table = QTableWidget(0, 3)
        self.cases_table.setHorizontalHeaderLabels(["Check", "Endpoint", "Expectations"])
        self.cases_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.Stretch)
        self.cases_table.setColumnWidth(2, 270)
        self.cases_table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.cases_table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        layout.addWidget(self.cases_table)
        controls = QHBoxLayout()
        for title, callback in (("+ Access expectation", self.add_case), ("Edit expectation…", self.edit_case), ("Remove expectation", self.remove_case)):
            button = QPushButton(title)
            button.clicked.connect(callback)
            controls.addWidget(button)
        controls.addStretch()
        layout.addLayout(controls)
        self.roles_table.doubleClicked.connect(self.edit_role)
        self.cases_table.doubleClicked.connect(self.edit_case)

    def set_config(self, roles, cases):
        self.roles, self.cases = list(roles), list(cases)
        self.session_values.clear()
        self.render()

    def render(self):
        self.roles_table.setRowCount(len(self.roles))
        for row, role in enumerate(self.roles):
            mode = "Anonymous" if role.anonymous else "Automatic login" if role.auth.login else "Environment references"
            for col, value in enumerate((role.name, mode, role.auth.verify_url or "No credentials")):
                self.roles_table.setItem(row, col, QTableWidgetItem(value))
        self.cases_table.setRowCount(len(self.cases))
        for row, case in enumerate(self.cases):
            for col, value in enumerate((case.title, f"{case.method} {case.url}", ', '.join(f"{name}: {value}" for name, value in case.expectations.items()))):
                self.cases_table.setItem(row, col, QTableWidgetItem(value))

    def store_role(self, role, index=None, session_values=None):
        old = self.roles[index].name if index is not None else None
        if index is None and len(self.roles) >= 8:
            raise ValueError("A project supports up to eight roles.")
        if role.name in {r.name for i, r in enumerate(self.roles) if i != index}:
            raise ValueError("Role names must be unique.")
        for i, case in enumerate(self.cases):
            values = dict(case.expectations)
            values[role.name] = values.pop(old) if old in values else "deny"
            self.cases[i] = PermissionCase.model_validate({**case.model_dump(), "expectations": values})
        if index is None:
            self.roles.append(role)
        else:
            self.roles[index] = role
        if old:
            self.session_values.pop(old, None)
        if session_values:
            self.session_values[role.name] = session_values
        self.render()

    def add_role(self):
        dialog = RoleDialog(parent=self)
        if dialog.exec():
            try:
                self.store_role(dialog.value, session_values=dialog.session_values)
            except ValueError as exc:
                message(self, exc)
        dialog.session_values = {}
        dialog.initial_values = {}
        dialog.deleteLater()

    def copy_primary(self):
        dialog = None
        try:
            auth = self.primary_provider()
            role = RoleConfig.model_construct(name="admin", anonymous=False, auth=auth)
            dialog = RoleDialog(role, self)
            values = self.primary_session_provider()
            dialog.session_bearer.setText(values.pop('__primary_bearer', '') or '')
            dialog.session_cookie.setText(values.pop('__primary_cookie', '') or '')
            dialog.initial_values = values
            if dialog.exec():
                self.store_role(dialog.value, session_values=dialog.session_values)
        except ValueError as exc:
            message(self, exc)
        finally:
            if dialog:
                dialog.session_values = {}
                dialog.initial_values = {}
                dialog.deleteLater()

    def edit_role(self, *args):
        index = self.roles_table.currentRow()
        if index < 0:
            return
        dialog = RoleDialog(self.roles[index], self)
        dialog.initial_values = dict(self.session_values.get(self.roles[index].name, {}))
        if dialog.exec():
            try:
                self.store_role(dialog.value, index, session_values=dialog.session_values)
            except ValueError as exc:
                message(self, exc)
        dialog.session_values = {}
        dialog.initial_values = {}
        dialog.deleteLater()

    def remove_role(self):
        index = self.roles_table.currentRow()
        if index < 0:
            return
        if self.cases and len(self.roles) <= 2:
            message(self, ValueError("Access comparisons require two roles. Remove the expectations first."))
            return
        name = self.roles.pop(index).name
        self.session_values.pop(name, None)
        self.cases = [PermissionCase.model_validate({**case.model_dump(), "expectations": {k: v for k, v in case.expectations.items() if k != name}}) for case in self.cases]
        self.render()

    def case_dialog(self, index=None):
        try:
            if len(self.roles) < 2:
                raise ValueError("Add at least two roles, including an anonymous role if useful.")
            dialog = PermissionDialog(self.roles, self.target_provider(), self.cases[index] if index is not None else None, self)
            if dialog.exec():
                if dialog.value.id in {c.id for i, c in enumerate(self.cases) if i != index}:
                    raise ValueError("Access check IDs must be unique.")
                if index is None:
                    self.cases.append(dialog.value)
                else:
                    self.cases[index] = dialog.value
                self.render()
        except ValueError as exc:
            message(self, exc)

    def add_case(self):
        self.case_dialog()

    def edit_case(self, *args):
        if self.cases_table.currentRow() >= 0:
            self.case_dialog(self.cases_table.currentRow())

    def remove_case(self):
        if self.cases_table.currentRow() >= 0:
            self.cases.pop(self.cases_table.currentRow())
            self.render()
