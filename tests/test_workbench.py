import pytest

pytest.importorskip("PySide6")

from PySide6.QtCore import QEventLoop, QTimer, Qt
from PySide6.QtWidgets import QApplication

from shensec import AuditResult, Finding, ScanResult, Severity, compare_audits, evaluate_gate
from shensec.gui.workbench import Workbench
from shensec.workspace import Workspace


@pytest.fixture
def qapp():
    return QApplication.instance() or QApplication([])


def wait_worker(workbench):
    loop = QEventLoop()
    worker = workbench.worker
    worker.finished.connect(loop.quit)
    deadline = QTimer()
    deadline.setSingleShot(True)
    deadline.timeout.connect(loop.quit)
    deadline.start(10000)
    loop.exec()
    deadline.stop()
    if workbench.worker is not None:
        workbench.cancel()
        worker.wait(5000)
        pytest.fail("Worker did not finish in time")


def make_audit(config, *, fixed=False, baseline=None):
    finding = Finding(
        rule_id="NEW-MEDIUM" if fixed else "OLD-HIGH", title="Review configuration",
        description="Controlled fixture", severity=Severity.MEDIUM if fixed else Severity.HIGH,
        evidence="Header absent", recommendation="Apply the documented fix",
    )
    audit = AuditResult(results=[ScanResult(target_url=config.targets[0], status_code=200, response_time_ms=1, findings=[finding])], duration_ms=25)
    if baseline:
        audit.comparison = compare_audits(audit, baseline)
    audit.gate = evaluate_gate(audit, only_new=baseline is not None)
    return audit


def test_workbench_runs_saved_project_accepts_baseline_and_compares_after_restart(qapp, tmp_path, monkeypatch):
    import shensec.gui.worker as module
    calls = []
    def run(config, baseline=None, auth=None, progress=None, **kwargs):
        assert auth.credentials["Authorization"] == "Bearer session-only-private-token"
        result = make_audit(config, fixed=bool(calls), baseline=baseline)
        calls.append(config)
        progress(1, 1, result.results[0])
        return result
    monkeypatch.setattr(module, "audit_project", run)
    workspace = Workspace(tmp_path)
    workbench = Workbench(workspace)
    workbench.targets.setPlainText("https://example.com/api/me\nhttps://example.com/api/me")
    workbench.session_bearer.setText("session-only-private-token")
    workbench.start_audit()
    assert workbench.session_bearer.text() == ""
    assert not workbench.start_button.isEnabled()
    wait_worker(workbench)
    assert workbench.history.count() == 1
    assert workbench.audit.gate.outcome == "failed"
    assert workbench.baseline_button.isEnabled()
    workbench.accept_baseline()
    assert workspace.baseline(workbench.project_id)
    # Repeated daily scans reuse credentials in memory without another paste.
    workbench.start_audit()
    wait_worker(workbench)
    assert workbench.history.count() == 2
    assert workbench.audit.gate.outcome == "passed"
    assert len(workbench.audit.comparison.resolved) == 1
    workbench.change_filter.setCurrentText("RESOLVED")
    assert workbench.proxy.rowCount() == 1
    workbench.findings.selectRow(0)
    workbench.show_details()
    assert "Apply the documented fix" in workbench.details.toPlainText()
    assert b"session-only-private-token" not in workspace.path.read_bytes()
    restarted = Workbench(Workspace(tmp_path))
    assert restarted.project_id == workbench.project_id
    assert restarted.history.count() == 2
    assert restarted.audit.comparison is not None
    assert restarted.audit.gate.outcome == "passed"
    assert restarted.collect_config().auth.required
    assert restarted._session_bearer is None


def test_workbench_cancelled_run_is_visible_and_not_baselineable(qapp, tmp_path, monkeypatch):
    import shensec.gui.worker as module
    def run(config, cancel_event=None, **kwargs):
        cancel_event.set()
        audit = AuditResult(results=[ScanResult(target_url=config.targets[0], status_code=0, response_time_ms=0, cancelled=True)], cancelled=True)
        audit.gate = evaluate_gate(audit)
        return audit
    monkeypatch.setattr(module, "audit_project", run)
    workbench = Workbench(Workspace(tmp_path))
    workbench.targets.setPlainText("https://example.com/")
    workbench.start_audit()
    wait_worker(workbench)
    assert "Cancelled" in workbench.status.text()
    assert not workbench.baseline_button.isEnabled()
    assert workbench.start_button.isEnabled()
    assert workbench.history.count() == 1


def test_workbench_keeps_scan_result_when_history_storage_fails(qapp, tmp_path, monkeypatch):
    import shensec.gui.worker as module
    monkeypatch.setattr(module, "audit_project", lambda config, **kwargs: make_audit(config))
    workspace = Workspace(tmp_path)
    monkeypatch.setattr(workspace, "save_run", lambda *args: (_ for _ in ()).throw(OSError("disk full")))
    workbench = Workbench(workspace)
    workbench.targets.setPlainText("https://example.com/")
    workbench.start_audit()
    wait_worker(workbench)
    assert workbench.audit is not None
    assert workbench.export_button.isEnabled()
    assert "history could not be saved" in workbench.status.text()
    assert not workbench.baseline_button.isEnabled()


def test_large_finding_table_is_lazy_and_filters_evidence(qapp, tmp_path):
    workbench = Workbench(Workspace(tmp_path))
    findings = [Finding(rule_id=f"RULE-{i}", title=f"Observation {i}", description="Fixture", severity=Severity.LOW, evidence="needle" if i == 123 else "other") for i in range(5000)]
    audit = AuditResult(results=[ScanResult(target_url="https://example.com/", status_code=200, response_time_ms=1, findings=findings)])
    workbench.display_audit(audit)
    assert workbench.model.rowCount() == 5000
    workbench.search.setText("needle")
    workbench.apply_filters()
    assert workbench.proxy.rowCount() == 1
    assert workbench.proxy.data(workbench.proxy.index(0, 3), Qt.DisplayRole) == "RULE-123"


def test_cached_credentials_are_not_reused_when_target_origin_changes(qapp, tmp_path, monkeypatch):
    import shensec.gui.worker as module
    from PySide6.QtWidgets import QMessageBox
    calls, errors = [], []
    def run(config, **kwargs):
        calls.append(config)
        return make_audit(config)
    monkeypatch.setattr(module, "audit_project", run)
    monkeypatch.setattr(QMessageBox, "warning", lambda *args: errors.append(args[-1]))
    workbench = Workbench(Workspace(tmp_path))
    workbench.targets.setPlainText("https://example.com/")
    workbench.session_bearer.setText("project-private-token")
    workbench.start_audit()
    wait_worker(workbench)
    workbench.targets.setPlainText("https://different.example/")
    workbench.start_audit()
    assert len(calls) == 1
    assert workbench._session_bearer is None
    assert "requires credentials" in errors[0]


def test_failed_worker_does_not_leave_previous_passed_summary_visible(qapp, tmp_path, monkeypatch):
    import shensec.gui.worker as module
    monkeypatch.setattr(module, "audit_project", lambda *args, **kwargs: (_ for _ in ()).throw(ValueError("Session verification failed")))
    workbench = Workbench(Workspace(tmp_path))
    workbench.targets.setPlainText("https://example.com/")
    previous = AuditResult(results=[ScanResult(target_url="https://example.com/", status_code=200, response_time_ms=1)])
    previous.gate = evaluate_gate(previous)
    workbench.display_audit(previous)
    assert "PASSED" in workbench.summary.text()
    workbench.start_audit()
    wait_worker(workbench)
    assert workbench.audit is None
    assert "PASSED" not in workbench.summary.text()
    assert "did not complete" in workbench.summary.text()
    assert not workbench.export_button.isEnabled()
    assert workbench.start_button.isEnabled()


def test_api_editors_persist_requests_network_and_exceptions(qapp, tmp_path):
    from shensec import RequestSpec, RuleException
    workbench = Workbench(Workspace(tmp_path))
    url = "https://example.com/api/search"
    workbench.targets.setPlainText(url)
    workbench.request_editor.add(RequestSpec(url=url, method="POST", body_env="SEARCH_BODY", expected_status=[201]))
    workbench.rate.setValue(5)
    workbench.retries.setValue(2)
    workbench.cors.setChecked(True)
    workbench.exception_editor.add(RuleException(rule_id="SEC-HDR-001", target=url, reason="TLS migration scheduled", expires="2099-12-31"))
    config = workbench.save_project()
    reopened = Workbench(Workspace(tmp_path))
    assert reopened.collect_config() == config
    assert reopened.request_editor.table.rowCount() == 1
    assert reopened.exception_editor.table.rowCount() == 1
    reopened.new_project()
    assert reopened.request_editor.table.rowCount() == 0
    assert reopened.exception_editor.table.rowCount() == 0
    assert reopened.retries.value() == 1


def test_openapi_gui_import_merges_targets_and_explains_skips(qapp, tmp_path):
    import json
    workbench = Workbench(Workspace(tmp_path / "workspace"))
    workbench.targets.setPlainText("https://example.com/existing")
    path = tmp_path / "api.json"
    path.write_text(json.dumps({"openapi": "3.0.3", "paths": {"/health": {"get": {}}, "/delete": {"delete": {}}}}))
    workbench.load_api(path, "https://example.com")
    config = workbench.collect_config()
    assert config.targets == ["https://example.com/existing", "https://example.com/health"]
    assert config.requests[0].url == "https://example.com/health"
    assert "DELETE" in workbench.request_editor.message.toPlainText()


def test_accept_finding_saves_expiring_exception_without_rewriting_history(qapp, tmp_path, monkeypatch):
    from PySide6.QtWidgets import QInputDialog
    workbench = Workbench(Workspace(tmp_path))
    workbench.targets.setPlainText("https://example.com/")
    finding = Finding(rule_id="SEC-HDR-001", title="Missing HSTS", description="Fixture", severity=Severity.HIGH)
    audit = AuditResult(results=[ScanResult(target_url="https://example.com/", status_code=200, response_time_ms=1, findings=[finding])])
    audit.gate = evaluate_gate(audit)
    workbench.display_audit(audit)
    workbench.findings.selectRow(0)
    answers = iter([("Managed by edge migration", True), ("2099-12-31", True)])
    monkeypatch.setattr(QInputDialog, "getText", lambda *args, **kwargs: next(answers))
    workbench.accept_finding()
    assert workbench.collect_config().exceptions[0].reason == "Managed by edge migration"
    assert finding.suppression is None
    assert workbench.audit.gate.outcome == "failed"
    from shensec.policy import apply_exceptions
    apply_exceptions(audit, workbench.collect_config().exceptions)
    workbench.display_audit(audit)
    workbench.change_filter.setCurrentText("ACCEPTED")
    assert workbench.proxy.rowCount() == 1


def test_login_test_reuses_session_and_ephemeral_password_never_persists(qapp, tmp_path, monkeypatch):
    import httpx
    import json
    from shensec import AuthConfig, LoginConfig, ProjectConfig
    calls = []
    original = httpx.Client
    def handler(request):
        calls.append(request)
        if request.url.path == '/login':
            assert json.loads(request.content) == {'username':'account-for-ui', 'password':'private-ui-password'}
            return httpx.Response(200, json={'access_token':'private-ui-access', 'expires_in':3600})
        if request.url.path == '/me':
            return httpx.Response(200, json={'role':'admin'})
        assert request.headers['authorization'] == 'Bearer private-ui-access'
        return httpx.Response(200, headers={'content-type':'application/json'})
    monkeypatch.setattr(httpx, 'Client', lambda **kwargs: original(transport=httpx.MockTransport(handler), **kwargs))
    monkeypatch.delenv('UI_LOGIN_USER', raising=False)
    monkeypatch.delenv('UI_LOGIN_PASSWORD', raising=False)
    config = ProjectConfig(targets=['https://example.com/api'], check_options=False, auth=AuthConfig(login=LoginConfig(url='https://example.com/login', fields_env={'username':'UI_LOGIN_USER', 'password':'UI_LOGIN_PASSWORD'}), verify_url='https://example.com/me', verify_json_pointer='/role', verify_json_value='admin'))
    workbench = Workbench(Workspace(tmp_path))
    workbench.apply_config(config)
    workbench.login_editor.account_value.setText('account-for-ui')
    workbench.login_editor.secret_value.setText('private-ui-password')
    workbench.test_login()
    wait_worker(workbench)
    assert 'test passed' in workbench.status.text()
    assert workbench.login_editor.secret_value.text() == ''
    assert not workbench.workspace.path.exists()
    workbench.start_audit()
    wait_worker(workbench)
    assert sum(r.url.path == '/login' for r in calls) == 1
    assert workbench.audit.sessions[0].logins == 0
    assert workbench.audit.failed_targets == 0
    for secret in ('private-ui-password', 'private-ui-access', 'account-for-ui'):
        assert secret.encode() not in workbench.workspace.path.read_bytes()
    assert workbench._runtime_auth is not None
    workbench.clear_session()
    assert workbench._runtime_auth is None
    assert workbench._role_sessions == {}


def test_role_dialog_supports_json_identity_and_cancel_clears_inputs(qapp, monkeypatch):
    from shensec.gui.auth_editors import RoleDialog
    from PySide6.QtWidgets import QMessageBox
    errors = []
    monkeypatch.setattr(QMessageBox, 'warning', lambda *args: errors.append(args[-1]))
    dialog = RoleDialog()
    dialog.name.setText('owner')
    dialog.bearer.setText('OWNER_TOKEN')
    dialog.verify.setText('https://example.com/me')
    dialog.verify_pointer.setText('/account/id')
    dialog.verify_value.setText('42')
    dialog.save()
    assert not errors
    assert dialog.value.auth.verify_json_value == 42
    cancelled = RoleDialog()
    cancelled.login.fields.setPlainText('username=USER_REF\npassword=PASSWORD_REF')
    cancelled.login.secret_value.setText('private-cancelled-input')
    cancelled.reject()
    assert cancelled.login.secret_value.text() == ''
    assert cancelled.session_values == {}


def test_access_matrix_displays_expected_denial_and_unexpected_allow(qapp, tmp_path):
    from shensec.models import PermissionResult
    workbench = Workbench(Workspace(tmp_path))
    result = ScanResult(target_url='https://example.com/api', status_code=200, response_time_ms=1)
    audit = AuditResult(results=[result], permissions=[
        PermissionResult(case_id='admin', title='Admin resource', target_url=result.target_url, role='admin', expected='allow', observed='allowed', outcome='passed', status_code=200),
        PermissionResult(case_id='admin', title='Admin resource', target_url=result.target_url, role='member', expected='deny', observed='allowed', outcome='failed', status_code=200, detail='Expected deny; observed allowed.'),
    ])
    audit.gate = evaluate_gate(audit)
    workbench.display_audit(audit)
    assert workbench.access_results.rowCount() == 1
    assert workbench.access_results.columnCount() == 3
    assert 'UNEXPECTED ALLOW' in workbench.access_results.item(0, 2).text()
    assert workbench.result_tabs.currentWidget() is workbench.access_results
    workbench.show_access_detail(0, 2)
    assert 'Expected: deny' in workbench.details.toPlainText()
    assert '1 violations' in workbench.cards['Access'].text()


def test_role_dialog_temporary_token_saves_only_generated_reference(qapp):
    from shensec.gui.auth_editors import RoleDialog
    dialog = RoleDialog()
    dialog.name.setText('member')
    dialog.session_bearer.setText('private-role-session-token')
    dialog.verify.setText('https://example.com/me')
    dialog.verify_pointer.setText('/role')
    dialog.verify_value.setText('"member"')
    dialog.save()
    assert dialog.value.auth.bearer_env == 'SHENSEC_ROLE_MEMBER_TOKEN'
    assert dialog.session_values['SHENSEC_ROLE_MEMBER_TOKEN'] == 'private-role-session-token'
    assert 'private-role-session-token' not in dialog.value.model_dump_json()
    assert dialog.session_bearer.text() == ''


def test_copy_primary_retains_pasted_credential_only_in_role_memory(qapp, tmp_path, monkeypatch):
    from shensec.gui.auth_editors import RoleDialog
    workbench = Workbench(Workspace(tmp_path))
    workbench.targets.setPlainText('https://example.com/api')
    workbench.verify_url.setText('https://example.com/me')
    workbench.verify_json.setText('/role="admin"')
    workbench.session_bearer.setText('private-primary-copy-token')
    def accept(dialog):
        dialog.save()
        return 1
    monkeypatch.setattr(RoleDialog, 'exec', accept)
    workbench.access_editor.copy_primary()
    assert len(workbench.access_editor.roles) == 1
    assert workbench.access_editor.session_values['admin']['SHENSEC_ROLE_ADMIN_TOKEN'] == 'private-primary-copy-token'
    workbench.save_project()
    assert b'private-primary-copy-token' not in workbench.workspace.path.read_bytes()
    workbench.clear_session()
    assert not workbench.access_editor.session_values
