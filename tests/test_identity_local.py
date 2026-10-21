import json

import pytest
from typer.testing import CliRunner

from shensec.cli import app
from shensec.identity_demo import DEMO_PASSWORD, demo_workspace, identity_project, identity_site
from shensec.project import project_toml


def test_real_auto_login_rotation_and_four_role_regressions(tmp_path):
    with demo_workspace(tmp_path) as (workspace, project, before, current):
        assert before.gate.outcome == 'failed'
        assert len(before.gate.violations) == 3
        assert current.gate.outcome == 'passed'
        assert len(current.comparison.resolved) == 3
        assert len(current.permissions) == 8
        assert all(r.outcome == 'passed' for r in current.permissions)
        assert sum(s.logins for s in before.sessions) == 4
        assert sum(s.refreshes for s in current.sessions) == 4
        assert not current.comparison.unverified
        assert DEMO_PASSWORD.encode() not in workspace.path.read_bytes()
        assert len(workspace.list_runs(project)) == 2
        for report in (before, current):
            assert DEMO_PASSWORD not in report.model_dump_json()


def test_identity_demo_cli_exports_complete_reports(tmp_path):
    result = CliRunner().invoke(app, ['demo', '--identities', '--output-dir', str(tmp_path)])
    assert result.exit_code == 0, result.output
    report = json.loads((tmp_path / 'report.json').read_text(encoding='utf-8'))
    assert report['gate']['outcome'] == 'passed'
    assert len(report['permissions']) == 8
    assert 'Role permission comparison' in (tmp_path / 'report.html').read_text(encoding='utf-8')
    assert 'Role permission comparison' in (tmp_path / 'report.md').read_text(encoding='utf-8')
    assert DEMO_PASSWORD not in (tmp_path / 'report.html').read_text(encoding='utf-8')
    assert not list(tmp_path.glob('.workspace-*'))


def test_cli_auth_test_verifies_a_role_without_permission_requests(tmp_path):
    with identity_site() as (url, server):
        settings = identity_project(url)
        path = tmp_path / 'identity.toml'
        path.write_text(project_toml(settings), encoding='utf-8')
        result = CliRunner().invoke(app, ['auth', 'test', '--config', str(path), '--role', 'owner'])
        assert result.exit_code == 0, result.output
        data = json.loads(result.stdout)
        assert data['session']['profile'] == 'owner'
        assert data['session']['logins'] == 1
        assert data['verification_configured'] is True
        assert server.logins == 1 and server.refreshes == 0
        assert DEMO_PASSWORD not in result.stdout


def test_real_desktop_auto_login_and_permission_matrix(tmp_path):
    pytest.importorskip('PySide6')
    from PySide6.QtCore import QEventLoop, QTimer
    from PySide6.QtWidgets import QApplication
    from shensec.gui.workbench import Workbench
    qapp = QApplication.instance() or QApplication([])
    with demo_workspace(tmp_path) as (workspace, project, before, current):
        window = Workbench(workspace)
        assert window.access_results.rowCount() == 2
        assert window.access_results.columnCount() == 5
        assert window.login_editor.enabled.isChecked()
        window.start_audit()
        loop = QEventLoop()
        worker = window.worker
        worker.finished.connect(loop.quit)
        deadline = QTimer()
        deadline.setSingleShot(True)
        deadline.timeout.connect(loop.quit)
        deadline.start(30000)
        loop.exec()
        deadline.stop()
        if window.worker:
            window.cancel()
            worker.wait(5000)
            pytest.fail('Desktop identity audit timed out')
        assert window.audit.gate.outcome == 'passed'
        assert len(window.audit.permissions) == 8
        assert window.session_results.rowCount() == 5
        assert window.result_tabs.currentWidget() is window.access_results
        assert len(workspace.list_runs(project)) == 3
        assert window._runtime_auth.manager is not None
        assert len(window._role_sessions) == 4
        window.clear_session()
        assert window._runtime_auth is None and not window._role_sessions
        window.close()
        qapp.processEvents()
