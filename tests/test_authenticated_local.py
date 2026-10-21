"""Real HTTP/1.1 credential, pooling, history and baseline integration."""

import pytest

from shensec import audit_project, scan_many
from shensec.auth import AuthConfig, resolve_auth, verify_auth
from shensec.demo import DEMO_TOKEN, demo_project, local_site
from shensec.workspace import Workspace


def test_authenticated_project_baseline_and_history_with_real_requests(tmp_path):
    with local_site() as (url, server):
        config = demo_project(url)
        store = Workspace(tmp_path)
        project_id = store.save_project(config)
        before = audit_project(config)
        before_id = store.save_run(project_id, config, before)
        store.set_baseline(project_id, before_id)
        server.hardened = True
        after = audit_project(config, baseline=store.baseline(project_id))
        store.save_run(project_id, config, after)
        assert server.post_count == 2
    assert before.gate.outcome == "failed"
    assert after.gate.outcome == "passed"
    assert all(result.authentication == "applied" for result in after.results)
    assert len(after.comparison.resolved) == 16
    assert len(after.comparison.new) == 2
    assert any(r.request_method == "POST" and r.status_code == 201 for r in after.results)
    assert any(f.rule_id == "SEC-CORS-ACTIVE-REFLECTION" for r in before.results for f in r.findings)
    assert not after.comparison.unverified
    assert len(Workspace(tmp_path).list_runs(project_id)) == 2
    assert DEMO_TOKEN.encode() not in store.path.read_bytes()
    assert DEMO_TOKEN not in after.model_dump_json()


def test_real_connection_pool_reuses_connections_without_changing_findings():
    with local_site() as (url, server):
        server.hardened = True
        targets = [f"{url}/api/item/{i}" for i in range(8)]
        config = AuthConfig(bearer_env="SHENSEC_DEMO_TOKEN", origins=[url])
        old = scan_many(targets, auth=config, workers=2, reuse_clients=False)
        old_connections = server.connections
        new = scan_many(targets, auth=config, workers=2)
        new_connections = server.connections - old_connections
    assert old.failed_targets == new.failed_targets == 0
    assert old_connections == 8
    assert new_connections <= 2
    assert [result.severity_counts for result in old.results] == [result.severity_counts for result in new.results]


def test_real_auth_verification_fails_for_expired_or_wrong_session():
    with local_site() as (url, server):
        config = demo_project(url)
        auth = resolve_auth(config.auth, config.targets, bearer="wrong-session")
        with pytest.raises(ValueError, match="HTTP 401"):
            verify_auth(auth, 1)
        assert server.connections == 1


def test_demo_command_produces_reviewable_reports_without_credentials(tmp_path):
    import json
    from typer.testing import CliRunner
    from shensec.cli import app
    result = CliRunner().invoke(app, ["demo", "--output-dir", str(tmp_path)])
    assert result.exit_code == 0, result.output
    data = json.loads((tmp_path / "report.json").read_text())
    assert data["gate"]["outcome"] == "passed"
    assert len(data["comparison"]["resolved"]) == 16
    assert (tmp_path / "report.sarif").is_file()
    assert DEMO_TOKEN not in (tmp_path / "report.html").read_text()
    assert not list(tmp_path.glob(".workspace-*"))


def test_real_desktop_worker_runs_api_plan_and_preserves_history(tmp_path):
    pytest.importorskip("PySide6")
    from PySide6.QtCore import QEventLoop, QTimer
    from PySide6.QtWidgets import QApplication
    from shensec.gui.workbench import Workbench
    app = QApplication.instance() or QApplication([])
    with local_site() as (url, server):
        store = Workspace(tmp_path)
        project_id = store.save_project(demo_project(url))
        workbench = Workbench(store)
        def run():
            workbench.start_audit()
            loop = QEventLoop()
            worker = workbench.worker
            worker.finished.connect(loop.quit)
            QTimer.singleShot(15000, loop.quit)
            loop.exec()
            if workbench.worker:
                workbench.cancel()
                worker.wait(5000)
                pytest.fail("Desktop API audit timed out")
        run()
        assert workbench.audit.gate.outcome == "failed"
        workbench.accept_baseline()
        server.hardened = True
        run()
        assert workbench.audit.gate.outcome == "passed"
        assert len(workbench.audit.comparison.resolved) == 16
        assert server.post_count == 2
        assert len(store.list_runs(project_id)) == 2
        assert workbench.request_editor.plans()[0].method == "POST"
        workbench.close()
        app.processEvents()
