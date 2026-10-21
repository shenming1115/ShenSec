import json
from pathlib import Path

import httpx
import pytest
from pydantic import ValidationError

from shensec import audit_project, compare_audits, evaluate_gate
from shensec.auth import AuthConfig
from shensec.access import PermissionCase, RoleConfig
from shensec.project import ProjectConfig, load_project, project_toml
from shensec.login_config import LoginConfig
from shensec.workspace import Workspace

URL = "https://example.com"


@pytest.fixture
def mock_http(monkeypatch):
    original = httpx.Client
    def install(handler):
        monkeypatch.setattr(httpx, "Client", lambda **kwargs: original(transport=httpx.MockTransport(handler), **kwargs))
    monkeypatch.setenv("ADMIN_TOKEN", "private-admin")
    monkeypatch.setenv("MEMBER_TOKEN", "private-member")
    return install


def role(name, env):
    return RoleConfig(name=name, auth=AuthConfig(bearer_env=env, verify_url=URL + '/me', verify_json_pointer='/role', verify_json_value=name))


def config(**kwargs):
    return ProjectConfig(targets=[URL + '/api/admin'], auth=AuthConfig(bearer_env="ADMIN_TOKEN"), check_options=False, roles=[role("admin", "ADMIN_TOKEN"), role("member", "MEMBER_TOKEN"), RoleConfig(name="anonymous", anonymous=True)], permissions=[PermissionCase(id="admin_panel", title="Admin data", url=URL + '/api/admin', expectations={"admin":"allow", "member":"deny", "anonymous":"deny"}, json_pointer='/resource', json_value='admin-data')], **kwargs)


def handler(*, fixed=False, html=False, broken_role=False, denied_status=403):
    def respond(request):
        token = request.headers.get('authorization', '')
        identity = 'admin' if token == 'Bearer private-admin' else 'member' if token == 'Bearer private-member' else None
        if request.url.path == '/me':
            return httpx.Response(401) if not identity else httpx.Response(200, json={'role': 'wrong' if broken_role and identity == 'member' else identity})
        if not identity:
            return httpx.Response(401)
        if html and identity == 'member':
            return httpx.Response(200, text='<html>Sign in</html>', headers={'content-type':'text/html'})
        if fixed and identity != 'admin':
            return httpx.Response(denied_status)
        return httpx.Response(200, json={'resource':'admin-data'}, headers={'content-type':'application/json'})
    return respond


def test_verified_roles_detect_unexpected_access_and_baseline_fix(mock_http):
    settings = config()
    mock_http(handler())
    before = audit_project(settings)
    assert [r.observed for r in before.permissions] == ['allowed', 'allowed', 'denied']
    assert [r.outcome for r in before.permissions] == ['passed', 'failed', 'passed']
    assert before.gate.outcome == 'failed'
    assert any(r.finding.rule_id == 'SEC-ACCESS-UNEXPECTED-ALLOW' for r in before.gate.violations)
    mock_http(handler(fixed=True))
    after = audit_project(settings, baseline=before)
    assert after.gate.outcome == 'passed'
    assert all(r.outcome == 'passed' for r in after.permissions)
    assert len(after.comparison.resolved) == 1
    assert before.access_context == after.access_context
    assert len(after.sessions) == 4
    assert 'private-admin' not in after.model_dump_json()
    assert 'private-member' not in after.model_dump_json()


def test_html_login_page_is_inconclusive_not_a_bypass(mock_http):
    mock_http(handler(html=True))
    report = audit_project(config())
    assert report.permissions[1].outcome == 'error'
    assert report.gate.exit_code == 2
    assert not any(f.rule_id == 'SEC-ACCESS-UNEXPECTED-ALLOW' for f in report.results[0].findings)


def test_wrong_identity_fails_before_endpoint_checks(mock_http):
    calls = []
    base = handler(broken_role=True)
    def respond(request):
        calls.append(request)
        return base(request)
    mock_http(respond)
    with pytest.raises(ValueError, match='Role member:.*identity assertion'):
        audit_project(config())
    assert all(r.url.path == '/me' for r in calls)


def test_changed_or_removed_expectations_cannot_claim_a_fix(mock_http):
    mock_http(handler())
    settings = config()
    before = audit_project(settings)
    changed = settings.model_copy(deep=True)
    changed.permissions[0].expectations['member'] = 'allow'
    after = audit_project(changed, baseline=before)
    assert after.gate.exit_code == 2
    assert after.comparison.context_changed_targets == settings.targets
    removed = settings.model_copy(update={'permissions': [], 'roles': []})
    after = audit_project(removed, baseline=before)
    assert after.gate.exit_code == 2
    assert any(r.finding.rule_id.startswith('SEC-ACCESS-') for r in after.comparison.unverified)


def test_role_state_and_reports_survive_sqlite_restart(mock_http, tmp_path):
    mock_http(handler())
    settings = config()
    report = audit_project(settings)
    store = Workspace(tmp_path)
    project = store.save_project(settings)
    run = store.save_run(project, settings, report)
    restored = Workspace(tmp_path).load_run(project, run)
    assert restored.permissions == report.permissions
    assert restored.sessions == report.sessions
    for secret in ('private-admin', 'private-member'):
        assert secret.encode() not in store.path.read_bytes()


def test_nested_login_roles_and_expectations_roundtrip_toml(tmp_path):
    settings = config()
    settings.auth = AuthConfig(login=LoginConfig(url=URL + '/login', fields_env={'username':'USER', 'password':'PASS'}), verify_url=URL + '/me', verify_json_pointer='/role', verify_json_value='admin')
    path = tmp_path / 'project.toml'
    path.write_text(project_toml(settings), encoding='utf-8')
    assert load_project(path) == settings


def test_cookie_login_and_disabled_defaults_survive_toml_roundtrip(tmp_path):
    settings = config()
    settings.auth = AuthConfig(login=LoginConfig(url=URL + '/login', encoding='form', token_pointer=None, refresh_pointer=None, expires_pointer=None, refresh_field=None), verify_url=URL + '/me', verify_header='X-Authenticated', verify_value='true')
    path = tmp_path / 'cookie-project.toml'
    path.write_text(project_toml(settings), encoding='utf-8')
    restored = load_project(path)
    assert restored == settings
    assert restored.auth.login.token_pointer is None
    assert restored.auth.login.refresh_field is None


def test_empty_login_url_is_rejected():
    with pytest.raises(ValidationError, match='Login URL is required'):
        LoginConfig(url='')


def test_permission_configuration_requires_explicit_complete_scopes():
    with pytest.raises(ValidationError, match='success header or JSON'):
        PermissionCase(id='check', url=URL, expectations={'admin':'allow', 'member':'deny'})
    with pytest.raises(ValidationError, match='identity assertion'):
        RoleConfig(name='admin', auth=AuthConfig(verify_url=URL))
    with pytest.raises(ValidationError, match='Anonymous roles'):
        RoleConfig(name='anonymous', anonymous=True, auth=AuthConfig(bearer_env='TOKEN'))
    with pytest.raises(ValidationError):
        PermissionCase(id='write', url=URL, method='POST', expectations={'admin':'allow', 'member':'deny'}, allow_header='X-OK', allow_value='yes')
    data = config().model_dump()
    data['permissions'][0]['expectations'].pop('member')
    with pytest.raises(ValidationError, match='exactly the configured roles'):
        ProjectConfig.model_validate(data)


def test_denial_401_is_verified_again_to_avoid_expired_session_false_pass(mock_http):
    counts = {'member': 0}
    def respond(request):
        token = request.headers.get('authorization', '')
        if request.url.path == '/me':
            identity = 'member' if token == 'Bearer private-member' else 'admin'
            if identity == 'member':
                counts['member'] += 1
                if counts['member'] > 1:
                    return httpx.Response(401)
            return httpx.Response(200, json={'role':identity})
        if token == 'Bearer private-member':
            return httpx.Response(401)
        return handler(fixed=True)(request)
    mock_http(respond)
    report = audit_project(config())
    assert report.permissions[1].outcome == 'error'
    assert report.gate.exit_code == 2


def test_temporary_role_tokens_reuse_in_memory_without_environment_or_config_values(mock_http, monkeypatch):
    mock_http(handler(fixed=True))
    monkeypatch.delenv('MEMBER_TOKEN')
    cached = {}
    settings = config()
    report = audit_project(settings, role_auth=cached, role_values={'member':{'MEMBER_TOKEN':'private-member'}})
    assert all(r.outcome == 'passed' for r in report.permissions)
    assert cached['member'].environment['MEMBER_TOKEN'] == 'private-member'
    assert 'private-member' not in settings.model_dump_json()
    repeated = audit_project(settings, role_auth=cached)
    assert all(r.outcome == 'passed' for r in repeated.permissions)


def test_cached_identity_cannot_treat_json_true_as_numeric_one(mock_http):
    def respond(request):
        if request.url.path == '/login':
            return httpx.Response(200, json={'access_token':'managed-token'})
        if request.url.path == '/me':
            return httpx.Response(200, json={'id':1})
        return httpx.Response(200, json={'resource':'admin-data'}) if request.headers.get('authorization') else httpx.Response(401)
    mock_http(respond)
    settings = config()
    automatic = AuthConfig(login=LoginConfig(url=URL + '/login'), verify_url=URL + '/me', verify_json_pointer='/id', verify_json_value=1)
    settings.roles = [RoleConfig(name='admin', auth=automatic), RoleConfig(name='anonymous', anonymous=True)]
    settings.permissions[0].expectations = {'admin':'allow', 'anonymous':'deny'}
    cached = {}
    audit_project(settings, role_auth=cached)
    changed = settings.model_copy(deep=True)
    changed.roles[0].auth.verify_json_value = True
    with pytest.raises(ValueError, match='identity assertion'):
        audit_project(changed, role_auth=cached)
