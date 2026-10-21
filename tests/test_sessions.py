from concurrent.futures import ThreadPoolExecutor
import json
from threading import Barrier, Event
from urllib.parse import parse_qs

import httpx
import pytest

from shensec.auth import AuthConfig, resolve_auth
from shensec.login_config import LoginConfig
from shensec.network import NetworkPolicy, RequestPacer
from shensec.sessions import prepare_auth
from shensec import RequestSpec, scan_many, scan_target

URL = "https://example.com"


@pytest.fixture
def mock_http(monkeypatch):
    original = httpx.Client
    def install(handler):
        monkeypatch.setattr(httpx, "Client", lambda **kwargs: original(transport=httpx.MockTransport(handler), **kwargs))
    monkeypatch.setenv("SHENSEC_TEST_LOGIN_USER", "private-user")
    monkeypatch.setenv("SHENSEC_TEST_LOGIN_PASSWORD", "private-password")
    return install


def config(**kwargs):
    return AuthConfig(required=True, login=LoginConfig(url=URL + '/login', fields_env={"username": "SHENSEC_TEST_LOGIN_USER", "password": "SHENSEC_TEST_LOGIN_PASSWORD"}, refresh_url=URL + '/refresh', **kwargs), verify_url=URL + '/me', verify_header="X-Authenticated", verify_value="true")


def token(value="private-access-1", refresh="private-refresh-1", ttl=3600):
    return httpx.Response(200, json={"access_token": value, "refresh_token": refresh, "expires_in": ttl})


def test_json_login_scans_and_redacts_access_password_and_rotated_refresh(mock_http):
    calls = []
    def handler(request):
        calls.append(request)
        if request.url.path == '/login':
            assert json.loads(request.content) == {"username": "private-user", "password": "private-password"}
            return token()
        assert request.headers["authorization"] == "Bearer private-access-1"
        return httpx.Response(200, headers={"X-Authenticated": "true", "server": "private-access-1/private-password/private-refresh-1"})
    mock_http(handler)
    report = scan_many([URL + '/api'], auth=config(), check_options=False)
    assert report.failed_targets == 0
    assert len(calls) == 3
    assert report.sessions[0].logins == 1
    for secret in ("private-access-1", "private-password", "private-refresh-1", "private-user"):
        assert secret not in report.model_dump_json()


def test_expiry_refreshes_and_keeps_context_stable(mock_http):
    exchanges = []
    def handler(request):
        if request.url.path == '/login':
            return token()
        if request.url.path == '/refresh':
            exchanges.append(parse_qs(request.content.decode()))
            return token("private-access-2", "private-refresh-2")
        return httpx.Response(200, headers={"X-Authenticated": "true"})
    mock_http(handler)
    auth = resolve_auth(config(), [URL + '/api'])
    pacer, event = RequestPacer(NetworkPolicy()), Event()
    prepare_auth(auth, 1, pacer, event)
    context = auth.context
    auth.manager.renew_at = 0
    result = scan_many([URL + '/api'], auth=auth, check_options=False)
    assert exchanges == [{"refresh_token": ["private-refresh-1"], "grant_type": ["refresh_token"]}]
    assert auth.context == context
    assert result.sessions[0].refreshes == 1
    assert auth.manager.refresh_token == "private-refresh-2"


def test_concurrent_401s_refresh_once(mock_http):
    barrier, refreshes = Barrier(4), []
    def handler(request):
        if request.url.path == '/login':
            return token()
        if request.url.path == '/refresh':
            refreshes.append(request)
            return token("private-access-2")
        if request.url.path.startswith('/api') and request.headers.get('authorization') == 'Bearer private-access-1':
            barrier.wait(timeout=5)
            return httpx.Response(401)
        return httpx.Response(200, headers={"X-Authenticated": "true"})
    mock_http(handler)
    audit = scan_many([URL + '/api/' + str(i) for i in range(4)], workers=4, auth=config(), check_options=False)
    assert audit.failed_targets == 0
    assert len(refreshes) == 1
    assert audit.sessions[0].refreshes == 1
    assert sum(r.retry_count for r in audit.results) == 4


def test_write_request_is_never_replayed_after_401(mock_http):
    posts = []
    def handler(request):
        if request.url.path == '/login':
            return token()
        if request.url.path == '/refresh':
            pytest.fail("A failed write must not trigger refresh/replay")
        if request.url.path == '/write':
            posts.append(request)
            return httpx.Response(401)
        return httpx.Response(200, headers={"X-Authenticated": "true"})
    mock_http(handler)
    result = scan_many([URL + '/write'], auth=config(), requests=[RequestSpec(url=URL + '/write', method="POST")], check_options=False)
    assert len(posts) == 1
    assert result.results[0].status == "error"


def test_rejected_refresh_reauthenticates_once(mock_http):
    logins, refreshes = [], []
    def handler(request):
        if request.url.path == '/login':
            logins.append(request)
            return token(f"private-access-{len(logins)}")
        if request.url.path == '/refresh':
            refreshes.append(request)
            return httpx.Response(401)
        if request.url.path == '/api' and request.headers.get('authorization') == 'Bearer private-access-1':
            return httpx.Response(401)
        return httpx.Response(200, headers={"X-Authenticated": "true"})
    mock_http(handler)
    report = scan_many([URL + '/api'], auth=config(), check_options=False)
    assert report.failed_targets == 0
    assert len(logins) == 2 and len(refreshes) == 1


def test_renewal_limit_prevents_a_login_loop(mock_http):
    refreshes = []
    def handler(request):
        if request.url.path == '/login':
            return token()
        if request.url.path == '/refresh':
            refreshes.append(request)
            return token("private-access-2")
        return httpx.Response(401) if request.url.path.startswith('/api') else httpx.Response(200, headers={"X-Authenticated": "true"})
    mock_http(handler)
    report = scan_many([URL + '/api/a', URL + '/api/b'], auth=config(max_renewals=1), workers=1, check_options=False)
    assert report.failed_targets == 2
    assert len(refreshes) == 1
    assert "renewal limit" in report.results[1].error


def test_form_cookie_login_uses_csrf_and_respects_cookie_path(mock_http):
    api_cookies = []
    def handler(request):
        if request.url.path == '/csrf':
            return httpx.Response(200, text='<input type="hidden" name="csrf_token" value="private-csrf">', headers={"set-cookie": "csrf=private-csrf-cookie; Path=/; Secure"})
        if request.url.path == '/login':
            fields = parse_qs(request.content.decode())
            assert fields['csrf_token'] == ['private-csrf']
            assert fields['password'] == ['private-password']
            assert 'csrf=private-csrf-cookie' in request.headers.get('cookie', '')
            return httpx.Response(302, headers={"set-cookie": "sid=private-session; Path=/api; Secure; HttpOnly", "location": "/home"})
        if request.url.path.startswith('/api'):
            api_cookies.append(request.headers.get('cookie', ''))
            assert 'sid=private-session' in request.headers.get('cookie', '')
        else:
            assert 'sid=private-session' not in request.headers.get('cookie', '')
        return httpx.Response(200, headers={"X-Authenticated": "true"})
    mock_http(handler)
    recipe = LoginConfig(url=URL + '/login', encoding="form", fields_env={"username": "SHENSEC_TEST_LOGIN_USER", "password": "SHENSEC_TEST_LOGIN_PASSWORD"}, csrf_url=URL + '/csrf', token_pointer=None, success_status=302)
    auth = AuthConfig(login=recipe, verify_url=URL + '/api/me', verify_header="X-Authenticated", verify_value="true")
    report = scan_many([URL + '/api/resource', URL + '/public'], auth=auth, check_options=False)
    assert report.failed_targets == 0
    assert len(api_cookies) == 2


@pytest.mark.parametrize("ttl", [0, -1, True, "3600"])
def test_invalid_expiration_is_not_accepted(mock_http, ttl):
    mock_http(lambda request: token(ttl=ttl))
    with pytest.raises(ValueError, match="expires_in"):
        scan_many([URL + '/api'], auth=config())


def test_login_redirect_cannot_send_credentials_to_another_origin(mock_http):
    calls = []
    def handler(request):
        calls.append(request)
        return httpx.Response(302, headers={"location": "https://elsewhere.example/"})
    mock_http(handler)
    with pytest.raises(ValueError, match="Automatic login failed"):
        scan_many([URL + '/api'], auth=config())
    assert len(calls) == 1


def test_bad_credentials_and_oversized_bodies_are_safe_errors(mock_http):
    mock_http(lambda request: httpx.Response(401, text="private-password and private-user"))
    with pytest.raises(ValueError) as error:
        scan_many([URL + '/api'], auth=config())
    assert 'private-password' not in str(error.value)
    mock_http(lambda request: httpx.Response(200, headers={"content-length": "9999999"}))
    with pytest.raises(ValueError, match="256 KiB"):
        scan_many([URL + '/api'], auth=config())


def test_direct_scan_initializes_login_and_scope_is_enforced(mock_http):
    mock_http(lambda r: token() if r.url.path == '/login' else httpx.Response(200, headers={"X-Authenticated": "true"}))
    result = scan_target(URL + '/api', auth=resolve_auth(config(), [URL + '/api']), check_options=False)
    assert result.authentication == "applied"
    with pytest.raises(ValueError, match="configured credential origins"):
        resolve_auth(AuthConfig(login=LoginConfig(url='https://elsewhere.example/login'), verify_url=URL + '/me', verify_header='X-Authenticated', verify_value='true'), [URL])
    with pytest.raises(ValueError, match="HTTPS"):
        resolve_auth(AuthConfig(login=LoginConfig(url='http://example.com/login'), verify_url='http://example.com/me', verify_header='X-Authenticated', verify_value='true'), ['http://example.com/'])


def test_auto_login_requires_positive_identity_verification():
    with pytest.raises(ValueError, match='identity assertion'):
        AuthConfig(login=LoginConfig(url=URL + '/login'), verify_url=URL + '/me')


def test_new_session_values_force_a_new_login(mock_http):
    accounts = []
    def handler(request):
        if request.url.path == '/login':
            accounts.append(json.loads(request.content)['username'])
            return token()
        return httpx.Response(200, headers={'X-Authenticated':'true'})
    mock_http(handler)
    auth = resolve_auth(config(), [URL + '/api'])
    pacer, event = RequestPacer(NetworkPolicy()), Event()
    prepare_auth(auth, 1, pacer, event)
    auth.set_environment({'SHENSEC_TEST_LOGIN_USER':'another-account'})
    prepare_auth(auth, 1, pacer, event)
    assert accounts == ['private-user', 'another-account']


def test_expired_session_is_renewed_before_a_write(mock_http):
    calls = []
    def handler(request):
        calls.append((request.method, request.url.path))
        if request.url.path == '/login':
            return token()
        if request.url.path == '/refresh':
            return token('private-access-2')
        if request.url.path == '/write':
            assert request.headers['authorization'] == 'Bearer private-access-2'
        return httpx.Response(200, headers={'X-Authenticated':'true'})
    mock_http(handler)
    auth = resolve_auth(config(), [URL + '/write'])
    prepare_auth(auth, 1, RequestPacer(NetworkPolicy()), Event())
    auth.manager.renew_at = 0
    report = scan_many([URL + '/write'], auth=auth, check_options=False, requests=[RequestSpec(url=URL + '/write', method='POST')])
    assert report.failed_targets == 0
    assert calls.index(('POST','/refresh')) < calls.index(('POST','/write'))
    assert calls.count(('POST','/write')) == 1


def test_cancel_during_login_returns_cancelled_audit(mock_http):
    event = Event()
    def handler(request):
        event.set()
        return token()
    mock_http(handler)
    report = scan_many([URL + '/api'], auth=config(), cancel_event=event)
    assert report.cancelled
    assert report.results[0].status == 'cancelled'


def test_json_assertion_reader_handles_escaped_pointers_and_rejects_nonfinite():
    from shensec.http_data import json_document, json_pointer
    document = {'a/b': [{'~key':'value'}]}
    assert json_pointer(document, '/a~1b/0/~0key') == 'value'
    with pytest.raises(ValueError):
        json_pointer(document, '/a~1b/00/~0key')
    with pytest.raises(ValueError, match='valid JSON'):
        json_document(b'{"expires_in":NaN}')


def test_json_refresh_uses_the_provider_field_without_oauth_form_fields(mock_http):
    def handler(request):
        if request.url.path == '/login':
            return token()
        if request.url.path == '/refresh':
            assert json.loads(request.content) == {'refresh_token':'private-refresh-1'}
            return token('private-access-2')
        return httpx.Response(200, headers={'X-Authenticated':'true'})
    mock_http(handler)
    auth = resolve_auth(config(refresh_encoding='json'), [URL + '/api'])
    prepare_auth(auth, 1, RequestPacer(NetworkPolicy()), Event())
    auth.manager.renew_at = 0
    report = scan_many([URL + '/api'], auth=auth, check_options=False)
    assert report.failed_targets == 0
    assert report.sessions[0].refreshes == 1
