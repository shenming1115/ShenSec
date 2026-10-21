import json
from threading import Event
from urllib.parse import quote

import httpx
import pytest
from pydantic import ValidationError

from shensec.auth import AuthConfig, resolve_auth, verify_auth
from shensec import AuditResult, ScanResult, compare_audits, evaluate_gate, scan_many, scan_target


@pytest.fixture
def mock_http(monkeypatch):
    original = httpx.Client
    def install(handler):
        monkeypatch.setattr(httpx, "Client", lambda **kwargs: original(transport=httpx.MockTransport(handler), **kwargs))
    return install


def test_auth_config_stores_references_and_resolves_all_credential_types():
    config = AuthConfig(bearer_env="TOKEN", cookie_env="COOKIE", header_env={"X-API-Key": "API_KEY"})
    auth = resolve_auth(config, ["https://example.com/api"], environ={"TOKEN": "private-token", "COOKIE": "session=private-session", "API_KEY": "private-api-key"})
    assert auth.headers_for("https://example.com/api")["Authorization"] == "Bearer private-token"
    assert auth.headers_for("https://example.com/api")["Cookie"] == "session=private-session"
    assert auth.headers_for("https://example.com/api")["X-API-Key"] == "private-api-key"
    assert auth.headers_for("https://example.com.evil/") == {}
    assert auth.headers_for("https://example.com:8443/") == {}
    assert "private-" not in config.model_dump_json()
    assert "private-" not in repr(auth)


def test_pasted_authorization_and_cookie_prefixes_are_accepted():
    auth = resolve_auth(AuthConfig(), ["https://example.com"], bearer="Bearer private-token", cookie="Cookie: sid=private-session")
    assert auth.credentials == {"Authorization": "Bearer private-token", "Cookie": "sid=private-session"}


@pytest.mark.parametrize("kwargs", [
    {"headers": {"Authorization": "secret"}}, {"headers": {"X-API-Key": "secret"}},
    {"bearer_env": "literal token here"}, {"header_env": {"Host": "HOST"}},
    {"headers": {"Accept": "x\r\nInjected: value"}},
    {"header_env": {"X-Key": "KEY", "x-key": "KEY2"}},
    {"header_env": {"X-Tenant": "TENANT"}, "headers": {"x-tenant": "tenant"}},
])
def test_invalid_or_plaintext_sensitive_configuration_rejected(kwargs):
    with pytest.raises(ValidationError):
        AuthConfig(**kwargs)


def test_missing_env_and_header_injection_fail_before_requests():
    with pytest.raises(ValueError, match="TOKEN is missing"):
        resolve_auth(AuthConfig(bearer_env="TOKEN"), ["https://example.com"], environ={})
    with pytest.raises(ValueError, match="single-line"):
        resolve_auth(AuthConfig(bearer_env="TOKEN"), ["https://example.com"], environ={"TOKEN": "a\r\nX: y"})
    with pytest.raises(ValueError, match="requires credentials"):
        resolve_auth(AuthConfig(required=True), ["https://example.com"])


def test_credentials_require_https_except_loopback_or_explicit_dev_opt_in():
    with pytest.raises(ValueError, match="HTTPS"):
        resolve_auth(AuthConfig(), ["http://internal.example"], bearer="credential")
    assert resolve_auth(AuthConfig(), ["http://127.0.0.1:8000"], bearer="credential")
    assert resolve_auth(AuthConfig(allow_http=True), ["http://internal.example"], bearer="credential")


def test_authenticated_get_and_options_receive_credentials_but_reports_do_not(mock_http):
    secret = "private/value+123"
    auth = resolve_auth(AuthConfig(header_env={"X-API-Key": "KEY"}), ["https://example.com"], bearer=secret, cookie="sid=private-session", environ={"KEY": "private-api-key"})
    methods = []
    def handler(request):
        methods.append(request.method)
        assert request.headers["authorization"] == "Bearer " + secret
        assert "sid=private-session" in request.headers["cookie"]
        assert request.headers["x-api-key"] == "private-api-key"
        return httpx.Response(200, headers={"server": secret, "x-powered-by": quote(secret, safe="")})
    mock_http(handler)
    result = scan_target("https://example.com/", auth=auth)
    assert result.status == "complete"
    assert methods == ["GET", "OPTIONS"]
    assert result.authentication == "applied"
    assert result.auth_context
    output = result.model_dump_json()
    assert secret not in output
    assert quote(secret, safe="") not in output
    assert "private-session" not in output


def test_credentials_never_follow_redirect_to_other_port_even_with_cross_origin_opt_in(mock_http):
    calls = []
    def handler(request):
        calls.append(str(request.url))
        return httpx.Response(302, headers={"location": "https://example.com:8443/steal"})
    mock_http(handler)
    auth = resolve_auth(AuthConfig(), ["https://example.com"], bearer="very-private-token")
    result = scan_target("https://example.com/", auth=auth, allow_cross_origin=True)
    assert result.status == "error"
    assert len(calls) == 1
    assert "very-private-token" not in result.model_dump_json()


@pytest.mark.parametrize("host", ["localhost", "127.0.0.1"])
def test_session_cookie_is_sent_on_loopback_hosts(mock_http, host):
    def handler(request):
        assert request.headers["cookie"] == "sid=private-session"
        return httpx.Response(200)
    mock_http(handler)
    url = f"http://{host}:8000/"
    result = scan_target(url, auth=resolve_auth(AuthConfig(), [url], cookie="sid=private-session"), check_options=False)
    assert result.status == "complete"


def test_rotated_cookie_is_used_on_redirect_and_redacted_from_echoed_evidence(mock_http):
    def handler(request):
        if request.url.path == "/start":
            assert "sid=initial-session" in request.headers["cookie"]
            return httpx.Response(302, headers={"location": "/end", "set-cookie": "sid=rotated-session; Path=/; Secure"})
        assert "sid=rotated-session" in request.headers["cookie"]
        assert "initial-session" not in request.headers["cookie"]
        return httpx.Response(200, headers={"server": "rotated-session"})
    mock_http(handler)
    auth = resolve_auth(AuthConfig(), ["https://example.com/start"], cookie="sid=initial-session")
    result = scan_target("https://example.com/start", auth=auth, check_options=False)
    assert result.status == "complete"
    assert "rotated-session" not in result.model_dump_json()


def test_reused_worker_does_not_carry_cookies_to_next_target(mock_http):
    def handler(request):
        assert "cookie" not in request.headers
        return httpx.Response(200, headers={"set-cookie": "sid=first-target-only; Path=/"})
    mock_http(handler)
    result = scan_many(["https://example.com/a", "https://example.com/b"], workers=1, check_options=False)
    assert result.failed_targets == 0


def test_session_verification_refuses_login_redirect_or_wrong_success_marker(mock_http):
    config = AuthConfig(verify_url="https://example.com/me", verify_header="X-Authenticated", verify_value="true")
    auth = resolve_auth(config, ["https://example.com/api"], bearer="private-token")
    mock_http(lambda request: httpx.Response(302, headers={"location": "/login"}))
    with pytest.raises(ValueError, match="verification failed"):
        verify_auth(auth, 1)
    mock_http(lambda request: httpx.Response(200, headers={"X-Authenticated": "false"}))
    with pytest.raises(ValueError, match="success header"):
        verify_auth(auth, 1)


def test_auth_context_rotation_is_stable_but_role_changes_cannot_fake_fixes():
    before_auth = resolve_auth(AuthConfig(profile="admin"), ["https://example.com/"], bearer="old-token")
    rotated = resolve_auth(AuthConfig(profile="admin"), ["https://example.com/"], bearer="new-token")
    assert before_auth.context == rotated.context
    verified = resolve_auth(AuthConfig(profile="admin", verify_url="https://example.com/me"), ["https://example.com/"], bearer="new-token")
    assert verified.context != rotated.context  # Disabling verification must change coverage.
    before = AuditResult(results=[ScanResult(target_url="https://example.com/", status_code=200, response_time_ms=1, auth_context=before_auth.context)])
    after = AuditResult(results=[ScanResult(target_url="https://example.com/", status_code=200, response_time_ms=1)])
    after.comparison = compare_audits(after, before)
    assert after.comparison.context_changed_targets == ["https://example.com/"]
    assert evaluate_gate(after, only_new=True).exit_code == 2


def test_cancel_stops_scheduling_and_cannot_pass_policy(monkeypatch):
    import shensec.audit as module
    event = Event()
    calls = []
    def fake_scan(url, *args, **kwargs):
        calls.append(url)
        event.set()
        return ScanResult(target_url=url, status_code=200, response_time_ms=1)
    monkeypatch.setattr(module, "scan_target", fake_scan)
    audit = scan_many([f"https://example.com/{i}" for i in range(20)], workers=1, cancel_event=event)
    assert len(calls) == 1
    assert audit.cancelled
    assert sum(result.cancelled for result in audit.results) == 19
    assert evaluate_gate(audit).exit_code == 2


def test_already_cancelled_scan_performs_no_http_request(mock_http):
    mock_http(lambda request: pytest.fail("Unexpected request"))
    event = Event()
    event.set()
    assert scan_target("https://example.com/", cancel_event=event).status == "cancelled"
