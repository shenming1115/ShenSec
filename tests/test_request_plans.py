import json
from threading import Event, Lock
import time

import httpx
import pytest
from pydantic import ValidationError

from shensec import AuditResult, NetworkPolicy, ProjectConfig, RequestSpec, audit_project, compare_audits, evaluate_gate, scan_many, scan_target
from shensec.network import RequestPacer, retry_delay
from shensec.project import load_project, project_toml

URL = "https://example.com/api/search"


@pytest.fixture
def mock_http(monkeypatch):
    original = httpx.Client
    def install(handler):
        monkeypatch.setattr(httpx, "Client", lambda **kwargs: original(transport=httpx.MockTransport(handler), **kwargs))
    return install


def test_explicit_post_body_and_expected_status_with_reflection_redaction(mock_http, monkeypatch):
    monkeypatch.setenv("SEARCH_BODY", '{"query":"private-customer-name"}')
    calls = []
    def handler(request):
        calls.append(request)
        assert request.method == "POST"
        assert json.loads(request.content) == {"query": "private-customer-name"}
        assert request.headers["content-type"] == "application/json"
        return httpx.Response(201, headers={"content-type": "application/json", "server": "private-customer-name"})
    mock_http(handler)
    config = ProjectConfig(targets=[URL], check_options=False, requests=[RequestSpec(url=URL, method="POST", body_env="SEARCH_BODY", expected_status=[201])])
    result = audit_project(config)
    assert len(calls) == 1
    assert result.results[0].request_method == "POST"
    assert result.results[0].status == "complete"
    assert "private-customer-name" not in result.model_dump_json()
    assert "<redacted>" in result.model_dump_json()
    assert "private-customer-name" not in project_toml(config)


@pytest.mark.parametrize("bad", [{"method": "GET", "body_env": "BODY"}, {"expected_status": [199]}, {"method": "TRACE"}, {"content_type": "application/json\r\nInjected: true"}])
def test_invalid_request_plans_rejected(bad):
    with pytest.raises(ValidationError):
        RequestSpec(url=URL, **bad)


def test_all_bodies_validated_before_any_request(mock_http, monkeypatch):
    monkeypatch.delenv("MISSING_BODY", raising=False)
    mock_http(lambda r: pytest.fail("No request should be sent"))
    with pytest.raises(ValueError, match="missing or empty"):
        scan_many([URL, URL + '/two'], requests=[RequestSpec(url=URL + '/two', method="POST", body_env="MISSING_BODY")])


def test_json_body_error_never_prints_value(mock_http, monkeypatch):
    monkeypatch.setenv("BODY", "private malformed data")
    mock_http(lambda r: pytest.fail("No request should be sent"))
    result = scan_target(URL, request_spec=RequestSpec(url=URL, method="POST", body_env="BODY"))
    assert result.status == "error"
    assert "private malformed data" not in result.model_dump_json()


@pytest.mark.parametrize("status,expected_method,expected_body", [(303, "GET", b""), (307, "POST", b'{"id":"private-id"}')])
def test_request_redirect_semantics(mock_http, monkeypatch, status, expected_method, expected_body):
    monkeypatch.setenv("BODY", '{"id":"private-id"}')
    calls = []
    def handler(request):
        calls.append(request)
        return httpx.Response(status, headers={"location": "/result"}) if len(calls) == 1 else httpx.Response(200)
    mock_http(handler)
    result = scan_target(URL, check_options=False, request_spec=RequestSpec(url=URL, method="POST", body_env="BODY"))
    assert result.status == "complete"
    assert calls[1].method == expected_method
    assert calls[1].content == expected_body


def test_request_body_cannot_redirect_to_another_origin(mock_http, monkeypatch):
    monkeypatch.setenv("BODY", '{"id":"private-id"}')
    calls = []
    def handler(request):
        calls.append(request)
        return httpx.Response(307, headers={"location": "https://elsewhere.example/"})
    mock_http(handler)
    result = scan_target(URL, check_options=False, allow_cross_origin=True, request_spec=RequestSpec(url=URL, method="POST", body_env="BODY"))
    assert result.status == "error"
    assert len(calls) == 1
    assert "body redirect" in result.error


def test_method_change_cannot_claim_old_findings_fixed(mock_http):
    mock_http(lambda r: httpx.Response(200, headers={"content-type": "application/json"}))
    before = AuditResult(results=[scan_target(URL, check_options=False)])
    current = AuditResult(results=[scan_target(URL, check_options=False, request_spec=RequestSpec(url=URL, method="HEAD"))])
    current.comparison = compare_audits(current, before)
    assert current.comparison.context_changed_targets == [URL]
    assert current.comparison.unverified
    assert evaluate_gate(current, only_new=True).exit_code == 2


@pytest.mark.parametrize("method,count", [("GET", 3), ("HEAD", 3), ("POST", 1), ("PUT", 1), ("PATCH", 1), ("DELETE", 1)])
def test_transient_status_retries_only_safe_methods(mock_http, method, count):
    calls = []
    def handler(request):
        calls.append(request)
        return httpx.Response(503 if len(calls) < 3 else 200)
    mock_http(handler)
    result = scan_many([URL], check_options=False, requests=[RequestSpec(url=URL, method=method)], network=NetworkPolicy(retries=2, backoff=0))
    assert len(calls) == count
    assert result.results[0].retry_count == count - 1
    assert result.results[0].status == ("complete" if count == 3 else "error")


def test_connection_retry_and_exhausted_retry_are_visible(mock_http):
    calls = []
    def handler(request):
        calls.append(request)
        raise httpx.ConnectError("Controlled refusal", request=request)
    mock_http(handler)
    result = scan_many([URL], check_options=False, network=NetworkPolicy(retries=1, backoff=0))
    assert result.results[0].status == "error"
    assert result.results[0].request_count == 2
    assert result.results[0].retry_count == 1


def test_retry_after_is_bounded_and_cancel_interrupts_wait(mock_http):
    policy = NetworkPolicy(retries=3, backoff=0, max_retry_after=2)
    assert retry_delay("3600", 0, policy) == 2
    assert retry_delay("Wed, 21 Oct 2099 07:28:00 GMT", 0, policy) == 2
    event = Event()
    calls = []
    def handler(request):
        calls.append(request)
        event.set()
        return httpx.Response(429, headers={"retry-after": "3600"})
    mock_http(handler)
    started = time.monotonic()
    result = scan_many([URL], cancel_event=event, network=policy)
    assert time.monotonic() - started < 1
    assert result.cancelled and result.results[0].status == "cancelled"
    assert len(calls) == 1


def test_worker_threads_share_origin_rate_budget(mock_http):
    calls, lock = [], Lock()
    def handler(request):
        with lock:
            calls.append(time.monotonic())
        return httpx.Response(200)
    mock_http(handler)
    result = scan_many([URL + str(i) for i in range(4)], workers=4, check_options=False, network=NetworkPolicy(requests_per_second=20))
    assert result.failed_targets == 0
    assert len(calls) == 4
    assert all(b - a >= 0.03 for a, b in zip(sorted(calls), sorted(calls)[1:]))


def test_cancelled_pacer_does_not_sleep():
    event = Event()
    event.set()
    assert not RequestPacer(NetworkPolicy(requests_per_second=0.01)).wait("https://example.com", event)


def test_project_roundtrip_preserves_new_fields(tmp_path):
    from shensec.policy import RuleException
    config = ProjectConfig(targets=[URL], check_cors=True, requests=[RequestSpec(url=URL, method="POST", body_env="BODY")], network=NetworkPolicy(requests_per_second=5), exceptions=[RuleException(rule_id="SEC-HDR-001", target=URL, reason="Managed at reverse proxy", expires="2099-12-31")])
    path = tmp_path / "project.toml"
    path.write_text(project_toml(config), encoding="utf-8")
    assert load_project(path) == config


def test_request_plans_require_unique_in_scope_urls():
    with pytest.raises(ValidationError, match="one request plan"):
        ProjectConfig(targets=[URL], requests=[RequestSpec(url=URL), RequestSpec(url=URL, method="HEAD")])
    with pytest.raises(ValidationError, match="also appear"):
        ProjectConfig(targets=[URL], requests=[RequestSpec(url=URL + '/other')])


def test_active_cors_uses_only_configured_target_and_has_coverage(mock_http):
    calls = []
    def handler(request):
        calls.append(request)
        assert str(request.url) == URL
        headers = {"content-type": "application/json"}
        if "origin" in request.headers:
            headers.update({"access-control-allow-origin": request.headers["origin"], "access-control-allow-credentials": "true"})
        return httpx.Response(200, headers=headers)
    mock_http(handler)
    result = scan_target(URL, check_options=False, check_cors=True)
    assert len(calls) == 3
    assert "cors-active" in result.checks
    assert any(f.rule_id == "SEC-CORS-ACTIVE-REFLECTION" and f.severity.value == "HIGH" for f in result.findings)
    # Turning the check off cannot make the observed reflection look fixed.
    current = AuditResult(results=[scan_target(URL, check_options=False)])
    current.comparison = compare_audits(current, AuditResult(results=[result]))
    assert any(r.finding.rule_id == "SEC-CORS-ACTIVE-REFLECTION" for r in current.comparison.unverified)


@pytest.mark.parametrize("mode", ["deny", "fixed", "wildcard", "failure"])
def test_cors_does_not_claim_reflection_without_two_confirmations(mock_http, mode):
    def handler(request):
        if "origin" not in request.headers:
            return httpx.Response(200)
        if mode == "deny":
            return httpx.Response(403)
        if mode == "failure":
            return httpx.Response(503)
        return httpx.Response(200, headers={"access-control-allow-origin": "*" if mode == "wildcard" else "https://trusted.example"})
    mock_http(handler)
    result = scan_target(URL, check_options=False, check_cors=True)
    assert not any(f.rule_id.startswith("SEC-CORS-ACTIVE") for f in result.findings)
    assert result.status == ("partial" if mode == "failure" else "complete")
