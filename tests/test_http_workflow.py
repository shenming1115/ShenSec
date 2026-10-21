import base64
import json

import httpx
import pytest

from shensec import analyze_jwt, analyze_response, scan_target, Severity
from shensec.scanner.cookies import analyze_cookies
from shensec.scanner.headers import analyze_headers


@pytest.fixture
def mock_http(monkeypatch):
    original_client = httpx.Client
    def install(handler):
        monkeypatch.setattr(httpx, "Client", lambda **kwargs: original_client(
            transport=httpx.MockTransport(handler), **kwargs,
        ))
    return install


def test_header_audit_never_reads_response_body(mock_http):
    class UnreadBody(httpx.SyncByteStream):
        closed = False
        def __iter__(self):
            raise AssertionError("Response body should not be downloaded")
        def close(self):
            self.closed = True
    body = UnreadBody()
    mock_http(lambda request: httpx.Response(200, stream=body))
    result = scan_target("https://example.com", check_options=False)
    assert result.status == "complete"
    assert result.severity_counts["HIGH"] >= 1
    assert body.closed


@pytest.mark.parametrize("allow", [False, True])
def test_cross_origin_redirects_require_opt_in(mock_http, allow):
    calls = []
    def handler(request):
        calls.append(str(request.url))
        return httpx.Response(302, headers={"location": "https://destination.example/"}) if request.url.host == "source.example" else httpx.Response(200)
    mock_http(handler)
    result = scan_target("https://source.example/", allow_cross_origin=allow, check_options=False)
    assert result.status == ("complete" if allow else "error")
    assert len(calls) == (2 if allow else 1)


def test_https_upgrade_redirect_cookies_and_final_options_are_recorded(mock_http):
    calls = []
    def handler(request):
        calls.append((request.method, str(request.url)))
        if request.url.scheme == "http":
            return httpx.Response(301, headers={"location": "https://example.com/login", "set-cookie": "sid=sensitive-value; Path=/"})
        return httpx.Response(200, headers={"allow": "GET, OPTIONS, DELETE"})
    mock_http(handler)
    result = scan_target("http://example.com/")
    assert result.status == "complete"
    assert result.final_url == "https://example.com/login"
    assert result.redirect_chain == ["http://example.com/"]
    assert calls[-1] == ("OPTIONS", "https://example.com/login")
    assert any(f.rule_id == "SEC-COOKIE-001" for f in result.findings)
    assert "sensitive-value" not in result.model_dump_json()


def test_redirect_loop_is_bounded(mock_http):
    calls = []
    def handler(request):
        calls.append(request)
        return httpx.Response(302, headers={"location": "/loop"})
    mock_http(handler)
    result = scan_target("https://example.com/")
    assert result.status == "error"
    assert "limit" in result.error.lower()
    assert len(calls) == 11


def test_options_failure_is_partial_not_clean_success(mock_http):
    def handler(request):
        if request.method == "OPTIONS":
            raise httpx.ReadTimeout("timeout", request=request)
        return httpx.Response(200)
    mock_http(handler)
    result = scan_target("https://example.com/")
    assert result.status == "partial"
    assert result.warnings
    assert "http-methods" not in result.checks


@pytest.mark.parametrize("status", [401, 404, 500])
def test_error_pages_are_not_successful_audits(mock_http, status):
    mock_http(lambda request: httpx.Response(status))
    result = scan_target("https://example.com/")
    assert result.status == "error"
    assert str(status) in result.error


def test_advertised_methods_are_parsed_as_exact_tokens(mock_http):
    mock_http(lambda request: httpx.Response(200, headers={"allow": "GET, DELETEALL, OUTPUT"}))
    result = scan_target("https://example.com/")
    assert not any(f.rule_id == "SEC-HTTP-METHODS" for f in result.findings)


def test_json_api_is_not_flagged_for_document_only_controls():
    response = httpx.Response(200, headers={"content-type": "application/json"}, request=httpx.Request("GET", "https://api.example/"))
    result = analyze_response(response, str(response.url))
    assert result.risk_rating == Severity.HIGH  # HSTS is still applicable.
    assert not {"SEC-HDR-002", "SEC-HDR-003", "SEC-HDR-006"} & {f.rule_id for f in result.findings}


def test_hsts_is_not_recommended_on_cleartext_http():
    response = httpx.Response(200, request=httpx.Request("GET", "http://example.com"))
    rules = {f.rule_id for f in analyze_headers(response)}
    assert "SEC-TRANSPORT-HTTP" in rules
    assert "SEC-HDR-001" not in rules


@pytest.mark.parametrize("value", ["max-age=0", "max-age=-1", "max-age=abc", "max-age=1; max-age=2"])
def test_disabled_or_invalid_hsts_is_reported(value):
    response = httpx.Response(200, headers={"strict-transport-security": value}, request=httpx.Request("GET", "https://example.com"))
    assert any(f.rule_id == "SEC-HDR-HSTS-WEAK" for f in analyze_headers(response))


def test_csp_frame_ancestors_avoids_duplicate_clickjacking_warning():
    response = httpx.Response(200, headers={"content-security-policy": "default-src 'self'; frame-ancestors 'none'"}, request=httpx.Request("GET", "https://example.com"))
    assert not any(f.rule_id == "SEC-HDR-002" for f in analyze_headers(response))


@pytest.mark.parametrize("policy", ["frame-ancestors", "frame-ancestors *", "frame-ancestors *; frame-ancestors 'none'"])
def test_empty_or_permissive_frame_ancestors_does_not_hide_clickjacking_warning(policy):
    response = httpx.Response(200, headers={"content-security-policy": policy}, request=httpx.Request("GET", "https://example.com"))
    assert any(f.rule_id == "SEC-HDR-002" for f in analyze_headers(response))


def test_cookie_name_cannot_masquerade_as_a_secure_attribute():
    response = httpx.Response(200, headers={"set-cookie": "secure=value; SameSite=None; Path=/CaseSensitive"}, request=httpx.Request("GET", "https://example.com"))
    findings = analyze_cookies(response)
    assert any(f.rule_id == "SEC-COOKIE-001" for f in findings)
    assert all("CaseSensitive" in f.location for f in findings)
    assert all("=value" not in f.evidence for f in findings)


@pytest.mark.parametrize("header,payload", [([], {}), ({"alg": 12}, {}), ({"alg": "HS256", "kid": []}, {}), ({"alg": "HS256"}, {"exp": True}), ({"alg": "HS256"}, {"exp": "tomorrow"})])
def test_invalid_jwt_claim_types_report_a_parse_problem(header, payload):
    def encode(data):
        return base64.urlsafe_b64encode(json.dumps(data).encode()).rstrip(b"=").decode()
    findings = analyze_jwt(f"{encode(header)}.{encode(payload)}.signature")
    assert [f.rule_id for f in findings] == ["SEC-JWT-004"]
