import httpx
from shensec.scanner.headers import analyze_headers
from shensec.scanner.cookies import analyze_cookies
from shensec.scanner.jwt import analyze_jwt

def test_analyze_headers_missing_all():
    # Mocking an empty response header
    response = httpx.Response(200, request=httpx.Request("GET", "http://test"))
    findings = analyze_headers(response)
    
    # We expect 6 HTTP headers to be missing
    assert len(findings) == 6
    rule_ids = [f.rule_id for f in findings]
    assert "SEC-HDR-001" in rule_ids
    assert "SEC-HDR-002" in rule_ids
    assert "SEC-HDR-003" in rule_ids
    assert "SEC-HDR-004" in rule_ids
    assert "SEC-HDR-005" in rule_ids
    assert "SEC-HDR-006" in rule_ids

def test_analyze_headers_present():
    headers = {
        "Strict-Transport-Security": "max-age=31536000; includeSubDomains; preload",
        "X-Frame-Options": "DENY",
        "Content-Security-Policy": "default-src 'self'",
        "X-Content-Type-Options": "nosniff",
        "Referrer-Policy": "strict-origin-when-cross-origin",
        "Permissions-Policy": "geolocation=(), camera=()"
    }
    response = httpx.Response(200, headers=headers, request=httpx.Request("GET", "http://test"))
    findings = analyze_headers(response)
    
    # No findings if all headers are present and properly configured
    assert len(findings) == 0

def test_analyze_cookies_missing_flags():
    headers = [
        (b"set-cookie", b"session_id=12345; Path=/")
    ]
    response = httpx.Response(200, headers=headers, request=httpx.Request("GET", "http://test"))
    findings = analyze_cookies(response)
    
    assert len(findings) == 3
    rule_ids = [f.rule_id for f in findings]
    assert "SEC-COOKIE-001" in rule_ids # Missing Secure
    assert "SEC-COOKIE-002" in rule_ids # Missing HttpOnly
    assert "SEC-COOKIE-003" in rule_ids # Missing SameSite

def test_analyze_jwt_malformed():
    findings = analyze_jwt("not_a_token")
    assert len(findings) == 1
    assert findings[0].rule_id == "SEC-JWT-001"
    
def test_analyze_jwt_alg_none():
    # Header: {"alg":"none"} -> eyJhbGciOiJub25lIn0
    # Payload: {"sub":"123"} -> eyJzdWIiOiIxMjMifQ
    token = "eyJhbGciOiJub25lIn0.eyJzdWIiOiIxMjMifQ.signature"
    findings = analyze_jwt(token)
    rule_ids = [f.rule_id for f in findings]
    assert "SEC-JWT-002" in rule_ids
    assert "SEC-JWT-NOEXP" in rule_ids
from shensec.scanner.core import analyze_tech_stack, scan_target, analyze_response
from shensec.models import Severity

def test_analyze_tech_stack():
    headers = {
        "Server": "nginx/1.18.0",
        "X-Powered-By": "Express",
        "Access-Control-Allow-Origin": "*"
    }
    response = httpx.Response(200, headers=headers, request=httpx.Request("GET", "http://test"))
    findings = analyze_tech_stack(response)
    
    assert len(findings) == 3
    rule_ids = [f.rule_id for f in findings]
    assert "SEC-SRV-INFO" in rule_ids
    assert "SEC-SRV-POWERED" in rule_ids
    assert "SEC-CORS-STAR" in rule_ids

    # Validate correct updated severities
    for f in findings:
        if f.rule_id == "SEC-CORS-STAR":
            assert f.severity == Severity.LOW
        elif f.rule_id == "SEC-SRV-POWERED":
            assert f.severity == Severity.INFO

def test_analyze_response():
    response = httpx.Response(200, request=httpx.Request("GET", "http://test"))
    result = analyze_response(response, "http://test")
    assert result.status_code == 200
    assert result.response_time_ms == 0.0 # Placeholder correctly set

def test_scan_target_network_error():
    result = scan_target("http://127.0.0.1:99999")
    assert result.status_code == 0
    assert len(result.findings) == 1
    assert result.findings[0].rule_id == "SEC-SCAN-ERR"
    assert result.risk_rating == Severity.CRITICAL

def test_scan_target_aggregation(monkeypatch):
    def mock_get(*args, **kwargs):
         headers = {
            "Server": "nginx/1.18.0",
            "Access-Control-Allow-Origin": "*",
            "Allow": "GET, POST, OPTIONS, PUT, DELETE"
         }
         return httpx.Response(200, headers=headers, request=httpx.Request("GET", "http://test"))
         
    def mock_options(*args, **kwargs):
         headers = {
            "Allow": "GET, POST, OPTIONS, PUT, DELETE"
         }
         return httpx.Response(200, headers=headers, request=httpx.Request("OPTIONS", "http://test"))
         
    monkeypatch.setattr(httpx, "get", mock_get)
    monkeypatch.setattr(httpx, "options", mock_options)
    
    result = scan_target("http://test")
    
    assert result.severity_counts[Severity.MEDIUM.value] >= 1
    assert result.response_time_ms >= 0
