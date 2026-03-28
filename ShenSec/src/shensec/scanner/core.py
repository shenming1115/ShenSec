import time
from collections import Counter
import httpx
from ..models import ScanResult, Finding, Severity
from .headers import analyze_headers
from .cookies import analyze_cookies

def calculate_risk_rating(findings: list[Finding]) -> Severity:
    counts = Counter(f.severity for f in findings)
    for sev in [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW]:
        if counts.get(sev, 0) > 0:
            return sev
    return Severity.INFO

def scan_target(url: str, timeout: float = 10.0) -> ScanResult:
    """Core function to orchestrate the scanning process on a given URL."""
    try:
        start_time = time.time()
        # Enforcing SSL verification as default behavior
        response = httpx.get(url, timeout=timeout, follow_redirects=True, verify=True) 
        end_time = time.time()
        
        response_time_ms = round((end_time - start_time) * 1000, 2)
        
        findings = []
        
        # 1. Inspect Headers
        header_findings = analyze_headers(response)
        findings.extend(header_findings)
        
        # 2. Inspect Cookies
        cookie_findings = analyze_cookies(response)
        findings.extend(cookie_findings)
        
        counts = {sev.value: 0 for sev in Severity}
        for f in findings:
            counts[f.severity.value] += 1
            
        risk_rating = calculate_risk_rating(findings)
        
        return ScanResult(
            target_url=url,
            status_code=response.status_code,
            response_time_ms=response_time_ms,
            findings=findings,
            risk_rating=risk_rating,
            severity_counts=counts
        )
    except httpx.ConnectError as e:
        err_msg = str(e)
        if "CERTIFICATE_VERIFY_FAILED" in err_msg or "certificate verify failed" in err_msg.lower():
            return _error_result(url, "REQ-SSL-ERR", "TLS/SSL Certificate Error", f"Failed to verify the target's SSL certificate. This often indicates a local environment trust issue or an invalid/expired target certificate. Error: {err_msg}")
        return _error_result(url, "REQ-CONN-ERR", "Connection Error", f"Failed to connect to {url}. Ensure the target is reachable. Error: {err_msg}")
    except httpx.TimeoutException as e:
        return _error_result(url, "REQ-TO-ERR", "Timeout Error", f"Request to {url} timed out after {timeout} seconds.")
    except httpx.RequestError as e:
        return _error_result(url, "REQ-ERR", "Request Failed", f"An error occurred while requesting {url}. Error: {str(e)}")

def _error_result(url: str, rule_id: str, title: str, description: str) -> ScanResult:
    f = Finding(
        rule_id=rule_id,
        title=title,
        description=description,
        severity=Severity.CRITICAL,
        recommendation="Verify connectivity, DNS settings, and target URL."
    )
    counts = {sev.value: 0 for sev in Severity}
    counts[Severity.CRITICAL.value] = 1
    
    return ScanResult(
        target_url=url,
        status_code=0,
        response_time_ms=0.0,
        findings=[f],
        risk_rating=Severity.CRITICAL,
        severity_counts=counts
    )