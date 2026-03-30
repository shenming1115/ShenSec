import httpx
import time
from typing import List, Optional
from ..models import ScanResult, Finding, Severity

from .headers import analyze_headers
from .cookies import analyze_cookies

def analyze_tech_stack(response: httpx.Response) -> List[Finding]:
    """Detect WAFs, CDNs, and Server Info leaks from Response."""
    findings = []
    
    server_header = response.headers.get("Server", "").lower()
    x_powered_by = response.headers.get("X-Powered-By", "")
    
    # 1. Tech Stack Leaks
    if server_header:
        findings.append(Finding(
            rule_id="SEC-SRV-INFO", title="Server Version Disclosure",
            description=f"Server header reveals: {server_header}",
            severity=Severity.INFO if not any(c.isdigit() for c in server_header) else Severity.LOW,
            recommendation="Configure your web server to hide specific software versions."
        ))
        
    if x_powered_by:
        findings.append(Finding(
            rule_id="SEC-SRV-POWERED", title="Backend Framework Exposure (X-Powered-By)",
            description=f"Identified framework: {x_powered_by}",
            severity=Severity.INFO,
            recommendation="Remove the X-Powered-By header to obscure the technology stack from attackers."
        ))

    # 2. WAF/CDN Detections (Heuristics)
    headers_str = str(response.headers).lower()
    waf_detected = "None identified"
    if "cloudflare" in server_header or "cf-ray" in headers_str:
        waf_detected = "Cloudflare"
    elif "awselb" in server_header:
        waf_detected = "AWS WAF / ELB"
    elif "x-sucuri" in headers_str:
        waf_detected = "Sucuri WAF"
        
    if waf_detected != "None identified":
        findings.append(Finding(
            rule_id="SEC-INFRA-WAF", title="WAF/CDN Detected",
            description=f"The target appears to be protected by {waf_detected}.",
            severity=Severity.INFO,
            recommendation="Information only. Note that WAFs may block deeper active scans."
        ))
        
    # 3. CORS Misconfiguration Detection
    aca_origin = response.headers.get("Access-Control-Allow-Origin")
    if aca_origin == "*":
        findings.append(Finding(
            rule_id="SEC-CORS-STAR", title="Permissive CORS Policy",
            description="Access-Control-Allow-Origin is set to '*'. Assess if this endpoint handles sensitive user session data.",
            severity=Severity.LOW,
            recommendation="If this is an authenticated API, restrict CORS to specific trusted domains."
        ))
        
    return findings

def analyze_response(response: httpx.Response, url: str) -> ScanResult:
    """Analyze a single HTTP response and gather all findings."""
    all_findings = []
    
    # Analyze Response Headers
    all_findings.extend(analyze_headers(response))
    
    # Analyze Cookies
    all_findings.extend(analyze_cookies(response))
    
    # Analyze Advanced Tech / WAF / CORS
    all_findings.extend(analyze_tech_stack(response))

    return ScanResult(
        target_url=url,
        status_code=response.status_code,
        response_time_ms=0.0,
        findings=all_findings
    )
    
def scan_target(url: str, timeout: float = 10.0) -> ScanResult:
    """Perform an active scan (Probing HTTP Methods, WAF heuristic, Framework exposure)."""
    start_time = time.time()
    
    findings = []
    try:
        # Step 1: Base HTTP GET request
        response = httpx.get(url, timeout=timeout, follow_redirects=True)
        scan_result = analyze_response(response, url=url)
        
        # Step 2: Active Recon (OPTIONS HTTP Method to check enabled features)
        try:
            options_resp = httpx.options(url, timeout=timeout)
            allow_header = options_resp.headers.get("Allow", "").upper()
            if allow_header:
                if "PUT" in allow_header or "DELETE" in allow_header or "TRACE" in allow_header:
                    scan_result.findings.append(Finding(
                        rule_id="SEC-HTTP-METHODS", title="Dangerous HTTP Methods Enabled",
                        description=f"The server allows potentially dangerous methods: {allow_header}",
                        severity=Severity.MEDIUM,
                        recommendation="Disable unnecessary HTTP methods (PUT, DELETE, TRACE) unless strictly required by the API."
                    ))
        except Exception:
            pass # Keep going if OPTIONS fails

    except Exception as e:
        # If the scan completely fails, return a synthetic result
        scan_result = ScanResult(
            target_url=url,
            status_code=0,
            response_time_ms=0.0,
            findings=[Finding(
                rule_id="SEC-SCAN-ERR", title="Scan Execution Failed",
                description=f"Could not connect to {url}. Error: {str(e)}",
                severity=Severity.CRITICAL, recommendation="Verify the host is up and accessible."
            )]
        )

    # Calculate overall risk based on highest severity finding
    counts = {s.value: 0 for s in Severity}
    for f in scan_result.findings:
        counts[f.severity.value] += 1
        
    rating = Severity.INFO
    if counts[Severity.CRITICAL.value] > 0:
        rating = Severity.CRITICAL
    elif counts[Severity.HIGH.value] > 0:
        rating = Severity.HIGH
    elif counts[Severity.MEDIUM.value] > 0:
        rating = Severity.MEDIUM
    elif counts[Severity.LOW.value] > 0:
        rating = Severity.LOW

    scan_result.severity_counts = counts
    scan_result.risk_rating = rating
    scan_result.response_time_ms = round((time.time() - start_time) * 1000, 2)
    return scan_result
