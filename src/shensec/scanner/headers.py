import httpx
from ..models import ScanResult, Finding, Severity

def analyze_headers(response: httpx.Response) -> list[Finding]:
    findings = []
    
    headers = {k.lower(): v.lower() for k, v in response.headers.items()}
    
    # 1. HSTS (Strict-Transport-Security)
    if "strict-transport-security" not in headers:
        findings.append(Finding(
            rule_id="SEC-HDR-001",
            title="Missing Strict-Transport-Security Header",
            description="The application does not enforce HTTPS connections using HSTS.",
            severity=Severity.HIGH,
            recommendation="Add the Strict-Transport-Security header with an appropriate max-age."
        ))
    else:
        hsts_val = headers["strict-transport-security"]
        if "max-age=" not in hsts_val:
            findings.append(Finding(
                rule_id="SEC-HDR-HSTS-WEAK",
                title="Weak HSTS Configuration",
                description="The HSTS header is missing a 'max-age' directive.",
                severity=Severity.MEDIUM,
                recommendation="Configure 'max-age' to a value like 31536000 (1 year)."
            ))
        if "includesubdomains" not in hsts_val:
            findings.append(Finding(
                rule_id="SEC-HDR-HSTS-NOSUB",
                title="HSTS Missing includeSubDomains",
                description="The HSTS header does not apply to subdomains.",
                severity=Severity.LOW,
                recommendation="Add 'includeSubDomains' to protect all subdomains."
            ))

    # 2. X-Frame-Options
    if "x-frame-options" not in headers:
        findings.append(Finding(
            rule_id="SEC-HDR-002",
            title="Missing X-Frame-Options Header",
            description="The application might be vulnerable to Clickjacking.",
            severity=Severity.MEDIUM,
            recommendation="Set X-Frame-Options to DENY or SAMEORIGIN."
        ))
    else:
        xfo_val = headers["x-frame-options"]
        if xfo_val not in ["deny", "sameorigin"]:
            findings.append(Finding(
                rule_id="SEC-HDR-XFO-WEAK",
                title="Weak X-Frame-Options",
                description=f"X-Frame-Options is set to '{xfo_val}', which is inherently weak or obsolete (like ALLOW-FROM).",
                severity=Severity.MEDIUM,
                recommendation="Change X-Frame-Options to 'DENY' or 'SAMEORIGIN'."
            ))
        
    # 3. Content-Security-Policy (CSP)
    if "content-security-policy" not in headers:
        findings.append(Finding(
            rule_id="SEC-HDR-003",
            title="Missing Content-Security-Policy Header",
            description="CSP helps prevent XSS and other cross-site injections.",
            severity=Severity.HIGH,
            recommendation="Implement a strict CSP restricting unauthorized resources."
        ))
    else:
        csp_val = headers["content-security-policy"]
        if "unsafe-inline" in csp_val or "unsafe-eval" in csp_val:
            findings.append(Finding(
                rule_id="SEC-HDR-CSP-WEAK",
                title="Weak Content-Security-Policy",
                description="The CSP allows 'unsafe-inline' or 'unsafe-eval' which significantly reduces XSS protection.",
                severity=Severity.HIGH,
                recommendation="Remove unsafe flags and rely on nonces or strict allowed domains."
            ))

    # 4. X-Content-Type-Options
    if "x-content-type-options" not in headers:
        findings.append(Finding(
            rule_id="SEC-HDR-004",
            title="Missing X-Content-Type-Options Header",
            description="Without this header, browsers may perform MIME sniffing, leading to potential XSS.",
            severity=Severity.MEDIUM,
            recommendation="Add the 'X-Content-Type-Options: nosniff' header."
        ))
    elif "nosniff" not in headers["x-content-type-options"]:
        findings.append(Finding(
            rule_id="SEC-HDR-CTO-WEAK",
            title="Incomplete X-Content-Type-Options",
            description="The header is present but not configured to 'nosniff'.",
            severity=Severity.LOW,
            recommendation="Ensure the value is exactly 'nosniff'."
        ))
        
    # 5. Referrer-Policy
    if "referrer-policy" not in headers:
        findings.append(Finding(
            rule_id="SEC-HDR-005",
            title="Missing Referrer-Policy Header",
            description="The site may leak sensitive URLs via the Referer header to external sites.",
            severity=Severity.LOW,
            recommendation="Add a Referrer-Policy header like 'strict-origin-when-cross-origin'."
        ))
    else:
        rp_val = headers["referrer-policy"]
        if "unsafe-url" in rp_val:
            findings.append(Finding(
                rule_id="SEC-HDR-RP-WEAK",
                title="Weak Referrer-Policy",
                description="Referrer-Policy is set to 'unsafe-url', actively leaking origin and path data to all environments.",
                severity=Severity.MEDIUM,
                recommendation="Use a safer policy like 'strict-origin-when-cross-origin'."
            ))
        
    # 6. Permissions-Policy
    if "permissions-policy" not in headers:
        findings.append(Finding(
            rule_id="SEC-HDR-006",
            title="Missing Permissions-Policy Header",
            description="Sensors and browser features are not explicitly locked down.",
            severity=Severity.INFO,
            recommendation="Add Permissions-Policy to restrict features like geolocation, camera, or microphone if unused."
        ))
            
    return findings
