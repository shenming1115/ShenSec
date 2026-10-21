import httpx
import re
from ..models import Finding, Severity

def analyze_headers(response: httpx.Response) -> list[Finding]:
    findings = []
    
    headers = {k.lower(): v.lower() for k, v in response.headers.items()}
    media_type = headers.get("content-type", "").split(";", 1)[0].strip()
    is_document = media_type in ("", "text/html", "application/xhtml+xml")
    csp = headers.get("content-security-policy", "")
    # Browsers use the first occurrence of each directive.
    csp_directives = {}
    for part in csp.split(";"):
        tokens = part.strip().split()
        if tokens:
            csp_directives.setdefault(tokens[0], tokens[1:])
    ancestors = csp_directives.get("frame-ancestors", [])
    framing_restricted = bool(ancestors) and all(
        token in {"'none'", "'self'"} or ("*" not in token and ("." in token or "://" in token))
        for token in ancestors
    )
    
    # 1. HSTS (Strict-Transport-Security)
    if response.url.scheme == "http":
        findings.append(Finding(
            rule_id="SEC-TRANSPORT-HTTP", title="Unencrypted HTTP Endpoint",
            description="The final response uses HTTP; request and response data are unencrypted.",
            severity=Severity.MEDIUM,
            recommendation="Serve the endpoint over HTTPS and redirect HTTP traffic to HTTPS.",
            evidence="Final response scheme: http",
        ))
    elif "strict-transport-security" not in headers:
        findings.append(Finding(
            rule_id="SEC-HDR-001",
            title="Missing Strict-Transport-Security Header",
            description="The application does not enforce HTTPS connections using HSTS.",
            severity=Severity.HIGH,
            recommendation="Add the Strict-Transport-Security header with an appropriate max-age."
        ))
    else:
        hsts_val = headers["strict-transport-security"]
        max_ages = re.findall(r"(?:^|;)\s*max-age\s*=\s*(\d+)\s*(?=;|$)", hsts_val)
        if len(max_ages) != 1 or not max_ages[0].strip('0'):
            findings.append(Finding(
                rule_id="SEC-HDR-HSTS-WEAK",
                title="Weak HSTS Configuration",
                description="HSTS requires a single positive max-age directive; missing, zero, or invalid values disable protection.",
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
    if is_document and "x-frame-options" not in headers and not framing_restricted:
        findings.append(Finding(
            rule_id="SEC-HDR-002",
            title="Missing X-Frame-Options Header",
            description="The application might be vulnerable to Clickjacking.",
            severity=Severity.MEDIUM,
            recommendation="Set X-Frame-Options to DENY or SAMEORIGIN."
        ))
    elif is_document and "x-frame-options" in headers:
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
    if is_document and "content-security-policy" not in headers:
        findings.append(Finding(
            rule_id="SEC-HDR-003",
            title="Missing Content-Security-Policy Header",
            description="CSP helps prevent XSS and other cross-site injections.",
            severity=Severity.HIGH,
            recommendation="Implement a strict CSP restricting unauthorized resources."
        ))
    elif is_document:
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
    elif headers["x-content-type-options"].strip() != "nosniff":
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
    if is_document and "permissions-policy" not in headers:
        findings.append(Finding(
            rule_id="SEC-HDR-006",
            title="Missing Permissions-Policy Header",
            description="Sensors and browser features are not explicitly locked down.",
            severity=Severity.INFO,
            recommendation="Add Permissions-Policy to restrict features like geolocation, camera, or microphone if unused."
        ))
            
    for finding in findings:
        if finding.evidence is None:
            header_name = {
                "SEC-HDR-001": "strict-transport-security", "SEC-HDR-HSTS-WEAK": "strict-transport-security",
                "SEC-HDR-HSTS-NOSUB": "strict-transport-security", "SEC-HDR-002": "x-frame-options",
                "SEC-HDR-XFO-WEAK": "x-frame-options", "SEC-HDR-003": "content-security-policy",
                "SEC-HDR-CSP-WEAK": "content-security-policy", "SEC-HDR-004": "x-content-type-options",
                "SEC-HDR-CTO-WEAK": "x-content-type-options", "SEC-HDR-005": "referrer-policy",
                "SEC-HDR-RP-WEAK": "referrer-policy", "SEC-HDR-006": "permissions-policy",
            }.get(finding.rule_id)
            finding.evidence = f"{header_name}: {response.headers.get(header_name, '<absent>')}" if header_name else None
    return findings
