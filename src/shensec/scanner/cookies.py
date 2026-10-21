import httpx
from ..models import Finding, Severity

def analyze_cookies(response: httpx.Response) -> list[Finding]:
    findings = []
    
    # We examine the raw Set-Cookie headers rather than just response.cookies
    # because response.cookies drops some directives or abstracts them.
    for name, value in response.headers.multi_items():
        if name.lower() == "set-cookie":
            parts = value.split(';')
            if '=' not in parts[0]:
                continue
            cookie_parts = [part.strip().lower() for part in parts[1:]]
            attributes = {part.partition('=')[0].strip().lower(): part.partition('=')[2].strip() for part in parts[1:]}
            cookie_name = parts[0].split('=', 1)[0].strip()
            first_finding = len(findings)
            
            is_secure = "secure" in cookie_parts
            is_httponly = "httponly" in cookie_parts
            
            samesite_kw = attributes.get("samesite", "").lower()
            is_samesite_none = samesite_kw == "none"
            
            is_session_cookie = not any(p.startswith("expires") or p.startswith("max-age") for p in cookie_parts)
            
            if not is_secure:
                findings.append(
                    Finding(
                        rule_id="SEC-COOKIE-001",
                        title=f"Cookie without Secure flag: {cookie_name}",
                        description=f"The cookie '{cookie_name}' (Session: {is_session_cookie}) is missing the 'Secure' flag.",
                        severity=Severity.HIGH,
                        recommendation="Add the 'Secure' attribute to the cookie."
                    )
                )
                
            if not is_httponly:
                findings.append(
                    Finding(
                        rule_id="SEC-COOKIE-002",
                        title=f"Cookie without HttpOnly flag: {cookie_name}",
                        description=f"The cookie '{cookie_name}' is missing the 'HttpOnly' flag, making it accessible to client-side scripts (XSS).",
                        severity=Severity.HIGH,
                        recommendation="Add the 'HttpOnly' attribute to the cookie."
                    )
                )
                
            if not samesite_kw:
                findings.append(
                    Finding(
                        rule_id="SEC-COOKIE-003",
                        title=f"Cookie without SameSite attribute: {cookie_name}",
                        description=f"The cookie '{cookie_name}' is missing the 'SameSite' attribute, leaving it prone to Cross-Site Request Forgery (CSRF).",
                        severity=Severity.MEDIUM,
                        recommendation="Set the 'SameSite' attribute to 'Lax' or 'Strict'."
                    )
                )
            elif is_samesite_none and not is_secure:
                findings.append(
                    Finding(
                        rule_id="SEC-COOKIE-004",
                        title=f"Incompatible SameSite/Secure: {cookie_name}",
                        description=f"The cookie '{cookie_name}' explicitly sets SameSite=None but lacks the Secure flag. Browsers will reject this cookie.",
                        severity=Severity.MEDIUM,
                        recommendation="SameSite=None must be paired with the Secure flag."
                    )
                )
            for finding in findings[first_finding:]:
                finding.location = f"{response.url} | cookie:{cookie_name} | path:{attributes.get('path', '<default>')} | domain:{attributes.get('domain', '<host>')}"
                finding.evidence = f"Set-Cookie: {cookie_name}=<redacted>; " + '; '.join(parts[1:]).strip()

    return findings
