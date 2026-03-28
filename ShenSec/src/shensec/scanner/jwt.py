import json
import base64
import time
from typing import List
from ..models import Finding, Severity

def decode_base64_url(encoded: str) -> str:
    """Helper to decode base64 URI encoded strings safely."""
    # Add padding if necessary
    padding_needed = len(encoded) % 4
    if padding_needed:
        encoded += '=' * (4 - padding_needed)
    # Replace URL-safe chars with standard base64 chars
    encoded = encoded.replace('-', '+').replace('_', '/')
    return base64.b64decode(encoded).decode('utf-8')

def analyze_jwt(token: str) -> List[Finding]:
    """Inspect a JWT for common misconfigurations and payload issues."""
    findings = []
    
    parts = token.split('.')
    if len(parts) != 3:
        findings.append(Finding(
            rule_id="SEC-JWT-001",
            title="Malformed JWT Structure",
            description="The provided token does not contain 3 dot-separated parts.",
            severity=Severity.CRITICAL,
            recommendation="Supply a valid JWT token."
        ))
        return findings
        
    try:
        header_json = decode_base64_url(parts[0])
        payload_json = decode_base64_url(parts[1])
        
        header = json.loads(header_json)
        payload = json.loads(payload_json)
        
        # 1. Header Analysis
        alg = header.get('alg', '').lower()
        if alg == 'none':
            findings.append(Finding(
                rule_id="SEC-JWT-002",
                title="JWT 'None' Algorithm Allowed",
                description="The JWT header specifies 'alg: none', which may bypass signature verification.",
                severity=Severity.CRITICAL,
                recommendation="Reject tokens stating 'alg: none' on your backend."
            ))
        elif alg == '':
            findings.append(Finding(
                rule_id="SEC-JWT-003",
                title="Missing JWT Algorithm",
                description="No algorithm specified in JWT header.",
                severity=Severity.HIGH,
                recommendation="Ensure a secure algorithm like 'HS256' or 'RS256' is specified."
            ))
        elif alg in ['hs128', 'rs128', 'md5', 'none']:
            findings.append(Finding(
                rule_id="SEC-JWT-WEAK-ALG",
                title="Weak JWT Algorithm",
                description=f"The JWT uses a formally weak or deprecated algorithm: {alg.upper()}.",
                severity=Severity.MEDIUM,
                recommendation="Upgrade to a stronger cryptographic algorithm such as HS256, RS256, or ES256."
            ))
            
        # 2. Payload Analysis
        current_time = time.time()
        
        # Expiration
        if 'exp' in payload:
            if payload['exp'] < current_time:
                findings.append(Finding(
                    rule_id="SEC-JWT-EXP",
                    title="JWT is Expired",
                    description="The 'exp' claim is in the past.",
                    severity=Severity.HIGH,
                    recommendation="Ensure the backend correctly invalidates expired tokens."
                ))
        else:
            findings.append(Finding(
                rule_id="SEC-JWT-NOEXP",
                title="Missing Expiration Claim",
                description="The token has no 'exp' claim, meaning it technically never expires.",
                severity=Severity.HIGH,
                recommendation="Always include short-lived 'exp' claims in session tokens to limit attack windows."
            ))
            
        # Not Before / Issued At
        if 'nbf' in payload and payload['nbf'] > current_time + 300: # 5 mins leeway
            findings.append(Finding(
                rule_id="SEC-JWT-NBF",
                title="JWT Not Yet Valid",
                description="The 'nbf' (Not Before) claim is in the future.",
                severity=Severity.MEDIUM,
                recommendation="Ensure server clocks are synced and tokens aren't issued for future dates unnecessarily."
            ))
            
        if 'sub' not in payload and 'id' not in payload:
            findings.append(Finding(
                rule_id="SEC-JWT-NOSUB",
                title="Missing Subject Claim",
                description="The token does not specify a 'sub' (subject) or equivalent identifying claim.",
                severity=Severity.INFO,
                recommendation="Use the 'sub' claim to identify the principal (user) the token is for."
            ))

    except Exception as e:
        findings.append(Finding(
            rule_id="SEC-JWT-004",
            title="Invalid JWT Base64/JSON",
            description=f"Failed to decode or parse JWT header/payload. Error: {str(e)}",
            severity=Severity.HIGH,
            recommendation="Ensure token is well-formed Base64-URL encoded JSON."
        ))
        
    return findings
