import json
import base64
import time
import re
import math
from typing import List
from ..models import Finding, ScanResult, Severity

def decode_base64_url(encoded: str) -> str:
    """Helper to decode base64 URI encoded strings safely."""
    if not re.fullmatch(r"[A-Za-z0-9_-]+", encoded):
        raise ValueError("JWT segments must use unpadded Base64URL encoding.")
    padding_needed = len(encoded) % 4
    if padding_needed:
        encoded += '=' * (4 - padding_needed)
    encoded = encoded.replace('-', '+').replace('_', '/')
    return base64.b64decode(encoded).decode('utf-8')

def analyze_jwt(token: str) -> List[Finding]:
    """Inspect a JWT for common misconfigurations and deeply analyze payload issues."""
    findings = []
    parts = token.split('.')
    if len(parts) != 3:
        findings.append(Finding(
            rule_id="SEC-JWT-001", title="Malformed JWT Structure",
            description="The provided token does not contain 3 dot-separated parts.",
            severity=Severity.CRITICAL, recommendation="Supply a valid JWT token."
        ))
        return findings

    try:
        header_json = decode_base64_url(parts[0])
        payload_json = decode_base64_url(parts[1])

        header = json.loads(header_json)
        payload = json.loads(payload_json)
        if not isinstance(header, dict) or not isinstance(payload, dict):
            raise ValueError("JWT header and payload must be JSON objects.")
        if not isinstance(header.get('alg', ''), str):
            raise ValueError("JWT alg must be a string.")
        if 'kid' in header and not isinstance(header['kid'], str):
            raise ValueError("JWT kid must be a string.")
        if 'exp' in payload and (
            isinstance(payload['exp'], bool) or not isinstance(payload['exp'], (int, float))
            or not math.isfinite(payload['exp'])
        ):
            raise ValueError("JWT exp must be a finite numeric timestamp.")

        # 1. Advanced Header Analysis
        alg = header.get('alg', '').lower()
        if alg == 'none':
            findings.append(Finding(
                rule_id="SEC-JWT-002", title="Unsigned JWT (alg: none)",
                description="The JWT declares alg: none. Local inspection does not establish whether any server accepts it.",
                severity=Severity.CRITICAL, recommendation="Reject tokens stating 'alg: none'."
            ))
        elif alg == '':
            findings.append(Finding(
                rule_id="SEC-JWT-003", title="Missing JWT Algorithm",
                description="No algorithm specified in JWT header.",
                severity=Severity.HIGH, recommendation="Specify a secure algorithm like 'HS256'."
            ))
        elif alg in ['hs128', 'rs128', 'md5', 'none']:
            findings.append(Finding(
                rule_id="SEC-JWT-WEAK-ALG", title="Weak JWT Algorithm",
                description=f"Token uses formally weak or deprecated algorithm: {alg.upper()}.",
                severity=Severity.MEDIUM, recommendation="Upgrade to stronger cryptography (HS256, RS256)."
            ))

        # Check for 'kid' injection
        if 'kid' in header and (header['kid'].startswith("../") or "://" in header['kid']):
            findings.append(Finding(
                rule_id="SEC-JWT-KID-INJ", title="Potential Key ID (kid) Injection",
                description="The 'kid' claim contains directory traversal or URL structures.",
                severity=Severity.CRITICAL, recommendation="Sanitize and map 'kid' values strictly."
            ))
            
        # Check for 'jku' and 'jwk' attacks
        if 'jku' in header or 'jwk' in header:
            findings.append(Finding(
                rule_id="SEC-JWT-EXT-KEY", title="External Key Reference Used (jku/jwk)",
                description="The header contains key material or a key URL. Verify the server's trust policy; presence alone does not prove spoofing.",
                severity=Severity.HIGH, recommendation="Ensure the server strictly validates and allows only trusted URI origins."
            ))

        # 2. Deep Payload Analysis
        current_time = time.time()

        if 'exp' in payload:
            if payload['exp'] < current_time:
                findings.append(Finding(
                    rule_id="SEC-JWT-EXP", title="JWT is Expired",
                    description="The 'exp' claim is in the past.",
                    severity=Severity.HIGH, recommendation="Invalidate expired tokens."
                ))
            elif payload['exp'] > current_time + (86400 * 30):
                findings.append(Finding(
                    rule_id="SEC-JWT-LONG-EXP", title="Excessive JWT Expiration Time",
                    description="Token lifespan exceeds 30 days. Compromised tokens remain valid too long.",
                    severity=Severity.MEDIUM, recommendation="Keep session tokens short-lived (e.g. 15-60 mins) and use refresh tokens."
                ))
        else:
            findings.append(Finding(
                rule_id="SEC-JWT-NOEXP", title="Missing Expiration Claim",
                description="The token has no exp claim. The server may enforce expiration through other controls.",
                severity=Severity.HIGH, recommendation="Always include short-lived 'exp' claims."
            ))

        # Data Leakage / Sensitive Claim detection
        sensitive_keys_pattern = re.compile(r'(?:^|_)(password|passwd|pass|secret|ssn|social_security|credit_card|cvv|token_key|private_key)(?:$|_)', re.IGNORECASE)
        for key, value in payload.items():
            if sensitive_keys_pattern.search(key):
                findings.append(Finding(
                    rule_id="SEC-JWT-SENSITIVE-DATA", title="Sensitive Data Leak in Token Payload",
                    description=f"Payload contains claim '{key}' which suggests hardcoded sensitive info. (JWTs are merely encoded, not encrypted!)",
                    severity=Severity.CRITICAL, recommendation="Never store passwords or secrets inside JWT claims.",
                    location=f"payload.{key}",
                ))
            if isinstance(value, str) and len(value) > 20 and value.startswith("sk_live_"):
                 findings.append(Finding(
                    rule_id="SEC-JWT-API-LEAK", title="API Key Leaked in JWT",
                    description=f"A potential Stripe or similar Secret API Key was found in the token payload.",
                    severity=Severity.CRITICAL, recommendation="Remove backend API keys from client-side tokens.",
                    location=f"payload.{key}",
                ))

        if 'sub' not in payload and 'id' not in payload:
            findings.append(Finding(
                rule_id="SEC-JWT-NOSUB", title="Missing Subject Claim",
                description="The token does not specify a 'sub' (subject).",
                severity=Severity.INFO, recommendation="Use the 'sub' claim to identify the principal."
            ))

    except Exception as e:
        findings.append(Finding(
            rule_id="SEC-JWT-004", title="Invalid JWT Base64/JSON",
            description=f"Failed to decode or parse JWT header/payload. Error: {str(e)}",
            severity=Severity.HIGH, recommendation="Ensure token is well-formed Base64-URL encoded JSON."
        ))

    return findings


def inspect_jwt(token: str) -> ScanResult:
    """A reportable local inspection; the token itself is never retained."""
    start = time.perf_counter()
    findings = analyze_jwt(token)
    return ScanResult(
        target_url="local JWT", status_code=0, scan_kind="jwt", checks=["jwt"],
        response_time_ms=round((time.perf_counter() - start) * 1000, 2),
        findings=findings,
    )
