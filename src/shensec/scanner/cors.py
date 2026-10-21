"""Interpret two bounded Origin probes sent only to the configured target."""

import httpx

from ..models import Finding, Severity

PROBE_ORIGINS = ("https://shensec-a.invalid", "https://shensec-b.invalid")


def analyze_cors_probes(responses: list[httpx.Response]) -> list[Finding]:
    if len(responses) != 2 or any(r.status_code >= 400 for r in responses):
        return []
    reflected = all(r.headers.get("access-control-allow-origin") == value for r, value in zip(responses, PROBE_ORIGINS))
    if not reflected:
        return []
    credentials = all(r.headers.get("access-control-allow-credentials", "").lower() == "true" for r in responses)
    findings = [Finding(
        rule_id="SEC-CORS-ACTIVE-REFLECTION", title="Untrusted Origins Accepted by CORS",
        description=("Two unrelated probe origins were reflected and credentialed browser access was enabled. Browser cookie policy and response sensitivity still determine impact." if credentials else "Two unrelated probe origins were reflected. Review whether unauthenticated browser access to this endpoint is intended."),
        severity=Severity.HIGH if credentials else Severity.LOW,
        recommendation="Match Origin against an explicit trusted allowlist before returning CORS headers; avoid reflecting arbitrary origins.",
        evidence='; '.join(f"Origin: {value} -> Allow-Origin: {r.headers.get('access-control-allow-origin')}, Allow-Credentials: {r.headers.get('access-control-allow-credentials', '<absent>')}" for r, value in zip(responses, PROBE_ORIGINS)),
    )]
    if any("origin" not in {v.strip().lower() for v in r.headers.get("vary", "").split(',')} and '*' not in r.headers.get("vary", "") for r in responses):
        findings.append(Finding(
            rule_id="SEC-CORS-ACTIVE-VARY", title="Origin-dependent CORS Response Without Vary",
            description="The allow-origin value changed across probes but Vary did not include Origin. Shared caches may reuse the wrong CORS response.",
            severity=Severity.LOW, recommendation="Include Vary: Origin when the response varies by request Origin.",
            evidence="Observed two different Allow-Origin values without Vary: Origin on every response.",
        ))
    return findings
