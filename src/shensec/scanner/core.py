"""Bounded HTTP configuration auditing with isolated credentials and sessions."""

import math
import time
from contextlib import nullcontext
from threading import Event
from http.cookies import SimpleCookie

import httpx

from ..models import Finding, ScanResult, Severity
from ..targets import normalize_target
from ..auth import RuntimeAuth, origin, resolve_auth
from ..network import NetworkPolicy, RequestPacer, retry_delay
from ..requests import RequestSpec, payload_secrets
from .cookies import analyze_cookies
from .headers import analyze_headers
from .cors import PROBE_ORIGINS, analyze_cors_probes


def analyze_tech_stack(response: httpx.Response) -> list[Finding]:
    findings = []
    server = response.headers.get("server", "")
    powered = response.headers.get("x-powered-by", "")
    if server:
        findings.append(Finding(
            rule_id="SEC-SRV-INFO", title="Server Version Disclosure",
            description=f"Server header reveals: {server}",
            severity=Severity.LOW if any(c.isdigit() for c in server) else Severity.INFO,
            recommendation="Hide specific software versions in the Server header.",
            evidence=f"Server: {server}",
        ))
    if powered:
        findings.append(Finding(
            rule_id="SEC-SRV-POWERED", title="Backend Framework Exposure (X-Powered-By)",
            description=f"Identified framework: {powered}", severity=Severity.INFO,
            recommendation="Remove the X-Powered-By header.",
            evidence=f"X-Powered-By: {powered}",
        ))
    waf = None
    if "cloudflare" in server.lower() or "cf-ray" in response.headers:
        waf = "Cloudflare"
    elif "awselb" in server.lower():
        waf = "AWS ELB"
    elif any(name.startswith("x-sucuri") for name in response.headers):
        waf = "Sucuri"
    if waf:
        findings.append(Finding(
            rule_id="SEC-INFRA-WAF", title="WAF/CDN Indicator Detected",
            description=f"Response headers contain indicators associated with {waf}.",
            severity=Severity.INFO,
            recommendation="Treat this as an infrastructure hint; it does not establish WAF protection.",
        ))
    if response.headers.get("access-control-allow-origin") == "*":
        findings.append(Finding(
            rule_id="SEC-CORS-STAR", title="Permissive CORS Policy",
            description="Any origin may read non-credentialed responses. Public APIs may intentionally allow this.",
            severity=Severity.LOW,
            recommendation="Restrict allowed origins when responses contain non-public data.",
            evidence="Access-Control-Allow-Origin: *",
        ))
    return findings


def analyze_response(response: httpx.Response, url: str) -> ScanResult:
    findings = analyze_headers(response) + analyze_cookies(response) + analyze_tech_stack(response)
    return ScanResult(
        target_url=url, final_url=str(response.url), status_code=response.status_code,
        response_time_ms=0.0, findings=findings,
        checks=["headers", "cookies", "server", "cors"],
    )


def _redirect_allowed(source: httpx.URL, destination: httpx.URL) -> bool:
    if (source.scheme, source.host, source.port) == (destination.scheme, destination.host, destination.port):
        return True
    # A normal same-host HTTP -> HTTPS upgrade remains convenient by default.
    return (
        source.scheme == "http" and source.port in (None, 80)
        and destination.scheme == "https" and destination.port in (None, 443)
        and source.host == destination.host
    )


class ScanCancelled(Exception):
    pass


def cancelled_result(url: str) -> ScanResult:
    return ScanResult(target_url=url, status_code=0, response_time_ms=0, cancelled=True, error="Cancelled by user.")


def _release(response: httpx.Response) -> None:
    # Drain only small, explicitly bounded, uncompressed bodies so the connection
    # can be reused. Bodies are not decoded, retained, or analyzed.
    length = response.headers.get("content-length", "")
    try:
        if length.isdecimal() and len(length) < 8 and int(length) <= 16384 and not response.is_stream_consumed and response.headers.get("content-encoding", "identity") == "identity":
            consumed = 0
            for chunk in response.iter_raw():
                consumed += len(chunk)
                if consumed > 16384:
                    break
    except httpx.HTTPError:
        pass  # An optional connection reuse optimization must not change findings.
    finally:
        response.close()


def scan_target(
    url: str, timeout: float = 10.0, *, check_options: bool = True,
    allow_cross_origin: bool = False, auth: RuntimeAuth | None = None,
    cancel_event: Event | None = None, client: httpx.Client | None = None,
    request_spec: RequestSpec | None = None, pacer: RequestPacer | None = None,
    check_cors: bool = False,
) -> ScanResult:
    """Audit one endpoint. An injected client must belong to this worker thread."""
    start = time.perf_counter()
    chain: list[str] = []
    requests = 0
    retries = 0
    event = cancel_event if cancel_event is not None else Event()
    pacer = pacer or RequestPacer(NetworkPolicy(retries=0))
    plan = request_spec
    supplied_auth = auth is not None
    jars: dict[str, httpx.Cookies] = {}
    seeded: set[str] = set()
    jar_generation = -1

    def checkpoint():
        if cancel_event is not None and cancel_event.is_set():
            raise ScanCancelled()

    try:
        checkpoint()
        if not math.isfinite(timeout) or timeout <= 0:
            raise ValueError("Timeout must be a finite positive number.")
        target = normalize_target(url)
        # A runtime also provides payload redaction for anonymous requests.
        auth = auth or resolve_auth(None, [target])
        plan = plan or RequestSpec(url=target)
        if plan.url != target:
            raise ValueError("Request plan URL must match the target.")
        payload = plan.payload()
        for secret in payload_secrets(payload):
            auth.remember_secret(secret)
        if auth and (auth.credentials or auth.config.login) and origin(target) not in auth.allowed:
            raise ValueError("Target is outside the configured authentication origins.")
        if auth.config.login and auth.manager is None:
            from ..sessions import prepare_auth
            prepare_auth(auth, timeout, pacer, event)
        manager = nullcontext(client) if client is not None else httpx.Client(timeout=timeout, follow_redirects=False)
        with manager as connection:
            def send_once(method: str, destination: str, body: bytes | None = None, probe_origin: str | None = None) -> httpx.Response:
                nonlocal requests, jar_generation
                checkpoint()
                scope = origin(destination)
                if auth.manager:
                    auth.manager.ensure(timeout, pacer, event)
                if auth.generation != jar_generation:
                    jars.clear()
                    seeded.clear()
                    jar_generation = auth.generation
                if not pacer.wait(scope, event):
                    raise ScanCancelled()
                headers = auth.headers_for(destination) if auth else {}
                if body is not None:
                    headers["Content-Type"] = plan.content_type
                if probe_origin:
                    headers = {k: v for k, v in headers.items() if k.lower() != "origin"}
                    headers["Origin"] = probe_origin
                jar = jars.setdefault(scope, auth.cookies_for(destination))
                cookie_header = next((key for key in headers if key.lower() == "cookie"), None)
                if cookie_header:
                    if scope not in seeded:
                        parsed = SimpleCookie()
                        parsed.load(headers[cookie_header])
                        if not parsed:
                            raise ValueError("Session cookie must contain valid name=value pairs.")
                        host = httpx.URL(destination).host
                        cookie_domain = host if '.' in host or ':' in host else host + '.local'
                        for morsel in parsed.values():
                            jar.set(morsel.key, morsel.value, domain=cookie_domain, path="/")
                        seeded.add(scope)
                    del headers[cookie_header]
                connection.cookies.clear()
                request = connection.build_request(
                    method, destination, headers=headers, cookies=jar, timeout=timeout, content=body,
                )
                requests += 1
                response = connection.send(request, stream=True, follow_redirects=False)
                response.extensions["shensec_auth_generation"] = jar_generation
                jars[scope].extract_cookies(response)
                if auth:
                    for cookie in response.cookies.jar:
                        auth.remember_secret(cookie.value)
                connection.cookies.clear()
                return response

            def send_retries(method: str, destination: str, body: bytes | None = None, probe_origin: str | None = None) -> httpx.Response:
                nonlocal retries
                policy = pacer.policy
                attempts = policy.retries if method in {"GET", "HEAD", "OPTIONS"} else 0
                for attempt in range(attempts + 1):
                    retry_after = None
                    try:
                        response = send_once(method, destination, body, probe_origin)
                        if response.status_code not in {429, 502, 503, 504} or attempt == attempts:
                            return response
                        retry_after = response.headers.get("retry-after")
                        _release(response)
                    except (httpx.TransportError, httpx.TimeoutException):
                        if attempt == attempts:
                            raise
                    retries += 1
                    if event.wait(retry_delay(retry_after, attempt, policy)):
                        raise ScanCancelled()

            def send(method: str, destination: str, body: bytes | None = None, probe_origin: str | None = None) -> httpx.Response:
                nonlocal retries
                response = send_retries(method, destination, body, probe_origin)
                if response.status_code == 401 and auth.manager and method in {"GET", "HEAD", "OPTIONS"} and 401 not in plan.expected_status:
                    generation = response.extensions["shensec_auth_generation"]
                    _release(response)
                    auth.manager.ensure(timeout, pacer, event, rejected_generation=generation)
                    retries += 1
                    response = send_retries(method, destination, body, probe_origin)
                return response

            destination = target
            method, body = plan.method, payload
            redirect_cookies: list[Finding] = []
            for hop in range(11):
                response = send(method, destination, body)
                try:
                    next_request = response.next_request
                    if next_request is None:
                        result = analyze_response(response, url=target)
                        break
                    if hop == 10:
                        raise ValueError("Redirect limit exceeded (10).")
                    destination = normalize_target(str(next_request.url))
                    if not allow_cross_origin and not _redirect_allowed(response.url, next_request.url):
                        raise ValueError("Cross-origin redirect blocked; use --allow-cross-origin for an authorized destination.")
                    if auth and (auth.credentials or auth.config.login) and origin(destination) not in auth.allowed:
                        raise ValueError("Authenticated redirect left the configured credential origins.")
                    if body is not None and origin(destination) != origin(str(response.url)):
                        raise ValueError("Request body redirect left its original origin.")
                    method = next_request.method
                    if method in {"GET", "HEAD"}:
                        body = None
                    redirect_cookies.extend(analyze_cookies(response))
                    chain.append(str(response.url))
                finally:
                    _release(response)
            result.findings = redirect_cookies + result.findings
            result.redirect_chain = chain
            accepted = result.status_code in plan.expected_status if plan.expected_status else 200 <= result.status_code < 300
            if not accepted:
                result.error = f"HTTP {result.status_code}; check endpoint readiness and authentication."
            if check_cors and plan.method in {"GET", "HEAD"} and not result.error:
                probes = []
                try:
                    for probe_origin in PROBE_ORIGINS:
                        probe = send(plan.method, result.final_url, probe_origin=probe_origin)
                        try:
                            if 300 <= probe.status_code < 400 or probe.status_code >= 500:
                                raise ValueError(f"CORS probe returned HTTP {probe.status_code}.")
                            probes.append(probe)
                        finally:
                            _release(probe)
                    result.findings.extend(analyze_cors_probes(probes))
                    result.checks.append("cors-active")
                except (httpx.HTTPError, ValueError) as exc:
                    result.warnings.append(f"CORS coverage incomplete: {type(exc).__name__}: {exc}")
            if check_options and result.error is None:
                try:
                    options = send("OPTIONS", result.final_url)
                    try:
                        if options.status_code >= 400 and options.status_code not in (405, 501):
                            result.warnings.append(f"OPTIONS returned HTTP {options.status_code}.")
                        elif 300 <= options.status_code < 400:
                            result.warnings.append("OPTIONS redirected; method coverage is incomplete.")
                        else:
                            result.checks.append("http-methods")
                            methods = {method.strip().upper() for method in options.headers.get("allow", "").split(",")}
                            flagged = sorted(methods & {"PUT", "DELETE", "TRACE"})
                            if flagged:
                                result.findings.append(Finding(
                                    rule_id="SEC-HTTP-METHODS", title="Review Advertised HTTP Methods",
                                    description=f"Allow advertises {', '.join(flagged)}. Methods were not executed; APIs may require PUT/DELETE.",
                                    severity=Severity.MEDIUM,
                                    recommendation="Confirm these methods are intended and enforce authorization on each endpoint.",
                                    evidence=f"Allow: {options.headers['allow']}",
                                ))
                    finally:
                        _release(options)
                except httpx.HTTPError as exc:
                    result.warnings.append(f"OPTIONS could not be checked: {type(exc).__name__}.")
            checkpoint()
    except ScanCancelled:
        result = cancelled_result(url)
    except (httpx.HTTPError, httpx.InvalidURL, ValueError) as exc:
        message = auth.redact(str(exc)) if auth else str(exc)
        result = ScanResult(
            target_url=url, status_code=0, response_time_ms=0.0, redirect_chain=chain,
            error=message, findings=[Finding(
                rule_id="SEC-SCAN-ERR", title="Scan Execution Failed", description=message,
                severity=Severity.INFO, recommendation="Check URL, connectivity, credentials, TLS trust, and redirect scope.",
            )],
        )
        if event.is_set():
            result = cancelled_result(url)
    result.response_time_ms = round((time.perf_counter() - start) * 1000, 2)
    result.request_count = requests
    result.retry_count = retries
    result.request_method = plan.method if plan else "GET"
    result.request_context = plan.context if plan else None
    if auth:
        result.auth_context = auth.context if supplied_auth else None
        result.authentication = "applied" if (auth.credentials or auth.cookies) and requests else "none"
        auth.sanitize(result)
    return result
