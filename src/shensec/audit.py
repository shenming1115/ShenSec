"""Batch orchestration, stable baseline comparisons, and CI policy decisions."""

from concurrent.futures import FIRST_COMPLETED, ThreadPoolExecutor, wait
import json
from pathlib import Path
from threading import Event, Lock, local
import time
from typing import Callable

import httpx

from pydantic import ValidationError

from .models import AuditResult, Comparison, FindingRecord, GateResult, ScanResult, Severity, SEVERITY_RANK
from .scanner.core import cancelled_result, scan_target
from .auth import AuthConfig, RuntimeAuth, origin, resolve_auth, verify_auth
from .project import ProjectConfig
from .targets import normalize_target, parse_targets
from .requests import RequestSpec
from .network import NetworkPolicy, RequestPacer
from .policy import apply_exceptions
from .sessions import prepare_auth, session_snapshot, validate_auth_inputs
from .access import complete_access, prepare_roles


def scan_many(
    targets: list[str], timeout: float = 10.0, *, workers: int = 4,
    check_options: bool = True, allow_cross_origin: bool = False,
    auth: AuthConfig | RuntimeAuth | None = None, cancel_event: Event | None = None,
    progress: Callable[[int, int, ScanResult], None] | None = None,
    reuse_clients: bool = True,
    requests: list[RequestSpec] | None = None, network: NetworkPolicy | None = None,
    check_cors: bool = False,
    pacer: RequestPacer | None = None, phase=None,
) -> AuditResult:
    """Bound both active/queued work, reuse clients per worker, preserve target order."""
    start = time.perf_counter()
    if not 1 <= workers <= 16:
        raise ValueError("Workers must be between 1 and 16.")
    targets = parse_targets(targets)
    if len(targets) > 1000:
        raise ValueError("An audit supports at most 1000 unique targets.")
    runtime = resolve_auth(auth, targets) if isinstance(auth, AuthConfig) else auth
    plans = {plan.url: plan for plan in requests or []}
    if len(plans) != len(requests or []) or set(plans) - set(targets):
        raise ValueError("Request plans must have unique URLs within the target list.")
    # Validate every body before any network activity, so a bad plan cannot cause a partial run.
    for plan in plans.values():
        plan.payload()
    pacer = pacer or RequestPacer(network or NetworkPolicy())
    event = cancel_event if cancel_event is not None else Event()
    if runtime and not event.is_set():
        try:
            prepare_auth(runtime, timeout, pacer, event, phase)
        except ValueError:
            if not event.is_set():
                raise
    if phase:
        phase("scan", f"Inspecting {len(targets)} endpoints")
    state, lock, clients = local(), Lock(), []

    def run(target: str) -> ScanResult:
        if event.is_set():
            return cancelled_result(target)
        if reuse_clients and not hasattr(state, "client"):
            state.client = httpx.Client(timeout=timeout, follow_redirects=False)
            with lock:
                clients.append(state.client)
        return scan_target(
            target, timeout, check_options=check_options, allow_cross_origin=allow_cross_origin,
            auth=runtime, cancel_event=event, client=getattr(state, "client", None),
            request_spec=plans.get(target), pacer=pacer,
            check_cors=check_cors,
        )

    results: list[ScanResult | None] = [None] * len(targets)
    completed = next_index = 0
    try:
        with ThreadPoolExecutor(max_workers=workers) as executor:
            pending = {}
            def fill():
                nonlocal next_index
                while len(pending) < workers and next_index < len(targets) and not event.is_set():
                    pending[executor.submit(run, targets[next_index])] = next_index
                    next_index += 1
            fill()
            while pending:
                done, _ = wait(pending, timeout=0.1, return_when=FIRST_COMPLETED)
                for future in done:
                    index = pending.pop(future)
                    results[index] = future.result()
                    completed += 1
                    if progress:
                        progress(completed, len(targets), results[index])
                fill()
    finally:
        for client in clients:
            client.close()
    for index, result in enumerate(results):
        if result is None:
            results[index] = cancelled_result(targets[index])
            plan = plans.get(targets[index])
            if plan:
                results[index].request_method = plan.method
                results[index].request_context = plan.context
    return AuditResult(
        results=results, cancelled=event.is_set(),
        sessions=[session_snapshot(runtime)] if runtime else [],
        duration_ms=round((time.perf_counter() - start) * 1000, 2),
    )


def audit_project(
    config: ProjectConfig, *, baseline: AuditResult | None = None,
    auth: RuntimeAuth | None = None, cancel_event: Event | None = None,
    progress: Callable[[int, int, ScanResult], None] | None = None,
    phase=None, role_auth: dict | None = None, role_values: dict | None = None,
) -> AuditResult:
    start = time.perf_counter()
    event = cancel_event if cancel_event is not None else Event()
    pacer = RequestPacer(config.network)
    cache = role_auth if role_auth is not None else {}
    runtime = auth or resolve_auth(config.auth, config.targets)
    validate_auth_inputs(runtime)
    for plan in config.requests:
        plan.payload()
    try:
        roles = prepare_roles(config, cache, pacer, event, phase, role_values) if config.permissions else {}
    except ValueError:
        if not event.is_set():
            raise
        roles = cache
    audit = scan_many(
        config.targets, config.timeout, workers=config.workers, check_options=config.check_options,
        allow_cross_origin=config.allow_cross_origin, auth=runtime,
        cancel_event=event, progress=progress,
        requests=config.requests, network=config.network,
        check_cors=config.check_cors,
        pacer=pacer, phase=phase,
    )
    complete_access(audit, config, roles, pacer, event, phase)
    audit.duration_ms = round((time.perf_counter() - start) * 1000, 2)
    apply_exceptions(audit, config.exceptions)
    if baseline is not None:
        audit.comparison = compare_audits(audit, baseline)
    audit.gate = evaluate_gate(audit, config.threshold, only_new=baseline is not None)
    return audit


def _target_key(result: ScanResult) -> str:
    return normalize_target(result.target_url) if result.scan_kind == "http" else result.target_url


def _index_results(audit: AuditResult) -> dict[str, ScanResult]:
    indexed = {}
    for result in audit.results:
        target = _target_key(result)
        if target in indexed:
            raise ValueError(f"Duplicate target in report: {target}")
        indexed[target] = result
    return indexed


def _records(results: dict[str, ScanResult]) -> dict[str, FindingRecord]:
    records = {}
    for target, result in results.items():
        if result.status in {"error", "cancelled"}:
            continue
        for finding in result.findings:
            if finding.rule_id == "SEC-SCAN-ERR":
                continue
            record = FindingRecord(target_url=target, finding=finding)
            records[record.fingerprint] = record
    return records


def _check_name(rule: str) -> str | None:
    for prefix, check in (
        ("SEC-HDR-", "headers"), ("SEC-TRANSPORT-", "headers"),
        ("SEC-COOKIE-", "cookies"), ("SEC-CORS-ACTIVE-", "cors-active"), ("SEC-CORS-", "cors"),
        ("SEC-SRV-", "server"), ("SEC-INFRA-", "server"),
        ("SEC-JWT-", "jwt"), ("SEC-HTTP-METHODS", "http-methods"),
        ("SEC-ACCESS-", "access"),
    ):
        if rule.startswith(prefix):
            return check
    return None


def compare_audits(current: AuditResult, baseline: AuditResult) -> Comparison:
    """Never call an absent finding resolved when its target/check was skipped."""
    current_targets = _index_results(current)
    baseline_targets = _index_results(baseline)
    current_records = _records(current_targets)
    previous_records = _records(baseline_targets)
    comparison = Comparison(
        added_targets=sorted(current_targets.keys() - baseline_targets.keys()),
        removed_targets=sorted(baseline_targets.keys() - current_targets.keys()),
        context_changed_targets=sorted(
            key for key in current_targets.keys() & baseline_targets.keys()
            if (current_targets[key].auth_context, current_targets[key].request_context)
            != (baseline_targets[key].auth_context, baseline_targets[key].request_context)
            or (current.access_context != baseline.access_context and key in {r.target_url for r in current.permissions + baseline.permissions})
        ),
    )
    for fingerprint, record in current_records.items():
        previous = previous_records.get(fingerprint) if record.target_url not in comparison.context_changed_targets else None
        if previous is None:
            comparison.new.append(record)
        elif (SEVERITY_RANK[record.finding.severity] > SEVERITY_RANK[previous.finding.severity]
              or previous.finding.suppression and not record.finding.suppression):
            if SEVERITY_RANK[record.finding.severity] > SEVERITY_RANK[previous.finding.severity]:
                record.previous_severity = previous.finding.severity
            if previous.finding.suppression and not record.finding.suppression:
                record.change_reason = "Previously accepted exception expired or was removed."
            comparison.regressed.append(record)
        else:
            comparison.existing.append(record)
    for fingerprint, record in previous_records.items():
        if fingerprint in current_records and record.target_url not in comparison.context_changed_targets:
            continue
        result = current_targets.get(record.target_url)
        check = _check_name(record.finding.rule_id)
        if (
            result is None or result.status != "complete"
            or record.target_url in comparison.context_changed_targets
            or (check is not None and check not in result.checks)
        ):
            comparison.unverified.append(record)
        else:
            comparison.resolved.append(record)
    return comparison


def evaluate_gate(
    audit: AuditResult, threshold: Severity | None = Severity.HIGH, *, only_new: bool = False,
) -> GateResult:
    if only_new and audit.comparison is None:
        raise ValueError("--only-new requires a baseline comparison.")
    if only_new:
        candidates = audit.comparison.new + audit.comparison.regressed
    else:
        candidates = list(_records(_index_results(audit)).values())
    violations = [
        record for record in candidates
        if not record.finding.suppression and threshold is not None and SEVERITY_RANK[record.finding.severity] >= SEVERITY_RANK[threshold]
    ]
    errors = [
        f"{result.target_url}: {result.error or '; '.join(result.warnings) or 'Scan did not complete'}"
        for result in audit.results if result.status != "complete"
    ]
    if audit.comparison and audit.comparison.unverified:
        errors.append("Some baseline findings could not be rechecked; review removed targets and skipped checks.")
    if audit.comparison and audit.comparison.removed_targets:
        errors.append("Baseline targets were removed from the audit; review the scope before replacing the baseline.")
    if audit.comparison and audit.comparison.context_changed_targets:
        errors.append("Authentication context changed or request plan changed; establish a reviewed baseline for the new context.")
    if audit.cancelled:
        errors.append("Audit was cancelled; incomplete results cannot pass the gate.")
    return GateResult(
        threshold=threshold, only_new=only_new, violations=violations, errors=errors,
        outcome="error" if errors else "failed" if violations else "passed",
    )


def load_baseline(path: str | Path) -> AuditResult:
    """Read current audit JSON or a single-target JSON report; never trust summaries."""
    try:
        data = json.loads(Path(path).read_text(encoding="utf-8-sig"))
        if not isinstance(data, dict):
            raise ValueError("Expected a JSON object.")
        if "results" in data:
            if data.get("schema_version") != 1:
                raise ValueError("Unsupported baseline schema_version; expected 1.")
            audit = AuditResult.model_validate(data)
        else:
            audit = AuditResult(results=[ScanResult.model_validate(data)])
        _index_results(audit)
        return audit
    except (OSError, ValueError, ValidationError) as exc:
        raise ValueError(f"Cannot load baseline {path}: {exc}") from exc
