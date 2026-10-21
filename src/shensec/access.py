"""Explicit role expectations and bounded permission probes, with no discovery."""

from hashlib import sha256
import json
import os
from typing import Literal
from threading import Event, Lock, local
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
import time

import httpx
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from .auth import AuthConfig, origin, resolve_auth, verify_auth
from .http_data import json_document, json_pointer, read_bounded
from .login_config import LoginConfig
from .models import Finding, PermissionResult, Severity
from .sessions import prepare_auth, session_snapshot, validate_auth_inputs
from .targets import normalize_target


class RoleConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str = Field(pattern=r"^[A-Za-z][A-Za-z0-9_-]{0,39}$")
    anonymous: bool = False
    auth: AuthConfig = Field(default_factory=AuthConfig)

    @model_validator(mode="after")
    def verify_identity(self):
        if self.anonymous:
            if self.auth.login or self.auth.required or self.auth.bearer_env or self.auth.cookie_env or self.auth.header_env or self.auth.verify_url:
                raise ValueError("Anonymous roles cannot contain credential sources or session verification.")
        elif not self.auth.verify_url or not (self.auth.verify_header or self.auth.verify_json_pointer is not None):
            raise ValueError("Authenticated roles require a verification URL and a header or JSON identity assertion.")
        return self


class PermissionCase(BaseModel):
    model_config = ConfigDict(extra="forbid")
    id: str = Field(pattern=r"^[A-Za-z][A-Za-z0-9_-]{0,59}$")
    title: str = Field(default="Access expectation", min_length=1, max_length=150)
    url: str
    method: Literal["GET", "HEAD"] = "GET"
    expectations: dict[str, Literal["allow", "deny"]] = Field(min_length=2, max_length=8)
    allow_status: list[int] = Field(default_factory=lambda: [200], min_length=1, max_length=10)
    deny_status: list[int] = Field(default_factory=lambda: [401, 403], min_length=1, max_length=10)
    allow_header: str | None = None
    allow_value: str | None = None
    json_pointer: str | None = None
    json_value: str | int | bool | None = None

    @field_validator("url")
    @classmethod
    def normalize_url(cls, value):
        return normalize_target(value)

    @field_validator("json_pointer")
    @classmethod
    def pointer(cls, value):
        return LoginConfig.validate_pointer(value)

    @field_validator("allow_header")
    @classmethod
    def header(cls, value):
        return LoginConfig.validate_header(value)

    @model_validator(mode="after")
    def assertions(self):
        if not self.allow_header and self.json_pointer is None:
            raise ValueError("Permission cases require a success header or JSON assertion, not status alone.")
        if bool(self.allow_header) != (self.allow_value is not None):
            raise ValueError("Success header and expected value must be provided together.")
        if self.method == "HEAD" and self.json_pointer:
            raise ValueError("HEAD permission probes require a header assertion.")
        if any(not 200 <= code <= 299 for code in self.allow_status) or any(code not in {401, 403, 404} for code in self.deny_status):
            raise ValueError("Allow statuses must be 2xx; denial statuses must be 401, 403 or explicit 404.")
        return self


def _role_step(name, function, *args, **kwargs):
    try:
        return function(*args, **kwargs)
    except ValueError as exc:
        raise ValueError(f"Role {name}: {exc}") from None


def prepare_roles(config, cache, pacer, event, phase=None, session_values=None):
    runtimes = {}
    # Resolve all references before logging in; malformed role inputs send nothing.
    for role in config.roles:
        role_auth = role.auth.model_copy(update={"profile": role.name, "required": not role.anonymous})
        previous = cache.get(role.name)
        values = dict(previous.environment) if previous and previous.config.model_dump_json() == role_auth.model_dump_json() else {}
        values.update((session_values or {}).get(role.name, {}))
        runtime = _role_step(role.name, resolve_auth, role_auth, config.targets, environ={**os.environ, **values})
        if previous and previous.manager and previous.config.model_dump_json() == runtime.config.model_dump_json():
            runtime = previous
        runtime.set_environment(values)
        runtimes[role.name] = runtime
    for runtime in runtimes.values():
        _role_step(runtime.config.profile, validate_auth_inputs, runtime)
    cache.clear()
    cache.update(runtimes)
    for name, runtime in runtimes.items():
        if event.is_set():
            break
        _role_step(name, prepare_auth, runtime, config.timeout, pacer, event, phase)
    return runtimes


def _probe(case, name, expected, auth, config, pacer, event, client):
    result = PermissionResult(case_id=case.id, title=case.title, target_url=case.url, method=case.method, role=name, expected=expected)
    started = time.perf_counter()
    try:
        for recovery in range(2):
            if event.is_set():
                raise ValueError("Cancelled before permission probe.")
            if (auth.credentials or auth.config.login) and origin(case.url) not in auth.allowed:
                raise ValueError("Permission target is outside this role's credential origins.")
            if auth.manager:
                auth.manager.ensure(config.timeout, pacer, event)
            generation = auth.generation
            if not pacer.wait(origin(case.url), event):
                raise ValueError("Cancelled before permission probe.")
            headers = {k: v for k, v in auth.headers_for(case.url).items() if k.lower() != "accept-encoding"}
            headers["Accept-Encoding"] = "identity"
            client.cookies.clear()
            request = client.build_request(case.method, case.url, headers=headers, cookies=auth.cookies_for(case.url), timeout=config.timeout)
            with closing(client.send(request, stream=True, follow_redirects=False)) as response:
                result.status_code = response.status_code
                for cookie in response.cookies.jar:
                    auth.remember_secret(cookie.value)
                # Confirm a 401 really means denied access rather than an expired login.
                if response.status_code in case.deny_status and auth.config.verify_url:
                    try:
                        if not pacer.wait(origin(auth.config.verify_url), event):
                            raise ValueError("Cancelled during role verification.")
                        verify_auth(auth, config.timeout)
                    except ValueError:
                        if auth.manager and recovery == 0 and not event.is_set():
                            auth.manager.ensure(config.timeout, pacer, event, rejected_generation=generation)
                            continue
                        raise ValueError("Role session could not be verified; denial is inconclusive.") from None
                if response.status_code in case.deny_status:
                    result.observed = "denied"
                elif response.status_code in case.allow_status:
                    matches = not case.allow_header or response.headers.get(case.allow_header) == case.allow_value
                    if case.json_pointer is not None:
                        media = response.headers.get("content-type", "").split(';')[0].strip().lower()
                        if media != "application/json" and not media.endswith('+json'):
                            raise ValueError("Success response was not JSON; a login page cannot establish access.")
                        actual = json_pointer(json_document(read_bounded(response, event)), case.json_pointer)
                        matches = matches and type(actual) is type(case.json_value) and actual == case.json_value
                    if not matches:
                        raise ValueError("Success assertion did not match; access is inconclusive.")
                    result.observed = "allowed"
                else:
                    raise ValueError("Unexpected HTTP status or redirect; access is inconclusive.")
                result.outcome = "passed" if (result.observed == "allowed") == (expected == "allow") else "failed"
                result.detail = f"Expected {expected}; observed {result.observed} (HTTP {response.status_code})."
                return result
    except (httpx.HTTPError, ValueError) as exc:
        result.outcome = "cancelled" if event.is_set() else "error"
        result.detail = auth.redact(str(exc)) if isinstance(exc, ValueError) else f"Permission request failed ({type(exc).__name__})."
    finally:
        client.cookies.clear()
        result.duration_ms = round((time.perf_counter() - started) * 1000, 2)
    return result


def complete_access(audit, config, runtimes, pacer, event, phase=None):
    if not config.permissions:
        return
    if phase:
        phase("permissions", f"Comparing {len(config.roles)} roles across {len(config.permissions)} access expectations")
    identity = {"roles": [r.model_dump(mode="json") for r in config.roles], "permissions": [c.model_dump(mode="json") for c in config.permissions]}
    audit.access_context = sha256(json.dumps(identity, sort_keys=True).encode()).hexdigest()[:24]
    indexed = dict(zip(config.targets, audit.results))
    tasks = [(case, role.name) for case in config.permissions for role in config.roles]
    state, lock, clients = local(), Lock(), []
    def run(task):
        case, name = task
        if not hasattr(state, "client"):
            state.client = httpx.Client(timeout=config.timeout, follow_redirects=False)
            with lock:
                clients.append(state.client)
        return _probe(case, name, case.expectations[name], runtimes[name], config, pacer, event, state.client)
    try:
        with ThreadPoolExecutor(max_workers=config.workers) as executor:
            for (case, name), observation in zip(tasks, executor.map(run, tasks)):
                target = indexed[case.url]
                audit.permissions.append(observation)
                if phase:
                    phase("permissions", f"{case.title} / {name}: {observation.outcome.upper()}")
                if observation.outcome == "failed":
                    unexpected_allow = observation.observed == "allowed"
                    target.findings.append(Finding(
                        rule_id="SEC-ACCESS-UNEXPECTED-ALLOW" if unexpected_allow else "SEC-ACCESS-UNEXPECTED-DENY",
                        title="Role Access Exceeded Expectation" if unexpected_allow else "Expected Role Access Was Denied",
                        description=f"{case.title}: {name}. {observation.detail}",
                        severity=Severity.HIGH if unexpected_allow else Severity.MEDIUM,
                        location=f"permission:{case.id}|role:{name}", evidence=observation.detail,
                        recommendation="Enforce the reviewed resource/role authorization policy on the server and repeat this expectation.",
                    ))
                elif observation.outcome in {"error", "cancelled"}:
                    target.warnings.append(f"Access check {case.id}/{name}: {observation.detail}")
    finally:
        for client in clients:
            client.close()
    for url, target in indexed.items():
        observations = [r for r in audit.permissions if r.target_url == url]
        if observations and all(r.outcome in {"passed", "failed"} for r in observations):
            target.checks.append("access")
    audit.cancelled = audit.cancelled or event.is_set()
    audit.sessions.extend(session_snapshot(auth).model_copy(update={"scope": "role"}) for auth in runtimes.values())
