"""Origin-scoped, in-memory credentials and report redaction."""

from dataclasses import dataclass, field
from hashlib import sha256
from html import escape
import ipaddress
import json
import os
import re
from threading import Lock
from urllib.parse import quote, quote_plus

import httpx
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from .models import ScanResult
from .targets import normalize_target
from .login_config import LoginConfig
from .http_data import read_bounded, json_document, json_pointer
from threading import Event


def origin(value: str) -> str:
    url = httpx.URL(normalize_target(value))
    return str(url.copy_with(raw_path=b"/", query=None, fragment=None)).rstrip("/")


def _header_name(value: str) -> bool:
    return bool(re.fullmatch(r"[!#$%&'*+.^_`|~0-9A-Za-z-]+", value))


class AuthConfig(BaseModel):
    """Only environment variable REFERENCES belong in saved configuration."""
    model_config = ConfigDict(extra="forbid")
    profile: str = Field(default="default", min_length=1, max_length=100)
    required: bool = False
    bearer_env: str | None = None
    cookie_env: str | None = None
    header_env: dict[str, str] = Field(default_factory=dict)
    headers: dict[str, str] = Field(default_factory=dict)
    origins: list[str] = Field(default_factory=list)
    allow_http: bool = False
    verify_url: str | None = None
    verify_status: int = Field(default=200, ge=200, le=299)
    verify_header: str | None = None
    verify_value: str | None = None
    login: LoginConfig | None = None
    verify_json_pointer: str | None = None
    verify_json_value: str | int | bool | None = None

    @field_validator("verify_json_pointer")
    @classmethod
    def validate_json_pointer(cls, value):
        return LoginConfig.validate_pointer(value)

    @field_validator("bearer_env", "cookie_env")
    @classmethod
    def validate_env(cls, value):
        if value is not None and not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", value):
            raise ValueError("Use an environment variable name, not a credential value.")
        return value

    @field_validator("header_env", "headers")
    @classmethod
    def validate_headers(cls, values, info):
        for name, value in values.items():
            if not _header_name(name) or name.lower() in {"host", "content-length", "transfer-encoding", "connection", "proxy-authorization"}:
                raise ValueError("Unsupported HTTP header name.")
            if '\r' in value or '\n' in value or not value.isascii():
                raise ValueError("Header values must be a single line.")
            if info.field_name == "header_env":
                cls.validate_env(value)
            elif any(word in name.lower() for word in ("authorization", "cookie", "key", "token", "secret")):
                raise ValueError("Sensitive headers must use header_env references.")
        return values

    @field_validator("origins")
    @classmethod
    def normalize_origins(cls, values):
        return list(dict.fromkeys(origin(value) for value in values))

    @field_validator("verify_url")
    @classmethod
    def normalize_verifier(cls, value):
        return normalize_target(value) if value else None

    @model_validator(mode="after")
    def validate_verifier(self):
        if bool(self.verify_header) != (self.verify_value is not None):
            raise ValueError("verify_header and verify_value must be provided together.")
        if self.verify_header and not _header_name(self.verify_header):
            raise ValueError("Invalid verification header name.")
        if self.verify_json_pointer is None and self.verify_json_value is not None:
            raise ValueError("JSON verification values require a pointer.")
        names = [name.lower() for name in self.header_env]
        if set(names) & {name.lower() for name in self.headers}:
            raise ValueError("A header cannot be configured as both a literal and an environment reference.")
        if len(names) != len(set(names)):
            raise ValueError("Duplicate credential header names.")
        if self.bearer_env and "authorization" in names or self.cookie_env and "cookie" in names:
            raise ValueError("Configure each credential header once.")
        if self.login:
            if self.bearer_env or self.cookie_env or set(names) & {"authorization", "cookie"}:
                raise ValueError("Automatic login cannot be combined with static Bearer/Cookie sources.")
            if not self.verify_url or not (self.verify_header or self.verify_json_pointer is not None):
                raise ValueError("Automatic login requires a verification URL and a header or JSON identity assertion.")
        return self


@dataclass(repr=False)
class RuntimeAuth:
    config: AuthConfig
    allowed: frozenset[str]
    credentials: dict[str, str] = field(repr=False)
    secrets: tuple[str, ...] = field(repr=False)
    context: str | None = None
    lock: Lock = field(default_factory=Lock, repr=False)
    cookies: httpx.Cookies = field(default_factory=httpx.Cookies, repr=False)
    generation: int = 0
    manager: object | None = field(default=None, repr=False)
    environment: dict[str, str] = field(default_factory=dict, repr=False)

    def set_environment(self, values):
        changed = any(self.environment.get(name, os.environ.get(name)) != value for name, value in values.items())
        self.environment.update(values)
        if changed and self.manager:
            self.manager.ready = False
            self.manager.failure = None

    def remember_secret(self, secret: str) -> None:
        if not secret:
            return
        variants = {secret, quote(secret, safe=""), quote_plus(secret), escape(secret)}
        with self.lock:
            self.secrets = tuple(sorted(set(self.secrets) | variants, key=len, reverse=True))

    def headers_for(self, url: str) -> dict[str, str]:
        headers = dict(self.config.headers)
        if origin(url) in self.allowed:
            with self.lock:
                headers.update(self.credentials)
        return headers

    def cookies_for(self, url: str) -> httpx.Cookies:
        with self.lock:
            return httpx.Cookies(self.cookies) if origin(url) in self.allowed else httpx.Cookies()

    def redact(self, value: str) -> str:
        for secret in self.secrets:
            value = value.replace(secret, "<redacted>")
        return value

    def sanitize(self, result: ScanResult) -> ScanResult:
        for name in ("target_url", "final_url", "error"):
            value = getattr(result, name)
            if value:
                setattr(result, name, self.redact(value))
        result.warnings = [self.redact(value) for value in result.warnings]
        result.redirect_chain = [self.redact(value) for value in result.redirect_chain]
        for finding in result.findings:
            for name in ("title", "description", "recommendation", "location", "evidence", "suppression"):
                value = getattr(finding, name)
                if value:
                    setattr(finding, name, self.redact(value))
        return result


def resolve_auth(
    config: AuthConfig | None, targets: list[str], *, bearer: str | None = None,
    cookie: str | None = None, environ: dict[str, str] | None = None,
) -> RuntimeAuth:
    config = config or AuthConfig()
    env = os.environ if environ is None else environ
    credentials = {}
    secrets = []

    def read(name: str) -> str:
        value = env.get(name, "").strip()
        if not value:
            raise ValueError(f"Environment variable {name} is missing or empty.")
        return value

    token = bearer.strip() if bearer else read(config.bearer_env) if config.bearer_env else None
    session = cookie.strip() if cookie else read(config.cookie_env) if config.cookie_env else None
    if token and token.lower().startswith("bearer "):
        token = token[7:].strip()
    if session and session.lower().startswith("cookie:"):
        session = session.partition(':')[2].strip()
    if token:
        credentials["Authorization"] = "Bearer " + token
        secrets.append(token)
    if session:
        credentials["Cookie"] = session
        secrets.extend(part.partition('=')[2].strip().strip('"') for part in session.split(';') if '=' in part)
    for name, env_name in config.header_env.items():
        if name.lower() in {key.lower() for key in credentials}:
            raise ValueError("Configure each credential header once.")
        credentials[name] = read(env_name)
    secrets.extend(credentials.values())
    for name, value in credentials.items():
        if name.lower() == "authorization" and value.lower().startswith("bearer "):
            secrets.append(value[7:])
        if name.lower() == "cookie":
            secrets.extend(part.partition('=')[2].strip().strip('"') for part in value.split(';') if '=' in part)
    for value in credentials.values():
        if '\r' in value or '\n' in value or not value.isascii():
            raise ValueError("Credentials must be single-line ASCII header values.")
    if config.login and (bearer or cookie):
        raise ValueError("Clear pasted session credentials before using automatic login.")
    if config.required and not credentials and not config.login:
        raise ValueError("This project requires credentials. Paste a session credential or configure its environment variable.")
    allowed = frozenset(config.origins or [origin(targets[0])])
    if credentials or config.login:
        for value in allowed:
            url = httpx.URL(value)
            try:
                loopback = ipaddress.ip_address(url.host).is_loopback
            except ValueError:
                loopback = url.host == "localhost"
            if url.scheme != "https" and not loopback and not config.allow_http:
                raise ValueError("Credentials require HTTPS; use allow_http only for an intended development origin.")
    variants = {variant for secret in secrets if secret for variant in (secret, quote(secret, safe=""), quote_plus(secret), escape(secret))}
    # Context excludes values so normal credential rotation does not invalidate a baseline.
    identity = [
        config.profile, sorted(allowed), sorted(name.lower() for name in credentials),
        config.bearer_env, config.cookie_env, sorted(config.header_env.items()),
        sorted(config.headers.items()), config.verify_url, config.verify_status,
        config.verify_header, config.verify_value,
    ]
    if config.login:
        identity.append(config.login.model_dump(mode="json"))
        for endpoint in (config.login.url, config.login.refresh_url, config.login.csrf_url):
            if endpoint and origin(endpoint) not in allowed:
                raise ValueError("Login, CSRF and refresh URLs must belong to configured credential origins.")
    if config.verify_json_pointer is not None:
        identity.extend([config.verify_json_pointer, config.verify_json_value])
    context = sha256(json.dumps(identity).encode()).hexdigest()[:24] if credentials or config.login else None
    return RuntimeAuth(config, allowed, credentials, tuple(sorted(variants, key=len, reverse=True)), context)


def verify_auth(auth: RuntimeAuth, timeout: float, cancel_event: Event | None = None) -> None:
    if not auth.config.verify_url:
        return
    url = auth.config.verify_url
    if not (auth.credentials or auth.cookies) or origin(url) not in auth.allowed:
        raise ValueError("Authentication verification URL must belong to a configured credential origin.")
    try:
        with httpx.Client(timeout=timeout, follow_redirects=False) as client:
            headers = {k: v for k, v in auth.headers_for(url).items() if k.lower() != "accept-encoding"}
            headers["Accept-Encoding"] = "identity"
            with client.stream("GET", url, headers=headers, cookies=auth.cookies_for(url)) as response:
                if response.status_code != auth.config.verify_status:
                    raise ValueError(f"Authentication verification failed (HTTP {response.status_code}); refresh your session.")
                if auth.config.verify_header and response.headers.get(auth.config.verify_header) != auth.config.verify_value:
                    raise ValueError("Authentication verification response did not match the configured success header.")
                if auth.config.verify_json_pointer is not None:
                    actual = json_pointer(json_document(read_bounded(response, cancel_event or Event())), auth.config.verify_json_pointer)
                    expected = auth.config.verify_json_value
                    if type(actual) is not type(expected) or actual != expected:
                        raise ValueError("Authentication verification JSON identity assertion did not match.")
    except httpx.HTTPError as exc:
        raise ValueError(f"Authentication verification failed ({type(exc).__name__}).") from None
