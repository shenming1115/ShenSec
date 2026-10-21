"""Single-flight automatic login and bounded renewal; secrets stay in memory."""

from html.parser import HTMLParser
import math
import os
from threading import Event, Lock
import time

import httpx

from .auth import RuntimeAuth, origin, verify_auth
from .http_data import json_document, json_pointer, read_bounded
from .models import SessionState
from .network import RequestPacer


class HiddenToken(HTMLParser):
    def __init__(self, name):
        super().__init__()
        self.name, self.values = name, []

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag == "input" and attrs.get("name") == self.name and attrs.get("value"):
            self.values.append(attrs["value"])


class SessionManager:
    def __init__(self, auth: RuntimeAuth):
        self.auth = auth
        self.recipe = auth.config.login
        self._operation = Lock()
        self.renew_at = None
        self.refresh_token = None
        self.logins = self.refreshes = self.renewals = self.requests = 0
        self.ready = False
        self.failure = None
        self.phase = None

    def announce(self, message):
        if self.phase:
            self.phase("authentication", f"{self.auth.config.profile}: {message}")

    def validate_inputs(self):
        for fields in (self.recipe.fields_env, self.recipe.refresh_fields_env):
            self.read_fields(fields)

    def begin_run(self, phase=None):
        self.phase = phase
        self.logins = self.refreshes = self.renewals = self.requests = 0
        self.failure = None

    def read_fields(self, references):
        fields = {}
        for field, env_name in references.items():
            value = self.auth.environment.get(env_name, os.environ.get(env_name, ""))
            if not value:
                raise ValueError(f"Login environment variable {env_name} is missing or empty.")
            if len(value.encode()) > 65536:
                raise ValueError("Login field exceeds 64 KiB.")
            if field.lower() not in {"username", "user", "email", "login", "client_id"}:
                self.auth.remember_secret(value)
            fields[field] = value
        return fields

    def _exchange(self, client, method, url, timeout, pacer, event, *, fields=None, encoding="json", headers=None):
        if event.is_set() or not pacer.wait(origin(url), event):
            raise ValueError("Cancelled before authentication request.")
        if origin(url) not in self.auth.allowed:
            raise ValueError("Authentication endpoint left its configured origins.")
        request_headers = self.auth.headers_for(url)
        # Bearer values are not needed at a password/token exchange endpoint.
        request_headers = {k: v for k, v in request_headers.items() if k.lower() not in {"authorization", "cookie", "accept-encoding"}}
        request_headers.update({"Accept-Encoding": "identity", **(headers or {})})
        kwargs = {"json" if encoding == "json" else "data": fields} if fields is not None else {}
        self.requests += 1
        with client.stream(method, url, headers=request_headers, timeout=timeout, follow_redirects=False, **kwargs) as response:
            for cookie in response.cookies.jar:
                self.auth.remember_secret(cookie.value)
            # Never echo a login response or server error text into exceptions.
            data = read_bounded(response, event)
            return response.status_code, data

    def _accept(self, client, data, *, refreshing):
        recipe = self.recipe
        document = json_document(data) if recipe.token_pointer is not None else None
        token = json_pointer(document, recipe.token_pointer) if recipe.token_pointer is not None else None
        if token is not None and (not isinstance(token, str) or not token or len(token) > 16384 or not token.isascii() or '\r' in token or '\n' in token):
            raise ValueError("Login returned an invalid access token.")
        if recipe.token_pointer is not None and token is None:
            raise ValueError("Login returned no access token.")
        refresh = None
        if document is not None and recipe.refresh_pointer:
            try:
                refresh = json_pointer(document, recipe.refresh_pointer)
            except ValueError:
                pass  # Refresh tokens may be omitted when rotating only the access token.
            if refresh is not None and (not isinstance(refresh, str) or not refresh or len(refresh) > 65536):
                raise ValueError("Login returned an invalid refresh token.")
        renew_at = None
        if document is not None and recipe.expires_pointer:
            try:
                ttl = json_pointer(document, recipe.expires_pointer)
            except ValueError:
                ttl = None
            if ttl is not None:
                if isinstance(ttl, bool) or not isinstance(ttl, (int, float)) or not math.isfinite(ttl) or not 0 < ttl <= 31536000:
                    raise ValueError("Login returned an invalid expires_in value.")
                renew_at = time.monotonic() + ttl - min(recipe.refresh_skew, ttl * 0.2)
        if token:
            self.auth.remember_secret(token)
            self.auth.remember_secret("Bearer " + token)
        if refresh:
            self.auth.remember_secret(refresh)
        if recipe.token_pointer is None and not client.cookies:
            raise ValueError("Cookie login did not produce a usable session cookie.")
        with self.auth.lock:
            credentials = {k: v for k, v in self.auth.credentials.items() if k.lower() != "authorization"}
            if token:
                credentials["Authorization"] = "Bearer " + token
            self.auth.credentials = credentials
            self.auth.cookies = httpx.Cookies(client.cookies)
            self.auth.generation += 1
        self.refresh_token = refresh or (self.refresh_token if refreshing else None)
        self.renew_at = renew_at
        self.ready = True

    def _login(self, timeout, pacer, event):
        self.announce("Signing in")
        recipe = self.recipe
        fields = self.read_fields(recipe.fields_env)
        with httpx.Client(timeout=timeout, follow_redirects=False) as client:
            headers = {}
            if recipe.csrf_url:
                code, body = self._exchange(client, "GET", recipe.csrf_url, timeout, pacer, event)
                if code != 200:
                    raise ValueError(f"CSRF initialization failed (HTTP {code}).")
                if recipe.csrf_pointer:
                    csrf = json_pointer(json_document(body), recipe.csrf_pointer)
                else:
                    parser = HiddenToken(recipe.csrf_field)
                    parser.feed(body.decode('utf-8', errors='replace'))
                    if len(parser.values) != 1:
                        raise ValueError("CSRF response must contain one matching hidden input.")
                    csrf = parser.values[0]
                if not isinstance(csrf, str) or not csrf or len(csrf) > 16384:
                    raise ValueError("Invalid CSRF token.")
                self.auth.remember_secret(csrf)
                if recipe.csrf_header:
                    if not csrf.isascii() or '\r' in csrf or '\n' in csrf:
                        raise ValueError("CSRF header must be single-line ASCII.")
                    headers[recipe.csrf_header] = csrf
                else:
                    fields[recipe.csrf_field] = csrf
            code, body = self._exchange(client, "POST", recipe.url, timeout, pacer, event, fields=fields, encoding=recipe.encoding, headers=headers)
            if code != recipe.success_status:
                raise ValueError(f"Automatic login failed (HTTP {code}); check credentials and recipe.")
            self._accept(client, body, refreshing=False)
            self.logins += 1

    def _renew(self, timeout, pacer, event):
        if self.renewals >= self.recipe.max_renewals:
            raise ValueError("Session renewal limit reached; check expiry and login configuration.")
        self.renewals += 1
        recipe = self.recipe
        if recipe.refresh_url and (self.refresh_token or recipe.refresh_field is None):
            self.announce("Refreshing session")
            fields = self.read_fields(recipe.refresh_fields_env)
            if recipe.refresh_field:
                fields[recipe.refresh_field] = self.refresh_token
                if recipe.refresh_encoding == "form":
                    fields.setdefault("grant_type", "refresh_token")
            with httpx.Client(timeout=timeout, follow_redirects=False, cookies=self.auth.cookies) as client:
                code, body = self._exchange(client, "POST", recipe.refresh_url, timeout, pacer, event, fields=fields, encoding=recipe.refresh_encoding)
                if code == 200:
                    self._accept(client, body, refreshing=True)
                    self.refreshes += 1
                    return
                if code not in {400, 401, 403}:
                    raise ValueError(f"Session refresh failed (HTTP {code}).")
            self.announce("Refresh rejected; signing in again")
        self._login(timeout, pacer, event)

    def ensure(self, timeout, pacer, event, *, rejected_generation=None):
        # Waiting callers check cancellation instead of blocking on a long login.
        while not self._operation.acquire(timeout=0.1):
            if event.is_set():
                raise ValueError("Cancelled while waiting for session renewal.")
        try:
            if event.is_set():
                raise ValueError("Cancelled before authentication.")
            if self.failure:
                raise ValueError(self.failure)
            rejected = rejected_generation is not None and rejected_generation == self.auth.generation
            expired = self.renew_at is not None and time.monotonic() >= self.renew_at
            changed = False
            if not self.ready:
                self._login(timeout, pacer, event)
                changed = True
            elif rejected or expired:
                self._renew(timeout, pacer, event)
                changed = True
            if changed:
                if self.auth.config.verify_url:
                    if not pacer.wait(origin(self.auth.config.verify_url), event):
                        raise ValueError("Cancelled before session verification.")
                    verify_auth(self.auth, timeout)
                self.announce("Session ready")
            return changed
        except (ValueError, httpx.HTTPError) as exc:
            self.ready = False
            self.failure = self.auth.redact(str(exc)) if isinstance(exc, ValueError) else f"Authentication transport failed ({type(exc).__name__})."
            self.announce("Authentication failed")
            raise ValueError(self.failure) from None
        finally:
            self._operation.release()

    def snapshot(self):
        return SessionState(profile=self.auth.config.profile, mode="automatic", state="error" if self.failure else "ready" if self.ready else "pending", logins=self.logins, refreshes=self.refreshes, renewals=self.renewals, requests=self.requests)


def prepare_auth(auth, timeout, pacer, event, phase=None):
    if auth.config.login:
        if auth.manager is None:
            auth.manager = SessionManager(auth)
        auth.manager.begin_run(phase)
        auth.manager.validate_inputs()
        changed = auth.manager.ensure(timeout, pacer, event)
        if not changed and auth.config.verify_url:
            if not pacer.wait(origin(auth.config.verify_url), event):
                raise ValueError("Cancelled before session verification.")
            try:
                verify_auth(auth, timeout)
            except ValueError:
                auth.manager.ensure(timeout, pacer, event, rejected_generation=auth.generation)
    elif auth.config.verify_url and not event.is_set():
        if phase:
            phase("authentication", f"{auth.config.profile}: Verifying session")
        if pacer.wait(origin(auth.config.verify_url), event):
            verify_auth(auth, timeout)


def validate_auth_inputs(auth):
    if auth.config.login:
        if auth.manager is None:
            auth.manager = SessionManager(auth)
        auth.manager.validate_inputs()


def session_snapshot(auth):
    if auth.manager:
        return auth.manager.snapshot()
    return SessionState(profile=auth.config.profile, mode="static" if auth.credentials else "anonymous", state="ready")
