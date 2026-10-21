"""Real loopback login, token rotation and vertical/horizontal access fixture."""

from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
import secrets
import socket
from threading import Lock, Thread
from urllib.parse import parse_qs

from .access import PermissionCase, RoleConfig
from .audit import audit_project
from .auth import AuthConfig, resolve_auth
from .login_config import LoginConfig
from .project import ProjectConfig
from .workspace import Workspace

DEMO_PASSWORD = "fixture-only-identity-password"


class IdentityServer(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self):
        super().__init__(("127.0.0.1", 0), IdentityHandler)
        self.guard = Lock()
        self.tokens, self.refresh_tokens = {}, {}
        self.expiring = set()
        self.hardened = False
        self.logins = self.refreshes = 0

    def issue(self, account, *, expires_once=False):
        access, refresh = secrets.token_urlsafe(24), secrets.token_urlsafe(24)
        with self.guard:
            self.tokens[access] = account
            self.refresh_tokens[refresh] = (account, access)
            if expires_once:
                self.expiring.add(access)
        return {"access_token": access, "refresh_token": refresh, "expires_in": 3600}

    def expire_all(self):
        with self.guard:
            self.tokens.clear()
            self.expiring.clear()


class IdentityHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "ShenSecIdentityFixture/1.0"
    sys_version = ""

    def setup(self):
        super().setup()
        self.connection.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)

    def handle(self):
        try:
            super().handle()
        except ConnectionError:
            pass

    def log_message(self, *args):
        pass

    def respond(self, code, data):
        body = json.dumps(data).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def identity(self, *, expire=False):
        header = self.headers.get("Authorization", "")
        token = header[7:] if header.startswith("Bearer ") else ""
        with self.server.guard:
            if expire and token in self.server.expiring:
                self.server.expiring.remove(token)
                self.server.tokens.pop(token, None)
            return self.server.tokens.get(token)

    def do_GET(self):
        account = self.identity(expire=self.path.startswith('/api/'))
        if not account:
            self.respond(401, {"error": "authentication required"})
        elif self.path == '/me':
            self.respond(200, {"role": account})
        elif self.path == '/api/admin':
            if self.server.hardened and account != 'admin':
                self.respond(403, {"error": "admin required"})
            else:
                self.respond(200, {"resource": "admin-dashboard"})
        elif self.path == '/api/records/42':
            if self.server.hardened and account not in {'admin', 'owner'}:
                self.respond(403, {"error": "record owner required"})
            else:
                self.respond(200, {"record": {"id": 42, "owner": "owner"}})
        else:
            self.respond(404, {"error": "not found"})

    def do_POST(self):
        length = int(self.headers.get("Content-Length", "0"))
        if not 0 <= length <= 65536:
            self.respond(413, {"error": "body too large"})
            self.close_connection = True
            return
        data = self.rfile.read(length)
        try:
            fields = json.loads(data) if self.headers.get("Content-Type", "").startswith('application/json') else {k: v[0] for k, v in parse_qs(data.decode()).items()}
        except ValueError:
            self.respond(400, {"error": "bad request"})
            return
        if self.path == '/login':
            account = fields.get('username')
            if account not in {'admin', 'owner', 'other'} or fields.get('password') != DEMO_PASSWORD:
                self.respond(401, {"error": "bad credentials"})
                return
            with self.server.guard:
                self.server.logins += 1
            self.respond(200, self.server.issue(account, expires_once=True))
        elif self.path == '/refresh':
            with self.server.guard:
                previous = self.server.refresh_tokens.pop(fields.get('refresh_token'), None)
                if previous:
                    self.server.tokens.pop(previous[1], None)
                    self.server.refreshes += 1
            if previous:
                self.respond(200, self.server.issue(previous[0]))
            else:
                self.respond(401, {"error": "invalid refresh token"})
        else:
            self.respond(404, {"error": "not found"})


@contextmanager
def identity_site():
    server = IdentityServer()
    thread = Thread(target=server.serve_forever, daemon=True)
    values = {"IDENTITY_PASSWORD": DEMO_PASSWORD, "IDENTITY_ADMIN_USER": "admin", "IDENTITY_OWNER_USER": "owner", "IDENTITY_OTHER_USER": "other"}
    saved = {key: os.environ.get(key) for key in (*values, "NO_PROXY")}
    os.environ.update(values)
    os.environ['NO_PROXY'] = ','.join(filter(None, [saved['NO_PROXY'], '127.0.0.1', 'localhost']))
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}", server
    finally:
        server.shutdown()
        server.server_close()
        thread.join()
        for key, value in saved.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value


def identity_project(url):
    def account(name, profile=None):
        return AuthConfig(profile=profile or name, required=True, origins=[url], verify_url=url + '/me', verify_json_pointer='/role', verify_json_value=name, login=LoginConfig(url=url + '/login', fields_env={"username": f"IDENTITY_{name.upper()}_USER", "password": "IDENTITY_PASSWORD"}, refresh_url=url + '/refresh'))
    return ProjectConfig(
        name="Login & role regression demo", targets=[url + '/api/admin', url + '/api/records/42'], check_options=False,
        auth=account('admin', 'primary-admin'), roles=[RoleConfig(name=name, auth=account(name)) for name in ('admin', 'owner', 'other')] + [RoleConfig(name='anonymous', anonymous=True)],
        permissions=[
            PermissionCase(id='admin_only', title='Admin dashboard', url=url + '/api/admin', expectations={"admin":"allow", "owner":"deny", "other":"deny", "anonymous":"deny"}, json_pointer='/resource', json_value='admin-dashboard'),
            PermissionCase(id='record_owner', title='Record 42 ownership', url=url + '/api/records/42', expectations={"admin":"allow", "owner":"allow", "other":"deny", "anonymous":"deny"}, json_pointer='/record/id', json_value=42),
        ],
    )


@contextmanager
def demo_workspace(root):
    with identity_site() as (url, server):
        config = identity_project(url)
        workspace = Workspace(root)
        project = workspace.save_project(config)
        auth, roles = resolve_auth(config.auth, config.targets), {}
        before = audit_project(config, auth=auth, role_auth=roles)
        before_id = workspace.save_run(project, config, before)
        workspace.set_baseline(project, before_id)
        server.hardened = True
        server.expire_all()
        current = audit_project(config, baseline=before, auth=auth, role_auth=roles)
        workspace.save_run(project, config, current)
        yield workspace, project, before, current
