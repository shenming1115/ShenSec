"""A real authenticated loopback fixture for onboarding and reproducible checks."""

from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import os
import socket
from threading import Lock, Thread

from .audit import audit_project
from .auth import AuthConfig
from .project import ProjectConfig
from .workspace import Workspace
from .requests import RequestSpec

DEMO_TOKEN = "shensec-local-demo-token"
DEMO_BODY = '{"query":"fixture-private-search"}'


class DemoServer(ThreadingHTTPServer):
    daemon_threads = True
    hardened = False
    connections = 0
    post_count = 0
    connection_lock = Lock()

    def get_request(self):
        request = super().get_request()
        with self.connection_lock:
            self.connections += 1
        return request


class DemoHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "ShenSecDemo/1.0"
    sys_version = ""

    def setup(self):
        super().setup()
        self.connection.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)

    def handle(self):
        try:
            super().handle()
        except ConnectionError:
            pass  # Header-only checks and cancellation may close a local socket early.

    def _respond(self, options=False):
        authenticated = self.headers.get("Authorization") == f"Bearer {DEMO_TOKEN}"
        status = 204 if options and authenticated else 201 if authenticated and self.command == "POST" else 200 if authenticated else 401
        api = self.path.startswith(("/api/", "/auth/"))
        body = b"" if options else b'{"authenticated":true}' if api else b"<!doctype html><title>Authenticated ShenSec fixture</title>"
        if not authenticated:
            body = b'{"error":"authentication required"}'
        self.send_response(status)
        self.send_header("Content-Type", "application/json" if api else "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        if authenticated:
            self.send_header("X-Authenticated", "true")
            if not self.server.hardened and self.headers.get("Origin"):
                self.send_header("Access-Control-Allow-Origin", self.headers["Origin"])
                self.send_header("Access-Control-Allow-Credentials", "true")
            if options:
                methods = "GET, OPTIONS, DELETE" if self.server.hardened and api else "GET, OPTIONS"
                self.send_header("Allow", methods)
            elif self.server.hardened:
                self.send_header("X-Content-Type-Options", "nosniff")
                self.send_header("Referrer-Policy", "strict-origin-when-cross-origin")
                if not api:
                    self.send_header("Content-Security-Policy", "default-src 'self'; frame-ancestors 'none'")
                    self.send_header("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
                    self.send_header("Set-Cookie", "session=fixture-only; Secure; HttpOnly; SameSite=Lax; Path=/")
            elif not api:
                self.send_header("Set-Cookie", "session=fixture-only; Path=/")
        self.end_headers()
        if body:
            self.wfile.write(body)

    def do_GET(self):
        self._respond()

    def do_OPTIONS(self):
        self._respond(options=True)

    def do_POST(self):
        length = int(self.headers.get("Content-Length", "0"))
        if length > 1024 * 1024:
            self.send_error(413)
            self.close_connection = True
            return
        body = self.rfile.read(length)
        if self.path != "/api/search" or body != DEMO_BODY.encode():
            self.send_error(400)
            return
        with self.server.connection_lock:
            self.server.post_count += 1
        self._respond()

    def log_message(self, format, *args):
        pass


@contextmanager
def local_site():
    server = DemoServer(("127.0.0.1", 0), DemoHandler)
    thread = Thread(target=server.serve_forever, daemon=True)
    saved = {name: os.environ.get(name) for name in ("SHENSEC_DEMO_TOKEN", "SHENSEC_DEMO_BODY", "NO_PROXY")}
    os.environ["SHENSEC_DEMO_TOKEN"] = DEMO_TOKEN
    os.environ["SHENSEC_DEMO_BODY"] = DEMO_BODY
    os.environ["NO_PROXY"] = ','.join(filter(None, [saved["NO_PROXY"], "127.0.0.1", "localhost"]))
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}", server
    finally:
        server.shutdown()
        server.server_close()
        thread.join()
        for name, value in saved.items():
            if value is None:
                os.environ.pop(name, None)
            else:
                os.environ[name] = value


def demo_project(url: str) -> ProjectConfig:
    return ProjectConfig(
        name="Local authenticated API demo", targets=[url + "/", url + "/api/me", url + "/api/search"], workers=2,
        check_cors=True,
        requests=[RequestSpec(url=url + "/api/search", method="POST", body_env="SHENSEC_DEMO_BODY", expected_status=[201])],
        auth=AuthConfig(
            profile="demo-user", bearer_env="SHENSEC_DEMO_TOKEN", origins=[url],
            verify_url=url + "/auth/check", verify_header="X-Authenticated", verify_value="true",
        ),
    )


@contextmanager
def demo_workspace(root):
    with local_site() as (url, server):
        config = demo_project(url)
        workspace = Workspace(root)
        project_id = workspace.save_project(config)
        baseline = audit_project(config)
        baseline_id = workspace.save_run(project_id, config, baseline)
        workspace.set_baseline(project_id, baseline_id)
        server.hardened = True
        current = audit_project(config, baseline=baseline)
        workspace.save_run(project_id, config, current)
        yield workspace, project_id, baseline, current
