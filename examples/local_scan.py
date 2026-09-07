"""Scan a temporary localhost fixture and print a Markdown report.

Run from the repository root: uv run python examples/local_scan.py
Only loopback requests are made. The server shuts down after the scan.
"""

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from threading import Thread

from shensec import generate_report, scan_target


class ExampleHandler(BaseHTTPRequestHandler):
    server_version = "ShenSecExample/1.0"
    sys_version = ""

    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Set-Cookie", "session=example; Path=/")
        self.end_headers()
        self.wfile.write(b"Controlled ShenSec example target.\n")

    def do_OPTIONS(self):
        self.send_response(204)
        self.send_header("Allow", "GET, OPTIONS")
        self.end_headers()

    def log_message(self, format, *args):
        pass


def scan_example():
    server = ThreadingHTTPServer(("127.0.0.1", 0), ExampleHandler)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        return scan_target(f"http://127.0.0.1:{server.server_port}", timeout=5.0)
    finally:
        server.shutdown()
        server.server_close()
        thread.join()


if __name__ == "__main__":
    print(generate_report(scan_example(), "markdown"))
