"""A complete localhost-only baseline -> fix -> compare workflow.

Run: uv run python examples/regression_demo.py
Outputs go to examples/demo-output/ unless --output-dir is supplied.
"""

import argparse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from threading import Thread

from shensec import compare_audits, evaluate_gate, generate_report, scan_many


class DemoHandler(BaseHTTPRequestHandler):
    server_version = "ShenSecDemo/1.0"
    sys_version = ""

    def do_GET(self):
        api = self.path.startswith("/api/")
        self.send_response(200)
        self.send_header("Content-Type", "application/json" if api else "text/html; charset=utf-8")
        if self.server.hardened:
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Referrer-Policy", "strict-origin-when-cross-origin")
            if not api:
                self.send_header("Content-Security-Policy", "default-src 'self'; frame-ancestors 'none'")
                self.send_header("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
                self.send_header("Set-Cookie", "session=demo; Secure; HttpOnly; SameSite=Lax; Path=/")
        elif not api:
            self.send_header("Set-Cookie", "session=demo; Path=/")
        self.end_headers()
        self.wfile.write(b'{"status":"ok"}' if api else b"<!doctype html><title>ShenSec local fixture</title>")

    def do_OPTIONS(self):
        self.send_response(204)
        # Demonstrate a new contextual MEDIUM observation below the HIGH gate.
        methods = "GET, OPTIONS, DELETE" if self.server.hardened and self.path.startswith("/api/") else "GET, OPTIONS"
        self.send_header("Allow", methods)
        self.end_headers()

    def log_message(self, format, *args):
        pass


def run_demo():
    server = ThreadingHTTPServer(("127.0.0.1", 0), DemoHandler)
    server.hardened = False
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        origin = f"http://127.0.0.1:{server.server_port}"
        targets = [origin + "/", origin + "/api/health"]
        baseline = scan_many(targets, timeout=3, workers=2)
        baseline.gate = evaluate_gate(baseline)
        server.hardened = True
        current = scan_many(targets, timeout=3, workers=2)
        current.comparison = compare_audits(current, baseline)
        current.gate = evaluate_gate(current, only_new=True)
        return baseline, current
    finally:
        server.shutdown()
        server.server_close()
        thread.join()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", type=Path, default=Path(__file__).parent / "demo-output")
    args = parser.parse_args()
    baseline, current = run_demo()
    args.output_dir.mkdir(parents=True, exist_ok=True)
    (args.output_dir / "baseline.json").write_text(generate_report(baseline, "json"), encoding="utf-8")
    for extension, format_name in (("json", "json"), ("html", "html"), ("md", "markdown")):
        (args.output_dir / f"report.{extension}").write_text(generate_report(current, format_name), encoding="utf-8")
    print(f"Baseline gate: {baseline.gate.outcome.upper()} -> Current gate: {current.gate.outcome.upper()}")
    print(f"New: {len(current.comparison.new)} | Resolved: {len(current.comparison.resolved)} | Unverified: {len(current.comparison.unverified)}")
    print(f"Report: {(args.output_dir / 'report.html').resolve()}")
    raise SystemExit(current.gate.exit_code)


if __name__ == "__main__":
    main()
