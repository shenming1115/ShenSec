"""Human-readable reports and clean machine-readable output for automation."""

from enum import Enum
from pathlib import Path
from typing import Optional
import json
import sqlite3
import time
from threading import Event
from tempfile import TemporaryDirectory

import typer
from pydantic import ValidationError

from .audit import compare_audits, evaluate_gate, load_baseline, scan_many
from .models import AuditResult, ScanResult, Severity
from .reporting.formatters import generate_report
from .scanner.core import scan_target
from .scanner.jwt import analyze_jwt, inspect_jwt
from .targets import normalize_target, parse_targets
from .auth import AuthConfig, resolve_auth
from .project import ProjectConfig, load_project, project_toml, validation_message
from .workspace import Workspace
from .policy import apply_exceptions
from .openapi import import_openapi
from .reporting.sarif import format_sarif
from .network import RequestPacer
from .access import complete_access, prepare_roles
from .sessions import validate_auth_inputs, prepare_auth, session_snapshot

app = typer.Typer(
    name="shensec", help="ShenSec: repeatable web security audits and configuration regression checks.",
    add_completion=False,
)


class FormatChoices(str, Enum):
    json = "json"
    markdown = "markdown"
    html = "html"
    sarif = "sarif"


def _error(message) -> None:
    if isinstance(message, ValidationError):
        message = validation_message(message)
    typer.secho(f"Error: {message}", fg=typer.colors.RED, err=True)
    raise typer.Exit(code=2)


def _emit(result: ScanResult | AuditResult, format: FormatChoices, output: Optional[Path], sarif_source: Path | None = None) -> None:
    try:
        if output and sarif_source and output.resolve() == sarif_source.resolve():
            raise ValueError("Preserve the SARIF source declarations; choose another output path.")
        if sarif_source and format == FormatChoices.sarif:
            if sarif_source.is_absolute() or '..' in sarif_source.parts:
                raise ValueError("--sarif-source must be a repository-relative file path.")
            if not sarif_source.resolve().is_relative_to(Path.cwd().resolve()):
                raise ValueError("--sarif-source must resolve inside the working repository.")
            lines = sarif_source.read_text(encoding="utf-8-sig").splitlines()
            scans = result.results if isinstance(result, AuditResult) else [result]
            anchors = {}
            for scan in scans:
                line = next((i for i, text in enumerate(lines, 1) if scan.target_url in text), None)
                if line is None:
                    raise ValueError(f"SARIF source must contain each target URL: {scan.target_url}")
                anchors[scan.target_url] = line
            content = format_sarif(result, source=sarif_source.as_posix(), source_lines=anchors)
        else:
            content = generate_report(result, format.value)
        if output:
            output.write_text(content, encoding="utf-8")
            typer.echo(f"Report saved to: {output}", err=True)
        else:
            typer.echo(content)
    except (OSError, ValueError) as exc:
        _error(str(exc))


@app.command()
def scan(
    url: str = typer.Argument(..., help="Absolute HTTP(S) URL to audit."),
    format: FormatChoices = typer.Option(FormatChoices.markdown, "--format", "-f"),
    output: Optional[Path] = typer.Option(None, "--output", "-o"),
    timeout: float = typer.Option(10.0, "--timeout", "-t", min=0.1, max=120),
    jwt: Optional[str] = typer.Option(None, "--jwt", help="Append local JWT inspection; prefer the jwt --token-file command for tokens."),
    fail_on: Optional[Severity] = typer.Option(None, "--fail-on", case_sensitive=False, help="Exit 1 for findings at or above this severity."),
    no_options: bool = typer.Option(False, "--no-options", help="Skip the OPTIONS request."),
    allow_cross_origin: bool = typer.Option(False, "--allow-cross-origin", help="Follow redirects to other origins within your authorized scope."),
):
    """Audit one endpoint. Exit 0: complete, 1: policy failed, 2: incomplete/error."""
    try:
        url = normalize_target(url)
    except ValueError as exc:
        _error(str(exc))
    typer.echo(f"Scanning {url}", err=True)
    result = scan_target(url, timeout, check_options=not no_options, allow_cross_origin=allow_cross_origin)
    if jwt:
        result.findings.extend(analyze_jwt(jwt))
        result.checks.append("jwt")
    gate = evaluate_gate(AuditResult(results=[result]), fail_on)
    _emit(result, format, output)
    if gate.errors:
        typer.echo("; ".join(gate.errors), err=True)
    raise typer.Exit(code=gate.exit_code)


@app.command()
def audit(
    urls: Optional[list[str]] = typer.Argument(None, help="One or more absolute HTTP(S) URLs."),
    targets: Optional[Path] = typer.Option(None, "--targets", help="UTF-8 file with one URL per line; # comments supported."),
    baseline: Optional[Path] = typer.Option(None, "--baseline", help="Previous JSON scan/audit report."),
    only_new: bool = typer.Option(False, "--only-new", help="Gate only new findings and severity increases; requires --baseline."),
    fail_on: Optional[Severity] = typer.Option(None, "--fail-on", case_sensitive=False, help="Default: project threshold or HIGH."),
    workers: Optional[int] = typer.Option(None, "--workers", "-j", min=1, max=16),
    timeout: Optional[float] = typer.Option(None, "--timeout", "-t", min=0.1, max=120),
    format: FormatChoices = typer.Option(FormatChoices.markdown, "--format", "-f"),
    output: Optional[Path] = typer.Option(None, "--output", "-o"),
    no_options: bool = typer.Option(False, "--no-options"),
    allow_cross_origin: bool = typer.Option(False, "--allow-cross-origin"),
    config: Optional[Path] = typer.Option(None, "--config", "-c", help="TOML/JSON project configuration."),
    project: Optional[str] = typer.Option(None, "--project", help="Saved workspace project ID; saves history and uses its accepted baseline."),
    workspace: Optional[Path] = typer.Option(None, "--workspace", help="Local workspace directory; also configurable via SHENSEC_HOME."),
    bearer_env: Optional[str] = typer.Option(None, "--bearer-env", help="Environment variable holding a Bearer token."),
    cookie_env: Optional[str] = typer.Option(None, "--cookie-env", help="Environment variable holding a session Cookie header."),
    auth_origin: Optional[list[str]] = typer.Option(None, "--auth-origin", help="Exact credential origin; repeat for additional origins."),
    sarif_source: Optional[Path] = typer.Option(None, "--sarif-source", help="Repository-relative config/manifest file containing target URLs; anchors SARIF alerts to actual declarations."),
):
    """Batch audit, compare a baseline, and enforce a security regression gate."""
    try:
        if config and project:
            raise ValueError("Use --config or --project, not both.")
        if sarif_source and format != FormatChoices.sarif:
            raise ValueError("--sarif-source requires --format sarif.")
        if baseline and output and baseline.resolve() == output.resolve():
            raise ValueError("Use a different output path to preserve the baseline.")
        if config and output and config.resolve() == output.resolve():
            raise ValueError("Use a different output path to preserve project configuration.")
        if targets and output and targets.resolve() == output.resolve():
            raise ValueError("Use a different output path to preserve the target list.")
        store = Workspace(workspace)
        settings = load_project(config) if config else store.load_project(project) if project else None
        previous = load_baseline(baseline) if baseline else store.baseline(project) if project else None
        gate_only_new = only_new or bool(project and previous)
        if gate_only_new and previous is None:
            raise ValueError("--only-new requires --baseline or an accepted project baseline.")
        lines = list(urls or [])
        if targets:
            lines.extend(targets.read_text(encoding="utf-8-sig").splitlines())
        normalized = parse_targets(lines or (settings.targets if settings else []))
        settings = settings or ProjectConfig(name="CLI audit", targets=normalized)
        if (lines or targets) and (settings.requests or settings.permissions) and normalized != settings.targets:
            raise ValueError("Target overrides cannot change a request plan or permission matrix. Edit the project configuration.")
        auth_data = settings.auth.model_dump()
        if bearer_env:
            auth_data["bearer_env"] = bearer_env
        if cookie_env:
            auth_data["cookie_env"] = cookie_env
        if auth_origin:
            auth_data["origins"] = auth_origin
        runtime = resolve_auth(AuthConfig.model_validate(auth_data), normalized)
        validate_auth_inputs(runtime)
        for plan in settings.requests:
            plan.payload()
        selected_workers = workers if workers is not None else settings.workers
        selected_timeout = timeout if timeout is not None else settings.timeout
        threshold = fail_on if fail_on is not None else settings.threshold
        started = time.perf_counter()
        event = Event()
        pacer = RequestPacer(settings.network)
        role_runtimes = prepare_roles(settings, {}, pacer, event) if settings.permissions else {}
        typer.echo(f"Auditing {len(normalized)} target(s) with {selected_workers} worker(s)", err=True)
        result = scan_many(
            normalized, selected_timeout, workers=selected_workers,
            check_options=settings.check_options and not no_options,
            allow_cross_origin=settings.allow_cross_origin or allow_cross_origin, auth=runtime,
            requests=settings.requests, network=settings.network,
            check_cors=settings.check_cors,
            pacer=pacer,
        )
        complete_access(result, settings, role_runtimes, pacer, event)
        result.duration_ms = round((time.perf_counter() - started) * 1000, 2)
        apply_exceptions(result, settings.exceptions)
        if previous:
            result.comparison = compare_audits(result, previous)
        result.gate = evaluate_gate(result, threshold, only_new=gate_only_new)
        if project:
            snapshot = settings.model_copy(update={
                "targets": normalized, "workers": selected_workers, "timeout": selected_timeout,
                "threshold": threshold, "auth": runtime.config,
                "check_options": settings.check_options and not no_options,
                "allow_cross_origin": settings.allow_cross_origin or allow_cross_origin,
            })
            try:
                run_id = store.save_run(project, snapshot, result)
                typer.echo(f"History saved: {run_id}", err=True)
            except (OSError, sqlite3.Error) as exc:
                result.gate.outcome = "error"
                result.gate.errors.append(f"Scan completed, but history could not be saved ({type(exc).__name__}).")
    except (OSError, ValueError, sqlite3.Error) as exc:
        _error(exc)
    _emit(result, format, output, sarif_source)
    typer.echo(
        f"Gate: {result.gate.outcome.upper()} | violations: {len(result.gate.violations)} "
        f"| incomplete targets: {result.failed_targets}", err=True,
    )
    for error in result.gate.errors:
        typer.echo(error, err=True)
    raise typer.Exit(code=result.gate.exit_code)


@app.command(name="jwt")
def jwt_command(
    token: Optional[str] = typer.Argument(None, help="JWT to inspect locally; token-file avoids shell history exposure."),
    token_file: Optional[Path] = typer.Option(None, "--token-file", help="Read the token from a UTF-8 file."),
    format: FormatChoices = typer.Option(FormatChoices.markdown, "--format", "-f"),
    output: Optional[Path] = typer.Option(None, "--output", "-o"),
    fail_on: Optional[Severity] = typer.Option(None, "--fail-on", case_sensitive=False),
):
    """Inspect and export a JWT locally, without retaining the original token."""
    try:
        if bool(token) == bool(token_file):
            raise ValueError("Supply exactly one token argument or --token-file.")
        if token_file:
            token = token_file.read_text(encoding="utf-8-sig").strip()
        if not token:
            raise ValueError("The token is empty.")
    except (OSError, ValueError) as exc:
        _error(str(exc))
    result = inspect_jwt(token)
    _emit(result, format, output)
    gate = evaluate_gate(AuditResult(results=[result]), fail_on)
    raise typer.Exit(code=gate.exit_code)


@app.command(name="report")
def report_command(
    source: Path = typer.Argument(..., help="Recorded JSON scan/audit; no network requests are made."),
    format: FormatChoices = typer.Option(FormatChoices.html, "--format", "-f"),
    output: Optional[Path] = typer.Option(None, "--output", "-o"),
    sarif_source: Optional[Path] = typer.Option(None, "--sarif-source"),
):
    """Convert a recorded JSON report to another format without rescanning."""
    try:
        if output and source.resolve() == output.resolve():
            raise ValueError("Preserve the input report; choose another output path.")
        if sarif_source and format != FormatChoices.sarif:
            raise ValueError("--sarif-source requires --format sarif.")
        recorded = load_baseline(source)
    except (ValueError, OSError) as exc:
        _error(exc)
    _emit(recorded, format, output, sarif_source)


@app.command()
def gui(workspace: Optional[Path] = typer.Option(None, "--workspace", help="Project/history workspace directory.")):
    """Launch the optional PySide6 desktop interface."""
    try:
        from .gui.app import run_gui
        typer.secho("Launching GUI...", fg=typer.colors.CYAN)
        run_gui(workspace=workspace)
    except ImportError as exc:
        typer.secho("Failed to load GUI. Please ensure PySide6 is installed. Try: pip install shensec[gui]", fg=typer.colors.RED)
        typer.secho(f"Error: {exc}", fg=typer.colors.RED)
        raise typer.Exit(code=1)


@app.command()
def init(
    target: list[str] = typer.Option(..., "--target", help="Initial URL; repeat for multiple targets."),
    name: str = typer.Option("My project", "--name"),
    output: Path = typer.Option(Path("shensec.toml"), "--output", "-o"),
    bearer_env: Optional[str] = typer.Option(None, "--bearer-env"),
    cookie_env: Optional[str] = typer.Option(None, "--cookie-env"),
):
    """Create a reusable project configuration without credential values."""
    try:
        config = ProjectConfig(name=name, targets=target, auth=AuthConfig(bearer_env=bearer_env, cookie_env=cookie_env))
        with output.open("x", encoding="utf-8") as handle:
            handle.write(project_toml(config))
        typer.echo(f"Project configuration created: {output}")
    except (OSError, ValueError) as exc:
        _error(exc)


project_app = typer.Typer(help="Local projects shared with the desktop workbench.")
app.add_typer(project_app, name="project")

auth_app = typer.Typer(help="Test configured login or session verification without scanning endpoints.")
app.add_typer(auth_app, name="auth")


@auth_app.command(name="test")
def test_auth_command(
    config: Optional[Path] = typer.Option(None, "--config", "-c"),
    project: Optional[str] = typer.Option(None, "--project"),
    role: Optional[str] = typer.Option(None, "--role", help="Test a named role instead of the primary identity."),
    workspace: Optional[Path] = typer.Option(None, "--workspace"),
):
    """Sign in/verify one identity and print safe session metadata; values are never output."""
    try:
        if bool(config) == bool(project):
            raise ValueError("Choose exactly one --config or --project.")
        settings = load_project(config) if config else Workspace(workspace).load_project(project)
        selected = settings.auth
        if role:
            configured = next((r for r in settings.roles if r.name == role), None)
            if configured is None:
                raise ValueError("Named role was not found in this project.")
            selected = configured.auth.model_copy(update={"profile": configured.name, "required": not configured.anonymous})
        runtime = resolve_auth(selected, settings.targets)
        if not selected.login and not selected.verify_url:
            raise ValueError("Configure automatic login or a verification URL before testing authentication.")
        prepare_auth(runtime, settings.timeout, RequestPacer(settings.network), Event())
        typer.echo(json.dumps({"session": session_snapshot(runtime).model_dump(mode="json"), "verification_configured": bool(selected.verify_url)}, indent=2))
    except (OSError, ValueError, sqlite3.Error) as exc:
        _error(exc)


@app.command(name="import-openapi")
def openapi_command(
    spec: Path = typer.Argument(..., help="Local OpenAPI 3.0/3.1 JSON document."),
    server: str = typer.Option(..., "--server", help="Explicit deployment base URL, including any API prefix."),
    param: Optional[list[str]] = typer.Option(None, "--param", help="Binding such as path.id=42 or query.page=1; repeat as needed."),
    output: Path = typer.Option(Path("shensec.toml"), "--output", "-o"),
):
    """Create a reviewed GET/HEAD project from OpenAPI without making requests."""
    try:
        bindings = {}
        for value in param or []:
            name, sep, binding = value.partition('=')
            if not name or not sep:
                raise ValueError("--param uses name=value.")
            bindings[name] = binding
        imported = import_openapi(spec, server, bindings)
        with output.open('x', encoding='utf-8') as handle:
            handle.write(project_toml(imported.config))
        typer.echo(f"Imported {len(imported.config.targets)} targets: {output}")
        for message in imported.skipped:
            typer.echo(f"Skipped: {message}", err=True)
    except (OSError, ValueError) as exc:
        _error(exc)


@project_app.command(name="import")
def import_project(config: Path, workspace: Optional[Path] = typer.Option(None, "--workspace")):
    """Import a TOML/JSON config and print its saved project ID."""
    try:
        typer.echo(Workspace(workspace).save_project(load_project(config)))
    except (OSError, ValueError, sqlite3.Error) as exc:
        _error(exc)


@project_app.command(name="list")
def list_projects(workspace: Optional[Path] = typer.Option(None, "--workspace")):
    """List saved projects as JSON."""
    try:
        typer.echo(json.dumps(Workspace(workspace).list_projects(), indent=2))
    except (OSError, sqlite3.Error) as exc:
        _error(exc)


@app.command()
def history(
    project: str, workspace: Optional[Path] = typer.Option(None, "--workspace"),
    run: Optional[str] = typer.Option(None, "--run", help="Export a specific recorded audit without rescanning."),
    format: FormatChoices = typer.Option(FormatChoices.json, "--format", "-f"),
    output: Optional[Path] = typer.Option(None, "--output", "-o"),
):
    """List project history as JSON or export one saved scan."""
    try:
        store = Workspace(workspace)
        store.load_project(project)
        if run:
            _emit(store.load_run(project, run), format, output)
        elif output:
            raise ValueError("--output requires --run.")
        else:
            typer.echo(json.dumps(store.list_runs(project), indent=2))
    except (OSError, ValueError, sqlite3.Error) as exc:
        _error(exc)


@app.command()
def baseline(
    project: str, run: str, workspace: Optional[Path] = typer.Option(None, "--workspace"),
):
    """Accept one complete saved run as a project's future comparison baseline."""
    try:
        Workspace(workspace).set_baseline(project, run)
        typer.echo("Baseline accepted.")
    except (OSError, ValueError, sqlite3.Error) as exc:
        _error(exc)


@app.command()
def demo(
    gui: bool = typer.Option(False, "--gui", help="Open a populated workbench with a live authenticated local target."),
    output_dir: Path = typer.Option(Path("shensec-demo"), "--output-dir", help="Save demonstration reports here."),
    identities: bool = typer.Option(False, "--identities", help="Demonstrate automatic login, renewal and four-role permission comparisons."),
):
    """Try authentication, history and baseline comparison on a built-in local target."""
    from .demo import demo_workspace
    if identities:
        from .identity_demo import demo_workspace
    try:
        output_dir.mkdir(parents=True, exist_ok=True)
        with TemporaryDirectory(prefix=".workspace-", dir=output_dir) as root:
            with demo_workspace(root) as (workspace, project_id, before, current):
                for extension, fmt in (("json", "json"), ("html", "html"), ("md", "markdown"), ("sarif", "sarif")):
                    (output_dir / f"report.{extension}").write_text(generate_report(current, fmt), encoding="utf-8")
                typer.echo(f"Authenticated localhost demo: {before.gate.outcome.upper()} -> {current.gate.outcome.upper()}")
                typer.echo(f"Resolved: {len(current.comparison.resolved)} | New: {len(current.comparison.new)} | Unverified: {len(current.comparison.unverified)}")
                typer.echo(f"Report: {(output_dir / 'report.html').resolve()}")
                if gui:
                    from .gui.app import run_gui
                    run_gui(workspace=workspace)
                else:
                    raise typer.Exit(code=current.gate.exit_code)
    except (ValueError, OSError, sqlite3.Error) as exc:
        _error(exc)
    except ImportError:
        _error("Install the GUI extra to open the demo workbench: uv sync --extra gui")


if __name__ == "__main__":
    app()
