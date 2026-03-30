import typer
from typing import Optional
from enum import Enum
from .scanner.core import scan_target
from .scanner.jwt import analyze_jwt
from .reporting.formatters import generate_report

app = typer.Typer(
    name="shensec",
    help="ShenSec: A Python Package for Web Security Auditing and Result Analysis",
    add_completion=False
)

class FormatChoices(str, Enum):
    json = "json"
    markdown = "markdown"
    html = "html"

@app.command()
def scan(
    url: str = typer.Argument(..., help="The target URL or API endpoint to audit (e.g., https://example.com)"),
    format: FormatChoices = typer.Option(FormatChoices.markdown, "--format", "-f", help="Output format of the report"),
    output: Optional[str] = typer.Option(None, "--output", "-o", help="File path to save the output report"),
    timeout: float = typer.Option(10.0, "--timeout", "-t", help="Timeout for HTTP requests in seconds"),
    jwt: Optional[str] = typer.Option(None, "--jwt", help="An optional JWT token to inspect locally")
):
    """
    Perform a basic web security audit against a specified URL.
    """
    typer.secho(f"Starting ShenSec Scan on: {url}", fg=typer.colors.CYAN, bold=True)
    
    # 1. Perform the scan
    result = scan_target(url, timeout=timeout)
    
    # Optional JWT inspection
    if jwt:
        typer.secho("Analyzing provided JWT token...", fg=typer.colors.YELLOW)
        jwt_findings = analyze_jwt(jwt)
        result.findings.extend(jwt_findings)
    
    # 2. Format the report
    try:
        report_content = generate_report(result, format.value)
    except ValueError as e:
        typer.secho(f"Error formatting report: {e}", fg=typer.colors.RED)
        raise typer.Exit(code=1)
        
    # 3. Handle Output
    if output:
        with open(output, "w", encoding="utf-8") as f:
            f.write(report_content)
        typer.secho(f"Scan complete. Report saved to: {output}", fg=typer.colors.GREEN)
    else:
        typer.echo("\n--- Scan Results ---\n")
        typer.echo(report_content)
        typer.echo("\n--------------------\n")

@app.command()
def gui():
    """
    Launch the ShenSec Graphical User Interface (PySide6).
    """
    try:
        from .gui.app import run_gui
        typer.secho("Launching GUI...", fg=typer.colors.CYAN)
        run_gui()
    except ImportError as e:
        typer.secho("Failed to load GUI. Please ensure PySide6 is installed. Try: pip install shensec[gui]", fg=typer.colors.RED)
        typer.secho(f"Error: {e}", fg=typer.colors.RED)
        raise typer.Exit(code=1)

if __name__ == "__main__":
    app()