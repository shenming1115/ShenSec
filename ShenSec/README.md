# ShenSec

**ShenSec** is a Python-based package designed to help developers perform basic web security auditing and generate useful analytical reports. Instead of acting as an offensive hacking tool, the package focuses on defensive auditing, allowing users to inspect their own websites or APIs and identify common weaknesses in a structured way.

## Features

- **Security Headers**: Check for missing or misconfigured security headers (HSTS, CSP, X-Frame-Options).
- **Cookies**: Audit cookie flags for security (Secure, HttpOnly, SameSite).
- **JWT Inspection**: Validate JWT structure and identify weak algorithms like `alg: none`.
- **Reporting**: Generate easily readable reports in format of your choice, including `markdown`, `json`, and `html`.
- **Modern CLI**: Powered by Typer for intuitive command-line inputs.

## Project Structure
```text
ShenSec/
├── src/shensec/
│   ├── cli.py             # Typer CLI application entrypoint
│   ├── models.py          # Pydantic data structures for Risks/Findings
│   ├── reporting/         # HTML/JSON/Markdown Formatters
│   └── scanner/           # Checking logic (headers.py, cookies.py, jwt.py, core.py)
├── tests/                 # Unit tests (pytest)
└── pyproject.toml         # Build / Dependency config (uv)
```

## Installation

Since the package uses `uv` for dependency management:
```bash
uv sync
uv build
```

Or run via `uv` directly from the source code:
```bash
uv run shensec --help
```

## Usage

### 1. Basic Scan (Markdown Output)
Run a quick security audit against a host and output a markdown report on the terminal:
```bash
uv run shensec https://example.com
```

### 2. Output to HTML
Save the output as a fully styled HTML file:
```bash
uv run shensec https://example.com --format html -o result.html
```

### 3. Local Token Inspection
Analyze a JWT locally alongside a target check:
```bash
uv run shensec https://example.com --jwt "eyJhbGciOiJub25lIn0.eyJzdWIiOiIxMjMifQ."
```

## Sample Output

```text
Starting ShenSec Scan on: https://example.com

--- Scan Results ---

# ShenSec Security Scan Report

**Target URL**: https://example.com
**Status Code**: 200
**Response Time**: 118.4 ms

## Security Risk Analysis
**Overall Risk Rating**: **HIGH**
- CRITICAL: 0
- HIGH: 2
- MEDIUM: 1
- LOW: 0
- INFO: 0

## Findings Summary
Total Issues Found: 3

## Detailed Findings

### 1. Missing Strict-Transport-Security Header (HIGH)
- **Rule ID**: SEC-HDR-001
- **Description**: The application does not enforce HTTPS connections using HSTS.
- **Recommendation**: Add the Strict-Transport-Security header with an appropriate max-age.
...
```

## Testing

Run the included automated tests via `pytest`:
```bash
uv run pytest
```

## Disclaimer & Limitations
ShenSec is designed **strictly for defensive auditing and educational purposes**. 
- It is **not** an enterprise DAST/SAST scanner and does not send offensive payloads, fuzz inputs, or execute SQL injection/Cross-Site Scripting attacks.
- It cannot read server-side backend logic.
- **Note on HTTPS Errors**: If the CLI returns a `TLS/SSL Certificate Error`, it often indicates that the target server is using an untrusted or expired certificate, or your local environment's certificate trust store is missing roots.