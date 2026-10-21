# ShenSec

**Catch web security and access regressions before deployment.**

An API security workbench with automatic login, session renewal, verified role comparisons, local history, baselines and CI gates. Review what changed without saving passwords or tokens in reports.

[![Python 3.13+](https://img.shields.io/badge/Python-3.13%2B-blue)](pyproject.toml)
[![Version](https://img.shields.io/badge/version-0.5.0b1-teal)](CHANGELOG.md)
[![Tests](https://github.com/shenming1115/ShenSec/actions/workflows/ci.yml/badge.svg)](https://github.com/shenming1115/ShenSec/actions/workflows/ci.yml)
[![Windows x64](https://img.shields.io/badge/Windows-x64-0078D4)](https://github.com/shenming1115/ShenSec/releases/tag/v0.5.0b1)
[![MIT](https://img.shields.io/badge/license-MIT-blue)](LICENSE)

[简体中文](README.zh-CN.md) · [Windows tutorial](docs/windows-guide.zh-CN.md) · [Authentication guide](docs/authentication.md) · [CI integration](docs/ci.md)

## Download and double-click

**Windows 10/11 x64 — no Python, uv, terminal or administrator rights required.**

1. Download the [standalone exe](https://github.com/shenming1115/ShenSec/releases/download/v0.5.0b1/ShenSec-0.5.0b1-windows-x64.exe) and double-click it.
2. Click **Try local demo** to explore login, renewal, four roles, history and baseline comparisons using a real local fixture.
3. Click **+ New** to configure your own project. **User guide** opens offline instructions from the toolbar.

For faster daily startup, use the [portable ZIP](https://github.com/shenming1115/ShenSec/releases/download/v0.5.0b1/ShenSec-0.5.0b1-windows-x64-portable.zip): extract everything, then open `ShenSec.exe`. Keep `_internal` alongside it. Both downloads are available on the [release page](https://github.com/shenming1115/ShenSec/releases/tag/v0.5.0b1), with SHA-256 checksums. This beta is unsigned; Windows may show an unknown-publisher prompt. Verify the official download and checksum before following your device's policy.

The demo runs in a separate temporary workspace, scans an authenticated loopback application before and after hardening, and opens populated history. It needs no production account or token. Select either run, inspect evidence, rescan and export reports. Closing its window stops the fixture and removes demo data.

![Real login and role comparison workbench showing unexpected access in a controlled fixture](docs/permissions-workbench.png)

The identity fixture checks **4 roles × 2 endpoints**, resolves **3 unexpected access observations**, and verifies **4 session renewals** in the post-fix run. The screenshot shows the controlled pre-fix state. HTTP transport observations remain because the fixture uses loopback HTTP. See [screenshots and reproducibility](docs/screenshots.md).

New in 0.5: **automatic JSON/form login, CSRF support, session renewal, verified role comparisons, a permission matrix and guided desktop setup**. Passwords and tokens stay in memory. [Identity workflows and examples](docs/identity-workflows.md).

API features: **OpenAPI import, explicit API requests, active CORS checks, per-origin pacing, safe retries, expiring exceptions and SARIF**. Configure these in the desktop tabs or shared TOML/JSON projects. See [API workflows](docs/api-workflows.md) for examples and supported boundaries. The built-in demo includes authenticated POST and CORS checks.

## Use it every day

Open the exe; projects and history persist across launches. The source launchers `ShenSec.cmd` and `shensec.sh` remain available for development with uv. Linux/macOS users currently run from source.

1. Create a project and paste/import your endpoint URLs.
2. Configure Bearer, session Cookie, or API-key/header environment references. You can also paste masked session credentials; they stay in memory until you switch projects, clear them, or close the app.
3. Run the audit and inspect the evidence and recommended actions. Accept a complete reviewed run as the baseline.
4. Scan again. New issues, severity increases, fixes, and unverified observations are tracked separately. Prioritize actionable changes or search across targets, evidence, and recommendations.

![Guided automatic login and identity verification](docs/login-workbench.png)

![Session state and renewal activity for each identity](docs/sessions-workbench.png)

Projects and indexed scan history live in `~/.shensec/workspace.sqlite3`. Use `--workspace PATH` or `SHENSEC_HOME` to choose another location. Configuration exports contain environment variable names, not credential values. Response Cookie changes remain isolated between target scans, while automatic login shares a verified seed session and single-flight renewal per identity. HTTP clients are reused per worker.

| Capability | What you get |
| --- | --- |
| Authenticated endpoints | Bearer, Cookie and custom header/API-key credentials; exact origin scope; optional session verification URL and success header |
| Project workbench | Bulk URL import, saved configuration, persistent history, baseline selection, text/severity/change filters |
| Feedback and control | Per-target progress, cooperative cancellation, explicit failed/partial/cancelled states, preserved partial results |
| Repeatable audits | Stable issue identities; new/existing/resolved/regressed/unverified comparisons; authentication context change detection |
| Automation | CLI/API, reusable TOML/JSON configs, clean JSON stdout, severity and new-issue gates |
| Shareable evidence | Escaped offline HTML, Markdown and JSON; severity sorting; cookie and credential redaction |
| Efficient execution | Bounded scheduling, 1–16 workers, per-worker HTTP client reuse, indexed history, lazy Qt findings table |

## CLI: authenticated audits and CI

```bash
# Create a shareable project; APP_TOKEN is an environment variable NAME.
uv run shensec init --name "Staging API" --target https://your-app.example/api/me --bearer-env APP_TOKEN

# Set APP_TOKEN in your process environment using your usual secret-management workflow.
uv run shensec audit --config shensec.toml --format json --output baseline.json

# On subsequent deployments, gate new HIGH/CRITICAL issues and severity increases.
uv run shensec audit --config shensec.toml --baseline baseline.json --only-new --fail-on HIGH --format json --output current.json

# Use the same project/history store as the desktop app.
uv run shensec project import shensec.toml
uv run shensec project list
uv run shensec audit --project PROJECT_ID --format json
uv run shensec history PROJECT_ID
uv run shensec baseline PROJECT_ID RUN_ID
uv run shensec history PROJECT_ID --run RUN_ID --format html --output audit.html
```

`audit --project` saves history and uses that project's accepted baseline automatically. `audit --config` is stateless for CI. Explicit URLs/`--targets` replace a configuration's URL list. Workers, timeout, and severity options override project settings.

| Exit | Meaning |
| --- | --- |
| `0` | All requested coverage completed and the policy passed |
| `1` | Findings met or exceeded the selected severity threshold |
| `2` | Invalid input, authentication/execution/output error, cancellation, or incomplete coverage |

`audit` defaults to HIGH. `scan` and `jwt` fail on findings only when `--fail-on` is supplied. Progress goes to stderr; JSON stdout remains parseable. A severity gate can fail while still writing a valid initial baseline report. Review that report before accepting it.

Removed targets, missing checks, changed authentication contexts, and failed scans cannot silently become fixes. See [coverage and compatibility](docs/limitations.md) and [CI report retention](docs/ci.md).

## Focused inspections

```bash
uv run shensec scan https://your-app.example --format html --output report.html
uv run shensec jwt --token-file token.txt --format json
uv run shensec demo --output-dir demo-reports
uv run shensec --help
```

Current checks cover transport/HSTS, CSP and framing headers, MIME/referrer/permissions policies, cookie flags, wildcard CORS, server/framework exposure, infrastructure indicators, and advertised HTTP methods. Local JWT inspection covers structure/types, algorithms, expiration, key references, and sensitive claim heuristics. JWT signatures and server acceptance are not verified.

Default HTTP scans use GET and optional OPTIONS. Explicit request plans support GET/HEAD/POST/PUT/PATCH/DELETE; advertised methods are never executed automatically. Optional Origin probes apply to GET/HEAD only. The tool does not crawl, fuzz or exploit targets. HTML-specific controls are skipped for explicit API content types. Findings are observations that require application context.

## Performance you can reproduce

```bash
uv run python examples/benchmark.py --targets 24 --rounds 3 --workers 4
```

One Windows/Python 3.13.3 loopback run measured a **5.30×** improvement from per-worker client reuse: median **7307.74 → 1379.49 ms**, **24 → 4 TCP connections**, identical findings. This compares client-creation strategies on a small authenticated HTTP/1.1 fixture; it is not a general internet-scan speed guarantee. [Method and raw sample](docs/performance.md).

Small declared uncompressed bodies up to 16 KiB may be drained without being retained, allowing connection reuse. Large, encoded, and unknown-length bodies are closed without downloading them. Concurrency is bounded and cancellation stops new scheduling; in-flight requests finish within their configured operation timeout.

## Python API and architecture

```python
from shensec import Workspace, audit_project, load_project

config = load_project("shensec.toml")
workspace = Workspace()
project_id = workspace.save_project(config)
result = audit_project(config, baseline=workspace.baseline(project_id))
run_id = workspace.save_run(project_id, config, result)
print(result.gate.outcome)
```

| Module | Responsibility |
| --- | --- |
| `auth.py`, `project.py` | Scoped runtime credentials, redaction, portable validated project configuration |
| `scanner/` | HTTP transport, contextual header/cookie rules, local JWT inspection |
| `audit.py`, `models.py` | Bounded batch scheduling, progress/cancellation, comparisons, gates and derived summaries |
| `workspace.py` | Transactional SQLite projects, indexed history and accepted baselines |
| `gui/` | Background workers, project workflow, lazy table models, quick scan/JWT pages |
| `reporting/`, `templates/`, `cli.py` | Reports and command-line workflows |

Existing `scan_target`, `analyze_response`, `analyze_jwt`, and `generate_report` APIs remain available. [Chinese project analysis](docs/project-direction.zh-CN.md) includes the development direction.

## Development and verification

```bash
uv sync --locked --extra gui
uv run pytest
uv build
```

To launch from source, run `uv run --locked --extra gui shensec gui`. To build both Windows distributions on a Windows x64 host:

```powershell
uv sync --locked --extra gui --group build
uv run --locked --group build python scripts/build_windows.py
```

See [release verification](RELEASE.md) for packaged-runtime checks and the automated Windows release workflow. Build tools are only needed by contributors.

Set `QT_QPA_PLATFORM=offscreen` for headless GUI tests. The local suite covers authenticated real HTTP requests, connection reuse, credential isolation/redaction, cancellation, history restart, baseline rules, report injection, and a 5000-finding Qt model. GUI tests are skipped if the extra is absent. CI is configured for Windows, Linux and macOS; remote runs must be verified after pushing.

See [contributing](CONTRIBUTING.md), [security reporting](SECURITY.md), and [release verification](RELEASE.md). Use only systems and redirect destinations you are authorized to assess.

## License

[MIT](LICENSE). Created by Ch'ng Shen Ming.
