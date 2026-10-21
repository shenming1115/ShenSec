# Changelog

## Windows desktop distribution (0.5.0b1)

- Added standalone Windows x64 exe and fast-starting portable ZIP with Python/Qt, versioned icon and dependency notices.
- Added a direct windowed entry point, safe startup diagnostics, offline guide, history-folder action and asynchronous isolated local demo.
- Added locked PyInstaller builds, packaged end-to-end verification and a GitHub tag-to-prerelease workflow.
- Reworked English/Chinese READMEs, refreshed real Qt screenshots and added a complete Windows tutorial.


All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### 0.5 beta managed identities
- Added verified JSON/form automatic login, hidden-input/JSON CSRF initialization, scoped session cookies and nested token/lifetime extraction.
- Added single-flight, bounded refresh/re-login, refresh-token rotation, proactive expiry renewal and one safe-request replay after 401; writes are never replayed automatically.
- Added named verified roles, anonymous controls and explicit GET/HEAD access expectations with header/JSON success assertions, integrated into history, context-aware baselines, gates and reports.
- Added role permission matrices, session activity, guided setup, sign-in testing and in-memory account/password/Bearer/Cookie input; copying primary settings can reuse temporary values without persisting them.
- Added safe CLI `auth test`, a real login/refresh/four-role fixture, reusable identity configuration and updated bilingual guides.
- Preserved disabled default pointers and cookie mode across TOML exports; automatic login requires positive identity verification.
- Updated local source beta metadata to 0.5.0b1; no external publication performed.

### 0.4 beta API workflows
- Added explicit API methods, environment-referenced bodies, expected statuses and comparison-context guards.
- Added offline OpenAPI 3.0/3.1 JSON import with bindings, local references, skipped reasons and required-auth guards.
- Added optional two-origin CORS reflection checks and baseline coverage tracking.
- Added shared origin pacing and cancellable safe-method retries with bounded Retry-After.
- Added expiring exceptions with retained evidence and expiry/removal regressions in new-issue gates.
- Added SARIF 2.1.0 export with source anchors at actual target declarations.
- Integrated request/import/network/exception editors into the desktop and real POST/CORS demo.
- Updated local source beta metadata to 0.4.0b1 without publication.

### 0.3 beta workbench
- Added origin-scoped Bearer/session Cookie/API-key credentials, environment-only config references, optional authentication verification and literal credential redaction.
- Added portable TOML/JSON projects and a transactional SQLite store shared by CLI and desktop for history and accepted baselines.
- Added a desktop project workbench with URL import, per-target progress, cooperative cancellation, history selection, comparison filters, cached in-memory session credentials, and report export.
- Reused HTTP clients per worker, isolated Cookie jars per target/origin, bounded queued work, and drained only small known uncompressed bodies for connection reuse.
- Added authentication-context coverage guards and preserved completed scan results when history storage fails.
- Added `init`, `project`, `history`, `baseline`, and a real authenticated `demo` command, source launch helpers, bilingual documentation, issue templates and a three-platform CI matrix.
- Added a 5000-finding lazy Qt table regression and a reproducible client-reuse benchmark. One local 24-target/4-worker/3-round Windows run measured 7307.74 → 1379.49 ms and 24 → 4 connections with identical observations; this is a fixture-specific result.
- Updated source beta metadata to 0.3.0b1 without publishing a release.

### Added
- Bounded multi-target audits, normalized target lists, stable finding fingerprints, JSON baselines, and new/existing/resolved/regressed/unverified comparisons.
- Severity policy gates, `--only-new`, reliable 0/1/2 CLI exit codes, and clean JSON stdout.
- Explicit execution status, coverage metadata, final URL, redirect history, evidence, and recommendations in reports.
- Reportable standalone JWT inspection via CLI/API and desktop export.
- Desktop finding search, details panel, meaningful severity sorting, and running-worker close protection.
- Self-contained localhost regression demonstration, CI usage guide, and Chinese project analysis/roadmap.

### Fixed
- Derived severity/risk summaries stay consistent after offline analysis and appended JWT findings.
- HTML/Markdown target content is escaped; offline HTML has no external assets or scripts.
- HTTP response bodies are not downloaded; redirect scope and hop count are bounded.
- API content types skip document-only controls; HSTS is checked on HTTPS; HTTP uses a transport observation.
- OPTIONS errors and HTTP error pages cannot silently pass the gate; skipped/removed coverage cannot be reported as resolved.
- Advertised methods use exact tokens; cookie values are redacted, locations retain path case, and redirect cookies are analyzed.
- JWT object/claim types are validated before analysis, with more precise local-inspection language.

### Compatibility
- Risk/count fields are computed rather than writable. Network errors use explicit execution status and INFO diagnostics rather than CRITICAL vulnerability severity.
- Cross-origin redirects require opt-in. See `docs/limitations.md` for the full behavior changes.

### Verification
- Local suite now includes authenticated transport, connection reuse, session scope/cache, Qt worker lifecycle, SQLite restart/history/baseline, policy and report safety coverage; see README for the latest verified count.
- Wheel and source distribution build successfully; no package release has been published.

## [0.2.1] - 2026-09-07

### Changed
- Refactored the repository into a standard root-level `src`-layout Python package.
- Improved package metadata and corrected repository links.
- Reworked the README for developer and recruiter readability.
- Added package architecture documentation.
- Added real GUI and CLI demonstration assets from a controlled localhost scan.
- Improved project organization and removed obsolete development artifacts.

### Testing / CI
- Added GitHub Actions continuous integration.
- Verified the full suite with 26 automated tests passing.
- Verified PySide6 GUI tests in a headless environment.
- Verified wheel and source distribution builds.

### Security / Scope
- Kept scanner logic and the public API unchanged.
- Retained ShenSec's focus on defensive web security auditing.

## [0.2.0] - 2026-03-29
### Added
- Standardized package metadata for PyPI publishing (`pyproject.toml`).
- Public API exported in `shensec.api` and `shensec`.
- `CHANGELOG.md` and `LICENSE` files.
- `examples/` directory for developer reference.

### Changed
- Refactored `__init__.py` to expose public library functions directly.

## [0.1.0] - 2026-03-28
### Added
- Initial prototype creation using `uv` and modular src layout.
- CLI application using `Typer` (`shensec`).
- Basic Security Header scanning (`HSTS`, `CSP`, `X-Frame-Options`, `X-Content-Type-Options`, `Referrer-Policy`, `Permissions-Policy`).
- Core Cookie attribute analysis (`Secure`, `HttpOnly`, `SameSite`).
- Offline JWT structure and payload validation (`exp`, weak algorithms).
- Customizable reporting engines (`Markdown`, `JSON`, `HTML`).
- Risk rating model.
