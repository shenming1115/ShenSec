# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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
