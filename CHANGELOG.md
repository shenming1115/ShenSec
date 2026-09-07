# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]
### Changed
- Flattened the Python project into the repository root.
- Corrected author and repository metadata; retained version 0.2.0.
- Reworked documentation around implemented behavior and known limitations.
- Removed unused development artifacts and added automated verification.

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
