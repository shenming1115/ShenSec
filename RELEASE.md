# Release verification

Run all commands from the repository root. A build does not publish a release.

## Before a release

- Run `uv sync --locked --extra gui`.
- Set `QT_QPA_PLATFORM=offscreen` for a headless environment and run `uv run pytest`.
- Review README examples and known limitations in `docs/limitations.md`.
- Verify that `pyproject.toml` and `src/shensec/__init__.py` agree on the version.
- Update `CHANGELOG.md` when preparing a new version; structural cleanup alone does not require a version bump.

## Build and inspect

```bash
uv build
uv run shensec --help
uv run python -c "import shensec; print(shensec.__version__)"
```

Inspect both the wheel and source archive in `dist/`. The wheel must contain the `shensec` package and `shensec/templates/report.html`, without backups, caches, or development scripts.

Install the wheel in a separate environment to verify installed-package behavior:

```bash
uv venv .venv-wheel
uv pip install --python .venv-wheel dist/shensec-0.2.0-py3-none-any.whl
```

Use `.venv-wheel/bin/python` on POSIX or `.venv-wheel/Scripts/python.exe` on Windows to import `shensec`, run `-m shensec --help`, and render a sample HTML report. Update the filename when releasing a different version. For a network smoke check, start a local example server and use `shensec scan http://127.0.0.1:8000`; do not rely on third-party availability.

## Publication

Publishing to PyPI, pushing tags, and publishing a GitHub release are separate maintainer decisions after verification. This cleanup does not perform any of those actions. Review metadata and release contents before authorizing a release at [the repository](https://github.com/shenming1115/ShenSec).
