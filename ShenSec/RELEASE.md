# ShenSec Release Guidelines

This document outlines the standard procedure for releasing a new version of ShenSec. Following these steps ensures version consistency, comprehensive documentation, and successful package distribution.

## 1. Pre-Release Checklist
Before initiating the build and release, ensure the following checks are complete:
- [ ] All tests pass locally (`uv run pytest tests/`).
- [ ] New features or adjustments are documented in the `README.md`.
- [ ] Any required updates to dependencies are correct in `pyproject.toml` or `uv.lock`.
- [ ] The version number has been bumped correctly according to Semantic Versioning (Major.Minor.Patch) in:
  - `pyproject.toml` (under `[project] version`)
  - `src/shensec/__init__.py` (`__version__` string)
- [ ] The `CHANGELOG.md` is updated with a new section detailing all additions, fixes, and changes for the upcoming version.

## 2. Build the Package
ShenSec uses Hatchling via `uv` for building the Python wheel and sdist files.

1. Remove any legacy builds (optional but recommended):
   ```bash
   # In bash/zsh
   rm -rf dist/
   # In PowerShell
   Remove-Item -Recurse -Force dist/
   ```

2. Build fresh artifacts using `uv`:
   ```bash
   uv build
   ```

3. Verify the contents of the `dist/` directory:
   You should see both a `.tar.gz` and a `.whl` file, e.g.:
   - `shensec-0.2.0.tar.gz`
   - `shensec-0.2.0-py3-none-any.whl`

## 3. Verify the Built Package
Before uploading, it is highly recommended to do a test installation in a clean environment.

```bash
# Create a temporary virtual environment
python -m venv test-env
# Activate it (Windows)
.\test-env\Scripts\activate
# Activate it (Unix)
source test-env/bin/activate

# Install the built wheel
pip install dist/shensec-X.Y.Z-py3-none-any.whl[gui]

# Test the core cli commands
shensec --help
shensec https://example.com
shensec gui

# Deactivate and clean up
deactivate
rm -rf test-env/
```

## 4. Tag the Release
Commit all your version bumps and changelog updates. Push them to the remote repository. Create an official Git tag:

```bash
git add .
git commit -m "chore: release version v0.2.0"
git tag -a v0.2.0 -m "Release v0.2.0"
git push origin main --tags
```

## 5. Publish to PyPI
If you plan to officially publish this package through PyPI:

1. Install `twine` if you haven't already:
   ```bash
   pip install twine
   ```

2. Upload the archives in `dist/`:
   ```bash
   twine upload dist/*
   ```
   *You'll be prompted for your PyPI token/credentials.*

## 6. Create a GitHub Release
Go to the project's GitHub repository, navigate to **Releases > Draft a new release**:
- Select the `vX.Y.Z` tag you just pushed.
- Re-use the notes from `CHANGELOG.md` for this version.
- Upload the `.whl` and `.tar.gz` files from your `dist/` directory as assets.
- Publish release.
