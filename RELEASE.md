# Release verification

End users download an exe or portable ZIP from GitHub Releases. Only contributors need the tools below.

## Build on Windows x64

```powershell
uv sync --locked --extra gui --group build --python 3.13.3
$env:QT_QPA_PLATFORM = 'offscreen'
uv run --locked pytest -q
uv run --locked --group build python scripts/build_windows.py
```

Outputs in `dist/`: a windowed single-file `ShenSec-0.5.0b1-windows-x64.exe`, a faster-starting portable ZIP, and `SHA256SUMS.txt`. Both include Python, Qt, certificates, templates, icon, offline guide and license notices. Keep `_internal` beside the portable exe; its runtime DLLs are replaceable.

`packaging/ShenSec.spec` defines both bundles. `scripts/build_windows.py` assembles notices and the ZIP. `uv.lock` pins build dependencies. `scripts/create_icon.py` reproduces the icon. Do not ship production data, credentials, workspace databases, caches or system fonts.

## Verify the actual executables

Use an empty working directory outside the checkout, clear PYTHONPATH/PYTHONHOME and remove Python/uv from PATH. Run each exe with `--self-test OUTPUT`: require exit 0, `frozen: true`, eight passed permission observations, two history rows and four renewals in `result.json`. Inspect `desktop.png` and all four report formats. Verification uses real authenticated loopback HTTP and reopens SQLite history.

Also launch without arguments and check the workbench, **Try local demo**, **User guide**, history-folder action, project save/reopen and normal close. Closing during demo preparation must cleanly stop its worker. Repeat packaged checks after changes to bundled code/resources.

Confirm version metadata matches pyproject.toml and shensec.__version__. Review both READMEs, the [Windows tutorial](docs/windows-guide.zh-CN.md), [screenshots](docs/screenshots.md) and [limitations](docs/limitations.md). Do not claim unmeasured speedups or a signed binary.

## GitHub publication

The `Windows executable` workflow supports manual dispatch for downloadable Actions artifacts. A new `v*` tag runs tests, builds both bundles, verifies them outside the source tree, uploads evidence, and creates a **prerelease** with exe, ZIP and checksums. It refuses to overwrite existing releases. Review `docs/releases/TAG.md` before tagging; otherwise GitHub generates notes.

Verify the target commit includes intended source/docs/resources and excludes runtime data, secrets, virtual environments and caches. Push source and tag only with user authorization. After pushing, inspect remote tests/build and confirm the release assets and SHA-256 values.

This beta has no code-signing certificate. Disclose this on the download page. Signing requires a publisher-controlled certificate; do not change Windows trust settings during installation.

## Python distribution

```powershell
uv build
uv run --locked shensec --help
```

Install the wheel in a separate environment and run `python -m shensec demo --identities` outside the checkout. Verify scanner/auth/session/access/workbench modules, templates and desktop resources. Building a wheel does not publish to PyPI.

Build references: [PyInstaller usage](https://pyinstaller.org/en/stable/usage.html), [spec files](https://pyinstaller.org/en/stable/spec-files.html), [resource paths](https://pyinstaller.org/en/stable/runtime-information.html).