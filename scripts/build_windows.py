"""Reproducible release assembly; end users only need the generated exe or ZIP."""

import hashlib
import os
from importlib.metadata import distribution
from pathlib import Path
import platform
import shutil
import subprocess
import sys
import tomllib
import zipfile

ROOT = Path(__file__).resolve().parents[1]
PACKAGES = ["httpx", "httpcore", "certifi", "anyio", "idna", "h11", "jinja2", "markupsafe",
            "pydantic", "pydantic-core", "annotated-types", "typing-extensions", "typing-inspection",
            "PySide6", "PySide6-Essentials", "PySide6-Addons", "shiboken6", "pyqtdarktheme", "darkdetect", "pyinstaller"]


def notices():
    text = ["ShenSec third-party notices", "ShenSec: MIT; source https://github.com/shenming1115/ShenSec", "",
            "Python runtime: https://www.python.org/psf/license/ (license included below).",
            "Qt / PySide6: https://www.qt.io/licensing/; https://code.qt.io/; https://download.qt.io/official_releases/QtForPython/",
            "Qt libraries are dynamically linked. The portable bundle allows replacing the DLLs in _internal.",
            "Build scripts and pinned dependencies are in the ShenSec source release. No restriction on debugging library modifications.", ""]
    for package in PACKAGES:
        dist = distribution(package)
        text.extend(["=" * 72, f"{dist.metadata['Name']} {dist.version}", dist.metadata.get("License-Expression") or dist.metadata.get("License", "See license text below")])
        for file in dist.files or []:
            if any(part.lower() in ("licenses", "license", "copying") for part in file.parts) or file.name.lower().startswith(("license", "copying", "notice")):
                path = dist.locate_file(file)
                if path.is_file() and path.suffix.lower() not in (".py", ".pyc", ".dll", ".pyd"):
                    text.extend([f"--- {file} ---", path.read_text(encoding="utf-8", errors="replace")])
    python_license = Path(sys.base_prefix) / "LICENSE.txt"
    if not python_license.is_file():
        python_license = Path(sys.base_prefix) / "LICENSE"
    if not python_license.is_file():
        raise RuntimeError("Python runtime license is missing")
    text.extend(["=" * 72, "Python runtime", python_license.read_text(encoding="utf-8")])
    return "\n".join(text)


def main():
    if sys.platform != "win32" or platform.machine().lower() not in ("amd64", "x86_64"):
        raise SystemExit("Build the Windows x64 release on a Windows x64 host.")
    version = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))["project"]["version"]
    (ROOT / "build").mkdir(exist_ok=True)
    license_text = notices()
    (ROOT / "build/THIRD_PARTY_NOTICES.txt").write_text(license_text, encoding="utf-8")
    build_environment = os.environ.copy()
    # Do not collect unrelated DLLs from tools on the developer's PATH (for
    # example Poppler's ICU has different exports from Windows' ICU shim).
    windows = Path(os.environ.get("SystemRoot", "C:/Windows"))
    build_environment["PATH"] = os.pathsep.join([str(windows / "System32"), str(windows)])
    build_environment.pop("PYTHONHOME", None)
    build_environment.pop("PYTHONPATH", None)
    subprocess.run([sys.executable, "-m", "PyInstaller", "--noconfirm", str(ROOT / "packaging/ShenSec.spec")], cwd=ROOT, env=build_environment, check=True)
    portable = ROOT / "dist/ShenSec"
    shutil.copy2(ROOT / "LICENSE", portable)
    (portable / "THIRD_PARTY_NOTICES.txt").write_text(license_text, encoding="utf-8")
    shutil.copy2(ROOT / "src/shensec/resources/desktop-guide.html", portable / "START-HERE.html")
    (portable / "READ-ME.txt").write_text("ShenSec " + version + "\n\nExtract this entire ZIP, then double-click ShenSec.exe. Keep _internal next to the exe.\nNo Python, uv, terminal, or administrator rights are required.\n\nClick Try local demo to explore safely. Click User guide for offline instructions.\nHistory: %USERPROFILE%\\.shensec\\workspace.sqlite3\nThis beta is unsigned.\n\nSource, license, issues: https://github.com/shenming1115/ShenSec\n", encoding="utf-8")
    archive = ROOT / "dist" / f"ShenSec-{version}-windows-x64-portable.zip"
    with zipfile.ZipFile(archive, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=6) as bundle:
        for path in sorted(portable.rglob("*")):
            if path.is_file():
                bundle.write(path, Path("ShenSec") / path.relative_to(portable))
    artifacts = [ROOT / "dist" / f"ShenSec-{version}-windows-x64.exe", archive]
    checksum = ROOT / "dist/SHA256SUMS.txt"
    checksum.write_text("".join(f"{hashlib.file_digest(path.open('rb'), 'sha256').hexdigest()}  {path.name}\n" for path in artifacts), encoding="utf-8")
    for path in artifacts + [checksum]:
        print(f"{path.name}: {path.stat().st_size:,} bytes")


if __name__ == "__main__":
    main()
