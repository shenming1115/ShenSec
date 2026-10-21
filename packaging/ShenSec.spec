# Build on Windows x64 with: uv run --group build python scripts/build_windows.py
from pathlib import Path
import tomllib
from PyInstaller.utils.hooks import collect_data_files, copy_metadata
from PyInstaller.utils.win32.versioninfo import (
    VSVersionInfo, FixedFileInfo, StringFileInfo, StringTable, StringStruct,
    VarFileInfo, VarStruct,
)
import PySide6

root = Path(SPECPATH).parent
version = tomllib.loads((root / "pyproject.toml").read_text(encoding="utf-8"))["project"]["version"]
datas = collect_data_files("shensec") + collect_data_files("qdarktheme")
for package in ("httpx", "httpcore", "certifi", "jinja2", "pydantic", "PySide6", "shiboken6", "pyqtdarktheme"):
    datas += copy_metadata(package)
datas += [(str(root / "LICENSE"), "licenses"), (str(root / "build" / "THIRD_PARTY_NOTICES.txt"), "licenses")]

a = Analysis(
    [str(root / "packaging" / "windows_entry.py")],
    pathex=[str(root / "src")], binaries=[], datas=datas,
    hiddenimports=["PySide6.QtSvg"], hookspath=[], runtime_hooks=[],
    excludes=["pytest", "tkinter", "PySide6.QtWebEngineCore", "PySide6.QtWebEngineWidgets", "PySide6.QtQml", "PySide6.QtQuick"],
    noarchive=False,
)
# Python 3.13.3 ships VC runtime 14.42, while Qt 6.11 needs 14.44.
# Keep Qt's newer compatible runtime at the bundle root; otherwise the Python
# bootloader loads the older copy first and QtWidgets fails with WinError 127.
for runtime in Path(PySide6.__file__).parent.glob("vcruntime140*.dll"):
    a.binaries = [entry for entry in a.binaries if Path(entry[0]).name.casefold() != runtime.name.casefold()]
    a.binaries.append((runtime.name, str(runtime), "BINARY"))
# Qt uses the operating system's ICU API, not an unrelated ICU from PATH.
# Never redistribute the host's Windows system DLL or a foreign substitute.
a.binaries = [entry for entry in a.binaries if Path(entry[0]).name.casefold() not in {"icuuc.dll", "icuin.dll"} and not Path(entry[0]).name.casefold().startswith("icudt")]
pyz = PYZ(a.pure)
info = VSVersionInfo(
    ffi=FixedFileInfo(filevers=(0, 5, 0, 1), prodvers=(0, 5, 0, 1), mask=0x3f, flags=0x2, OS=0x40004, fileType=1, subtype=0, date=(0, 0)),
    kids=[StringFileInfo([StringTable("040904B0", [
        StringStruct("CompanyName", "ShenSec contributors"),
        StringStruct("FileDescription", "ShenSec security regression workbench"),
        StringStruct("FileVersion", version), StringStruct("ProductVersion", version),
        StringStruct("ProductName", "ShenSec"), StringStruct("OriginalFilename", "ShenSec.exe"),
        StringStruct("LegalCopyright", "MIT · ShenSec contributors"),
    ])]), VarFileInfo([VarStruct("Translation", [1033, 1200])])],
)
options = dict(debug=False, strip=False, upx=False, console=False,
               disable_windowed_traceback=True, icon=str(root / "src/shensec/resources/shensec.ico"), version=info)
portable = EXE(pyz, a.scripts, [], exclude_binaries=True, name="ShenSec", **options)
COLLECT(portable, a.binaries, a.datas, strip=False, upx=False, name="ShenSec")
EXE(pyz, a.scripts, a.binaries, a.datas, [], name=f"ShenSec-{version}-windows-x64", **options)
