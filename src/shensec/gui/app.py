import sys
import os
from pathlib import Path
from PySide6.QtWidgets import QApplication
from PySide6.QtGui import QFont, QFontDatabase, QIcon
from .main_window import MainWindow

def run_gui(test_mode=False, workspace=None):
    """Entry point for the PySide6 Graphical User Interface."""
    app = QApplication.instance()
    if app is None:
        app = QApplication(sys.argv)
    app.setApplicationName("ShenSec")
    app.setOrganizationName("ShenSec")
    app.setWindowIcon(QIcon(str(Path(__file__).resolve().parents[1] / "resources" / "shensec.ico")))
    # Some headless Qt backends cannot enumerate Windows fonts. Load an installed
    # font explicitly; no proprietary font is copied into the package.
    if not QFontDatabase.families():
        candidates = [
            Path(os.environ.get("WINDIR", "C:/Windows")) / "Fonts" / "segoeui.ttf",
            Path("/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf"),
            Path("/System/Library/Fonts/Supplemental/Arial.ttf"),
        ]
        for path in candidates:
            if path.is_file():
                identifier = QFontDatabase.addApplicationFont(str(path))
                families = QFontDatabase.applicationFontFamilies(identifier)
                if families:
                    app.setFont(QFont(families[0], 10))
                    break
        
    try:
        import qdarktheme
        qdarktheme.setup_theme("dark", corner_shape="rounded")
    except ImportError:
        pass # Better to fallback than crash if not installed

    window = MainWindow(workspace=workspace)
    if not test_mode:
        window.show()
        sys.exit(app.exec())
    return app, window

if __name__ == "__main__":
    run_gui()
