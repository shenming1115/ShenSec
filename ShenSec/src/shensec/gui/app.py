import sys
from PySide6.QtWidgets import QApplication
from .main_window import MainWindow

def run_gui(test_mode=False):
    """Entry point for the PySide6 Graphical User Interface."""
    app = QApplication.instance()
    if app is None:
        app = QApplication(sys.argv)
        
    try:
        import qdarktheme
        qdarktheme.setup_theme("dark", corner_shape="rounded")
    except ImportError:
        pass # Better to fallback than crash if not installed

    window = MainWindow()
    if not test_mode:
        window.show()
        sys.exit(app.exec())
    return app, window

if __name__ == "__main__":
    run_gui()