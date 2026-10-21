"""Keep the isolated local demo alive without blocking the desktop event loop."""

from tempfile import TemporaryDirectory
from threading import Event

from PySide6.QtCore import QThread, Signal

from ..identity_demo import demo_workspace


class DemoWorker(QThread):
    ready = Signal(object)
    error = Signal(str)

    def __init__(self, parent=None):
        super().__init__(parent)
        self._stop = Event()

    def stop(self):
        self._stop.set()

    def run(self):
        try:
            with TemporaryDirectory(prefix="shensec-demo-") as root:
                with demo_workspace(root) as result:
                    if not self._stop.is_set():
                        self.ready.emit(result)
                    self._stop.wait()
        except Exception:
            # The demo has no production inputs; avoid spilling environment values.
            self.error.emit("The local demo could not start. Check that loopback connections are allowed, then try again.")
