from PySide6.QtCore import QThread, Signal
from typing import Optional, List
from ..api import scan_target, analyze_jwt, ScanResult, Finding

class ScanWorker(QThread):
    finished_signal = Signal(object)  # Emits ScanResult or Exception
    error_signal = Signal(str)

    def __init__(self, target_url: str, timeout: float = 10.0, parent=None):
        super().__init__(parent)
        self.target_url = target_url
        self.timeout = timeout

    def run(self):
        try:
            result = scan_target(self.target_url, timeout=self.timeout)
            self.finished_signal.emit(result)
        except Exception as e:
            self.error_signal.emit(str(e))

class JwtWorker(QThread):
    finished_signal = Signal(list)  # Emits List[Finding]
    error_signal = Signal(str)

    def __init__(self, token: str, parent=None):
        super().__init__(parent)
        self.token = token

    def run(self):
        try:
            findings = analyze_jwt(self.token)
            self.finished_signal.emit(findings)
        except Exception as e:
            self.error_signal.emit(str(e))
