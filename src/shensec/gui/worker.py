from PySide6.QtCore import QThread, Signal
from typing import Optional, List
from ..api import scan_target, analyze_jwt, ScanResult, Finding
from threading import Event
from ..audit import audit_project
import sqlite3

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


class AuditWorker(QThread):
    result_signal = Signal(object, str)
    progress_signal = Signal(int, int, object)
    error_signal = Signal(str)
    phase_signal = Signal(str, str)

    def __init__(self, config, auth, workspace, project_id, baseline=None, parent=None, role_auth=None, role_values=None):
        super().__init__(parent)
        self.config, self.auth, self.workspace = config, auth, workspace
        self.project_id, self.baseline = project_id, baseline
        self.cancel_event = Event()
        self.role_auth = role_auth if role_auth is not None else {}
        self.role_values = role_values or {}

    def cancel(self):
        self.cancel_event.set()

    def run(self):
        try:
            audit = audit_project(
                self.config, baseline=self.baseline, auth=self.auth,
                cancel_event=self.cancel_event, progress=self.progress_signal.emit,
                phase=self.phase_signal.emit, role_auth=self.role_auth, role_values=self.role_values,
            )
            try:
                run_id = self.workspace.save_run(self.project_id, self.config, audit)
            except (OSError, sqlite3.Error) as exc:
                self.result_signal.emit(audit, "")
                self.error_signal.emit(f"Scan completed, but history could not be saved ({type(exc).__name__}). Export the report to preserve it.")
                return
            self.result_signal.emit(audit, run_id)
        except Exception as exc:
            message = self.auth.redact(str(exc)) if self.auth else str(exc)
            self.error_signal.emit(message)
        finally:
            self.auth = None
            self.role_values = {}


class SessionWorker(QThread):
    result_signal = Signal(object)
    error_signal = Signal(str)
    phase_signal = Signal(str, str)

    def __init__(self, auth, config, parent=None):
        super().__init__(parent)
        self.auth, self.config = auth, config
        self.cancel_event = Event()

    def cancel(self):
        self.cancel_event.set()

    def run(self):
        from ..network import RequestPacer
        from ..sessions import prepare_auth
        try:
            prepare_auth(self.auth, self.config.timeout, RequestPacer(self.config.network), self.cancel_event, self.phase_signal.emit)
            if not self.cancel_event.is_set():
                self.result_signal.emit(self.auth)
        except Exception as exc:
            self.error_signal.emit(self.auth.redact(str(exc)))
        finally:
            self.auth = None

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
        finally:
            self.token = ""
