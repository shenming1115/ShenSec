"""Indexed local projects/history. SQLite transactions keep saves atomic."""

from contextlib import contextmanager
import json
import os
from pathlib import Path
import sqlite3
from uuid import uuid4

from .models import AuditResult
from .project import ProjectConfig


class Workspace:
    def __init__(self, root: str | Path | None = None):
        self.root = Path(root or os.environ.get("SHENSEC_HOME", Path.home() / ".shensec"))
        self.path = self.root / "workspace.sqlite3"

    @contextmanager
    def _connect(self):
        self.root.mkdir(parents=True, exist_ok=True, mode=0o700)
        connection = sqlite3.connect(self.path, timeout=10)
        connection.row_factory = sqlite3.Row
        try:
            connection.executescript("""
                PRAGMA foreign_keys=ON;
                CREATE TABLE IF NOT EXISTS projects (
                    id TEXT PRIMARY KEY, name TEXT NOT NULL, config TEXT NOT NULL,
                    baseline_id TEXT, updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
                );
                CREATE TABLE IF NOT EXISTS runs (
                    id TEXT PRIMARY KEY, project_id TEXT NOT NULL REFERENCES projects(id),
                    created_at TEXT NOT NULL, target_count INTEGER NOT NULL,
                    outcome TEXT NOT NULL, findings INTEGER NOT NULL, duration_ms REAL NOT NULL,
                    config TEXT NOT NULL, audit TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS runs_by_project ON runs(project_id, created_at DESC);
            """)
            with connection:
                yield connection
        finally:
            connection.close()

    def list_projects(self) -> list[dict]:
        if not self.path.exists():
            return []
        with self._connect() as db:
            return [dict(row) for row in db.execute("SELECT id,name,baseline_id,updated_at FROM projects ORDER BY updated_at DESC")]

    def save_project(self, config: ProjectConfig, project_id: str | None = None) -> str:
        project_id = project_id or uuid4().hex
        with self._connect() as db:
            db.execute("""INSERT INTO projects(id,name,config) VALUES(?,?,?)
                ON CONFLICT(id) DO UPDATE SET name=excluded.name,config=excluded.config,
                updated_at=strftime('%Y-%m-%dT%H:%M:%fZ','now')""", (project_id, config.name, config.model_dump_json()))
        return project_id

    def load_project(self, project_id: str) -> ProjectConfig:
        if not self.path.exists():
            raise ValueError("Project not found.")
        with self._connect() as db:
            row = db.execute("SELECT config FROM projects WHERE id=?", (project_id,)).fetchone()
        if row is None:
            raise ValueError("Project not found.")
        return ProjectConfig.model_validate_json(row["config"])

    def save_run(self, project_id: str, config: ProjectConfig, audit: AuditResult) -> str:
        run_id = uuid4().hex
        with self._connect() as db:
            db.execute("INSERT INTO runs(id,project_id,created_at,target_count,outcome,findings,duration_ms,config,audit) VALUES(?,?,?,?,?,?,?,?,?)", (
                run_id, project_id, audit.created_at.isoformat(), len(audit.results),
                audit.gate.outcome if audit.gate else "not evaluated",
                sum(len(result.findings) for result in audit.results), audit.duration_ms,
                config.model_dump_json(), audit.model_dump_json(),
            ))
        return run_id

    def list_runs(self, project_id: str, limit: int = 200) -> list[dict]:
        if not self.path.exists():
            return []
        with self._connect() as db:
            return [dict(row) for row in db.execute(
                "SELECT id,created_at,target_count,outcome,findings,duration_ms FROM runs WHERE project_id=? ORDER BY created_at DESC,id DESC LIMIT ?",
                (project_id, max(1, min(limit, 1000))),
            )]

    def load_run(self, project_id: str, run_id: str) -> AuditResult:
        if not self.path.exists():
            raise ValueError("History entry not found.")
        with self._connect() as db:
            row = db.execute("SELECT audit FROM runs WHERE id=? AND project_id=?", (run_id, project_id)).fetchone()
        if row is None:
            raise ValueError("History entry not found in this project.")
        return AuditResult.model_validate_json(row["audit"])

    def baseline(self, project_id: str) -> AuditResult | None:
        if not self.path.exists():
            return None
        with self._connect() as db:
            row = db.execute("SELECT baseline_id FROM projects WHERE id=?", (project_id,)).fetchone()
        return self.load_run(project_id, row["baseline_id"]) if row and row["baseline_id"] else None

    def set_baseline(self, project_id: str, run_id: str) -> None:
        audit = self.load_run(project_id, run_id)
        if audit.failed_targets or audit.cancelled:
            raise ValueError("A baseline requires a complete, non-cancelled audit.")
        with self._connect() as db:
            db.execute("UPDATE projects SET baseline_id=? WHERE id=?", (run_id, project_id))
