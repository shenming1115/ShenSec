"""Lazy Qt table data: no per-cell widgets for large project scans."""

from dataclasses import dataclass

from PySide6.QtCore import QAbstractTableModel, QModelIndex, QSortFilterProxyModel, Qt
from PySide6.QtGui import QColor

from ..models import AuditResult, FindingRecord, SEVERITY_RANK


@dataclass
class FindingRow:
    change: str
    record: FindingRecord
    search: str = ""

    def __post_init__(self):
        finding = self.record.finding
        self.search = " ".join(value or "" for value in (
            self.change, self.record.target_url, finding.rule_id, finding.title,
            finding.description, finding.evidence, finding.recommendation, finding.location,
        )).casefold()


class FindingsModel(QAbstractTableModel):
    columns = ("Change", "Severity", "Target", "Rule", "Finding", "Recommended action")

    def __init__(self, parent=None):
        super().__init__(parent)
        self.rows: list[FindingRow] = []

    def set_audit(self, audit: AuditResult):
        self.beginResetModel()
        labels = {}
        if audit.comparison:
            for name in ("new", "existing", "regressed"):
                labels.update({record.fingerprint: (name.upper(), record) for record in getattr(audit.comparison, name)})
        self.rows = []
        for result in audit.results:
            for finding in result.findings:
                record = FindingRecord(target_url=result.target_url, finding=finding)
                default = "CURRENT" if result.status == "complete" else result.status.upper()
                change, record = labels.get(record.fingerprint, (default, record))
                if finding.suppression:
                    change = "ACCEPTED"
                self.rows.append(FindingRow(change, record))
        if audit.comparison:
            for name in ("resolved", "unverified"):
                self.rows.extend(FindingRow(name.upper(), record) for record in getattr(audit.comparison, name))
        self.endResetModel()

    def rowCount(self, parent=QModelIndex()):
        return 0 if parent.isValid() else len(self.rows)

    def columnCount(self, parent=QModelIndex()):
        return 0 if parent.isValid() else len(self.columns)

    def headerData(self, section, orientation, role=Qt.DisplayRole):
        if role == Qt.DisplayRole and orientation == Qt.Horizontal:
            return self.columns[section]
        return None

    def data(self, index, role=Qt.DisplayRole):
        if not index.isValid() or index.row() >= len(self.rows):
            return None
        row = self.rows[index.row()]
        finding = row.record.finding
        if role == Qt.DisplayRole:
            return (row.change, finding.severity.value, row.record.target_url, finding.rule_id, finding.title, finding.recommendation or "")[index.column()]
        if role == Qt.ToolTipRole:
            return finding.description
        if role == Qt.ForegroundRole and index.column() in (0, 1):
            if index.column() == 0:
                return QColor({"RESOLVED": "#7edac8", "EXISTING": "#a3adbc", "NEW": "#ffb56b", "REGRESSED": "#ff777f", "UNVERIFIED": "#e4cf79", "ERROR": "#ff777f"}.get(row.change, "#b9c6d8"))
            return QColor({"CRITICAL": "#ff777f", "HIGH": "#ffb56b", "MEDIUM": "#e4cf79", "LOW": "#76bfff", "INFO": "#7edac8"}[finding.severity.value])
        return None


class FindingsFilter(QSortFilterProxyModel):
    query = ""
    severity = "ALL"
    change = "ALL"

    def update_filters(self, query: str, severity: str, change: str):
        self.query, self.severity, self.change = query.casefold().strip(), severity, change
        self.invalidate()

    def filterAcceptsRow(self, source_row, source_parent):
        row = self.sourceModel().rows[source_row]
        return (
            self.query in row.search
            and (self.severity == "ALL" or row.record.finding.severity.value == self.severity)
            and (self.change == "ALL" or row.change == self.change or self.change == "ACTIONABLE" and row.change in {"NEW", "REGRESSED", "UNVERIFIED", "ERROR", "CANCELLED"})
        )

    def lessThan(self, left, right):
        if left.column() == 1:
            rows = self.sourceModel().rows
            return SEVERITY_RANK[rows[left.row()].record.finding.severity] < SEVERITY_RANK[rows[right.row()].record.finding.severity]
        return super().lessThan(left, right)
