"""Compact request and exception editors shared by project import and save."""

from PySide6.QtWidgets import (
    QAbstractItemView, QComboBox, QHBoxLayout, QHeaderView, QLabel, QPushButton,
    QPlainTextEdit, QTableWidget, QTableWidgetItem, QVBoxLayout, QWidget,
)

from ..policy import RuleException
from ..requests import RequestSpec


class PlanEditor(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        layout = QVBoxLayout(self)
        layout.addWidget(QLabel("URL targets use GET unless overridden here. Body values come from environment variables."))
        self.table = QTableWidget(0, 5)
        self.table.setHorizontalHeaderLabels(["Method", "URL", "Body variable", "Content type", "Expected statuses"])
        self.table.horizontalHeader().setSectionResizeMode(1, QHeaderView.Stretch)
        for column, width in ((0, 95), (2, 170), (3, 155), (4, 145)):
            self.table.setColumnWidth(column, width)
        self.table.setSelectionBehavior(QAbstractItemView.SelectRows)
        layout.addWidget(self.table)
        controls = QHBoxLayout()
        self.add_button = QPushButton("+ Request")
        self.import_button = QPushButton("Import OpenAPI JSON…")
        self.remove_button = QPushButton("Remove selected")
        self.remove_button.clicked.connect(self.remove_selected)
        for widget in (self.add_button, self.import_button, self.remove_button):
            controls.addWidget(widget)
        controls.addStretch()
        layout.addLayout(controls)
        self.message = QPlainTextEdit()
        self.message.setReadOnly(True)
        self.message.setMaximumHeight(65)
        self.message.hide()
        layout.addWidget(self.message)

    def add(self, plan: RequestSpec):
        row = self.table.rowCount()
        self.table.insertRow(row)
        method = QComboBox()
        method.addItems(["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE"])
        method.setCurrentText(plan.method)
        self.table.setCellWidget(row, 0, method)
        for col, value in enumerate((plan.url, plan.body_env or "", plan.content_type, ','.join(map(str, plan.expected_status))), 1):
            item = QTableWidgetItem(value)
            item.setToolTip(value)
            self.table.setItem(row, col, item)

    def set_plans(self, plans):
        self.table.setRowCount(0)
        for plan in plans:
            self.add(plan)
        self.message.clear()
        self.message.hide()

    def plans(self):
        plans = []
        for row in range(self.table.rowCount()):
            values = [self.table.item(row, col).text().strip() for col in range(1, 5)]
            try:
                statuses = [int(value.strip()) for value in values[3].split(',') if value.strip()]
            except ValueError:
                raise ValueError("Expected statuses use comma-separated HTTP codes, e.g. 200,201.") from None
            plans.append(RequestSpec(url=values[0], method=self.table.cellWidget(row, 0).currentText(), body_env=values[1] or None, content_type=values[2], expected_status=statuses))
        return plans

    def remove_selected(self):
        for row in sorted({index.row() for index in self.table.selectedIndexes()}, reverse=True):
            self.table.removeRow(row)


class ExceptionEditor(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        layout = QVBoxLayout(self)
        layout.addWidget(QLabel("Exceptions keep findings visible. A reason and expiry date are required; execution errors cannot be waived."))
        self.table = QTableWidget(0, 4)
        self.table.setHorizontalHeaderLabels(["Rule", "Target URL / glob", "Reason", "Expires YYYY-MM-DD"])
        self.table.setColumnWidth(1, 260)
        self.table.setColumnWidth(2, 300)
        self.table.setSelectionBehavior(QAbstractItemView.SelectRows)
        layout.addWidget(self.table)
        self.remove_button = QPushButton("Remove selected exception")
        self.remove_button.clicked.connect(self.remove_selected)
        layout.addWidget(self.remove_button)

    def add(self, exception: RuleException):
        row = self.table.rowCount()
        self.table.insertRow(row)
        for col, value in enumerate((exception.rule_id, exception.target, exception.reason, exception.expires.isoformat())):
            self.table.setItem(row, col, QTableWidgetItem(value))

    def set_exceptions(self, exceptions):
        self.table.setRowCount(0)
        for exception in exceptions:
            self.add(exception)

    def exceptions(self):
        return [RuleException(**dict(zip(("rule_id", "target", "reason", "expires"), [self.table.item(row, col).text().strip() for col in range(4)]))) for row in range(self.table.rowCount())]

    def remove_selected(self):
        for row in sorted({index.row() for index in self.table.selectedIndexes()}, reverse=True):
            self.table.removeRow(row)
