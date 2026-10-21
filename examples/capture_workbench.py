"""Render the real Qt workbench with real authenticated localhost scan results.

Use QT_QPA_PLATFORM=offscreen for a headless documentation screenshot.
"""

import argparse
from pathlib import Path
from tempfile import TemporaryDirectory

from shensec.demo import demo_workspace


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=Path("docs/workbench.png"))
    parser.add_argument("--configure", action="store_true", help="Show the API request editor.")
    parser.add_argument("--identities", action="store_true", help="Capture the login and role comparison demo.")
    parser.add_argument("--view", choices=["findings", "permissions", "sessions", "login"])
    parser.add_argument("--before", action="store_true", help="Select the pre-fix run.")
    args = parser.parse_args()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with TemporaryDirectory(prefix=".preview-", dir=args.output.parent) as root:
        if args.identities:
            from shensec.identity_demo import demo_workspace as create_demo
        else:
            create_demo = demo_workspace
        with create_demo(root) as (workspace, project_id, baseline, current):
            from shensec.gui.app import run_gui
            from PySide6.QtCore import Qt
            app, window = run_gui(test_mode=True, workspace=workspace)
            window.workbench.change_filter.setCurrentText("ALL")
            if args.before:
                window.workbench.history.setCurrentRow(1)
            if args.configure:
                window.workbench.configure_button.setChecked(True)
                window.workbench.settings.setCurrentWidget(window.workbench.request_editor)
            views = {"findings": window.workbench.findings, "permissions": window.workbench.access_results, "sessions": window.workbench.session_results}
            if args.view in views:
                window.workbench.result_tabs.setCurrentWidget(views[args.view])
            elif args.view == "login":
                window.workbench.configure_button.setChecked(True)
                window.workbench.settings.setCurrentWidget(window.workbench.login_editor)
            window.show()
            app.processEvents()
            if window.workbench.proxy.rowCount():
                window.workbench.findings.selectRow(0)
            if args.view == "permissions":
                table = window.workbench.access_results
                chosen = None
                for row in range(table.rowCount()):
                    for column in range(1, table.columnCount()):
                        observation = table.item(row, column).data(Qt.UserRole)
                        if chosen is None or observation.outcome == 'failed':
                            chosen = (row, column)
                        if observation.outcome == 'failed':
                            break
                    if chosen and table.item(*chosen).data(Qt.UserRole).outcome == 'failed':
                        break
                if chosen:
                    table.setCurrentCell(*chosen)
                    window.workbench.show_access_detail(*chosen)
            app.processEvents()
            assert window.grab().save(str(args.output.resolve()))
            window.close()
            app.processEvents()
    print(args.output.resolve())


if __name__ == "__main__":
    main()
