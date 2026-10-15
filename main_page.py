"""Qt desktop interface for Secure Endpoint Health Checker."""

from functools import partial
import logging
import sys
import time
import webbrowser

from PySide6.QtCore import QTimer
from PySide6.QtWidgets import (
    QComboBox, QGridLayout, QGroupBox, QHBoxLayout, QMainWindow,
    QMessageBox, QProgressBar, QScrollArea, QVBoxLayout, QWidget,
)

import popups
from gui import TaskRunner, application, button, fit_window, set_badge, text_label


STATUS_FIELDS = (
    ("SE version", "version"), ("CPU usage", "cpu"), ("Connector debug", "debug"),
    ("SE uptime", "uptime"), ("Isolation", "isolation"),
    ("Unlock code", "unlock"), ("Connector UUID", "uuid"), ("API credentials", "api"),
)
ACTIONS = (
    ("Live paths / processes", "live"), ("Run analysis", "analysis"),
    ("Live top processes", "processes"), ("Manual SFC analysis", "manual"),
    ("Connectivity test", "connectivity"), ("Engine status", "engines"),
    ("Generate diagnostic", "diagnostic"), ("View exclusions", "exclusions"),
    ("Recommend exclusions", "recommendations"),
)


def create_data():
    """Import Windows services only when starting the real connector backend."""
    if sys.platform != "win32":
        raise RuntimeError("Connector diagnostics require Windows with Secure Endpoint installed.")
    from data import Data
    return Data()


def set_tool_log_level(name):
    """Change the Health Checker logger independently of connector debug settings."""
    levels = {"INFO": logging.INFO, "WARNING": logging.WARNING, "DEBUG": logging.DEBUG}
    if name not in levels:
        raise ValueError("Unsupported tool log level")
    logging.getLogger().setLevel(levels[name])
    logging.log(levels[name], "Health Checker log level changed to %s", name)


def tone_for_color(color):
    """Translate existing backend status colors into accessible Qt status badges."""
    return {"green": "good", "yellow": "warning", "red": "bad"}.get(str(color).lower(), "neutral")


class MainWindow(QMainWindow):
    """Keep the dashboard responsive while serializing all connector operations."""

    def __init__(self, data_factory=create_data):
        """Build the complete interface before loading connector data in the background."""
        super().__init__()
        self.data_factory, self.data = data_factory, None
        self.runner = TaskRunner(self)
        self.closing, self.can_close = False, False
        self.active_dialog = None
        self.theme = application().theme
        self.last_api_refresh = time.monotonic()
        self.setWindowTitle("Secure Endpoint Health Checker")
        self.fields = {}
        self.build_dashboard()
        self.runner.busy_changed.connect(self.set_busy)
        self.timer = QTimer(self)
        self.timer.setInterval(5000)
        self.timer.timeout.connect(self.poll)
        self.timer.start()
        fit_window(self, 1120, 760)
        self.set_busy(False)
        QTimer.singleShot(0, self.initialize)

    def build_dashboard(self):
        """Arrange status cards and actions in shared columns with a fixed footer."""
        root = QWidget()
        root.setObjectName("dashboard")
        layout = QVBoxLayout(root)
        layout.setContentsMargins(24, 20, 24, 16)
        layout.setSpacing(16)
        header = QHBoxLayout()
        header.addWidget(text_label("Secure Endpoint", "heading"), 1)
        self.theme_button = button("", self.toggle_theme)
        self.theme_button.setCheckable(True)
        self.theme_button.setAccessibleName("Dark mode")
        self.theme.changed.connect(self.update_theme_button)
        self.update_theme_button(self.theme.current)
        header.addWidget(self.theme_button)
        layout.addLayout(header)
        layout.addWidget(text_label("Health Checker · Connector health, live activity, and diagnostics", "muted"))
        content = QWidget()
        grid = QGridLayout(content)
        grid.setContentsMargins(0, 0, 0, 0)
        grid.setSpacing(18)
        self.content_grid = grid
        self.left_panel = QWidget()
        left = QVBoxLayout(self.left_panel)
        left.setContentsMargins(0, 0, 0, 0)
        left.setSpacing(16)
        left.addWidget(self.connector_card())
        left.addWidget(self.versions_card())
        left.addStretch()
        grid.addWidget(self.left_panel, 0, 0)
        grid.addWidget(self.actions_card(), 0, 1)
        grid.setColumnStretch(0, 3)
        grid.setColumnStretch(1, 2)
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setWidget(content)
        layout.addWidget(scroll, 1)
        layout.addLayout(self.footer_layout())
        self.setCentralWidget(root)
        self.progress = QProgressBar()
        self.progress.setRange(0, 0)
        self.progress.setMaximumWidth(130)
        self.progress.setMaximumHeight(12)
        self.statusBar().addPermanentWidget(self.progress)
        self.statusBar().showMessage("Loading connector…")

    def toggle_theme(self):
        """Switch and save the application appearance without interrupting connector work."""
        self.theme.select("light" if self.theme.current == "dark" else "dark")

    def update_theme_button(self, name):
        """Expose the current mode and next action through text, check state, and a tooltip."""
        dark = name == "dark"
        self.theme_button.setChecked(dark)
        self.theme_button.setText("Dark mode: On" if dark else "Dark mode: Off")
        self.theme_button.setToolTip(f"Switch to {'light' if dark else 'dark'} mode. Your choice is saved.")

    def resizeEvent(self, event):
        """Stack dashboard cards on narrow windows instead of introducing horizontal clipping."""
        super().resizeEvent(event)
        if not hasattr(self, "content_grid"):
            return
        self.reflow_footer()
        stacked = self.width() < 950
        if stacked == getattr(self, "stacked", None):
            return
        self.stacked = stacked
        self.content_grid.removeWidget(self.actions)
        self.content_grid.addWidget(self.actions, 1 if stacked else 0, 0 if stacked else 1)
        self.content_grid.setColumnStretch(1, 0 if stacked else 2)

    def reflow_footer(self):
        """Wrap utility controls onto a second row on smaller or scaled desktops."""
        narrow = self.width() < 760
        if narrow == getattr(self, "footer_narrow", None):
            return
        self.footer_narrow = narrow
        self.footer_grid.removeWidget(self.utility_controls)
        self.footer_grid.addWidget(self.utility_controls, 1 if narrow else 0, 0 if narrow else 1)

    def connector_card(self):
        """Align connector labels and long values using one grid rather than text padding."""
        group = QGroupBox("Connector health")
        grid = QGridLayout(group)
        grid.setVerticalSpacing(12)
        grid.setColumnMinimumWidth(0, 130)
        grid.setColumnStretch(1, 1)
        for row, (title, key) in enumerate(STATUS_FIELDS):
            grid.addWidget(text_label(title, "muted"), row, 0)
            value = text_label("Loading…" if key == "version" else "—")
            grid.addWidget(value, row, 1)
            self.fields[key] = value
        self.setup_notice = text_label()
        self.setup_notice.hide()
        grid.addWidget(self.setup_notice, len(STATUS_FIELDS), 0, 1, 2)
        return group

    def versions_card(self):
        """Place installed versions, cloud results, and check buttons on matching rows."""
        group = QGroupBox("Definitions and policy")
        grid = QGridLayout(group)
        grid.setColumnStretch(1, 1)
        grid.setColumnMinimumWidth(0, 105)
        self.check_buttons = {}
        for index, (name, key) in enumerate((("TETRA", "tetra"), ("Policy serial", "policy"))):
            row = index * 2
            value, result = text_label("—"), text_label("Cloud version has not been checked.", "muted")
            self.fields[key], self.fields[key + "_result"] = value, result
            check = button("Check version", partial(self.check_version, key))
            check.setToolTip(f"Compare the installed {name} version with the cloud.")
            self.check_buttons[key] = check
            grid.addWidget(text_label(name, "muted"), row, 0)
            grid.addWidget(value, row, 1)
            grid.addWidget(check, row, 2)
            grid.addWidget(result, row + 1, 0, 1, 3)
        grid.setVerticalSpacing(12)
        return group

    def actions_card(self):
        """Use equal-width action columns and a clear description beneath the tools."""
        self.actions = QGroupBox("Tools")
        layout = QVBoxLayout(self.actions)
        grid = QGridLayout()
        grid.setHorizontalSpacing(10)
        grid.setVerticalSpacing(12)
        self.action_buttons = {}
        for index, (title, key) in enumerate(ACTIONS):
            action = button(title, partial(self.handle_action, key))
            self.action_buttons[key] = action
            grid.addWidget(action, index // 2, index % 2)
        grid.setColumnStretch(0, 1)
        grid.setColumnStretch(1, 1)
        layout.addLayout(grid)
        layout.addSpacing(12)
        layout.addWidget(text_label("Live views explain what the connector is scanning. Diagnostic checks help identify policy, connectivity, and configuration issues.", "muted"))
        layout.addStretch()
        return self.actions

    def footer_layout(self):
        """Keep logging and utility controls aligned along a single bottom row."""
        self.footer_grid = QGridLayout()
        self.footer_grid.setContentsMargins(0, 0, 0, 0)
        logging_controls = QWidget()
        levels = QHBoxLayout(logging_controls)
        levels.setContentsMargins(0, 0, 0, 0)
        levels.addWidget(text_label("Tool log level", "muted", wrap=False))
        self.log_level = QComboBox()
        self.log_level.addItems(("INFO", "WARNING", "DEBUG"))
        self.log_level.setToolTip("Controls amp_health_checker_log.log. Connector debug is shown in Connector health.")
        self.log_level.currentTextChanged.connect(set_tool_log_level)
        levels.addWidget(self.log_level)
        levels.addStretch()
        self.utility_controls = QWidget()
        layout = QHBoxLayout(self.utility_controls)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(10)
        layout.addStretch()
        layout.addWidget(button("Links", self.show_links))
        layout.addWidget(button("Feedback", self.feedback))
        self.refresh_button = button("Refresh", self.refresh)
        layout.addWidget(self.refresh_button)
        layout.addWidget(button("Close", self.close))
        self.footer_grid.addWidget(logging_controls, 0, 0)
        self.footer_grid.addWidget(self.utility_controls, 0, 1)
        self.footer_grid.setColumnStretch(0, 1)
        return self.footer_grid

    def initialize(self):
        """Load connector services after the first paint, unless the user has already closed."""
        if not self.closing:
            self.runner.submit(self.data_factory, self.initialized, self.startup_failed)

    def initialized(self, data):
        """Show initialized state or finish closing after an in-flight startup."""
        self.data = data
        if self.closing:
            self.shutdown()
            return
        self.update_status()
        self.setup_notice.hide()
        self.check_version("tetra")

    def startup_failed(self, message):
        """Keep connectivity testing available and show connector setup errors inline."""
        if self.closing:
            self.shutdown()
            return
        self.fields["version"].setText("Unavailable")
        set_badge(self.setup_notice, message, "warning")
        self.setup_notice.show()
        self.statusBar().showMessage("Connector unavailable · Connectivity test available · Refresh to retry")

    def set_busy(self, busy):
        """Disable overlapping actions while keeping window movement and close responsive."""
        ready = self.data is not None and not busy and not self.closing
        idle = not busy and not self.closing
        self.actions.setEnabled(idle)
        for key, control in self.action_buttons.items():
            control.setEnabled(idle if key == "connectivity" else ready)
        for control in self.check_buttons.values():
            control.setEnabled(ready)
        self.refresh_button.setEnabled(not busy and not self.closing)
        self.progress.setVisible(busy)
        if self.closing and not busy:
            self.shutdown()

    def update_status(self, result=None):
        """Render backend values and meaningful cloud-check errors after worker completion."""
        data = self.data
        values = {"version": data.version, "cpu": f"{data.current_cpu:.2f}%",
                  "debug": data.get_connector_debug_text(), "uptime": data.converted_uptime,
                  "isolation": data.isolated, "unlock": (data.unlock_code or "—").removeprefix("Unlock Code: "),
                  "uuid": data.local_uuid}
        for key, value in values.items():
            self.fields[key].setText(str(value))
        self.fields["debug"].setToolTip(data.connector_logging.detail)
        set_badge(self.fields["api"], "Valid" if data.api_cred_valid else "Invalid", "good" if data.api_cred_valid else "warning")
        set_badge(self.fields["tetra"], data.tetra_version_display, tone_for_color(getattr(data, "tetra_color", None)))
        set_badge(self.fields["policy"], data.policy_dict.get("policy_sn", "Unknown"), tone_for_color(getattr(data, "policy_color", None)))
        if getattr(data, "tetra_error", ""):
            self.fields["tetra_result"].setText(data.tetra_error)
        elif getattr(data, "tetra_latest", 0):
            self.fields["tetra_result"].setText(f"Latest cloud version: {data.tetra_latest}")
        if hasattr(data, "policy_error"):
            self.fields["policy_result"].setText(data.get_policy_check_text())

    def poll(self):
        """Refresh live state only while no dialog owns collection and no operation is active."""
        if self.data is None or self.runner.busy or self.closing or self.active_dialog is not None:
            return
        self.runner.submit(self.poll_data, self.update_status, self.show_error)

    def poll_data(self):
        """Keep cloud checks on a monotonic interval independent of button click frequency."""
        self.data.update()
        if self.data.api_cred_valid and time.monotonic() - self.last_api_refresh >= 55:
            self.data.update_api_calls()
            self.last_api_refresh = time.monotonic()

    def refresh(self):
        """Retry setup or refresh the existing connector and clear collected statistics."""
        if self.data is None:
            self.initialize()
        else:
            self.start_operation("Refreshing connector…", self.data.reset_data)

    def start_operation(self, description, operation, done=None):
        """Run a user action with visible progress and a consistent failure path."""
        if self.runner.submit(operation, done or self.operation_done, self.show_error):
            self.statusBar().showMessage(description)

    def operation_done(self, result=None):
        """Refresh the dashboard after a diagnostic operation completes."""
        if not self.closing:
            self.update_status()
            self.statusBar().showMessage("Ready")

    def check_version(self, key):
        """Perform cloud lookups in the worker queue and keep result rows correctly aligned."""
        self.fields[key + "_result"].setText("Checking cloud version…")
        operation = self.data.tetra_def_compare if key == "tetra" else partial(popups.check_policy, self.data)
        self.start_operation("Checking version…", operation)

    def show_dialog(self, dialog):
        """Suspend dashboard polling while a modal tool controls collection."""
        self.active_dialog = dialog
        try:
            dialog.exec()
        finally:
            self.active_dialog = None
            dialog.retire(self.runner)
            if not self.runner.busy and self.data is not None:
                self.update_status()

    def handle_action(self, key):
        """Open all existing tools using Qt dialogs and serialize slower diagnostic commands."""
        if self.runner.busy or self.closing or (self.data is None and key != "connectivity"):
            return
        constructors = {"live": partial(popups.LiveScanDialog, self.data, self.runner, self),
                        "processes": partial(popups.LiveScanDialog, self.data, self.runner, self, processes=True),
                        "analysis": partial(popups.AnalysisDialog, self.data, self.runner, self),
                        "manual": partial(popups.ManualAnalysisDialog, self.data, self.runner, self),
                        "connectivity": partial(popups.ConnectivityDialog, self.data, self.runner, self),
                        "engines": partial(popups.EnginesDialog, self.data, self),
                        "exclusions": partial(popups.ExclusionsDialog, self.data, self),
                        "recommendations": partial(popups.RecommendationsDialog, self.data, self.runner, self)}
        if key in constructors:
            self.show_dialog(constructors[key]())
        elif key == "diagnostic":
            self.start_operation("Generating diagnostic…", self.data.generate_diagnostic, self.diagnostic_done)

    def diagnostic_done(self, result=None):
        """Report the diagnostic launch result without claiming asynchronous creation has finished."""
        self.operation_done()
        if self.data.diag_failed:
            self.show_error("Diagnostic gathering failed. Run Support Diagnostic Tool from the Start menu, and collect its .7z file and amp_health_checker_log.log.")
        elif not self.closing:
            QMessageBox.information(self, "Diagnostic started", "The Support Diagnostic Tool has started. Collect its diagnostic bundle and the Health Checker log from the Desktop.")

    def show_links(self):
        """Open documentation links even when connector initialization is unavailable."""
        self.show_dialog(popups.LinksDialog(self))

    def feedback(self):
        """Open this repository's issue form in the user's browser."""
        webbrowser.open("https://github.com/mafranks/CSE_Health_Checker/issues/new")

    def show_error(self, message):
        """Present actionable errors on the GUI thread while retaining existing data."""
        if not self.closing:
            self.statusBar().showMessage("Check failed · see the message for details")
            QMessageBox.warning(self, "Health Checker", message)

    def shutdown(self):
        """Wait for active work, then clean up only the tool's verified debug override."""
        if self.runner.busy or self.can_close:
            return
        if self.data is None:
            self.cleanup_done()
        else:
            self.runner.submit(self.cleanup_connector, self.cleanup_done, self.cleanup_failed)

    def cleanup_connector(self):
        """Surface CLI cleanup failures that the backend records without raising."""
        self.data.disable_debug()
        if self.data.enabled_debug:
            raise RuntimeError(self.data.debug_error or "Unable to restore the temporary connector debug setting.")

    def cleanup_done(self, result=None):
        """Allow the window to close after connector cleanup has completed."""
        self.can_close = True
        self.close()

    def cleanup_failed(self, message):
        """Report a failed cleanup explicitly before finishing application shutdown."""
        QMessageBox.warning(self, "Connector cleanup", message)
        self.cleanup_done()

    def closeEvent(self, event):
        """Defer shutdown until in-flight work completes."""
        if self.can_close:
            event.accept()
            return
        event.ignore()
        self.closing = True
        self.timer.stop()
        self.statusBar().showMessage("Finishing current operation and restoring temporary debug settings…")
        self.set_busy(self.runner.busy)


def main():
    """Launch the Qt application and retain the dashboard for its full lifetime."""
    logging.basicConfig(
        format="%(asctime)s %(name)-12s %(levelname)-8s %(filename)s %(funcName)s %(message)s",
        datefmt="%m-%d %H:%M:%S", level=logging.INFO, filename="amp_health_checker_log.log",
    )
    app = application()
    window = MainWindow()
    window.show()
    return app.exec()


if __name__ == "__main__":
    sys.exit(main())
