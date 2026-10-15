"""Exercise the real Qt layouts, background queue, and migrated diagnostic workflows."""

from pathlib import Path
from types import SimpleNamespace
import tempfile
import threading
import unittest
from unittest.mock import Mock, patch

from PySide6.QtCore import QTimer, Qt
from PySide6.QtGui import QContextMenuEvent, QKeySequence, QPalette
from PySide6.QtTest import QTest
from PySide6.QtWidgets import QFileDialog, QPushButton, QScrollArea

from qt_helpers import APP, wait_until
from gui_fixtures import sample_data
import gui
import main_page
import popups
import connectivity
from themes import COLORS
from test_sfc_log import scan_event


class QtGuiTests(unittest.TestCase):
    """Verify controls and result windows without Windows services or live API access."""

    def setUp(self):
        """Create offline data and initialize the real dashboard through its worker queue."""
        self.original_theme = (APP.theme.preference, APP.theme.system, APP.theme.current)
        self.addCleanup(self.restore_theme)
        warnings = patch.object(gui.QMessageBox, "warning")
        self.warnings = warnings.start()
        self.addCleanup(warnings.stop)
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name)
        self.data = sample_data(self.root)
        self.window = main_page.MainWindow(data_factory=lambda: self.data)
        self.window.show()
        wait_until(lambda: self.window.data is not None and not self.window.runner.busy)
        self.window.timer.stop()
        self.addCleanup(self.close_window)

    def restore_theme(self):
        """Keep theme tests independent and store preferences only in the temporary test settings."""
        preference, system, current = self.original_theme
        APP.theme.preference, APP.theme.system = preference, system
        if preference is None:
            APP.theme.settings.remove("theme")
            APP.styleHints().unsetColorScheme()
        else:
            APP.theme.select(preference)
        APP.processEvents()
        APP.theme.apply(current)

    def close_window(self):
        """Ensure test windows finish cleanup before their worker objects are destroyed."""
        self.window.close()
        wait_until(lambda: self.window.can_close and not self.window.runner.busy)
        self.warnings.assert_not_called()

    def test_startup_checks_tetra_in_background_without_api_credentials(self):
        """Check TETRA once after loading while keeping the dashboard responsive."""
        gate, started = threading.Event(), threading.Event()
        worker_threads = []
        self.data.api_cred_valid = False
        self.data.tetra_latest = 0
        self.data.tetra_def_compare.reset_mock()

        def compare():
            """Hold the cloud lookup until the test verifies the pending UI state."""
            worker_threads.append(threading.get_ident())
            started.set()
            gate.wait(3)
            self.data.tetra_latest = "97527"

        self.data.tetra_def_compare.side_effect = compare
        window = main_page.MainWindow(data_factory=lambda: self.data)

        def close_window():
            """Release any pending lookup before closing this extra test window."""
            gate.set()
            window.close()
            wait_until(lambda: window.can_close and not window.runner.busy)

        self.addCleanup(close_window)
        window.show()
        wait_until(started.is_set)
        self.assertTrue(window.runner.busy)
        self.assertEqual(window.fields["tetra_result"].text(), "Checking cloud version…")
        self.assertFalse(window.check_buttons["tetra"].isEnabled())
        self.assertTrue(window.theme_button.isEnabled())
        self.assertNotEqual(worker_threads[0], threading.get_ident())
        gate.set()
        wait_until(lambda: not window.runner.busy)
        self.data.tetra_def_compare.assert_called_once_with()
        self.assertEqual(window.fields["tetra_result"].text(), "Latest cloud version: 97527")
        self.assertTrue(window.check_buttons["tetra"].isEnabled())
        window.check_buttons["tetra"].click()
        wait_until(lambda: not window.runner.busy)
        self.assertEqual(self.data.tetra_def_compare.call_count, 2)

    def test_tetra_lookup_failure_remains_visible_and_allows_retry(self):
        """Show a failed startup lookup without disabling a subsequent manual check."""
        self.data.tetra_latest = 0
        self.data.tetra_color = "yellow"
        self.data.tetra_error = "Latest TETRA version unavailable. Check network connectivity and retry."
        self.window.operation_done()
        self.assertEqual(self.window.fields["tetra_result"].text(), self.data.tetra_error)
        self.assertEqual(self.window.fields["tetra"].property("tone"), "warning")
        self.assertTrue(self.window.check_buttons["tetra"].isEnabled())

    def test_dashboard_reflows_without_horizontal_scroll(self):
        """Keep labels aligned and all footer controls reachable at several window sizes."""
        sizes = ((1120, 760), (820, 620), (640, 480))
        for theme, width, height in ((theme, width, height) for theme in COLORS for width, height in sizes):
            with self.subTest(theme=theme, width=width):
                APP.theme.select(theme)
                self.window.resize(width, height)
                for _ in range(4):
                    APP.processEvents()
                scroll = self.window.findChild(QScrollArea)
                self.assertEqual(scroll.horizontalScrollBar().maximum(), 0)
                positions = [self.window.fields[key].x() for _, key in main_page.STATUS_FIELDS]
                self.assertEqual(len(set(positions)), 1)
                self.assertEqual(self.window.stacked, width < 950)
                for control in self.window.centralWidget().findChildren(QPushButton):
                    if control.parentWidget() is self.window.centralWidget():
                        self.assertLessEqual(control.geometry().right(), width)

    def test_theme_toggle_updates_open_tools_and_preserves_results(self):
        """Switch existing reports/tables and dashboard backgrounds without losing visible data."""
        APP.theme.select("light")
        dialog = popups.EnginesDialog(self.data, self.window)
        report = popups.TextDialog("Report", "Description", "Saved diagnostic text", self.window)
        self.addCleanup(dialog.close)
        self.addCleanup(report.close)
        dialog.show()
        report.show()
        dialog.results.selectRow(0)
        previous_geometry = dialog.geometry()
        previous_value = self.window.fields["api"].text()
        for expected in ("dark", "light"):
            QTest.mouseClick(self.window.theme_button, Qt.MouseButton.LeftButton)
            APP.processEvents()
            self.assertEqual(APP.theme.current, expected)
            self.assertEqual(APP.theme.settings.value("theme"), expected)
            self.assertEqual(self.window.theme_button.isChecked(), expected == "dark")
            self.assertIn("On" if expected == "dark" else "Off", self.window.theme_button.text())
            background = self.window.centralWidget().grab().toImage().pixelColor(5, 5).name()
            self.assertEqual(background, COLORS[expected]["window"])
            self.assertEqual(dialog.results.palette().color(QPalette.ColorRole.Base).name(), COLORS[expected]["surface"])
            self.assertEqual(report.results.palette().color(QPalette.ColorRole.Text).name(), COLORS[expected]["text"])
            self.assertEqual([index.row() for index in dialog.results.selectionModel().selectedRows()], [0])
            self.assertEqual(report.results.toPlainText(), "Saved diagnostic text")
            self.assertEqual(dialog.geometry(), previous_geometry)
            self.assertEqual(self.window.fields["api"].text(), previous_value)
            self.assertEqual(self.window.fields["api"].property("tone"), "good")
            self.assertIs(gui.application(), APP)
            self.assertEqual(APP.theme.current, expected)

    def test_theme_toggle_remains_available_during_connector_work(self):
        """Change appearance while the worker is busy without starting another backend action."""
        APP.theme.select("light")
        gate = threading.Event()
        self.addCleanup(gate.set)
        self.window.runner.submit(lambda: gate.wait(3), self.window.operation_done)
        self.assertFalse(self.window.actions.isEnabled())
        self.assertTrue(self.window.theme_button.isEnabled())
        self.window.theme_button.click()
        self.assertEqual(APP.theme.current, "dark")
        self.assertTrue(self.window.runner.busy)
        gate.set()
        wait_until(lambda: not self.window.runner.busy)
        self.assertTrue(self.window.actions.isEnabled())

    def test_tool_buttons_dispatch_without_extra_signal_arguments(self):
        """Drive real clicked signals for every migrated modal tool."""
        dialog_buttons = [title for title, key in main_page.ACTIONS
                          if key not in ("diagnostic",)]
        with patch.object(self.window, "show_dialog") as show:
            for title in dialog_buttons:
                control = next(widget for widget in self.window.actions.findChildren(QPushButton) if widget.text() == title)
                control.click()
                dialog = show.call_args.args[0]
                self.assertIsInstance(dialog, gui.ResultDialog)
                dialog.close()
                APP.processEvents()
                wait_until(lambda: not self.window.runner.busy)
        self.assertEqual(show.call_count, len(dialog_buttons))

    def test_background_queue_keeps_event_loop_responsive_and_serial(self):
        """Keep timers running while slow work executes and reject duplicate submissions."""
        gate, started, callbacks, ticks = threading.Event(), threading.Event(), [], []

        def slow_operation():
            """Wait for a test-controlled release outside the GUI thread."""
            started.set()
            gate.wait(3)
            return "finished"

        timer = QTimer()
        timer.setInterval(10)
        timer.timeout.connect(lambda: ticks.append(True))
        timer.start()
        self.addCleanup(timer.stop)
        self.addCleanup(gate.set)
        self.assertTrue(self.window.runner.submit(slow_operation, callbacks.append))
        self.assertFalse(self.window.runner.submit(Mock(), Mock()))
        wait_until(lambda: started.is_set() and len(ticks) >= 2)
        self.assertFalse(self.window.actions.isEnabled())
        gate.set()
        wait_until(lambda: not self.window.runner.busy)
        self.assertEqual(callbacks, ["finished"])
        self.assertTrue(self.window.actions.isEnabled())

    def test_policy_failure_is_visible_and_check_is_reenabled(self):
        """Show lookup errors without leaving the dashboard's policy action disabled."""
        def denied(data):
            """Simulate the established backend policy error contract."""
            self.data.policy_error = "API access denied (HTTP 403)"
            self.data.policy_color = "Yellow"

        with patch.object(popups, "check_policy", side_effect=denied):
            self.window.check_buttons["policy"].click()
            self.assertFalse(self.window.check_buttons["policy"].isEnabled())
            wait_until(lambda: not self.window.runner.busy)
        self.assertIn("API access denied", self.window.fields["policy_result"].text())
        self.assertEqual(self.window.fields["policy"].property("tone"), "warning")
        self.assertTrue(self.window.check_buttons["policy"].isEnabled())

    def test_live_pause_resume_and_reset_preserve_reader_cursor(self):
        """Pause incoming collection, resume appended records, and reset without rereading history."""
        dialog = popups.LiveScanDialog(self.data, self.window.runner, self.window)
        self.addCleanup(dialog.close)
        dialog.start_button.click()
        wait_until(lambda: not self.window.runner.busy)
        dialog.pause_button.click()
        self.assertEqual(dialog.status.text(), "PAUSED")
        with Path(self.data.sfc_path).open("a") as output:
            output.write(scan_event())
        before = len(self.data.data)
        dialog.collect()
        self.assertEqual(len(self.data.data), before)
        dialog.start_button.click()
        wait_until(lambda: not self.window.runner.busy)
        self.assertEqual(len(self.data.data), before + 1)
        self.assertEqual(dialog.results.rowCount(), 1)
        self.assertEqual(dialog.results.item(0, 0).text(), "1")
        with Path(self.data.sfc_path).open("a") as output:
            output.write(scan_event())
        dialog.collect()
        wait_until(lambda: not self.window.runner.busy)
        self.assertEqual(dialog.results.rowCount(), 1)
        self.assertEqual(dialog.results.item(0, 0).text(), "2")
        dialog.reset_button.click()
        self.assertEqual(dialog.results.rowCount(), 0)
        self.assertEqual(dialog.status.text(), "READY")
        self.assertEqual(self.data.get_log_status()[0], "WAITING FOR SCAN EVENTS")

    def test_manual_file_selection_is_independent_and_clears_stale_results(self):
        """Select another file, analyze it, and leave the live path/data unchanged."""
        dialog = popups.ManualAnalysisDialog(self.data, self.window.runner, self.window)
        self.addCleanup(dialog.close)
        APP.processEvents()
        wait_until(lambda: not self.window.runner.busy)
        original_path, original_count = self.data.sfc_path, len(self.data.data)
        external = self.root / "external.log"
        external.write_text(scan_event())
        with patch.object(QFileDialog, "getOpenFileName", return_value=(str(external), "")):
            dialog.choose_button.click()
        self.assertEqual(dialog.tables["_top_processes"].rowCount(), 0)
        self.assertFalse(dialog.save_button.isEnabled())
        dialog.refresh_button.click()
        wait_until(lambda: not self.window.runner.busy)
        self.assertEqual(dialog.data.sfc_path, str(external))
        self.assertEqual(len(dialog.data.data), 1)
        self.assertEqual(dialog.status.text(), "ANALYSIS COMPLETE")
        self.assertEqual(self.data.sfc_path, original_path)
        self.assertEqual(len(self.data.data), original_count)
        self.assertTrue(dialog.save_button.isEnabled())

    def test_save_all_tabs_and_overwrite_same_path(self):
        """Export IPs and allow saving new results to the same filename again."""
        dialog = popups.AnalysisDialog(self.data, self.window.runner, self.window)
        self.addCleanup(dialog.close)
        target = self.root / "saved.log"
        with patch.object(QFileDialog, "getSaveFileName", return_value=(str(target), "")):
            dialog.save_button.click()
            first = target.read_text()
            self.data.ip_list.append("2.2.2.2")
            dialog.save_button.click()
        self.assertIn("Top 10 IPs", first)
        self.assertIn("1.1.1.1", first)
        self.assertIn("2.2.2.2", target.read_text())

    def test_connectivity_results_have_text_and_do_not_need_widget_callbacks(self):
        """Show connected/failed outcomes in the Qt table after worker completion."""
        results = {"good.example": "Green", "bad.example": "Red"}
        with patch.object(popups, "check_endpoints", return_value=results):
            dialog = popups.ConnectivityDialog(self.data, self.window.runner, self.window)
            self.addCleanup(dialog.close)
            APP.processEvents()
            wait_until(lambda: not self.window.runner.busy)
        self.assertEqual(dialog.results.item(0, 1).text(), "Connected")
        self.assertEqual(dialog.results.item(1, 1).text(), "Connection failed")
        self.assertIn("1 failed", dialog.status.text())
        self.assertTrue(dialog.test_button.isEnabled())

    def test_close_waits_for_inflight_work(self):
        """Allow an active operation to finish before closing the dashboard."""
        gate = threading.Event()
        self.addCleanup(gate.set)
        self.window.runner.submit(lambda: gate.wait(3), self.window.operation_done)
        self.window.close()
        self.assertFalse(self.window.can_close)
        gate.set()
        wait_until(lambda: self.window.can_close and not self.window.runner.busy)
        self.assertFalse(self.window.isVisible())

    def test_setup_error_is_visible_and_retry_is_possible(self):
        """Return worker startup errors to Qt without quitting silently or hiding retry."""
        create = Mock(side_effect=RuntimeError("Secure Endpoint is not installed"))
        window = main_page.MainWindow(data_factory=create)
        with self.assertLogs(level="ERROR"):
            wait_until(lambda: not window.runner.busy and create.called)
        self.assertIn("not installed", window.setup_notice.text())
        self.assertTrue(window.refresh_button.isEnabled())
        self.assertTrue(window.action_buttons["connectivity"].isEnabled())
        self.assertTrue(window.action_buttons["certificates"].isEnabled())
        self.assertFalse(window.action_buttons["live"].isEnabled())
        window.close()
        self.assertTrue(window.can_close)

    def test_close_during_startup_waits_for_returned_data(self):
        """Wait for connector initialization before completing a requested close."""
        gate = threading.Event()
        self.addCleanup(gate.set)
        self.data.tetra_def_compare.reset_mock()

        def load_data():
            """Return initialized connector data after a controlled startup delay."""
            gate.wait(3)
            return self.data

        window = main_page.MainWindow(data_factory=load_data)
        wait_until(lambda: window.runner.busy)
        window.close()
        self.assertFalse(window.can_close)
        gate.set()
        wait_until(lambda: window.can_close and not window.runner.busy)
        self.data.tetra_def_compare.assert_not_called()

    def test_closing_does_not_open_new_result_dialogs(self):
        """Suppress completed diagnostic reports after the user has requested shutdown."""
        self.window.closing = True
        with patch.object(self.window, "show_dialog") as show:
            self.window.show_certificates()
        show.assert_not_called()

    def test_certificates_is_standalone_and_has_no_bundled_catalog(self):
        """Open an empty local viewer without connector access or bundled issuer information."""
        self.window.data = None
        self.window.set_busy(False)
        with patch("subprocess.check_output") as command, patch.object(self.window.runner, "submit") as submit:
            with patch.object(self.window, "show_dialog") as show:
                self.window.action_buttons["certificates"].click()
        command.assert_not_called()
        submit.assert_not_called()
        dialog = show.call_args.args[0]
        self.addCleanup(dialog.close)
        self.assertEqual(dialog.windowTitle(), "Certificate viewer")
        self.assertTrue(all(view.isReadOnly() for view in dialog.views.values()))
        self.assertEqual([dialog.tabs.tabText(i) for i in range(dialog.tabs.count())],
                         ["Valid dates (0)", "Historical (0)"])
        self.assertFalse(dialog.save_button.isEnabled())

    def test_certificate_tabs_export_selected_certificates_and_preserve_results_on_failure(self):
        """Keep expired variants separate and preserve the previous selection after invalid input."""
        from test_certificates import CURRENT, EXPIRED, NOW
        dialog = popups.CertificatesDialog(certificates=(CURRENT, EXPIRED), as_of=NOW)
        self.addCleanup(dialog.close)
        self.assertEqual([dialog.tabs.tabText(i) for i in range(dialog.tabs.count())],
                         ["Valid dates (1)", "Historical (1)"])
        self.assertIn(CURRENT.sha256, dialog.views["Valid dates"].toPlainText())
        self.assertNotIn(EXPIRED.sha256, dialog.views["Valid dates"].toPlainText())
        self.assertIn(EXPIRED.sha256, dialog.views["Historical"].toPlainText())
        with patch.object(popups, "save_text") as save:
            dialog.save_button.click()
        for view in dialog.views.values():
            self.assertIn(view.toPlainText(), save.call_args.args[1])
        reports = dialog.reports.copy()
        with patch.object(popups.QFileDialog, "getOpenFileNames", return_value=(["invalid.pem"], "")):
            with patch.object(popups, "load_certificates", side_effect=ValueError("Invalid certificate")):
                dialog.open_button.click()
        self.assertEqual(dialog.reports, reports)
        self.assertEqual(dialog.notice.text(), "Invalid certificate")

    def test_live_preview_limit_does_not_limit_export(self):
        """Preview the busiest 500 pairs and export all pairs with complete counts."""
        record = dict(self.data.data[0])
        self.data.data = [dict(record, path=f"C:\\Example\\file-{i}.txt") for i in range(600)]
        last = self.data.data[-1]
        self.data.data.extend([last] * 5)
        dialog = popups.LiveScanDialog(self.data, self.window.runner, self.window)
        self.addCleanup(dialog.close)
        self.assertEqual(dialog.results.rowCount(), 500)
        self.assertEqual(dialog.results.item(0, 0).text(), "6")
        self.assertEqual(dialog.results.item(0, 2).text(), last["path"])
        self.assertIn("500 of 600 unique process/path pairs from 605 scan events", dialog.limit_note.text())
        with patch.object(popups, "save_text") as save:
            dialog.save_button.click()
        exported = save.call_args.args[1].splitlines()
        self.assertEqual(len(exported), 601)
        self.assertTrue(exported[1].startswith("6     | "))
        self.assertIn("file-598.txt", exported[-1])

    def test_live_pairs_accumulate_counts_and_keep_selection_on_refresh(self):
        """Keep repeated scans in one counted row and follow it when rankings change."""
        record = dict(self.data.data[0])
        self.data.data = [record] * 600
        dialog = popups.LiveScanDialog(self.data, self.window.runner, self.window)
        self.addCleanup(dialog.close)
        self.assertEqual([dialog.results.horizontalHeaderItem(i).text() for i in range(3)],
                         ["Count", "Process", "File path"])
        self.assertEqual(dialog.results.rowCount(), 1)
        self.assertEqual(dialog.results.item(0, 0).text(), "600")
        dialog.results.selectRow(0)
        self.data.data.extend([dict(record, path=r"C:\Example\other.txt")] * 602 + [record])
        dialog.render_results()
        dialog.results.copy_selection()
        self.assertEqual(dialog.results.rowCount(), 2)
        self.assertEqual(APP.clipboard().text(), f"601\t{record['process']}\t{record['path']}")
        dialog.render_results()
        self.assertEqual(dialog.results.item(1, 0).text(), "601")

    def test_readonly_engine_and_report_views(self):
        """Make policy diagnostics visibly read-only and expose missing values as Unknown."""
        self.data.policy_dict.pop("tetra")
        engine = popups.EnginesDialog(self.data, self.window)
        report = popups.TextDialog("Report", "Description", "Result", self.window)
        self.addCleanup(engine.close)
        self.addCleanup(report.close)
        self.assertEqual(engine.results.item(1, 1).text(), "Unknown")
        self.assertTrue(report.results.isReadOnly())

    def test_exclusions_preserve_complete_stored_entries_and_export_both_tabs(self):
        """Keep unrecognized entries visible while exporting decoded and original values."""
        entries = ["Example policy entry", "", None]
        self.data.policy_dict["path_exclusions"] = entries
        dialog = popups.ExclusionsDialog(self.data, self.window)
        self.addCleanup(dialog.close)
        for theme in ("light", "dark"):
            APP.theme.select(theme)
            self.assertEqual(dialog.views["general"].rowCount(), 4)
            self.assertEqual(dialog.views["general"].item(0, 0).text(), "Unknown")
            self.assertEqual(dialog.views["general"].item(0, 1).text(), entries[0])
            self.assertEqual(dialog.views["general"].item(1, 1).text(), "(empty entry)")
        process = self.data.policy_dict["process_exclusions"][0]
        self.assertEqual(dialog.views["process"].item(0, 0).text(), "File Scan")
        self.assertEqual(dialog.views["process"].item(0, 1).text(), r"C:\Example\worker.exe")
        self.assertEqual(dialog.views["process"].item(0, 3).text(), "Yes")
        with patch.object(popups, "save_text") as save:
            dialog.save_button.click()
        self.assertIn(process, save.call_args.args[1])
        self.assertIn(entries[0], save.call_args.args[1])

    def test_exclusion_type_filters_and_complete_export_in_both_themes(self):
        """Filter each tab independently and export every rule despite an active filter."""
        dialog = popups.ExclusionsDialog(self.data, self.window)
        self.addCleanup(dialog.close)
        for theme in ("light", "dark"):
            APP.theme.select(theme)
            for key, kinds in (("general", ("File Extension", "Path", "Wildcard", "Executable")),
                               ("process", ("File Scan", "System Process Protection", "Malicious Activity Protection", "Behavioral Protection"))):
                for kind in kinds:
                    with self.subTest(theme=theme, tab=key, kind=kind):
                        dialog.filters[key].setCurrentText(kind)
                        self.assertEqual(dialog.views[key].rowCount(), 1)
                        self.assertEqual(dialog.views[key].item(0, 0).text(), kind)
                        self.assertIn("Showing 1 of 4", dialog.messages[key].text())
            dialog.filters["general"].setCurrentText("IOC")
            self.assertEqual(dialog.views["general"].rowCount(), 0)
            self.assertIn("unavailable", dialog.messages["general"].text())
        with patch.object(popups, "save_text") as save:
            dialog.save_button.click()
        content = save.call_args.args[1]
        for kind in ("File Extension", "Path", "Wildcard", "Executable", "File Scan", "System Process Protection",
                     "Malicious Activity Protection", "Behavioral Protection"):
            self.assertIn(kind, content)
        self.assertIn("Child processes", content)
        self.assertIn("Stored entry", content)

    def test_leading_wildcard_button_only_reports_decoded_wildcard_rules(self):
        """Restore the report without misclassifying threat names or ordinary paths."""
        pattern = r"^.*\\Example\\Cache"
        self.data.policy_dict["path_exclusions"] = ["256|6|0|0|" + pattern, "256|1|0|0|*ExampleThreat",
                                                    r"256|2|1|0|C:\Example\Cache"]
        dialog = popups.ExclusionsDialog(self.data, self.window)
        self.addCleanup(dialog.close)
        with patch.object(popups, "TextDialog") as report:
            dialog.wildcard_button.click()
        self.assertEqual(report.call_args.args[2], pattern)
        report.return_value.exec.assert_called_once_with()

    def test_trusted_signer_reference_is_standalone_and_exports_all_tabs(self):
        """Keep built-in current, historical, and unresolved references available without a connector."""
        self.window.data = None
        self.window.set_busy(False)
        self.assertTrue(self.window.action_buttons["signers"].isEnabled())
        with patch.object(self.window, "show_dialog") as show:
            self.window.action_buttons["signers"].click()
        dialog = show.call_args.args[0]
        self.addCleanup(dialog.close)
        for title in ("Valid dates", "Historical", "Unverified"):
            self.assertIn(title, dialog.views)
            self.assertTrue(dialog.views[title].isReadOnly())
        with patch.object(popups, "save_text") as save:
            dialog.save_button.click()
        for view in dialog.views.values():
            self.assertIn(view.toPlainText(), save.call_args.args[1])

    def test_recommendations_refresh_in_background_and_export_catalog_details(self):
        """Show candidate sets with source age, allow refresh, and save complete results."""
        dialog = popups.RecommendationsDialog(self.data, self.window.runner, self.window)
        self.addCleanup(dialog.close)
        dialog.show()
        wait_until(lambda: dialog.report is not None and not self.window.runner.busy)
        self.assertEqual(dialog.results.item(0, 0).text(), "Example product")
        self.assertEqual(dialog.results.item(0, 1).text(), "example.exe")
        self.assertIn("2024-10-30", dialog.source.text())
        self.assertTrue(dialog.refresh_button.isEnabled())
        self.assertTrue(dialog.save_button.isEnabled())
        self.data.recommend_exclusions.assert_called_once_with()
        with patch.object(popups, "save_text") as save:
            dialog.save_button.click()
        self.assertIn("Example product\texample.exe", save.call_args.args[1])
        self.assertIn("Catalog updated: 2024-10-30", save.call_args.args[1])
        dialog.refresh_button.click()
        wait_until(lambda: not self.window.runner.busy)
        self.assertEqual(self.data.recommend_exclusions.call_count, 2)

    def test_combined_process_exclusion_has_individual_child_scope_and_copying(self):
        """Display combined flags under each protection with its own child setting."""
        sha = "ab" * 32
        raw = fr"3|1|{sha}|C:\Example\app.exe|52|"
        self.data.policy_dict["process_exclusions"] = [raw]
        dialog = popups.ExclusionsDialog(self.data, self.window)
        self.addCleanup(dialog.close)
        view = dialog.views["process"]
        self.assertEqual(view.rowCount(), 2)
        for kind, children in (("Malicious Activity Protection", "Yes"), ("System Process Protection", "No")):
            dialog.filters["process"].setCurrentText(kind)
            self.assertEqual(view.rowCount(), 1)
            self.assertEqual(view.item(0, 0).text(), kind)
            self.assertEqual(view.item(0, 1).text(), r"C:\Example\app.exe")
            self.assertEqual(view.item(0, 2).text(), sha)
            self.assertEqual(view.item(0, 3).text(), children)
            self.assertIn(raw, view.item(0, 0).toolTip())
            view.selectRow(0)
            view.copy_selection()
            self.assertEqual(APP.clipboard().text(), f"{kind}\tC:\\Example\\app.exe\t{sha}\t{children}")

    def test_unlock_value_does_not_repeat_its_field_label(self):
        """Keep the backend's legacy unlock-code prefix out of the aligned value column."""
        self.data.unlock_code = "Unlock Code: 12345678"
        self.window.update_status()
        self.assertEqual(self.window.fields["unlock"].text(), "12345678")

    def test_default_factory_constructs_real_backend(self):
        """Ensure normal startup uses Data rather than the offline layout fixtures."""
        create = Mock(return_value=object())
        with patch.dict("sys.modules", {"data": SimpleNamespace(Data=create)}):
            with patch.object(main_page.sys, "platform", "win32"):
                result = main_page.create_data()
        create.assert_called_once_with()
        self.assertIs(result, create.return_value)

    def test_dashboard_live_button_is_neutral_by_default(self):
        """Keep Live paths / processes styled like the other dashboard actions."""
        self.assertFalse(self.window.action_buttons["live"].property("primary"))
        self.assertFalse(self.window.action_buttons["live"].isChecked())

    def test_all_tool_dialogs_support_fullscreen_and_escape_restore(self):
        """Exercise the common fullscreen action without closing a tool on the first Escape."""
        constructors = (
            lambda: popups.LiveScanDialog(self.data, self.window.runner, self.window),
            lambda: popups.AnalysisDialog(self.data, self.window.runner, self.window),
            lambda: popups.ManualAnalysisDialog(self.data, self.window.runner, self.window),
            lambda: popups.EnginesDialog(self.data, self.window),
            lambda: popups.ExclusionsDialog(self.data, self.window),
            lambda: popups.TextDialog("Report", "Description", "Result", self.window),
            lambda: popups.LinksDialog(self.window),
            lambda: popups.ConnectivityDialog(self.data, self.window.runner, self.window),
        )
        with patch.object(popups, "check_endpoints", return_value={}):
            for create in constructors:
                dialog = create()
                dialog.show()
                APP.processEvents()
                wait_until(lambda: not self.window.runner.busy)
                self.assertTrue(dialog.windowFlags() & Qt.WindowType.WindowMaximizeButtonHint)
                previous_size = dialog.size()
                dialog.fullscreen_button.click()
                APP.processEvents()
                self.assertTrue(dialog.isFullScreen())
                self.assertEqual(dialog.fullscreen_button.text(), "Exit full screen")
                QTest.keyClick(dialog, Qt.Key.Key_Escape)
                APP.processEvents()
                self.assertFalse(dialog.isFullScreen())
                self.assertFalse(dialog.closed)
                self.assertEqual(dialog.size(), previous_size)
                dialog.close()

    def test_f11_restores_a_maximized_tool_window(self):
        """Toggle through the real shortcut and retain the prior maximized state."""
        dialog = popups.LiveScanDialog(self.data, self.window.runner, self.window)
        self.addCleanup(dialog.close)
        dialog.showMaximized()
        dialog.activateWindow()
        APP.processEvents()
        QTest.keyClick(dialog, Qt.Key.Key_F11)
        APP.processEvents()
        self.assertTrue(dialog.isFullScreen())
        QTest.keyClick(dialog, Qt.Key.Key_F11)
        APP.processEvents()
        self.assertFalse(dialog.isFullScreen())
        self.assertTrue(dialog.isMaximized())

    def test_copy_shortcut_preserves_full_unicode_paths_and_row_order(self):
        """Copy complete values across multiple selected rows despite visual truncation."""
        view = gui.table(("Count", "Path"))
        path = "C:\\A very long folder name\\Unicode Ω\\" + "x" * 180 + ".txt"
        gui.fill_table(view, [(2, path), (4, "C:\\second.txt")])
        view.selectAll()
        QTest.keySequence(view, QKeySequence(QKeySequence.StandardKey.Copy))
        self.assertEqual(APP.clipboard().text(), f"2\t{path}\n4\tC:\\second.txt")

    def test_copy_value_context_menu_uses_the_clicked_cell(self):
        """Copy just the clicked file path rather than the whole selected row."""
        view = gui.table(("Count", "Path"))
        gui.fill_table(view, [(2, "C:\\one.txt"), (4, "C:\\two.txt")])
        view.resize(600, 240)
        view.show()
        self.addCleanup(view.close)
        APP.processEvents()
        point = view.visualItemRect(view.item(1, 1)).center()
        event = QContextMenuEvent(QContextMenuEvent.Reason.Mouse, point, view.viewport().mapToGlobal(point))

        def choose_value():
            """Trigger the actual context-menu action after Qt opens its native popup."""
            menu = APP.activePopupWidget()
            if menu is not None:
                next(action for action in menu.actions() if action.text() == "Copy value").trigger()
                menu.close()

        QTimer.singleShot(0, choose_value)
        view.contextMenuEvent(event)
        self.assertEqual(APP.clipboard().text(), "C:\\two.txt")

    def test_selected_path_survives_live_insertions_and_updated_counts(self):
        """Keep the selected record tied to its path while incoming results reorder rows."""
        view = gui.table(("Count", "Path"))
        gui.fill_table(view, [(2, "C:\\selected.txt")])
        view.selectRow(0)
        gui.fill_table(view, [(10, "C:\\new.txt"), (3, "C:\\selected.txt")])
        view.copy_selection()
        self.assertEqual(APP.clipboard().text(), "3\tC:\\selected.txt")

    def test_standalone_connectivity_completes_without_connector_or_credentials(self):
        """Open the actual Connectivity action after connector startup fails and complete the check."""
        from test_health_checker import Data, data_module
        create = Mock(side_effect=Data)
        with patch.object(data_module.psutil, "process_iter", return_value=[]):
            with patch.object(data_module.requests, "get") as api:
                window = main_page.MainWindow(data_factory=create)
                with self.assertLogs(level="ERROR"):
                    wait_until(lambda: create.called and not window.runner.busy)
                api.assert_not_called()
        self.assertIsNone(window.data)
        self.assertTrue(window.action_buttons["connectivity"].isEnabled())
        with patch.object(popups, "environment_settings", return_value=connectivity.ConnectivitySettings("EU")):
            with patch.object(window, "show_dialog") as show:
                window.action_buttons["connectivity"].click()
                dialog = show.call_args.args[0]

        def reachable(endpoints, **kwargs):
            """Return and emit per-host results without a connector, API, or live sockets."""
            for host in endpoints:
                kwargs["on_result"](host, "Green")
            return dict.fromkeys(endpoints, "Green")

        with patch.object(popups, "check_endpoints", side_effect=reachable) as check:
            dialog.show()
            APP.processEvents()
            wait_until(lambda: not window.runner.busy)
        self.assertIn("COMPLETE", dialog.status.text())
        self.assertGreater(dialog.results.rowCount(), 0)
        self.assertTrue(all(".eu.amp.cisco.com" in host for host in check.call_args.args[0]))
        self.assertEqual(create.call_count, 1)
        dialog.close()
        window.close()
        self.assertTrue(window.can_close)

    def test_private_cloud_domain_is_editable_without_env_credentials(self):
        """Require a domain for Private Cloud, then test the entered domain independently."""
        with patch.object(popups, "environment_settings", return_value=connectivity.ConnectivitySettings("PC")):
            dialog = popups.ConnectivityDialog(None, self.window.runner, self.window)
        self.addCleanup(dialog.close)
        APP.processEvents()
        self.assertEqual(dialog.status.property("tone"), "bad")
        self.assertFalse(self.window.runner.busy)
        dialog.domain_input.setText("private.example")
        with patch.object(popups, "check_endpoints", return_value={"console.private.example": "Green"}) as check:
            dialog.test_button.click()
            wait_until(lambda: not self.window.runner.busy)
        self.assertEqual(check.call_args.args[0], connectivity.endpoints_for_region("PC", "private.example"))


if __name__ == "__main__":
    unittest.main()
