"""Exercise startup, ownership, cleanup, and GUI/tool logging separation."""

from pathlib import Path
import subprocess
import tempfile
import time
import unittest
from unittest.mock import Mock, patch
import xml.etree.ElementTree as ET

from test_health_checker import Data, data_module, main_page
from qt_helpers import APP, wait_until
from gui_fixtures import populate_test_dashboard_metadata


class ConnectorDebugTests(unittest.TestCase):
    """Preserve settings established outside the Health Checker and clean up verified changes."""

    def setUp(self):
        """Create isolated connector XML fixtures and a minimal Health Checker instance."""
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name)
        self.data = Data.__new__(Data)
        self.data.root_path = str(self.root)
        self.data.path_prelude = str(self.root)
        self.data.policy_dict = {"log_level": "0"}
        self.data.enabled_debug = False
        self.data._debug_override = None
        self.data.debug_error = ""
        self.save_override()
        commands = patch.object(data_module.subprocess, "run", side_effect=self.apply_command)
        self.run = commands.start()
        self.addCleanup(commands.stop)

    def save_override(self, source=None, level=6, timestamp=None):
        """Write a connector-owned fixture record or a configuration with no override."""
        fields = ""
        if source is not None:
            timestamp = int(time.time()) if timestamp is None else timestamp
            fields = (f"<local_level>{level}</local_level><local_source>{source}</local_source>"
                      f"<local_time_set>{timestamp}</local_time_set>")
        (self.root / "local.xml").write_text(f"<config><agent><log>{fields}</log></agent></config>")

    def apply_command(self, args, **kwargs):
        """Simulate the existing connector CLI saving or clearing its own metadata."""
        self.save_override(source=3 if args[-1] == "start" else None)
        return subprocess.CompletedProcess(args, 0)

    def test_policy_values_other_than_historical_mask_are_preserved(self):
        """Leave any valid nonzero policy debug setting alone on startup and shutdown."""
        for level in ("1", "17179869183", "549755813887"):
            with self.subTest(level=level):
                self.data.policy_dict["log_level"] = level
                self.data.debug_check()
                self.data.disable_debug()
                self.assertFalse(self.data.enabled_debug)
        self.run.assert_not_called()

    def test_existing_local_and_remote_debug_are_preserved(self):
        """Never start or stop debug that was enabled by GUI/CLI or another source."""
        for source in (2, 3, 4, 5):
            with self.subTest(source=source):
                self.save_override(source=source)
                original = (self.root / "local.xml").read_bytes()
                self.data.debug_check()
                self.data.disable_debug()
                self.assertEqual((self.root / "local.xml").read_bytes(), original)
                self.assertFalse(self.data.enabled_debug)
        self.run.assert_not_called()

    def test_existing_disabled_override_is_not_overwritten(self):
        """Preserve a higher-priority non-debug override even when policy enables debug."""
        self.data.policy_dict["log_level"] = "1"
        self.save_override(source=5, level=3)
        with self.assertLogs(level="WARNING"):
            self.data.debug_check()
        self.assertFalse(self.data.connector_logging.enabled)
        self.run.assert_not_called()

    def test_automatic_crash_debug_without_manual_record_is_preserved(self):
        """Preserve automatic debug that the connector enables after consecutive crashes."""
        self.data.connector_started_at = time.time() - 10
        xml = ("<config><agent><log/><counter><consecutive_unclean_shutdown_count>3</consecutive_unclean_shutdown_count>"
               "</counter></agent></config>")
        (self.root / "local.xml").write_text(xml)
        self.data.debug_check()
        self.data.disable_debug()
        self.assertTrue(self.data.connector_logging.enabled)
        self.assertEqual(self.data.connector_logging.source, "crash recovery")
        self.run.assert_not_called()

    def test_verified_temporary_override_is_cleaned_up(self):
        """Stop exactly the fresh user-source override established by the tool's command."""
        self.data.debug_check()
        self.assertTrue(self.data.enabled_debug)
        self.assertIn("Health Checker", self.data.get_connector_debug_text())
        self.data.disable_debug()
        self.assertEqual([call.args[0][-1] for call in self.run.call_args_list], ["start", "stop"])
        self.assertFalse(self.data.enabled_debug)

    def test_external_override_change_prevents_cleanup(self):
        """Do not clear a later remote or GUI logging change when the tool exits."""
        for source in (3, 5):
            with self.subTest(source=source):
                self.save_override()
                self.data.debug_check()
                timestamp = self.data._debug_override[2] + 1
                self.save_override(source=source, timestamp=timestamp)
                self.run.reset_mock()
                self.data.disable_debug()
                self.run.assert_not_called()
                self.assertFalse(self.data.enabled_debug)

    def test_expired_preexisting_setting_is_preserved_as_unknown(self):
        """Avoid claiming an expired saved setting proves the live service has already reset."""
        self.save_override(source=3, timestamp=int(time.time()) - 901)
        with self.assertLogs(level="WARNING"):
            self.data.debug_check()
        self.assertIsNone(self.data.connector_logging.enabled)
        self.assertIn("expired", self.data.debug_error)
        self.run.assert_not_called()

    def test_unknown_local_file_does_not_change_logging(self):
        """Treat missing, inaccessible, or malformed local settings as unknown."""
        (self.root / "local.xml").write_text("<config>")
        with self.assertLogs(level="WARNING"):
            self.data.debug_check()
        self.assertIsNone(self.data.connector_logging.enabled)
        self.run.assert_not_called()

    def test_read_failure_during_cleanup_preserves_settings(self):
        """Avoid sending stop when the tool cannot verify its original override still exists."""
        self.data.debug_check()
        self.run.reset_mock()
        (self.root / "local.xml").write_text("<config>")
        self.data.disable_debug()
        self.run.assert_not_called()

    def test_manual_enable_clears_stale_unavailable_status(self):
        """Clear an earlier unknown-state message once a valid external debug setting appears."""
        self.save_override(source=3, timestamp=int(time.time()) - 901)
        with self.assertLogs(level="WARNING"):
            self.data.debug_check()
        self.save_override(source=3)
        self.data.refresh_connector_logging(force=True)
        self.assertTrue(self.data.connector_logging.enabled)
        self.assertEqual(self.data.debug_error, "")
        self.assertFalse(self.data.enabled_debug)
        self.run.assert_not_called()

    def test_command_success_without_saved_override_is_not_owned(self):
        """Do not stop an unverified override simply because the CLI returned success."""
        self.run.side_effect = None
        self.run.return_value = subprocess.CompletedProcess([], 0)
        with patch.object(data_module.time, "sleep"):
            with self.assertLogs(level="WARNING"):
                self.data.debug_check()
        self.data.disable_debug()
        self.assertFalse(self.data.enabled_debug)
        self.assertEqual(self.run.call_count, 1)
        self.assertIn("could not be verified", self.data.debug_error)

    def test_old_unrelated_override_after_command_is_not_owned(self):
        """Reject an override outside the command window instead of clearing it on exit."""
        def delayed_old_record(args, **kwargs):
            """Simulate a concurrent saved record that predates the tool's command."""
            self.save_override(source=3, timestamp=int(time.time()) - 10)
            return subprocess.CompletedProcess(args, 0)

        self.run.side_effect = delayed_old_record
        with patch.object(data_module.time, "sleep"):
            with self.assertLogs(level="WARNING"):
                self.data.debug_check()
        self.data.disable_debug()
        self.assertFalse(self.data.enabled_debug)
        self.assertEqual(self.run.call_count, 1)

    def test_repeated_debug_check_keeps_original_cleanup_ownership(self):
        """Avoid reissuing start or losing ownership if debug_check is called twice."""
        self.data.debug_check()
        token = self.data._debug_override
        self.data.debug_check()
        self.assertEqual(self.run.call_count, 1)
        self.assertEqual(self.data._debug_override, token)
        self.data.disable_debug()
        self.assertEqual(self.run.call_count, 2)

    def test_cleanup_does_not_clear_policy_debug_enabled_during_run(self):
        """Release the tool's override while allowing the connector to restore its policy."""
        self.data.debug_check()
        (self.root / "policy.xml").write_text("<config><agent><log><level>1</level></log></agent></config>")
        self.data.disable_debug()
        self.assertTrue(self.data.connector_logging.enabled)
        self.assertFalse(self.data.enabled_debug)

    def test_main_close_cleans_up_verified_override(self):
        """Close the real Qt dashboard and verify its serialized cleanup command."""
        self.data.debug_check()
        populate_test_dashboard_metadata(self.data)
        window = main_page.MainWindow(data_factory=lambda: self.data)
        window.show()
        wait_until(lambda: window.data is not None and not window.runner.busy)
        window.close()
        wait_until(lambda: window.can_close and not window.runner.busy)
        self.assertEqual([call.args[0][-1] for call in self.run.call_args_list], ["start", "stop"])
        self.assertFalse(window.isVisible())

    def test_cancel_before_initialization_leaves_connector_untouched(self):
        """Exit before the first Qt event tick without starting connector operations."""
        create = Mock()
        window = main_page.MainWindow(data_factory=create)
        window.close()
        APP.processEvents()
        create.assert_not_called()
        self.run.assert_not_called()
        self.assertTrue(window.can_close)

    def test_initialization_failure_cleans_up_verified_override(self):
        """Clean up logging even when Data construction fails after enabling it."""
        def configure(instance):
            """Redirect only the test instance's connector paths to temporary fixtures."""
            instance.root_path = str(self.root)
            instance.path_prelude = str(self.root)

        def parse_policy(instance, path):
            """Supply a policy without API or platform access during construction."""
            instance.policy_dict = {"log_level": "0"}
            instance.policy_xml_root = ET.fromstring("<config><agent><log><level>0</level></log></agent></config>")

        with patch.object(Data, "check_for_amp"), patch.object(Data, "configure_connector_paths", configure):
            with patch.object(Data, "get_cpu_usage", return_value=0), patch.object(Data, "load_dotenv_data"), patch.object(Data, "verify_api_creds"):
                with patch.object(Data, "get_root", return_value=ET.fromstring("<config/>")), patch.object(Data, "parse_xml", parse_policy):
                    with patch.object(Data, "finish_initialization", side_effect=SystemExit("Initialization failed")):
                        with self.assertRaises(SystemExit):
                            Data()
        self.assertEqual([call.args[0][-1] for call in self.run.call_args_list], ["start", "stop"])

    def test_tool_log_selection_does_not_issue_connector_commands(self):
        """Keep Python INFO/WARNING/DEBUG selection independent of connector debug."""
        logger = main_page.logging.getLogger()
        original = logger.level
        try:
            for name in ("INFO", "WARNING", "DEBUG"):
                main_page.set_tool_log_level(name)
                self.assertEqual(logger.level, getattr(main_page.logging, name))
        finally:
            logger.setLevel(original)
        self.run.assert_not_called()


if __name__ == "__main__":
    unittest.main()
