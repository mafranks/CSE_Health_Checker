"""Test Data and GUI collection flows without Windows, API access, or a display."""

import importlib.util
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from qt_helpers import wait_until
from gui import TaskRunner
from sfc_log import SfcLogReader
from test_sfc_log import scan_event


class ProcessUnavailable(Exception):
    """Represent a process that exits or denies inspection during a test."""


class ApiRequestError(Exception):
    """Represent a requests transport failure without using a live API."""


def load_modules():
    """Import actual application code with only external/platform services stubbed."""
    root = Path(__file__).resolve().parents[1]
    psutil = SimpleNamespace(NoSuchProcess=ProcessUnavailable, AccessDenied=ProcessUnavailable,
                             process_iter=Mock(return_value=[]), cpu_count=Mock(return_value=4))
    registry = SimpleNamespace(HKEY_LOCAL_MACHINE=1, KEY_WOW64_64KEY=2, KEY_READ=4,
                               OpenKey=Mock(), QueryValueEx=Mock())
    requests = Mock()
    requests.exceptions = SimpleNamespace(RequestException=ApiRequestError)
    services = {"psutil": psutil, "winreg": registry,
                "requests": requests, "dotenv": SimpleNamespace(load_dotenv=Mock())}
    with patch.dict("sys.modules", services):
        spec = importlib.util.spec_from_file_location("data", root / "data.py")
        data = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(data)
    import popups
    import main_page
    return data, popups, main_page


data_module, popups, main_page = load_modules()
Data = data_module.Data


class HealthCheckerTests(unittest.TestCase):
    """Cover log collection, debug command failures, and active installation selection."""

    def setUp(self):
        """Create a Data instance without performing initialization/API requests."""
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.path = Path(directory.name) / "sfc.exe.log"
        self.data = Data.__new__(Data)
        self.data.sfc_path = str(self.path)
        self.data.default_sfc_path = str(self.path)
        self.data.path_prelude = directory.name
        self.data.root_path = directory.name
        self.data.region = "NAM"
        self.data.cpu_list = []
        self.data.current_cpu = 0.4
        self.data.policy_dict = {"log_level": "0"}
        (Path(directory.name) / "local.xml").write_text("<config><agent><log/></agent></config>")
        self.data.log_reader = SfcLogReader()
        self.data.get_cpu_usage = Mock(return_value=0.4)
        self.data.reset_scan_data()
        data_module.psutil.process_iter.reset_mock()
        data_module.psutil.process_iter.return_value = []
        data_module.winreg.OpenKey.reset_mock()
        data_module.winreg.OpenKey.side_effect = None
        data_module.winreg.QueryValueEx.reset_mock()
        data_module.winreg.QueryValueEx.side_effect = None

    def test_history_populates_both_views_once(self):
        """Populate process/path rankings and engine counters without repeat counting."""
        self.path.write_text(scan_event() + "Cache::Get: age 10\n")
        self.data.update()
        self.data.update()
        self.assertEqual(len(self.data.data), 1)
        self.assertEqual(self.data.cache_hit_count, 1)
        self.assertIn("worker.exe", self.data.get_top_processes(10))
        self.assertIn("sample.txt", self.data.convert_to_layout())
        self.assertEqual(self.data.get_log_status()[0], "RUNNING")

    def test_path_process_counts_group_pairs_across_timestamps(self):
        """Combine repeated pairs while retaining other processes and file paths."""
        process, other = r"C:\Example\worker.exe", r"C:\Example\other.exe"
        path, second = r"D:\Example\sample.txt", r"D:\Example\second.txt"
        self.data.data = [
            {"time": "first", "process": process, "path": path},
            {"time": "second", "process": process, "path": second},
            {"time": "third", "process": other, "path": path},
            {"time": "fourth", "process": process, "path": second},
            {"time": "fifth", "process": process, "path": second},
        ]
        self.assertEqual(self.data.get_path_process_counts(),
                         [(3, process, second), (1, process, path), (1, other, path)])
        self.assertEqual(sum(row[0] for row in self.data.get_path_process_counts()), 5)

    def test_pair_and_process_counts_ignore_scan_metadata(self):
        """Count new events once even when their metadata differs between scans."""
        self.path.write_text(scan_event() + scan_event().replace("flags=0", "flags=1"))
        self.data.update()
        self.data.update()
        process = r"C:\Program Files\Example\worker.exe"
        path = r"C:\Program Files (x86)\Example\sample.txt"
        self.assertEqual(self.data.get_path_process_counts(), [(2, process, path)])
        self.assertEqual(self.data.get_top_processes().split("|", 1)[1].strip(), process)
        self.assertEqual(self.data.get_top_processes().split("|", 1)[0].strip(), "2")
        self.data.reset_scan_data()
        self.data.update()
        self.assertEqual(self.data.get_path_process_counts(), [])

    def test_pair_export_preserves_full_paths_and_total_counts(self):
        """Export one row per pair without dropping Unicode, commas, or separators."""
        process = r"C:\Example, Inc\résumé.exe"
        path = r"D:\Example\資料 | sample.txt"
        self.data.data = [{"time": "first", "process": process, "path": path}] * 600
        self.assertEqual(self.data.get_path_process_counts(), [(600, process, path)])
        self.assertEqual(self.data.export_path_process_counts(),
                         f"Count | Process | File path\n600   | {process} | {path}")

    def test_malformed_event_does_not_stop_subsequent_records(self):
        """Ignore incomplete records while continuing to collect valid events."""
        self.path.write_text("Sep 22 10:31:18 Event::Handle invalid\n" + scan_event())
        self.data.update()
        self.assertEqual(len(self.data.data), 1)

    def test_read_failure_still_updates_cpu_and_status(self):
        """Show a read failure even though process CPU sampling succeeds."""
        with self.assertLogs(level="WARNING"):
            self.data.update()
        self.assertEqual(self.data.current_cpu, 0.4)
        self.assertEqual(self.data.get_log_status()[0], "LOG READ ERROR")

    def test_readable_unrecognized_log_waits_for_events(self):
        """Avoid displaying RUNNING when only unrelated connector activity exists."""
        self.path.write_text("Sep 22 10:31:18 unrelated activity\n")
        self.data.update()
        self.assertEqual(self.data.get_log_status()[0], "WAITING FOR SCAN EVENTS")

    def test_active_connector_beats_newer_inactive_folder(self):
        """Use the running build rather than an installed but inactive newer version."""
        active = Path(self.data.root_path) / "8.6.2.30642"
        newer = Path(self.data.root_path) / "8.7.0.31000"
        active.mkdir()
        newer.mkdir()
        (newer / "sfc.exe").touch()
        proc = Mock()
        proc.name.return_value = "sfc.exe"
        proc.exe.return_value = str(active / "sfc.exe")
        data_module.psutil.process_iter.return_value = [proc]
        self.data.configure_connector_paths()
        self.assertEqual(self.data.version, "8.6.2.30642")
        self.assertEqual(self.data.sfc_path, str(active / "sfc.exe.log"))

    def test_fallback_uses_numeric_version_order(self):
        """Select a valid executable folder and compare version parts numerically."""
        for version in ("8.9.0.10000", "8.10.0.10001", "9.0.0.99999"):
            folder = Path(self.data.root_path) / version
            folder.mkdir()
            if not version.startswith("9"):
                (folder / "sfc.exe").touch()
        with self.assertLogs(level="WARNING"):
            self.data.configure_connector_paths()
        self.assertEqual(self.data.version, "8.10.0.10001")

    def test_small_folder_rankings_retain_the_last_entries(self):
        """Keep one- and two-folder results that the legacy ranking loop dropped."""
        self.data.every_folder = [r"C:\Example\Cache"]
        self.assertIn(r"C:\Example\Cache", self.data.get_top_folders(10))
        self.data.every_folder.append(r"D:\Example")
        self.assertIn(r"D:\Example", self.data.get_top_folders(10))

    def test_folder_rankings_collapse_only_matching_parent_counts(self):
        """Preserve distinct folder counts while avoiding an identical adjacent parent summary."""
        self.data.every_folder = [r"C:\Example", r"C:\Example\Cache", r"D:\Example"]
        self.assertEqual(len(self.data.get_top_folders().splitlines()), 2)
        self.data.every_folder.append(r"C:\Example")
        self.assertEqual(len(self.data.get_top_folders().splitlines()), 3)

    def test_manual_analysis_isolated_from_live_cursor_and_data(self):
        """Reanalyze a static file without duplicating or redirecting live collection."""
        self.path.write_text(scan_event())
        self.data.update()
        live_offset = self.data.log_reader.offset
        other = self.path.with_name("customer.log")
        other.write_text(scan_event(path=r"D:\Customer\other.txt").rstrip("\n"))
        first = self.data.create_log_analysis(other)
        second = self.data.create_log_analysis(other)
        self.assertEqual(len(first.data), 1)
        self.assertEqual(len(second.data), 1)
        self.assertEqual(self.data.sfc_path, str(self.path))
        self.assertEqual(self.data.log_reader.offset, live_offset)
        self.assertIn("sample.txt", self.data.data[0]["path"])
        self.assertIn("other.txt", first.data[0]["path"])

    def test_reset_clears_all_rankings_without_replaying_history(self):
        """Reset folder/IP/exclusion lists along with counters and keep the read position."""
        self.path.write_text(scan_event() + "Exclusion::IsExcluded: result: 1 for C:\\test.txt\n")
        self.data.update()
        self.data.reset_scan_data()
        self.data.update()
        self.assertEqual(self.data.data, [])
        self.assertEqual(self.data.every_folder, [])
        self.assertEqual(self.data.excluded_list, [])
        self.assertEqual(self.data.excluded_count, 0)

    def test_missing_isolation_value_is_normal(self):
        """Treat absence of an unlock code as a normal nonisolated endpoint."""
        manager = Mock()
        manager.__enter__ = Mock(return_value=Mock())
        manager.__exit__ = Mock(return_value=False)
        data_module.winreg.OpenKey.return_value = manager
        data_module.winreg.QueryValueEx.side_effect = FileNotFoundError()
        with patch.object(data_module.logging, "warning") as warning:
            self.data.isolation_check()
        warning.assert_not_called()
        self.assertEqual(self.data.isolated, "Not Isolated")
        self.assertEqual(data_module.winreg.OpenKey.call_args.args[1], r"SOFTWARE\Immunet Protect")

    def test_isolation_read_failure_reports_unknown(self):
        """Avoid reporting Not Isolated when registry access actually fails."""
        data_module.winreg.OpenKey.side_effect = PermissionError("Denied")
        with self.assertLogs(level="WARNING"):
            self.data.isolation_check()
        self.assertEqual(self.data.isolated, "Unknown")

    def test_live_window_surfaces_log_read_error(self):
        """Start a real Qt live window and verify visible collection failure details."""
        runner = TaskRunner()
        window = popups.LiveScanDialog(self.data, runner)
        self.addCleanup(window.close)
        with self.assertLogs(level="WARNING"):
            window.start()
            wait_until(lambda: not runner.busy)
        self.assertEqual(window.status.text(), "LOG READ ERROR")
        self.assertIn(str(self.path), window.detail.text())

    def test_diagnostic_launch_uses_one_executable_path_and_resets_failure(self):
        """Preserve a spaced installation path as one process argument and allow successful retries."""
        self.data.path_prelude = r"C:\Program Files\Cisco\AMP\8.6.4.30695"
        self.data.diag_failed = True
        with patch.dict(data_module.os.environ, {"HOMEPATH": r"C:\Users\Example"}):
            with patch.object(data_module.shutil, "copy"):
                with patch.object(data_module.subprocess, "Popen") as launch:
                    self.data.generate_diagnostic()
        self.assertFalse(self.data.diag_failed)
        self.assertEqual(launch.call_args.args[0],
                         [data_module.os.path.join(self.data.path_prelude, "ipsupporttool.exe")])

    def test_analysis_refreshes_ips_and_status(self):
        """Refresh every real Qt analysis table, including IPs and collection status."""
        self.path.write_text(scan_event() + "NFMMemCache::Get: rip: 16843009\n")
        runner = TaskRunner()
        window = popups.AnalysisDialog(self.data, runner)
        self.addCleanup(window.close)
        window.refresh_data()
        wait_until(lambda: not runner.busy)
        self.assertEqual(window.status.text(), "RUNNING")
        self.assertEqual(window.tables["_top_ips"].item(0, 1).text(), "1.1.1.1")


if __name__ == "__main__":
    unittest.main()
