"""Exercise real file updates and representative connector event formats."""

import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from sfc_log import SfcLogReader, parse_scan_event


def scan_event(timestamp="Sep 22 10:31:18", extended=True,
               path=r"C:\Program Files (x86)\Example\sample.txt"):
    """Build the three-path event structure used by the existing connector parser."""
    prefix = "\\\\?\\" if extended else ""
    process = r"C:\Program Files\Example\worker.exe"
    return f"{timestamp} [123] Event::Handle EVENT_FILE_SCAN {prefix}{path}({prefix}{path}, {prefix}{process}, flags=0)\n"


class ScanEventTests(unittest.TestCase):
    """Check useful fields and reject incomplete or unrelated log records."""

    def test_supported_timestamp_variants(self):
        """Accept padded days and ISO timestamps without changing parsed paths."""
        timestamps = ("Sep 22 10:31:18", "Sep  2 10:31:18", "Sep 2 10:31:18",
                      "2026-09-22 10:31:18.123", "2026-09-22T10:31:18")
        for timestamp in timestamps:
            with self.subTest(timestamp=timestamp):
                result = parse_scan_event(scan_event(timestamp))
                self.assertEqual(result["time"], timestamp)
                self.assertEqual(result["path"], r"C:\Program Files (x86)\Example\sample.txt")
                self.assertEqual(result["process"].split(",")[0], r"C:\Program Files\Example\worker.exe")

    def test_normal_windows_paths(self):
        """Accept paths without the extended Windows prefix."""
        result = parse_scan_event(scan_event(extended=False))
        self.assertEqual(result["path"], r"C:\Program Files (x86)\Example\sample.txt")

    def test_unc_paths(self):
        """Preserve a network share path in the parsed scan event."""
        result = parse_scan_event(scan_event(extended=False, path=r"\\server\share\sample.txt"))
        self.assertEqual(result["path"], r"\\server\share\sample.txt")

    def test_extended_unc_and_volume_paths(self):
        """Retain support for extended share and volume paths accepted by the old parser."""
        result = parse_scan_event(scan_event(path=r"UNC\server\share\sample.txt"))
        self.assertEqual(result["path"], r"\\server\share\sample.txt")
        result = parse_scan_event(scan_event(path=r"Volume{1234}\folder\sample.txt"))
        self.assertEqual(result["path"], r"Volume{1234}\folder\sample.txt")

    def test_malformed_records(self):
        """Reject incomplete paths, absent timestamps, and unrelated operations."""
        records = (None, "", "Sep 22 10:31:18 Event::Handle no paths",
                   r"Sep 22 10:31:18 Event::Handle \\?\C:\one.txt(\\?\C:\one.txt" ,
                   scan_event().split("Event::Handle", 1)[1],
                   scan_event().replace("Event::Handle", "Other::Handle"))
        for record in records:
            with self.subTest(record=record):
                self.assertIsNone(parse_scan_event(record))


class LogReaderTests(unittest.TestCase):
    """Follow files across appends, replacements, truncation, and read errors."""

    def setUp(self):
        """Create an independent temporary log and reader for each test."""
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.path = Path(directory.name) / "sfc.exe.log"
        self.reader = SfcLogReader()

    def test_initial_history_and_no_duplicate_polling(self):
        """Read existing history exactly once, including a single-line file."""
        self.path.write_text("first\nsecond\n")
        self.assertEqual(self.reader.read_new_lines(self.path), ["first", "second"])
        self.assertEqual(self.reader.read_new_lines(self.path), [])
        self.path.write_text("single\n")
        self.assertEqual(self.reader.read_new_lines(self.path), ["single"])

    def test_identical_appended_records_are_distinct_events(self):
        """Use position rather than line content to distinguish repeated events."""
        self.path.write_text("same\n")
        self.assertEqual(self.reader.read_new_lines(self.path), ["same"])
        with self.path.open("a") as output:
            output.write("same\n")
        self.assertEqual(self.reader.read_new_lines(self.path), ["same"])
        self.assertEqual(self.reader.read_new_lines(self.path), [])

    def test_partial_lines_wait_for_completion(self):
        """Avoid consuming a record while the connector is still writing it."""
        self.path.write_text("complete\npart")
        self.assertEqual(self.reader.read_new_lines(self.path), ["complete"])
        self.assertEqual(self.reader.read_new_lines(self.path), [])
        with self.path.open("a") as output:
            output.write("ial\n")
        self.assertEqual(self.reader.read_new_lines(self.path), ["partial"])

    def test_static_analysis_accepts_final_line_without_newline(self):
        """Include the final record of a completed manual snapshot."""
        self.path.write_text("first\nlast")
        self.assertEqual(self.reader.read_new_lines(self.path, include_partial=True), ["first", "last"])

    def test_replaced_log_is_read_from_beginning(self):
        """Rewind when a rotated log replaces the existing path."""
        self.path.write_text("old record\n")
        self.reader.read_new_lines(self.path)
        replacement = self.path.with_name("replacement.log")
        replacement.write_text("new first\nnew second\n")
        os.replace(replacement, self.path)
        self.assertEqual(self.reader.read_new_lines(self.path), ["new first", "new second"])

    def test_in_place_rewrite_larger_than_old_file(self):
        """Detect truncation and regrowth even when the file identity is unchanged."""
        self.path.write_text("old\n")
        self.reader.read_new_lines(self.path)
        self.path.write_text("replacement\nsecond\n")
        self.assertEqual(self.reader.read_new_lines(self.path), ["replacement", "second"])

    def test_switching_paths_starts_new_analysis(self):
        """Read a selected second file even when its records resemble the first."""
        self.path.write_text("first\n")
        self.reader.read_new_lines(self.path)
        other = self.path.with_name("other.log")
        other.write_text("first\nsecond\n")
        self.assertEqual(self.reader.read_new_lines(other), ["first", "second"])

    def test_read_error_and_recovery(self):
        """Expose missing-file errors, then recover when the log becomes available."""
        with self.assertLogs(level="WARNING"):
            self.assertEqual(self.reader.read_new_lines(self.path), [])
        self.assertIn("Unable to read SFC log", self.reader.error)
        self.path.write_text("recovered\n")
        self.assertEqual(self.reader.read_new_lines(self.path), ["recovered"])
        self.assertEqual(self.reader.error, "")

    def test_permission_denied(self):
        """Report inaccessible logs without raising through the GUI update."""
        with patch("builtins.open", side_effect=PermissionError("Access is denied")):
            with self.assertLogs(level="WARNING"):
                self.assertEqual(self.reader.read_new_lines(self.path), [])
        self.assertIn("Access is denied", self.reader.error)

    def test_empty_log(self):
        """Distinguish a readable empty log from a read failure."""
        self.path.write_text("")
        self.assertEqual(self.reader.read_new_lines(self.path), [])
        self.assertTrue(self.reader.empty)
        self.assertEqual(self.reader.error, "")


if __name__ == "__main__":
    unittest.main()
