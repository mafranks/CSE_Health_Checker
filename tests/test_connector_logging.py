"""Verify policy conversion and saved override semantics against connector source."""

from pathlib import Path
import tempfile
import unittest
import xml.etree.ElementTree as ET

from connector_logging import read_logging_settings, resolve_logging_state


def saved_override(level=6, source=3, timestamp=1000):
    """Create a persisted logging record using the connector's native field names."""
    return {"local_level": str(level), "local_source": str(source), "local_time_set": str(timestamp)}


class ConnectorLoggingTests(unittest.TestCase):
    """Separate policy masks from severity enums and handle override uncertainty."""

    def test_every_valid_nonzero_policy_value_enables_debug(self):
        """Recognize small values and historical masks without requiring an exact mask."""
        for level in (1, 3, 6, 17179869183, 549755813887, " 1 "):
            with self.subTest(level=level):
                state = resolve_logging_state({"level": level}, {}, {}, 1000)
                self.assertTrue(state.enabled)
                self.assertFalse(state.may_enable)

    def test_zero_and_missing_sentinel_use_error_logging(self):
        """Match the connector's zero/default error severity and -1 sentinel handling."""
        for level in (0, "0", -1):
            with self.subTest(level=level):
                state = resolve_logging_state({"level": level}, {}, {}, 1000)
                self.assertFalse(state.enabled)
                self.assertTrue(state.may_enable)

    def test_global_default_supplies_missing_policy_level(self):
        """Use the connector's readable default when policy has no explicit level."""
        state = resolve_logging_state({}, {}, {"level": "1"}, 1000)
        self.assertTrue(state.enabled)
        self.assertFalse(state.may_enable)

    def test_local_debug_overrides_policy_zero(self):
        """Recognize GUI/CLI debug without requiring the policy XML value to change."""
        state = resolve_logging_state({"level": "0"}, saved_override(), {}, 1100)
        self.assertTrue(state.enabled)
        self.assertFalse(state.may_enable)
        self.assertEqual(state.source, "local setting")
        self.assertEqual(state.override, (6, 3, 1000))

    def test_all_preexisting_sources_are_preserved(self):
        """Preserve crash, local, debug-pipe, and remote overrides."""
        for source in (2, 3, 4, 5):
            with self.subTest(source=source):
                state = resolve_logging_state({"level": "0"}, saved_override(source=source), {}, 1100)
                self.assertTrue(state.enabled)
                self.assertFalse(state.may_enable)

    def test_nonzero_local_severity_is_not_a_policy_mask(self):
        """Do not interpret runtime severity 3 as debug simply because it is nonzero."""
        state = resolve_logging_state({"level": "1"}, saved_override(level=3), {}, 1100)
        self.assertFalse(state.enabled)
        self.assertFalse(state.may_enable)

    def test_expiry_boundary_matches_connector_seconds(self):
        """Keep overrides valid at the exact lifetime boundary and uncertain after expiry."""
        for now in (1900, 1900.9):
            self.assertTrue(resolve_logging_state({"level": "0"}, saved_override(), {}, now).enabled)
        expired = resolve_logging_state({"level": "0"}, saved_override(), {}, 1901)
        self.assertIsNone(expired.enabled)
        self.assertFalse(expired.may_enable)
        self.assertEqual(expired.expires_at, 1900)
        self.assertEqual(expired.override, (6, 3, 1000))

    def test_policy_duration_takes_precedence_over_global_default(self):
        """Respect the configured lifetime rather than always assuming 15 minutes."""
        policy = {"level": "0", "minimum_logging_persistence_duration_s": "1200"}
        defaults = {"minimum_logging_persistence_duration_s": "600"}
        self.assertTrue(resolve_logging_state(policy, saved_override(), defaults, 2100).enabled)
        self.assertIsNone(resolve_logging_state({"level": "0"}, saved_override(), defaults, 2100).enabled)

    def test_incomplete_or_unsupported_override_is_unknown(self):
        """Avoid changing settings when persisted override metadata is incomplete or invalid."""
        settings = ({"local_level": "6"}, saved_override(source=1),
                    saved_override(level=0), saved_override(level=7), saved_override(timestamp=-2))
        for local in settings:
            with self.subTest(local=local):
                state = resolve_logging_state({"level": "0"}, local, {}, 1100)
                self.assertIsNone(state.enabled)
                self.assertFalse(state.may_enable)

    def test_invalid_policy_values_are_unknown(self):
        """Reject malformed, negative, fractional, boolean, and overflowing policy values."""
        for level in ("invalid", -2, 3.5, True, 1 << 63):
            with self.subTest(level=level):
                state = resolve_logging_state({"level": level}, {}, {}, 1100)
                self.assertIsNone(state.enabled)
                self.assertFalse(state.may_enable)

    def test_clock_rollback_preserves_override_like_connector(self):
        """Keep a saved override when the current clock is earlier than its set timestamp."""
        state = resolve_logging_state({"level": "0"}, saved_override(timestamp=1200), {}, 1100)
        self.assertTrue(state.enabled)
        self.assertFalse(state.may_enable)

    def test_crash_recovery_without_manual_metadata_is_preserved(self):
        """Recognize the connector's automatic crash logging during its initial logging window."""
        for count in (3, 4, 5, 6, 7):
            with self.subTest(count=count):
                local = {"consecutive_unclean_shutdown_count": str(count)}
                state = resolve_logging_state({"level": "0"}, local, {}, 1100, started_at=1000)
                self.assertTrue(state.enabled)
                self.assertFalse(state.may_enable)
                self.assertEqual(state.source, "crash recovery")

    def test_crash_recovery_after_window_or_unknown_uptime_is_uncertain(self):
        """Avoid assuming the crash override reset merely because process uptime exceeds the window."""
        local = {"consecutive_unclean_shutdown_count": "3"}
        for started_at in (None, 1000):
            with self.subTest(started_at=started_at):
                state = resolve_logging_state({"level": "0"}, local, {}, 2000, started_at=started_at)
                self.assertIsNone(state.enabled)
                self.assertFalse(state.may_enable)

    def test_crash_counts_outside_auto_debug_range_use_policy(self):
        """Match the connector's limit of only three through seven consecutive crashes."""
        for count in (0, 1, 2, 8, 9):
            with self.subTest(count=count):
                local = {"consecutive_unclean_shutdown_count": str(count)}
                state = resolve_logging_state({"level": "0"}, local, {}, 1100, started_at=1000)
                self.assertFalse(state.enabled)
                self.assertTrue(state.may_enable)

    def test_namespaced_xml_settings(self):
        """Read current field names from a signed namespace-qualified XML document."""
        xml = ('<SignedInfo xmlns="http://www.w3.org/2000/09/xmldsig#"><Object><config>'
               '<agent><log><level>1</level><minimum_logging_persistence_duration_s>1200</minimum_logging_persistence_duration_s>'
               '</log></agent></config></Object></SignedInfo>')
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "policy.xml"
            path.write_text(xml)
            settings = read_logging_settings(path)
        self.assertEqual(settings["level"], "1")
        self.assertEqual(settings["minimum_logging_persistence_duration_s"], "1200")

    def test_bad_xml_is_rejected(self):
        """Expose malformed configuration for the application to report as unknown."""
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "local.xml"
            path.write_text("<config>")
            with self.assertRaises(ET.ParseError):
                read_logging_settings(path)


if __name__ == "__main__":
    unittest.main()
