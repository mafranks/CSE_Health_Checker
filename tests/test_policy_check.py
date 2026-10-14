"""Reproduce successful and failed policy lookups without customer credentials."""

from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch

from test_health_checker import ApiRequestError, Data, data_module, popups


LOCAL_POLICY = "00000000-0000-0000-0000-000000000001"
ASSIGNED_POLICY = "00000000-0000-0000-0000-000000000002"
CONNECTOR = "00000000-0000-0000-0000-000000000003"


def response(status=200, data=None):
    """Build an API envelope with an independent HTTP status for each request."""
    result = Mock(status_code=status)
    result.json.return_value = {"data": {} if data is None else data}
    return result


class PolicyVersionTests(unittest.TestCase):
    """Check serial comparisons, bounded recovery, and honest GUI failure states."""

    def setUp(self):
        """Create a minimal policy-check instance and intercept every API request."""
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.data = Data.__new__(Data)
        self.data.root_path = directory.name
        self.data.local_uuid = CONNECTOR
        self.data.region = "EU"
        self.data.auth = ("test-client", "test-key")
        self.data.proxies = None
        self.data.api_cred_valid = True
        self.data.policy_dict = {"policy_uuid": LOCAL_POLICY, "policy_sn": "4147"}
        requests = patch.object(data_module.requests, "get")
        self.get = requests.start()
        self.addCleanup(requests.stop)

    def test_matching_serial_is_green_and_uses_https(self):
        """Compare a verified cloud serial to the locally installed serial."""
        self.get.return_value = response(data={"serial_number": 4147})
        self.assertTrue(self.data.policy_serial_compare(LOCAL_POLICY, "4147"))
        self.assertEqual(self.data.policy_color, "Green")
        self.assertEqual(self.data.get_policy_check_text(), "Latest Serial: 4147")
        self.assertEqual(self.get.call_args.args[0], f"https://api.eu.amp.cisco.com/v1/policies/{LOCAL_POLICY}")
        self.assertEqual(self.get.call_args.kwargs["timeout"], 10)

    def test_different_verified_serial_is_red(self):
        """Use red only when a successful lookup establishes a serial mismatch."""
        self.get.return_value = response(data={"serial_number": 4148})
        self.assertTrue(self.data.policy_serial_compare(LOCAL_POLICY, "4147"))
        self.assertEqual(self.data.policy_serial, 4148)
        self.assertEqual(self.data.policy_color, "Red")

    def test_not_found_retries_current_connector_assignment(self):
        """Recover a missing local policy GUID through the current cloud assignment."""
        self.get.side_effect = [response(404), response(data={"policy": {"guid": ASSIGNED_POLICY}}),
                                response(data={"serial_number": 4148})]
        with self.assertLogs(level="WARNING"):
            self.assertTrue(self.data.policy_serial_compare(LOCAL_POLICY, "4147"))
        self.assertEqual(self.get.call_count, 3)
        self.assertEqual(self.data.latest_policy_uuid, ASSIGNED_POLICY)
        self.assertEqual(self.data.policy_dict["policy_uuid"], LOCAL_POLICY)
        self.assertEqual(self.data.policy_serial, 4148)
        self.assertEqual(self.data.policy_color, "Yellow")
        self.assertIn("identifiers differ", self.data.get_policy_check_text())

    def test_customer_404_with_same_assignment_reports_error(self):
        """Keep valid credential status but report the failed lookup instead of None/red."""
        self.get.side_effect = [response(404), response(data={"policy": {"guid": LOCAL_POLICY}})]
        with self.assertLogs(level="WARNING"):
            self.assertFalse(self.data.policy_serial_compare(LOCAL_POLICY, "4147"))
        self.assertTrue(self.data.api_cred_valid)
        self.assertIsNone(self.data.policy_serial)
        self.assertEqual(self.data.policy_color, "Yellow")
        self.assertIn("Policy not found", self.data.get_policy_check_text())
        self.assertNotIn("None", self.data.get_policy_check_text())
        self.assertEqual(self.get.call_count, 2)

    def test_connector_inaccessible_in_selected_organization(self):
        """Do not guess another policy when the connector also returns 404."""
        self.get.side_effect = [response(404), response(404)]
        with self.assertLogs(level="WARNING"):
            self.assertFalse(self.data.policy_serial_compare(LOCAL_POLICY, "4147"))
        self.assertIn("Connector not found", self.data.get_policy_check_text())
        self.assertEqual(self.data.policy_color, "Yellow")

    def test_missing_connector_policy_assignment_stops_fallback(self):
        """Report incomplete connector data without issuing an unverified policy request."""
        self.get.side_effect = [response(404), response(data={})]
        with self.assertLogs(level="WARNING"):
            self.assertFalse(self.data.policy_serial_compare(LOCAL_POLICY, "4147"))
        self.assertEqual(self.get.call_count, 2)
        self.assertIn("no assigned policy", self.data.get_policy_check_text())

    def test_invalid_identifier_does_not_make_api_request(self):
        """Reject missing or malformed identifiers before using them in request paths."""
        for guid in (None, "", "invalid", "../version"):
            with self.subTest(guid=guid):
                with self.assertLogs(level="WARNING"):
                    self.assertFalse(self.data.policy_serial_compare(guid, "4147"))
                self.assertIn("identifier is missing or invalid", self.data.get_policy_check_text())
        self.get.assert_not_called()

    def test_invalid_api_envelopes_are_rejected(self):
        """Reject unexpected data shapes and error envelopes even with HTTP 200."""
        for payload in ([], {"data": []}, {"data": {}, "errors": [{"description": "Failed"}]}):
            with self.subTest(payload=payload):
                result = response()
                result.json.return_value = payload
                self.get.return_value = result
                with self.assertLogs(level="WARNING"):
                    self.assertFalse(self.data.policy_serial_compare(LOCAL_POLICY, "4147"))
                self.assertEqual(self.data.policy_color, "Yellow")
                self.assertIn("Invalid policy API response", self.data.get_policy_check_text())

    def test_access_denied_and_server_errors_do_not_retry(self):
        """Distinguish authorization/API failures from stale identifiers and version mismatches."""
        for status in (401, 403, 429, 500):
            with self.subTest(status=status):
                self.get.reset_mock()
                self.get.return_value = response(status)
                with self.assertLogs(level="WARNING"):
                    self.assertFalse(self.data.policy_serial_compare(LOCAL_POLICY, "4147"))
                self.assertEqual(self.get.call_count, 1)
                self.assertEqual(self.data.policy_color, "Yellow")
                self.assertIn(str(status), self.data.get_policy_check_text())

    def test_error_clears_stale_successful_serial(self):
        """Avoid showing an earlier successful cloud serial after the next request fails."""
        self.get.return_value = response(data={"serial_number": 4147})
        self.data.policy_serial_compare(LOCAL_POLICY, "4147")
        self.get.return_value = response(403)
        with self.assertLogs(level="WARNING"):
            self.data.policy_serial_compare(LOCAL_POLICY, "4147")
        self.assertIsNone(self.data.policy_serial)
        self.assertIn("API access denied", self.data.get_policy_check_text())

    def test_missing_or_invalid_cloud_serial_is_not_a_mismatch(self):
        """Reject missing, negative, fractional, and boolean serial values."""
        for serial in (None, "invalid", -1, 3.5, True):
            with self.subTest(serial=serial):
                self.get.return_value = response(data={"serial_number": serial})
                with self.assertLogs(level="WARNING"):
                    self.assertFalse(self.data.policy_serial_compare(LOCAL_POLICY, "4147"))
                self.assertEqual(self.data.policy_color, "Yellow")

    def test_zero_and_camel_case_serials(self):
        """Accept serial zero and the documented camel-case serial field."""
        self.get.return_value = response(data={"serialNumber": 0})
        self.assertTrue(self.data.policy_serial_compare(LOCAL_POLICY, "0"))
        self.assertEqual(self.data.policy_color, "Green")

    def test_transport_and_json_failures_do_not_crash(self):
        """Show a recoverable failure for network timeouts and non-JSON responses."""
        self.get.side_effect = ApiRequestError("Request timed out")
        with self.assertLogs(level="WARNING"):
            self.assertFalse(self.data.policy_serial_compare(LOCAL_POLICY, "4147"))
        self.get.side_effect = None
        result = response()
        result.json.side_effect = ValueError("Invalid JSON")
        self.get.return_value = result
        with self.assertLogs(level="WARNING"):
            self.assertFalse(self.data.policy_serial_compare(LOCAL_POLICY, "4147"))
        self.assertEqual(self.data.policy_color, "Yellow")

    def test_private_cloud_retains_ca_and_proxy_settings(self):
        """Use the configured Private Cloud host, certificate, and proxy for policy checks."""
        self.data.region = "PC"
        self.data.pc_domain = "example.invalid"
        self.data.pc_ca_path = "rootCA.crt"
        self.data.proxies = {"https": "http://proxy.invalid:8080"}
        self.get.return_value = response(data={"serial_number": 4147})
        self.assertTrue(self.data.policy_serial_compare(LOCAL_POLICY, "4147"))
        self.assertEqual(self.get.call_args.args[0], f"https://console.example.invalid/v1/policies/{LOCAL_POLICY}")
        self.assertEqual(self.get.call_args.kwargs["verify"], "rootCA.crt")
        self.assertEqual(self.get.call_args.kwargs["proxies"], self.data.proxies)

    def test_local_refresh_updates_identifier_as_well_as_serial(self):
        """Avoid using a stale in-memory GUID after the installed XML policy changes."""
        namespace = "http://www.w3.org/2000/09/xmldsig#"
        policy = (f'<SignedInfo xmlns="{namespace}"><Object><config><janus><policy>'
                  f'<uuid>{ASSIGNED_POLICY}</uuid><serial_number>4148</serial_number>'
                  '</policy></janus></config></Object></SignedInfo>')
        (Path(self.data.root_path) / "policy.xml").write_text(policy)
        self.data.refresh_local_policy_serial()
        self.assertEqual(self.data.policy_dict["policy_uuid"], ASSIGNED_POLICY)
        self.assertEqual(self.data.policy_dict["policy_sn"], "4148")

    def test_policy_action_reports_lookup_error(self):
        """Preserve explanatory policy failures in the background action used by Qt."""
        self.data.refresh_local_policy_serial = Mock()
        self.get.return_value = response(403)
        with self.assertLogs(level="WARNING"):
            popups.check_policy(self.data)
        self.assertIn("API access denied", self.data.get_policy_check_text())
        self.assertEqual(self.data.policy_color, "Yellow")


if __name__ == "__main__":
    unittest.main()
