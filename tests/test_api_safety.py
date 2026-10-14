"""Exercise authenticated policy retrieval with synthetic credentials and no network access."""

import logging
from unittest import TestCase
from unittest.mock import Mock, patch
import xml.etree.ElementTree as ET

from test_health_checker import Data, data_module


LOCAL_GUID = "00000000-0000-4000-8000-000000000002"


def response(payload=None, status=200, content=b""):
    """Create a synthetic bounded API response for a single request."""
    return Mock(status_code=status, json=Mock(return_value=payload), content=content)


class ApiSafetyTests(TestCase):
    """Reject malformed authentication and keep credentials and policy data out of logs."""

    def setUp(self):
        """Create an uninitialized backend with clearly synthetic local settings."""
        self.data = Data.__new__(Data)
        self.data.region = "NAM"
        self.data.client_id, self.data.api_key = "example-client", "example-api-key"
        self.data.sx_client_id, self.data.sx_api_key = "example-xdr-client", "example-xdr-key"
        self.data.auth = (self.data.client_id, self.data.api_key)
        self.data.proxies = {"https": "http://proxy.example:3128"}
        self.data.org_name = "Example organization"
        self.data.local_uuid = LOCAL_GUID
        self.data.set_region_urls()

    def test_empty_credentials_do_not_make_a_request(self):
        """Treat absent optional API credentials as unavailable without sending empty authentication."""
        self.data.client_id = ""
        with patch.object(data_module.requests, "get") as get:
            self.data.verify_api_creds()
        get.assert_not_called()
        self.assertFalse(self.data.api_cred_valid)

    def test_token_exchange_preserves_proxy_and_never_logs_tokens(self):
        """Exchange both token stages with bounded requests without logging credentials or bearer tokens."""
        replies = [response({"access_token": "example-xdr-token"}), response({"access_token": "example-endpoint-token"})]
        with patch.object(data_module.requests, "post", side_effect=replies) as post:
            with patch.object(logging, "debug") as debug:
                token = self.data.get_se_access_token()
        self.assertEqual(token, "example-endpoint-token")
        self.assertEqual(post.call_count, 2)
        debug.assert_not_called()
        for call in post.call_args_list:
            self.assertEqual(call.kwargs["proxies"], self.data.proxies)
            self.assertEqual(call.kwargs["timeout"], 15)

    def test_authentication_http_and_payload_failures_are_rejected(self):
        """Stop at failed HTTP or missing tokens instead of passing a None bearer value onward."""
        cases = (response({}, 401), response({}), response({"access_token": None}), response([]))
        self.assertEqual(self.data.response_access_token(response({"access_token": "example-token"}, 201)), "example-token")
        for reply in cases:
            with self.subTest(status=reply.status_code), self.assertRaises(RuntimeError):
                self.data.response_access_token(reply)

    def test_cloud_policy_fetch_checks_status_and_does_not_log_payloads(self):
        """Resolve the selected organization and parse XML without logging any API response body."""
        replies = [response({"data": [{"name": "Example organization", "organizationIdentifier": "example-org"}]}),
                   response(content=b"<config><agent/></config>")]
        with patch.object(self.data, "get_policy_api_data", return_value={"policy": {"guid": LOCAL_GUID}}):
            with patch.object(self.data, "get_se_access_token", return_value="example-token"):
                with patch.object(data_module.requests, "get", side_effect=replies) as get:
                    with patch.object(logging, "debug") as debug:
                        root = self.data.pull_policy_from_sx()
        self.assertEqual(root.tag, "config")
        self.assertTrue(get.call_args.args[0].endswith(f"/example-org/policies/{LOCAL_GUID}/xml"))
        debug.assert_not_called()

    def test_private_policy_fetch_preserves_custom_ca(self):
        """Keep Private Cloud trust configuration and reject unsuccessful policy downloads."""
        self.data.region, self.data.pc_domain, self.data.pc_ca_path = "PC", "example.invalid", "example-ca.pem"
        self.data.set_region_urls()
        with patch.object(self.data, "get_policy_api_data", return_value={"policy": {"guid": LOCAL_GUID}}):
            with patch.object(data_module.requests, "get", return_value=response(content=b"<config/>")) as get:
                self.assertEqual(self.data.pull_private_policy().tag, "config")
            self.assertEqual(get.call_args.kwargs["verify"], "example-ca.pem")
            with patch.object(data_module.requests, "get", return_value=response(status=403)):
                with self.assertRaises(data_module.PolicyLookupError):
                    self.data.pull_private_policy()

    def test_policy_collection_omits_unneeded_sensitive_settings(self):
        """Read dashboard fields without retaining proxy passwords or uninstall settings in the policy dictionary."""
        root = ET.fromstring('<config><proxy><password>example-only</password></proxy></config>')
        with patch.object(self.data, "get_root", return_value=root):
            with patch.object(logging, "debug") as debug:
                self.data.parse_xml("example.xml")
        self.assertNotIn("proxy_password", self.data.policy_dict)
        self.assertNotIn("uninstall_password", self.data.policy_dict)
        debug.assert_not_called()
