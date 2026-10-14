"""Check standalone regional settings, socket failures, and HTTP CONNECT handling."""

import base64
import os
import threading
import unittest
from unittest.mock import Mock, patch

import connectivity


class ConnectivityTests(unittest.TestCase):
    """Exercise network configuration without a connector, API credentials, or remote servers."""

    def test_missing_env_and_credentials_use_visible_nam_default(self):
        """Allow connectivity settings to load with no installation-specific configuration."""
        with patch.dict(os.environ, {}, clear=True), patch.object(connectivity, "load_dotenv"):
            settings = connectivity.environment_settings()
        self.assertEqual(settings, connectivity.ConnectivitySettings())
        self.assertGreater(len(connectivity.endpoints_for_region(settings.region)), 0)

    def test_region_domain_and_proxy_load_without_api_fields(self):
        """Read only the optional network settings when API credentials are absent."""
        values = {"REGION": " pc ", "PC_DOMAIN": "private.example", "PROXIES": "{'https': 'http://proxy.example:8080'}"}
        with patch.dict(os.environ, values, clear=True), patch.object(connectivity, "load_dotenv"):
            settings = connectivity.environment_settings()
        self.assertEqual(settings.region, "PC")
        self.assertEqual(settings.domain, "private.example")
        self.assertEqual(connectivity.parse_proxy(settings.proxies).port, 8080)

    def test_invalid_proxy_env_is_reported_before_connecting(self):
        """Reject malformed proxy input instead of accidentally running a direct connection."""
        for value in ("invalid", "[]", "'http://proxy.example'"):
            with self.subTest(value=value):
                with patch.dict(os.environ, {"PROXIES": value}, clear=True), patch.object(connectivity, "load_dotenv"):
                    with self.assertRaises(ValueError):
                        connectivity.environment_settings()

    def test_private_cloud_endpoints_follow_current_domain(self):
        """Generate fresh names after a domain change without relying on imported environment values."""
        first = connectivity.endpoints_for_region("PC", "first.example")
        second = connectivity.endpoints_for_region("PC", "second.example")
        self.assertEqual(len(first), len(second))
        self.assertTrue(all(host.endswith(".second.example") for host in second))
        self.assertNotEqual(first, second)

    def test_invalid_domains_and_regions_do_not_reach_sockets(self):
        """Reject missing domains, URLs, invalid labels, and unknown cloud regions."""
        for domain in ("", "https://example.local", "example.local:443", "example\r\nInjected", "-bad.example"):
            with self.subTest(domain=domain):
                with self.assertRaises(ValueError):
                    connectivity.endpoints_for_region("PC", domain)
        with self.assertRaises(ValueError):
            connectivity.endpoints_for_region("UNKNOWN")

    def test_endpoint_failures_are_reported_and_remaining_hosts_continue(self):
        """Collect both success and failure outcomes while emitting progress for each host."""
        progress = Mock()
        with patch.object(connectivity, "endpoint_reachable", side_effect=[OSError("timed out"), None]):
            with self.assertLogs(level="WARNING"):
                results = connectivity.check_endpoints(["bad.example", "good.example"], on_result=progress)
        self.assertEqual(results, {"bad.example": "Red", "good.example": "Green"})
        self.assertEqual([call.args for call in progress.call_args_list], [("bad.example", "Red"), ("good.example", "Green")])

    def test_cancellation_stops_between_endpoint_checks(self):
        """Honor a closed dialog's cancellation event before starting the next host."""
        cancelled = threading.Event()
        with patch.object(connectivity, "endpoint_reachable") as check:
            results = connectivity.check_endpoints(["one.example", "two.example"], cancelled=cancelled.is_set,
                                                   on_result=lambda host, color: cancelled.set())
        self.assertEqual(results, {"one.example": "Green"})
        check.assert_called_once()

    def test_invalid_parameters_fail_before_any_network_requests(self):
        """Validate callbacks, endpoint collections, and proxy types before socket access."""
        with patch.object(connectivity, "endpoint_reachable") as check:
            for kwargs in ({"endpoints": "not-a-list"}, {"endpoints": ["bad/host"]},
                           {"endpoints": ["valid.example"], "cancelled": True},
                           {"endpoints": ["valid.example"], "proxies": []}):
                with self.subTest(kwargs=kwargs), self.assertRaises(ValueError):
                    connectivity.check_endpoints(**kwargs)
        check.assert_not_called()

    def test_connect_tunnel_reads_fragmented_headers_and_authenticates_proxy(self):
        """Wait for complete proxy headers and safely encode configured credentials."""
        proxy = connectivity.parse_proxy({"https": "http://user%40name:pa%3Ass@proxy.example:8080"})
        sock = Mock()
        sock.recv.side_effect = [b"HTTP/1.1 200", b" OK\r\nProxy-Agent: example\r\n", b"\r\n"]
        connectivity.open_tunnel(sock, "endpoint.example", proxy)
        request = sock.sendall.call_args.args[0]
        expected = base64.b64encode(b"user@name:pa:ss")
        self.assertIn(b"CONNECT endpoint.example:443 HTTP/1.1\r\n", request)
        self.assertIn(b"Proxy-Authorization: Basic " + expected + b"\r\n", request)
        self.assertEqual(sock.recv.call_count, 3)
        self.assertTrue(all(0 < call.args[0] <= 10 for call in sock.settimeout.call_args_list))

    def test_proxy_refusal_and_incomplete_response_are_failures(self):
        """Avoid reporting TLS reachability when CONNECT did not establish a complete tunnel."""
        proxy = connectivity.parse_proxy({"http": "http://proxy.example"})
        for chunks in ([b"HTTP/1.1 407 Authentication Required\r\n\r\n"], [b"HTTP/1.1 200 OK\r\n", b""]):
            with self.subTest(chunks=chunks):
                sock = Mock()
                sock.recv.side_effect = chunks
                with self.assertRaises(OSError):
                    connectivity.open_tunnel(sock, "endpoint.example", proxy)


if __name__ == "__main__":
    unittest.main()
