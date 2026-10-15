"""Verify catalog refresh, dated fallback, and process matching without live services."""

import base64
import hashlib
import json
import unittest
from unittest.mock import Mock, patch

import recommendations as rec


class RecommendationTests(unittest.TestCase):
    """Keep recommendations advisory, deterministic, and independent of API credentials."""

    def response(self, source):
        """Return a bounded fake public GitHub contents response with its Git blob digest."""
        raw = source.encode()
        digest = hashlib.sha1(f"blob {len(raw)}\0".encode() + raw).hexdigest()
        payload = json.dumps({"content": base64.b64encode(raw).decode(), "sha": digest}).encode()
        return Mock(status_code=200, iter_content=Mock(return_value=[payload]))

    def test_matches_case_insensitively_and_deduplicates_running_processes(self):
        """Match full paths and repeated process names once per applicable product set."""
        products = {"Example Product": ["worker.exe", "other.exe"], "Second Product": ["worker.exe"]}
        matches = rec.match_products([r"C:\Example\WORKER.EXE", "WORKER.EXE", "unrelated.exe"], products)
        self.assertEqual(matches["Example Product"], ("WORKER.EXE",))
        self.assertEqual(matches["Second Product"], ("WORKER.EXE",))
        self.assertEqual(matches["Microsoft Windows Default"], ("Windows baseline",))

    def test_catalog_data_is_read_without_executing_downloaded_code(self):
        """Accept literal data and reject function calls or malformed product entries."""
        source = 'TEMP_MAINTAINED_EXCLUSIONS = {"Example": ["worker.exe"]}'
        self.assertEqual(rec.parse_catalog_source(source), {"Example": ["worker.exe"]})
        for value in ('TEMP_MAINTAINED_EXCLUSIONS = dict(Example=["worker.exe"])',
                      'TEMP_MAINTAINED_EXCLUSIONS = {"Example": "worker.exe"}', 'unrelated = {}'):
            with self.subTest(source=value), self.assertRaises(ValueError):
                rec.parse_catalog_source(value)

    def test_https_refresh_checks_content_identity_and_uses_bounded_requests(self):
        """Fetch public data without credentials, honor proxy settings, and close the response."""
        response = self.response('TEMP_MAINTAINED_EXCLUSIONS = {"Example": ["worker.exe"]}')
        proxies = {"https": "http://proxy.example:3128"}
        with patch.object(rec.requests, "get", return_value=response) as request:
            result = rec.fetch_catalog(proxies)
        self.assertEqual(result["products"], {"Example": ["worker.exe"]})
        self.assertTrue(result["checked_on"])
        self.assertEqual(request.call_args.args, (rec.CATALOG_API,))
        self.assertEqual(request.call_args.kwargs, {"timeout": 15, "stream": True, "allow_redirects": False, "proxies": proxies})
        response.raise_for_status.assert_called_once_with()
        response.close.assert_called_once_with()

    def test_refresh_rejects_excessive_payload_or_wrong_revision(self):
        """Stop oversized responses and inconsistent catalog contents before parsing them."""
        large = Mock(status_code=200, iter_content=Mock(return_value=[b"x" * 2_097_153]))
        wrong = Mock(status_code=200, iter_content=Mock(return_value=[b'{"content":"eA==","sha":"incorrect"}']))
        for response in (large, wrong):
            with patch.object(rec.requests, "get", return_value=response), self.assertRaises(ValueError):
                rec.fetch_catalog()
            response.close.assert_called_once_with()

    def test_offline_fallback_keeps_source_age_visible(self):
        """Retain useful matches while explicitly reporting the dated fallback catalog."""
        with patch.object(rec, "fetch_catalog", side_effect=ValueError("Unavailable")):
            report = rec.recommend_exclusions(["1Password.exe"])
        self.assertEqual(report.updated_on, "2024-10-30")
        self.assertIn("Catalog refresh unavailable", report.note)
        self.assertIn("2024-10-30", report.note)
        content = rec.format_recommendations(report)
        self.assertIn(report.source, content)
        self.assertIn("Windows baseline", content)

    def test_live_catalog_is_preferred_without_rewriting_the_bundle(self):
        """Use a refreshed product map rather than old bundled process mappings."""
        fresh = {"products": {"Fresh Product": ["new.exe"]}, "source": rec.CATALOG_SOURCE,
                 "updated_on": "2026-10-15", "checked_on": "2026-10-15"}
        with patch.object(rec, "fetch_catalog", return_value=fresh):
            report = rec.recommend_exclusions(["new.exe"])
        self.assertIn("Fresh Product", report.candidates)
        self.assertEqual(report.updated_on, "2026-10-15")
        self.assertIn("retrieved", report.note)

    def test_backend_skips_inaccessible_or_exited_processes(self):
        """Keep software matching useful when individual processes cannot be inspected."""
        from test_health_checker import Data, ProcessUnavailable, data_module
        data = Data.__new__(Data)
        data.proxies = None
        inaccessible = Mock()
        inaccessible.name.side_effect = ProcessUnavailable()
        visible = Mock()
        visible.name.return_value = "worker.exe"
        with patch.object(data_module.psutil, "process_iter", return_value=[inaccessible, visible]):
            with patch.object(data_module, "recommend_exclusions", return_value="report") as recommend:
                self.assertEqual(data.recommend_exclusions(), "report")
        recommend.assert_called_once_with(["worker.exe"], proxies=None)
