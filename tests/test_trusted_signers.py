"""Verify reference fingerprints, date categories, and public-only publisher links."""

from datetime import datetime, timezone
import json
from pathlib import Path
import tempfile
import unittest

from trusted_signers import load_signer_reference, public_publisher_url, signer_reports


NOW = datetime(2026, 10, 15, tzinfo=timezone.utc)


class TrustedSignerTests(unittest.TestCase):
    """Keep historical and unresolved identities separate from valid-date certificates."""

    def test_bundle_retains_all_requested_names_and_distinct_publisher_variants(self):
        """Retain nineteen names, eighteen verified variants, and two unresolved identities."""
        reference = load_signer_reference()
        self.assertEqual(len(reference["entries"]), 19)
        variants = [variant for entry in reference["entries"] for variant in entry["variants"]]
        self.assertEqual(len(variants), 18)
        self.assertEqual(len({variant["sha256"] for variant in variants}), 18)
        self.assertEqual(sum(not entry["variants"] for entry in reference["entries"]), 2)
        self.assertTrue(all(public_publisher_url(variant["source"]) for variant in variants))

    def test_expired_certificates_stay_out_of_valid_dates(self):
        """Move the expired PCA 2011 certificate into Historical using the actual UTC date."""
        reports = signer_reports(as_of=NOW)
        self.assertEqual({name: count for name, (count, text) in reports.items()},
                         {"Valid dates": 9, "Historical": 9, "Unverified": 2})
        self.assertIn("Microsoft Code Signing PCA 2011", reports["Historical"][1])
        self.assertNotIn("Microsoft Code Signing PCA 2011", reports["Valid dates"][1])
        self.assertIn("Microsoft Windows Production PCA 2026", reports["Valid dates"][1])
        self.assertIn("\n9. ", reports["Valid dates"][1])
        self.assertIn("VeriSign Class 3 Code Signing\n", reports["Unverified"][1])
        self.assertNotIn("SHA-256:", reports["Unverified"][1])

    def test_all_validity_boundaries_are_exact_and_future_has_its_own_tab(self):
        """Classify each variant at its validity start/end and immediately outside that range."""
        entry = load_signer_reference()["entries"][-1]
        reference = {"verified_on": "2026-10-14", "entries": [entry]}
        variant = entry["variants"][0]
        for field in ("valid_from", "valid_to"):
            self.assertEqual(signer_reports(reference, datetime.fromisoformat(variant[field]))["Valid dates"][0], 1)
        reports = signer_reports(reference, datetime(2000, 1, 1, tzinfo=timezone.utc))
        self.assertEqual(reports["Not yet valid"][0], 1)

    def test_invalid_fingerprint_and_nonpublisher_sources_are_rejected(self):
        """Reject corrupted metadata and misleading URLs before displaying reference identities."""
        for value in ("https://private.example.invalid/reference", "https://microsoft.com.evil.example.invalid/cert", "https://user@www.microsoft.com/cert"):
            self.assertFalse(public_publisher_url(value))
        reference = load_signer_reference()
        reference["entries"][-1]["variants"][0]["sha256"] = "not-a-fingerprint"
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "reference.json"
            path.write_text(json.dumps(reference))
            with self.assertRaises(ValueError):
                load_signer_reference(path)
