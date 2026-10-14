"""Verify local certificate parsing and exact UTC validity categories offline."""

from datetime import datetime, timedelta, timezone
from pathlib import Path
import tempfile
import unittest

from certificates import (Certificate, certificate_groups, certificate_reports,
                          load_certificates, read_certificate_file)


NOW = datetime(2026, 10, 14, 12, tzinfo=timezone.utc)
CURRENT = Certificate("Example current issuer", "Example parent", "A" * 40, "B" * 64,
                      "2026-01-01T00:00:00+00:00", "2031-08-04T19:49:15+00:00")
EXPIRED = Certificate("Example historical issuer", "Example parent", "C" * 40, "D" * 64,
                      "2011-01-01T00:00:00+00:00", "2020-08-31T22:29:32+00:00")
FIXTURE = Path(__file__).parent / "fixtures" / "example_certificate.pem"


class CertificateViewerTests(unittest.TestCase):
    """Cover file boundaries, exact dates, mixed variants, and complete reports."""

    def test_empty_viewer_contains_no_bundled_catalog(self):
        """Require explicit local inputs before displaying any certificate identities."""
        reports = certificate_reports(as_of=NOW)
        self.assertEqual([count for count, _ in reports.values()], [0, 0])
        self.assertTrue(all("No certificates in this category" in text for _, text in reports.values()))

    def test_reference_preserves_identity_fingerprints_and_utc_dates(self):
        """Keep complete identities and dates available for copying and export."""
        _, result = certificate_reports((CURRENT,), NOW)["Valid dates"]
        self.assertIn("1. Example current issuer", result)
        self.assertIn("Issuer: Example parent", result)
        self.assertIn("SHA-1: " + "A" * 40, result)
        self.assertIn("SHA-256: " + "B" * 64, result)
        self.assertIn("Valid through: 2031-08-04 19:49:15 UTC", result)
        self.assertIn("does not establish current trust", result)

    def test_exact_start_and_expiry_boundaries(self):
        """Use exact UTC timestamps with inclusive X.509 validity endpoints."""
        end = NOW + timedelta(hours=1)
        certificate = CURRENT._replace(valid_from=NOW.isoformat(), valid_to=end.isoformat())
        cases = ((NOW - timedelta(microseconds=1), "Not yet valid"), (NOW, "Valid dates"),
                 (end, "Valid dates"), (end + timedelta(microseconds=1), "Historical"))
        for moment, category in cases:
            with self.subTest(moment=moment):
                groups = certificate_groups((certificate,), moment)
                self.assertEqual(groups[category], [certificate])
                self.assertEqual(sum(len(entries) for entries in groups.values()), 1)

    def test_variants_stay_in_separate_date_categories(self):
        """Keep expired fingerprints out of the default tab while preserving all exports."""
        reports = certificate_reports((CURRENT, EXPIRED), NOW)
        self.assertEqual(reports["Valid dates"][0], 1)
        self.assertEqual(reports["Historical"][0], 1)
        self.assertIn(CURRENT.sha256, reports["Valid dates"][1])
        self.assertNotIn(EXPIRED.sha256, reports["Valid dates"][1])
        self.assertIn(EXPIRED.sha256, reports["Historical"][1])
        self.assertIn("have expired", reports["Historical"][1])

    def test_future_certificates_have_their_own_category(self):
        """Avoid describing certificates whose validity has not started as current or expired."""
        future = CURRENT._replace(valid_from="2027-01-01T00:00:00+00:00")
        reports = certificate_reports((future,), NOW)
        self.assertEqual(reports["Not yet valid"][0], 1)
        self.assertNotIn(future.sha256, reports["Valid dates"][1])
        self.assertNotIn(future.sha256, reports["Historical"][1])

    def test_invalid_or_naive_times_are_rejected(self):
        """Reject missing timezones and reversed validity ranges before classification."""
        for moment in ("2026-10-14", datetime(2026, 10, 14)):
            with self.subTest(moment=moment), self.assertRaises(ValueError):
                certificate_reports(as_of=moment)
        for certificate in (CURRENT._replace(valid_from="2032-01-01T00:00:00+00:00"),
                            CURRENT._replace(valid_to="2031-08-04")):
            with self.assertRaises(ValueError):
                certificate_reports((certificate,), NOW)

    def test_pem_der_and_duplicate_files_have_one_identity(self):
        """Read a synthetic public certificate in both encodings without inventing identities."""
        from PySide6.QtNetwork import QSslCertificate
        certificate = read_certificate_file(FIXTURE)[0]
        self.assertEqual(certificate.subject_name, "example.invalid")
        self.assertEqual(certificate.issuer_name, "example.invalid")
        self.assertEqual(len(certificate.sha1), 40)
        self.assertEqual(certificate.sha256,
                         "1D90E281ED00AA56BD8ECF5453625784D433363152CBFF503FEA06CADC7646B6")
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "example.der"
            path.write_bytes(bytes(QSslCertificate.fromData(FIXTURE.read_bytes())[0].toDer()))
            self.assertEqual(load_certificates([FIXTURE, path, FIXTURE]), (certificate,))

    def test_invalid_large_mixed_and_private_key_files_are_rejected(self):
        """Reject invalid certificate content, excessive input, and PEM files containing keys."""
        private_marker = b"-----BEGIN PRIVATE KEY-----\nexample\n-----END PRIVATE KEY-----"
        invalid_certificate = b"-----BEGIN CERTIFICATE-----\ninvalid\n-----END CERTIFICATE-----"
        samples = (b"", b"not a certificate", b"x" * 1_048_577,
                   FIXTURE.read_bytes() + private_marker, FIXTURE.read_bytes() + invalid_certificate)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "input.pem"
            for raw in samples:
                with self.subTest(length=len(raw)):
                    path.write_bytes(raw)
                    with self.assertRaises(ValueError):
                        read_certificate_file(path)

    def test_selection_limits_and_missing_files_fail_atomically(self):
        """Reject oversized selections and missing files instead of returning partial results."""
        for paths in ([], "example.pem", [FIXTURE] * 33, [None]):
            with self.subTest(paths_type=type(paths).__name__), self.assertRaises(ValueError):
                load_certificates(paths)
        with tempfile.TemporaryDirectory() as directory, self.assertRaises(OSError):
            load_certificates([FIXTURE, Path(directory) / "missing.pem"])


if __name__ == "__main__":
    unittest.main()
