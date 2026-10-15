"""Read local X.509 certificates and report fingerprints and validity dates."""

from datetime import datetime, timezone
import hashlib
from os import PathLike
from pathlib import Path
from typing import NamedTuple

from PySide6.QtNetwork import QSsl, QSslCertificate


class Certificate(NamedTuple):
    """Describe certificate contents without asserting trust or installation requirements."""

    subject_name: str
    issuer_name: str
    sha1: str
    sha256: str
    valid_from: str
    valid_to: str


def reference_time(as_of=None):
    """Choose one timezone-aware UTC timestamp for classification and reporting."""
    moment = datetime.now(timezone.utc) if as_of is None else as_of
    if not isinstance(moment, datetime) or moment.utcoffset() is None:
        raise ValueError("The reference time must be a timezone-aware datetime.")
    return moment.astimezone(timezone.utc)


def certificate_time(value):
    """Parse an exact certificate validity timestamp and require timezone information."""
    if not isinstance(value, str):
        raise ValueError("Certificate validity timestamps must be ISO-formatted strings.")
    return reference_time(datetime.fromisoformat(value))


def describe_certificate(certificate):
    """Compute fingerprints from the parsed certificate's complete DER encoding."""
    if not isinstance(certificate, QSslCertificate) or certificate.isNull():
        raise ValueError("A parsed X.509 certificate is required.")
    start, end = certificate.effectiveDate(), certificate.expiryDate()
    if not start.isValid() or not end.isValid():
        raise ValueError("The certificate has missing or invalid validity dates.")
    der = bytes(certificate.toDer())
    subject = ", ".join(certificate.subjectInfo(QSslCertificate.SubjectInfo.CommonName))
    issuer = ", ".join(certificate.issuerInfo(QSslCertificate.SubjectInfo.CommonName))
    dates = [datetime.fromtimestamp(value.toSecsSinceEpoch(), timezone.utc).isoformat()
             for value in (start, end)]
    return Certificate(subject or "(no common name)", issuer or "(no common name)",
                       hashlib.sha1(der).hexdigest().upper(), hashlib.sha256(der).hexdigest().upper(), *dates)


def read_certificate_file(path):
    """Read bounded PEM/DER certificate input and reject files containing private keys."""
    with Path(path).open("rb") as source:
        raw = source.read(1_048_577)
    if not raw or len(raw) > 1_048_576:
        raise ValueError("Each certificate file must contain between 1 byte and 1 MiB.")
    if b"PRIVATE KEY" in raw:
        raise ValueError("Choose certificate-only files. Files containing private keys are rejected.")
    encoding = QSsl.EncodingFormat.Pem if b"-----BEGIN CERTIFICATE-----" in raw else QSsl.EncodingFormat.Der
    parsed = QSslCertificate.fromData(raw, encoding)
    if not parsed or len(parsed) > 256:
        raise ValueError("Choose a PEM or DER file containing 1 to 256 X.509 certificates.")
    if encoding == QSsl.EncodingFormat.Pem and len(parsed) != raw.count(b"-----BEGIN CERTIFICATE-----"):
        raise ValueError("The PEM file contains an invalid certificate.")
    return tuple(describe_certificate(certificate) for certificate in parsed)


def load_certificates(paths):
    """Load a bounded selection atomically and deduplicate identical certificate variants."""
    if not isinstance(paths, (list, tuple)) or not 1 <= len(paths) <= 32:
        raise ValueError("Choose between 1 and 32 certificate files.")
    if any(not isinstance(path, (str, PathLike)) for path in paths):
        raise ValueError("Certificate paths must be filenames.")
    certificates = {}
    for path in paths:
        for certificate in read_certificate_file(path):
            certificates[certificate.sha256] = certificate
    return tuple(certificates.values())


def certificate_groups(certificates, as_of=None):
    """Separate supplied certificates into current, expired, and future date ranges."""
    moment = reference_time(as_of)
    groups = {title: [] for title in ("Valid dates", "Historical", "Not yet valid")}
    for certificate in certificates:
        start, end = certificate_time(certificate.valid_from), certificate_time(certificate.valid_to)
        if start > end:
            raise ValueError("Certificate validity starts after its expiry time.")
        title = "Not yet valid" if moment < start else "Historical" if moment > end else "Valid dates"
        groups[title].append(certificate)
    return groups


def format_certificates(certificates, start=1):
    """Format copyable identities, fingerprints, and exact UTC validity dates."""
    if isinstance(start, bool) or not isinstance(start, int) or start < 1:
        raise ValueError("Certificate numbering must start with a positive integer.")
    lines = []
    for index, certificate in enumerate(certificates, start):
        start = certificate_time(certificate.valid_from).strftime("%Y-%m-%d %H:%M:%S UTC")
        end = certificate_time(certificate.valid_to).strftime("%Y-%m-%d %H:%M:%S UTC")
        lines.extend(("", f"{index}. {certificate.subject_name}",
                      "   Issuer: " + certificate.issuer_name,
                      "   SHA-1: " + certificate.sha1, "   SHA-256: " + certificate.sha256,
                      "   Valid from: " + start, "   Valid through: " + end))
    return "\n".join(lines) if lines else "\nNo certificates in this category."


def certificate_reports(certificates=(), as_of=None):
    """Build complete tab reports from user-selected files using a single UTC instant."""
    moment = reference_time(as_of)
    descriptions = {
        "Valid dates": "These certificates are within their recorded validity periods.",
        "Historical": "These certificates have expired. Retained for historical reference only.",
        "Not yet valid": "These certificates have not reached the start of their validity periods.",
    }
    reports = {}
    for title, entries in certificate_groups(certificates, moment).items():
        if title == "Not yet valid" and not entries:
            continue
        lines = ["Certificate viewer — " + title, descriptions[title],
                 "Date classification does not establish current trust, revocation status, or signer acceptance.",
                 "These are locally selected certificates, not mandatory installed certificates.", "",
                 "As of: " + moment.strftime("%Y-%m-%d %H:%M:%S UTC"),
                 f"Certificate variants: {len(entries)}", format_certificates(entries)]
        reports[title] = (len(entries), "\n".join(lines))
    return reports
