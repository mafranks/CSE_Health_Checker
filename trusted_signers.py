"""Present publisher certificate identities separately from installed trust checks."""

import json
from pathlib import Path
import re
from urllib.parse import urlsplit

from certificates import Certificate, certificate_time, format_certificates, reference_time


PUBLISHER_DOMAINS = ("microsoft.com", "digicert.com", "sectigo.com", "verisign.com")


def public_publisher_url(value):
    """Accept only direct public certificate-publisher links in the bundled reference."""
    if not isinstance(value, str):
        return False
    url = urlsplit(value)
    return (url.scheme in ("http", "https") and not url.username and not url.password
            and any(url.hostname == domain or (url.hostname or "").endswith("." + domain) for domain in PUBLISHER_DOMAINS))


def load_signer_reference(path=None):
    """Validate bundled identities, fingerprints, timestamps, and publisher-only URLs."""
    source = Path(path) if path is not None else Path(__file__).with_name("trusted_signers.json")
    if source.stat().st_size > 1_048_576:
        raise ValueError("The signer reference is too large.")
    payload = json.loads(source.read_text())
    entries = payload.get("entries")
    if not isinstance(entries, list) or not 1 <= len(entries) <= 100:
        raise ValueError("Invalid signer reference entries.")
    for entry in entries:
        if not isinstance(entry, dict) or not isinstance(entry.get("name"), str) or not entry["name"].strip():
            raise ValueError("Invalid signer reference name.")
        variants = entry.get("variants")
        if not isinstance(variants, list) or len(variants) > 32:
            raise ValueError("Invalid signer certificate variants.")
        for variant in variants:
            validate_variant(variant)
    return payload


def validate_variant(variant):
    """Require complete verified certificate metadata without inventing missing hashes."""
    if not isinstance(variant, dict) or not public_publisher_url(variant.get("source")):
        raise ValueError("Invalid certificate publisher source.")
    for key, length in (("sha1", 40), ("sha256", 64)):
        if not isinstance(variant.get(key), str) or not re.fullmatch(f"[A-Fa-f0-9]{{{length}}}", variant[key]):
            raise ValueError("Invalid certificate fingerprint.")
    for key in ("subject_name", "issuer_name"):
        if not isinstance(variant.get(key), str) or not variant[key].strip():
            raise ValueError("Invalid certificate identity.")
    if certificate_time(variant["valid_from"]) > certificate_time(variant["valid_to"]):
        raise ValueError("Invalid certificate validity range.")


def signer_reports(reference=None, as_of=None):
    """Separate current, expired, future, and unverified identities using one UTC instant."""
    payload = load_signer_reference() if reference is None else reference
    moment = reference_time(as_of)
    groups = {name: [] for name in ("Valid dates", "Historical", "Not yet valid", "Unverified")}
    for entry in payload["entries"]:
        if not entry["variants"]:
            groups["Unverified"].append(entry)
        for variant in entry["variants"]:
            start, end = certificate_time(variant["valid_from"]), certificate_time(variant["valid_to"])
            group = "Not yet valid" if moment < start else "Historical" if moment > end else "Valid dates"
            groups[group].append(variant)
    reports = {}
    for group, entries in groups.items():
        if group == "Not yet valid" and not entries:
            continue
        lines = ["Trusted signer reference — " + group,
                 "Reference identities; date validity does not establish trust, revocation, or signer acceptance.",
                 "These are not mandatory installed certificates.",
                 "Publisher metadata verified: " + payload["verified_on"],
                 "As of: " + moment.strftime("%Y-%m-%d %H:%M:%S UTC"), ""]
        lines.extend(format_signer_entries(group, entries))
        reports[group] = (len(entries), "\n".join(lines))
    return reports


def format_signer_entries(group, entries):
    """Keep every publisher variant and leave unresolved identities explicitly unverified."""
    if group == "Unverified":
        return [entry["name"] + "\n  " + entry.get("reason", "Certificate identity has not been established.") for entry in entries]
    lines = []
    for index, variant in enumerate(entries, 1):
        certificate = Certificate(*(variant[key] for key in Certificate._fields))
        lines.extend((format_certificates((certificate,), start=index), "   Publisher: " + variant["source"]))
    return lines or ["No certificates in this category."]
