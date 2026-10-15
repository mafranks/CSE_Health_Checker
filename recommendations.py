"""Match running applications to publicly published exclusion-set candidates."""

import ast
import base64
import hashlib
from dataclasses import dataclass
from datetime import datetime, timezone
import json
import ntpath
from pathlib import Path

import requests


CATALOG_API = "https://api.github.com/repos/CiscoSecurity/amp-05-health-checker-windows/contents/temp_maintained_exclusions.py"
CATALOG_SOURCE = "https://github.com/CiscoSecurity/amp-05-health-checker-windows/blob/master/temp_maintained_exclusions.py"


@dataclass(frozen=True)
class RecommendationReport:
    """Carry software matches and catalog freshness without changing any exclusions."""

    candidates: dict
    source: str
    updated_on: str
    checked_on: str
    note: str = ""


def validate_products(products):
    """Reject malformed or excessive catalogs before comparing process names."""
    if not isinstance(products, dict) or not 1 <= len(products) <= 500:
        raise ValueError("The exclusion catalog must contain 1 to 500 product sets.")
    for name, processes in products.items():
        if not isinstance(name, str) or not name.strip() or not isinstance(processes, list):
            raise ValueError("Invalid exclusion catalog product.")
        if not 1 <= len(processes) <= 1000 or any(not isinstance(value, str) or not value.strip() for value in processes):
            raise ValueError("Invalid exclusion catalog process list.")
    return products


def bundled_catalog():
    """Read the bundled public catalog and retain its actual source update date."""
    payload = json.loads(Path(__file__).with_name("exclusion_catalog.json").read_text())
    validate_products(payload.get("products"))
    return payload


def parse_catalog_source(source):
    """Read the public data assignment without executing downloaded Python code."""
    if not isinstance(source, str) or len(source) > 1_048_576:
        raise ValueError("Invalid exclusion catalog source size.")
    for node in ast.parse(source).body:
        if isinstance(node, ast.Assign) and any(isinstance(target, ast.Name) and target.id == "TEMP_MAINTAINED_EXCLUSIONS" for target in node.targets):
            return validate_products(ast.literal_eval(node.value))
    raise ValueError("The exclusion catalog assignment is missing.")


def fetch_catalog(proxies=None):
    """Retrieve bounded public catalog data over HTTPS without API credentials."""
    options = {"timeout": 15, "stream": True, "allow_redirects": False}
    if proxies:
        options["proxies"] = proxies
    response = requests.get(CATALOG_API, **options)
    try:
        response.raise_for_status()
        if response.status_code != 200:
            raise ValueError("The catalog server returned an unexpected status.")
        content = bytearray()
        for chunk in response.iter_content(chunk_size=65536):
            content.extend(chunk)
            if len(content) > 2_097_152:
                raise ValueError("The catalog response is too large.")
        payload = json.loads(content)
        raw = base64.b64decode("".join(payload["content"].split()), validate=True)
        digest = hashlib.sha1(f"blob {len(raw)}\0".encode() + raw).hexdigest()
        if digest != payload.get("sha"):
            raise ValueError("The catalog content does not match its revision.")
        source = raw.decode("utf-8")
        products = parse_catalog_source(source)
        bundled = bundled_catalog()
        updated = bundled["updated_on"] if digest == bundled.get("source_blob_sha") else "Not supplied by upstream"
        return {"products": products, "source": CATALOG_SOURCE, "updated_on": updated,
                "checked_on": datetime.now(timezone.utc).date().isoformat()}
    finally:
        response.close()


def match_products(process_names, products):
    """Match exact executable names case-insensitively and deduplicate each product's matches."""
    validate_products(products)
    names = {ntpath.basename(name).casefold(): ntpath.basename(name) for name in process_names if isinstance(name, str) and name}
    matches = {"Microsoft Windows Default": ("Windows baseline",)}
    for product, processes in products.items():
        found = sorted({names[name.casefold()] for name in processes if name.casefold() in names}, key=str.casefold)
        if found:
            matches[product] = tuple(found)
    return matches


def recommend_exclusions(process_names, proxies=None, refresh=True):
    """Prefer fresh public data, falling back explicitly to the dated bundled catalog."""
    catalog = bundled_catalog()
    note = "Bundled reference catalog; review each candidate in the Secure Endpoint console."
    if refresh:
        try:
            catalog = fetch_catalog(proxies)
            note = "Public catalog retrieved for this check; confirm current availability in the console."
        except (requests.exceptions.RequestException, ValueError, TypeError, KeyError, SyntaxError):
            note = "Catalog refresh unavailable. Using the bundled reference dated " + catalog["updated_on"] + "."
    return RecommendationReport(match_products(process_names, catalog["products"]), catalog["source"],
                                catalog["updated_on"], catalog.get("checked_on", "Not refreshed"), note)


def format_recommendations(report):
    """Export every candidate together with catalog provenance and freshness."""
    lines = ["Exclusion-set candidates", "Review candidates before changing policy.",
             "Catalog: " + report.source, "Catalog updated: " + report.updated_on,
             "Checked: " + report.checked_on, report.note, "", "Exclusion set\tDetected processes"]
    lines.extend(name + "\t" + ", ".join(processes) for name, processes in report.candidates.items())
    return "\n".join(lines)
