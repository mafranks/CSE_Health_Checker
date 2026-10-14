"""Connector-independent DNS/TLS reachability checks for the existing regional endpoints."""

import ast
import base64
from dataclasses import dataclass
import logging
import os
import re
import socket
import ssl
import time
from urllib.parse import unquote, urlsplit

from dotenv import load_dotenv
from apjc_urls import APJCADDRESSLIST
from eu_urls import EUADDRESSLIST
from nam_urls import NAMADDRESSLIST


REGIONS = ("NAM", "EU", "APJC", "PC")


@dataclass(frozen=True)
class ConnectivitySettings:
    """Contain network settings without connector state, API credentials, or Windows services."""

    region: str = "NAM"
    domain: str = ""
    proxies: dict[str, str] | None = None


def environment_settings():
    """Load optional region/proxy settings while allowing a completely absent .env file."""
    load_dotenv()
    raw = os.getenv("PROXIES", "").strip()
    try:
        proxies = ast.literal_eval(raw) if raw else None
    except (ValueError, SyntaxError) as error:
        raise ValueError("Invalid PROXIES setting in .env; use a dictionary of proxy URLs.") from error
    if proxies is not None and not isinstance(proxies, dict):
        raise ValueError("PROXIES in .env must be a dictionary of proxy URLs.")
    return ConnectivitySettings(os.getenv("REGION", "NAM").strip().upper() or "NAM",
                                os.getenv("PC_DOMAIN", "").strip(), proxies)


def validate_hostname(value):
    """Reject URLs, ports, or malformed domains before creating DNS or tunnel requests."""
    if not isinstance(value, str) or not value.strip():
        raise ValueError("Enter a hostname, such as example.local, without https:// or a port.")
    try:
        hostname = value.strip().rstrip(".").encode("idna").decode("ascii")
    except UnicodeError as error:
        raise ValueError("Invalid hostname.") from error
    labels = hostname.split(".")
    if len(hostname) > 253 or any(not re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?", label) for label in labels):
        raise ValueError("Enter a valid hostname without https://, a path, or a port.")
    return hostname


def endpoints_for_region(region, domain=""):
    """Use the existing endpoint lists, generating Private Cloud names from the current input."""
    public = {"NAM": NAMADDRESSLIST, "EU": EUADDRESSLIST, "APJC": APJCADDRESSLIST}
    if region in public:
        return list(public[region])
    if region != "PC":
        raise ValueError("Choose NAM, EU, APJC, or PC for Connectivity Test.")
    hostname = validate_hostname(domain)
    return [f"{prefix}.{hostname}" for prefix in ("console", "auth", "disp", "disp-ext", "disp-update", "fmc")]


def parse_proxy(proxies):
    """Validate the existing HTTP CONNECT proxy configuration before any connections start."""
    if proxies is None:
        return None
    if not isinstance(proxies, dict):
        raise ValueError("PROXIES must be a dictionary of proxy URLs.")
    if not proxies:
        return None
    url = proxies.get("https") or proxies.get("http")
    if not isinstance(url, str) or not url:
        raise ValueError("PROXIES must provide an https or http proxy URL.")
    try:
        proxy = urlsplit(url)
        port = proxy.port
    except ValueError as error:
        raise ValueError("Invalid proxy host or port in PROXIES.") from error
    if proxy.scheme != "http" or not proxy.hostname or port == 0:
        raise ValueError("Connectivity Test requires an HTTP CONNECT proxy URL, such as http://proxy.example:8080.")
    return proxy


def open_tunnel(sock, hostname, proxy):
    """Read a bounded complete CONNECT response and support configured proxy credentials."""
    headers = [f"CONNECT {hostname}:443 HTTP/1.1", f"Host: {hostname}:443"]
    if proxy.username is not None:
        credentials = f"{unquote(proxy.username)}:{unquote(proxy.password or '')}".encode("utf-8")
        headers.append("Proxy-Authorization: Basic " + base64.b64encode(credentials).decode("ascii"))
    sock.sendall(("\r\n".join(headers) + "\r\n\r\n").encode("ascii"))
    response, deadline = b"", time.monotonic() + 10
    for _ in range(64):
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError("Proxy CONNECT timed out")
        sock.settimeout(remaining)
        chunk = sock.recv(1024)
        response += chunk
        if len(response) > 16384:
            raise OSError("Proxy CONNECT response is too large")
        if b"\r\n\r\n" in response:
            parts = response.split(b"\r\n", 1)[0].split()
            if len(parts) < 2 or parts[1] != b"200":
                raise OSError("Proxy refused CONNECT")
            sock.settimeout(10)
            return
        if not chunk:
            break
    raise OSError("Incomplete proxy CONNECT response")


def endpoint_reachable(hostname, proxy):
    """Perform the existing TCP/TLS handshake test with bounded network timeouts."""
    address = (proxy.hostname, proxy.port or 80) if proxy else (hostname, 443)
    context = ssl._create_unverified_context()
    with socket.create_connection(address, timeout=10) as sock:
        if proxy:
            open_tunnel(sock, hostname, proxy)
        with context.wrap_socket(sock, server_hostname=hostname):
            pass


def check_endpoints(endpoints, proxies=None, cancelled=None, on_result=None):
    """Return and optionally report per-host reachability without accessing connector or GUI state."""
    if not isinstance(endpoints, (list, tuple)):
        raise ValueError("Connectivity endpoints must be a list or tuple of hostnames.")
    if any(callback is not None and not callable(callback) for callback in (cancelled, on_result)):
        raise ValueError("Connectivity callbacks must be callable.")
    hosts = [validate_hostname(host) for host in endpoints]
    proxy = parse_proxy(proxies)
    results = {}
    for hostname in hosts:
        if cancelled is not None and cancelled():
            break
        try:
            endpoint_reachable(hostname, proxy)
            results[hostname] = "Green"
        except OSError as error:
            logging.warning("Connection failed for %s: %s", hostname, error)
            results[hostname] = "Red"
        if on_result is not None:
            on_result(hostname, results[hostname])
    return results
