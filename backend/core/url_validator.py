"""Validate scan target URLs — block private/internal addresses."""

import ipaddress
import socket
from urllib.parse import urlparse

BLOCKED_HOSTNAMES = {
    "localhost",
    "localhost.localdomain",
    "metadata.google.internal",
    "metadata.google",
    "instance-data",
}

BLOCKED_SUFFIXES = (
    ".local",
    ".internal",
    ".localhost",
)


class URLValidationError(ValueError):
    pass


def _is_blocked_ip(ip_str: str) -> bool:
    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        return False

    return (
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_reserved
        or ip.is_multicast
    )


def validate_target_url(url: str) -> str:
    """Validate and normalize a scan target URL. Raises URLValidationError on block."""
    parsed = urlparse(url.strip())

    if parsed.scheme not in ("http", "https"):
        raise URLValidationError("URL must use http or https")

    hostname = parsed.hostname
    if not hostname:
        raise URLValidationError("URL must include a valid hostname")

    hostname_lower = hostname.lower().rstrip(".")

    if hostname_lower in BLOCKED_HOSTNAMES:
        raise URLValidationError(f"Blocked hostname: {hostname}")

    for suffix in BLOCKED_SUFFIXES:
        if hostname_lower.endswith(suffix):
            raise URLValidationError(f"Blocked hostname suffix: {suffix}")

    # Direct IP in URL
    try:
        if _is_blocked_ip(hostname):
            raise URLValidationError("Cannot scan private, loopback, or reserved IP addresses")
    except URLValidationError:
        raise
    except ValueError:
        pass

    # Resolve DNS and check all resolved IPs
    try:
        results = socket.getaddrinfo(hostname, None, proto=socket.IPPROTO_TCP)
        for family, _, _, _, sockaddr in results:
            ip = sockaddr[0]
            if _is_blocked_ip(ip):
                raise URLValidationError(
                    f"Hostname {hostname} resolves to blocked address: {ip}"
                )
    except socket.gaierror:
        raise URLValidationError(f"Cannot resolve hostname: {hostname}")

    return url.strip()
