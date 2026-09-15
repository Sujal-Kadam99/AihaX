"""Deterministic Scope Validation and Asset Normalization Engine.

Designed for Phase 1 scope definition and Phase 2 Central Request Engine enforcement.
Guarantees Default-Deny, strict wildcard isolation, and explicit exclusion precedence.
"""

from __future__ import annotations

import fnmatch
import ipaddress
import re
from dataclasses import dataclass
from enum import Enum
from typing import Any, Optional
from urllib.parse import urlparse


class ScopeStatus(str, Enum):
    IN_SCOPE = "IN_SCOPE"
    OUT_OF_SCOPE = "OUT_OF_SCOPE"
    INVALID = "INVALID"
    DENIED_BY_DEFAULT = "DENIED_BY_DEFAULT"


@dataclass(frozen=True)
class ScopeDecision:
    allowed: bool
    status: ScopeStatus
    reason: str
    asset: str
    matched_rule: Optional[str] = None

    @property
    def in_scope(self) -> bool:
        return self.allowed

    def to_dict(self) -> dict[str, Any]:
        return {
            "allowed": self.allowed,
            "status": self.status.value,
            "reason": self.reason,
            "asset": self.asset,
            "matched_rule": self.matched_rule,
        }


def normalize_domain(domain: str) -> str:
    """Normalize a domain/host name to lowercase without ports or credentials."""
    if not domain or not isinstance(domain, str):
        return ""
    d = domain.strip().lower()
    # Strip userinfo if present in raw string (e.g. user:pass@host)
    if "@" in d:
        d = d.split("@")[-1]
    # Strip port if present for host:port (single colon), but preserve IPv6 (multiple colons)
    if d.startswith("[") and "]" in d:  # IPv6 literal with brackets [::1]:8080 or [::1]
        d = d[1 : d.index("]")]
    elif d.count(":") == 1:  # single colon = hostname:port or ipv4:port
        d = d.split(":")[0]
    # Strip trailing dot
    return d.rstrip(".")


def normalize_url(raw_url: str) -> tuple[str, str, int, str]:
    """Parse and normalize a URL deterministically.

    Returns (scheme, host, port, path).
    Guarantees userinfo attacks (e.g. https://example.com@evil.com) correctly identify evil.com.
    """
    if not raw_url or not isinstance(raw_url, str):
        raise ValueError("URL must be a non-empty string")

    cleaned = raw_url.strip()
    # Check if a scheme is present (e.g. scheme://...)
    if "://" not in cleaned:
        cleaned = "https://" + cleaned

    parsed = urlparse(cleaned)

    scheme = (parsed.scheme or "https").lower()
    if scheme not in ("http", "https"):
        raise ValueError(f"Unsupported scheme: {scheme}")

    # urlparse correctly isolates hostname even when userinfo is present
    hostname = parsed.hostname
    if not hostname:
        raise ValueError("Invalid URL: missing or malformed hostname")

    host = normalize_domain(hostname)
    if not host:
        raise ValueError("Invalid URL: empty hostname after normalization")

    port = parsed.port or (443 if scheme == "https" else 80)
    path = parsed.path or "/"

    return scheme, host, port, path


def validate_concrete_target_url(raw_url: str) -> tuple[str, str, int, str, str]:
    """Deterministically parse and validate a concrete assessment target URL.

    Requirements:
    - Must be a non-empty string without only whitespace.
    - Must explicitly start with http:// or https:// (bare hostnames like example.com or *.example.com are rejected).
    - Hostname and URL must NOT contain '*'.
    - Scheme must be strictly 'http' or 'https' (reject javascript:, data:, file:, mailto:, etc.).
    - Userinfo (e.g. user:pass@host) is strictly rejected.
    - Port must be valid (1-65535).
    - Hostname must be non-empty and well-formed.

    Returns:
        (scheme, host, port, path, canonical_url)
    Raises:
        ValueError on any violation with descriptive reason.
    """
    if not raw_url or not isinstance(raw_url, str):
        raise ValueError("Target URL must be a non-empty string")

    cleaned = raw_url.strip()
    if not cleaned:
        raise ValueError("Target URL must not be whitespace-only")

    # Reject wildcards explicitly
    if "*" in cleaned:
        raise ValueError("Wildcard scope rules cannot be used as executable assessment targets. Enter a concrete host.")

    # Must start with explicit scheme
    if not (cleaned.startswith("http://") or cleaned.startswith("https://")):
        raise ValueError("Assessment target must start with http:// or https:// (e.g. https://example.com)")

    parsed = urlparse(cleaned)

    # Scheme validation
    scheme = (parsed.scheme or "").lower()
    if scheme not in ("http", "https"):
        raise ValueError(f"Unsupported scheme '{scheme}'. Only http:// and https:// are permitted.")

    # Reject userinfo
    if parsed.username or parsed.password or "@" in (parsed.netloc.split(":")[0] if parsed.netloc else ""):
        raise ValueError("Userinfo / credentials in target URL are not permitted")

    # Hostname validation
    hostname = parsed.hostname
    if not hostname:
        raise ValueError("Invalid target URL: missing or malformed hostname")

    if "*" in hostname:
        raise ValueError("Wildcard scope rules cannot be used as executable assessment targets. Enter a concrete host.")

    host = normalize_domain(hostname)
    if not host or "*" in host:
        raise ValueError("Invalid target URL: empty or invalid hostname")

    # Port validation
    port = parsed.port
    if port is not None:
        if port <= 0 or port > 65535:
            raise ValueError(f"Invalid port number: {port}. Port must be between 1 and 65535.")
    else:
        port = 443 if scheme == "https" else 80

    path = parsed.path or "/"

    # Destination safety verification (blocks cloud metadata and link-local SSRF targets)
    is_safe, safety_reason = validate_destination_safety(cleaned, allow_loopback=True)
    if not is_safe:
        raise ValueError(safety_reason)

    # Canonical URL format
    if (scheme == "http" and port == 80) or (scheme == "https" and port == 443):
        canonical_url = f"{scheme}://{host}{path if path != '/' else ''}" or f"{scheme}://{host}/"
    else:
        canonical_url = f"{scheme}://{host}:{port}{path if path != '/' else ''}" or f"{scheme}://{host}:{port}/"

    return scheme, host, port, path, canonical_url


PROHIBITED_METADATA_HOSTS = {
    "169.254.169.254",
    "metadata.google.internal",
    "metadata.google",
    "instance-data",
    "169.254.169.254.nip.io",
    "169.254.169.254.xip.io",
}

PROHIBITED_HOST_SUFFIXES = (
    ".metadata.google.internal",
    ".instance-data",
)


SAFE_HTTP_PORTS = {80, 443, 8080, 8443}

PROHIBITED_PORTS = {
    21, 22, 23, 25, 53, 110, 111, 135, 139, 143, 445, 993, 995,
    1433, 1521, 3306, 3389, 5432, 5601, 5900, 6379, 9200, 11211, 27017, 28017,
}


def validate_destination_safety(
    raw_url: str,
    allow_loopback: bool = False,
    strict: bool = False,
    allowed_ports: Optional[set[int]] = None,
) -> tuple[bool, str]:
    """Validate that a target or redirect destination URL is safe from SSRF / Cloud Metadata attacks.

    Checks:
    - Cloud metadata addresses (169.254.169.254, metadata.google.internal, instance-data).
    - IPv4 link-local (169.254.0.0/16) and IPv6 link-local (fe80::/10).
    - Multicast, broadcast, reserved IP spaces (224.0.0.0/4, 240.0.0.0/4, 0.0.0.0).
    - Loopback addresses (127.0.0.0/8, ::1, localhost) unless allow_loopback is True and not strict.
    - Private RFC1918 subnets (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16).
    - Prohibited non-standard ports (ssh 22, mysql 3306, redis 6379, etc.).

    Returns:
        (is_safe: bool, reason: str)
    """
    if strict:
        allow_loopback = False

    if not raw_url or not isinstance(raw_url, str):
        return False, "Destination URL must be a non-empty string"

    cleaned = raw_url.strip()
    if "://" not in cleaned:
        cleaned = "https://" + cleaned

    try:
        parsed = urlparse(cleaned)
        if parsed.scheme and parsed.scheme.lower() not in ("http", "https"):
            return False, f"Prohibited scheme '{parsed.scheme}': only HTTP and HTTPS are permitted."

        hostname = parsed.hostname
        if not hostname:
            return False, "Invalid destination URL: missing hostname"

        host_lower = normalize_domain(hostname)

        # Port validation
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        if allowed_ports is not None:
            if port not in allowed_ports:
                return False, f"Destination port '{port}' is prohibited for HTTP verification."
        else:
            if port in PROHIBITED_PORTS:
                return False, f"Destination port '{port}' is prohibited for HTTP verification (unsafe service port)."

        # 1. Prohibited cloud metadata hostnames
        if host_lower in PROHIBITED_METADATA_HOSTS:
            return False, f"Destination '{hostname}' is a prohibited cloud metadata endpoint (SSRF protection)."

        for suffix in PROHIBITED_HOST_SUFFIXES:
            if host_lower.endswith(suffix):
                return False, f"Destination '{hostname}' is a prohibited cloud metadata domain (SSRF protection)."

        # 2. IP address checks (if hostname is an IP literal)
        try:
            ip_str = host_lower.strip("[]")
            ip = ipaddress.ip_address(ip_str)

            # Block link-local (169.254.0.0/16, fe80::/10) - cloud metadata / autoconfig
            if ip.is_link_local:
                return False, f"Destination IP '{ip}' is a link-local address (prohibited metadata range)."

            # Block multicast, reserved, unspecified
            if ip.is_multicast or ip.is_reserved or ip.is_unspecified:
                return False, f"Destination IP '{ip}' is a reserved, multicast, or unspecified address."

            # Loopback checks
            if ip.is_loopback and not allow_loopback:
                return False, f"Destination IP '{ip}' is a loopback address (SSRF protection)."

            # Private IP checks
            if ip.is_private and not allow_loopback:
                return False, f"Destination IP '{ip}' is a private network address (SSRF protection)."

        except ValueError:
            # Not an IP literal, it's a domain name
            if not allow_loopback and host_lower in ("localhost", "localhost.localdomain", "ip6-localhost", "ip6-loopback"):
                return False, f"Destination '{hostname}' is a loopback hostname (SSRF protection)."

        return True, "Destination is safe"

    except Exception as e:
        return False, f"Failed to validate destination safety: {e}"




class ScopeValidator:
    """Deterministic Scope Validator for Bug Bounty programs.

    Precedence:
    EXPLICIT EXCLUSION > EXPLICIT INCLUSION > WILDCARD INCLUSION > DEFAULT DENY
    """

    def __init__(
        self,
        in_scope_assets: Optional[list[str]] = None,
        out_of_scope_assets: Optional[list[str]] = None,
        allowed_ports: Optional[list[int]] = None,
        excluded_ports: Optional[list[int]] = None,
        allowed_schemes: Optional[list[str]] = None,
        excluded_paths: Optional[list[str]] = None,
        scope_notes: Optional[str] = None,
    ) -> None:
        self.raw_in_scope = in_scope_assets or []
        self.raw_out_of_scope = out_of_scope_assets or []
        self.allowed_ports = set(allowed_ports) if allowed_ports else None
        self.excluded_ports = set(excluded_ports) if excluded_ports else set()
        self.allowed_schemes = set(s.lower() for s in allowed_schemes) if allowed_schemes else {"http", "https"}
        self.excluded_paths = [p.strip() for p in (excluded_paths or []) if p.strip()]
        self.scope_notes = scope_notes or ""

        # Parse normalized in-scope rules
        self._explicit_in_hosts: set[str] = set()
        self._wildcard_in_hosts: list[str] = []
        self._url_in_rules: list[dict[str, Any]] = []

        # Parse normalized out-of-scope rules
        self._explicit_out_hosts: set[str] = set()
        self._wildcard_out_hosts: list[str] = []
        self._url_out_rules: list[dict[str, Any]] = []

        self._parse_rules()

    def _parse_rules(self) -> None:
        """Parse raw scope entries into categorized deterministic matchers."""
        for entry in self.raw_in_scope:
            self._add_rule(entry, is_in_scope=True)

        for entry in self.raw_out_of_scope:
            self._add_rule(entry, is_in_scope=False)

    def add_domain(self, domain: str, is_in_scope: bool = True) -> None:
        """Convenience method to add an in-scope or out-of-scope domain dynamically."""
        self._add_rule(domain, is_in_scope=is_in_scope)

    def _add_rule(self, raw_entry: str, is_in_scope: bool) -> None:
        if not raw_entry or not isinstance(raw_entry, str):
            return
        entry = raw_entry.strip()
        if not entry:
            return

        # Check if entry is a wildcard domain (e.g., *.example.com)
        if entry.startswith("*."):
            base_domain = normalize_domain(entry[2:])
            if base_domain:
                if is_in_scope:
                    self._wildcard_in_hosts.append(base_domain)
                else:
                    self._wildcard_out_hosts.append(base_domain)
            return

        # Check if entry is a URL with path/scheme (e.g., https://api.example.com/v1/*, http://127.0.0.1:8080)
        if entry.startswith("http://") or entry.startswith("https://") or "/" in entry:
            try:
                scheme, host, port, path = normalize_url(entry)
                rule = {
                    "raw": entry,
                    "scheme": scheme,
                    "host": host,
                    "port": port,
                    "path_rule": path,
                }
                if is_in_scope:
                    self._url_in_rules.append(rule)
                    if host.startswith("*."):
                        base = normalize_domain(host[2:])
                        if base:
                            self._wildcard_in_hosts.append(base)
                    elif not (path and path != "/") and port in (80, 443):
                        self._explicit_in_hosts.add(host)
                else:
                    self._url_out_rules.append(rule)
                    if host.startswith("*."):
                        base = normalize_domain(host[2:])
                        if base:
                            self._wildcard_out_hosts.append(base)
                    elif not (path and path != "/") and port in (80, 443):
                        self._explicit_out_hosts.add(host)
                return
            except Exception:
                pass  # Fall back to host-level parsing

        # Standard explicit host / domain
        host = normalize_domain(entry)
        if host:
            if is_in_scope:
                self._explicit_in_hosts.add(host)
            else:
                self._explicit_out_hosts.add(host)


    def is_host_in_scope(self, raw_host: str) -> ScopeDecision:
        """Check whether a hostname/domain is authorized.

        Enforces:
        1. Exact exclusions
        2. Wildcard exclusions
        3. Exact inclusions
        4. Wildcard inclusions
        5. Default deny
        """
        if not raw_host or not isinstance(raw_host, str) or not raw_host.strip():
            return ScopeDecision(
                allowed=False,
                status=ScopeStatus.INVALID,
                reason="Invalid or empty hostname",
                asset=str(raw_host),
            )

        if "*" in raw_host:
            return ScopeDecision(
                allowed=False,
                status=ScopeStatus.INVALID,
                reason="Wildcard scope rules cannot be used as executable assessment targets. Enter a concrete host.",
                asset=raw_host,
            )

        if "@" in raw_host:
            return ScopeDecision(
                allowed=False,
                status=ScopeStatus.INVALID,
                reason="Userinfo / credentials in target hostname are not permitted",
                asset=raw_host,
            )

        host = normalize_domain(raw_host)
        if not host or "*" in host:
            return ScopeDecision(
                allowed=False,
                status=ScopeStatus.INVALID,
                reason="Malformed hostname after normalization",
                asset=raw_host,
            )

        # 1. Check Explicit Out-of-Scope
        if host in self._explicit_out_hosts:
            return ScopeDecision(
                allowed=False,
                status=ScopeStatus.OUT_OF_SCOPE,
                reason=f"Host '{host}' is explicitly marked out-of-scope",
                asset=host,
                matched_rule=host,
            )

        # 2. Check Wildcard Out-of-Scope (e.g. *.internal.example.com)
        for out_wildcard in self._wildcard_out_hosts:
            if self._matches_wildcard(host, out_wildcard):
                return ScopeDecision(
                    allowed=False,
                    status=ScopeStatus.OUT_OF_SCOPE,
                    reason=f"Host '{host}' matches out-of-scope wildcard '*.{out_wildcard}'",
                    asset=host,
                    matched_rule=f"*.{out_wildcard}",
                )

        # 3. Check Explicit In-Scope
        if host in self._explicit_in_hosts:
            return ScopeDecision(
                allowed=True,
                status=ScopeStatus.IN_SCOPE,
                reason=f"Host '{host}' is explicitly in-scope",
                asset=host,
                matched_rule=host,
            )

        # 4. Check Wildcard In-Scope (e.g. *.example.com)
        for in_wildcard in self._wildcard_in_hosts:
            if self._matches_wildcard(host, in_wildcard):
                return ScopeDecision(
                    allowed=True,
                    status=ScopeStatus.IN_SCOPE,
                    reason=f"Host '{host}' matches in-scope wildcard '*.{in_wildcard}'",
                    asset=host,
                    matched_rule=f"*.{in_wildcard}",
                )

        # 5. Default Deny
        return ScopeDecision(
            allowed=False,
            status=ScopeStatus.DENIED_BY_DEFAULT,
            reason=f"Host '{host}' does not match any authorized in-scope rules (Default Deny)",
            asset=host,
        )

    def is_port_in_scope(self, host: str, port: int) -> ScopeDecision:
        """Check whether a port is authorized for scanning."""
        if port in self.excluded_ports:
            return ScopeDecision(
                allowed=False,
                status=ScopeStatus.OUT_OF_SCOPE,
                reason=f"Port {port} is explicitly excluded from scope",
                asset=f"{host}:{port}",
            )

        if self.allowed_ports is not None and port not in self.allowed_ports:
            return ScopeDecision(
                allowed=False,
                status=ScopeStatus.OUT_OF_SCOPE,
                reason=f"Port {port} is not in the allowed ports list",
                asset=f"{host}:{port}",
            )

        return ScopeDecision(
            allowed=True,
            status=ScopeStatus.IN_SCOPE,
            reason=f"Port {port} is permitted",
            asset=f"{host}:{port}",
        )

    def is_url_in_scope(self, raw_url: str) -> ScopeDecision:
        """Evaluate full URL against scope including scheme, host, port, and path rules."""
        if not raw_url or not isinstance(raw_url, str) or not raw_url.strip():
            return ScopeDecision(
                allowed=False,
                status=ScopeStatus.INVALID,
                reason="URL must be a non-empty string",
                asset=str(raw_url),
            )

        try:
            scheme, host, port, path = normalize_url(raw_url)
        except Exception as e:
            return ScopeDecision(
                allowed=False,
                status=ScopeStatus.INVALID,
                reason=f"Malformed or invalid target URL: {e}",
                asset=raw_url,
            )

        if "*" in host:
            return ScopeDecision(
                allowed=False,
                status=ScopeStatus.INVALID,
                reason="Wildcard scope rules cannot be used as executable assessment targets. Enter a concrete host.",
                asset=raw_url,
            )

        # Destination safety check (blocks cloud metadata and link-local SSRF targets)
        is_safe, safety_reason = validate_destination_safety(raw_url, allow_loopback=True)
        if not is_safe:
            return ScopeDecision(
                allowed=False,
                status=ScopeStatus.INVALID,
                reason=f"SSRF destination check failed: {safety_reason}",
                asset=raw_url,
            )

        # 1. Scheme Check
        if scheme not in self.allowed_schemes:
            return ScopeDecision(
                allowed=False,
                status=ScopeStatus.OUT_OF_SCOPE,
                reason=f"Scheme '{scheme}' is not permitted (allowed: {', '.join(sorted(self.allowed_schemes))})",
                asset=raw_url,
            )

        # 2. Port Check
        port_decision = self.is_port_in_scope(host, port)
        if not port_decision.allowed:
            return port_decision

        # 3. Path Exclusions
        for excluded_path in self.excluded_paths:
            if self._matches_path(path, excluded_path):
                return ScopeDecision(
                    allowed=False,
                    status=ScopeStatus.OUT_OF_SCOPE,
                    reason=f"Path '{path}' matches excluded path rule '{excluded_path}'",
                    asset=raw_url,
                    matched_rule=excluded_path,
                )

        # 4. Out-of-Scope URL Rules
        for out_rule in self._url_out_rules:
            rule_port = out_rule.get("port")
            if rule_port is not None and rule_port != port:
                continue

            rule_host = out_rule["host"]
            host_match = False
            if rule_host.startswith("*."):
                host_match = self._matches_wildcard(host, rule_host[2:])
            else:
                host_match = (host == rule_host)

            if host_match and self._matches_path(path, out_rule["path_rule"]):
                return ScopeDecision(
                    allowed=False,
                    status=ScopeStatus.OUT_OF_SCOPE,
                    reason=f"URL matches out-of-scope URL rule '{out_rule['raw']}'",
                    asset=raw_url,
                    matched_rule=out_rule["raw"],
                )

        # 5. In-Scope URL Rules
        for in_rule in self._url_in_rules:
            rule_port = in_rule.get("port")
            if rule_port is not None and rule_port != port:
                continue

            rule_host = in_rule["host"]
            host_match = False
            if rule_host.startswith("*."):
                host_match = self._matches_wildcard(host, rule_host[2:])
            else:
                host_match = (host == rule_host)

            if host_match and self._matches_path(path, in_rule["path_rule"]):
                return ScopeDecision(
                    allowed=True,
                    status=ScopeStatus.IN_SCOPE,
                    reason=f"URL matches in-scope URL rule '{in_rule['raw']}'",
                    asset=raw_url,
                    matched_rule=in_rule["raw"],
                )


        # 6. Host Scope Check
        host_decision = self.is_host_in_scope(host)
        if not host_decision.allowed:
            return host_decision

        return ScopeDecision(
            allowed=True,
            status=ScopeStatus.IN_SCOPE,
            reason=f"Target URL is fully in-scope ({host_decision.reason})",
            asset=raw_url,
            matched_rule=host_decision.matched_rule,
        )

    def is_asset_in_scope(self, asset: str) -> ScopeDecision:
        """Universal dispatcher for any asset (URL, host, or IP)."""
        if not asset or not isinstance(asset, str):
            return ScopeDecision(
                allowed=False,
                status=ScopeStatus.INVALID,
                reason="Asset must be a non-empty string",
                asset=str(asset),
            )

        trimmed = asset.strip()
        if not trimmed:
            return ScopeDecision(
                allowed=False,
                status=ScopeStatus.INVALID,
                reason="Asset must be a non-empty string",
                asset=str(asset),
            )

        if "://" in trimmed or "/" in trimmed:
            return self.is_url_in_scope(trimmed)

        if "*" in trimmed:
            return ScopeDecision(
                allowed=False,
                status=ScopeStatus.INVALID,
                reason="Wildcard scope rules cannot be used as executable assessment targets. Enter a concrete host.",
                asset=trimmed,
            )

        return self.is_host_in_scope(trimmed)

    # Alias for convenience and test compatibility
    validate_url = is_url_in_scope
    validate_url_in_scope = is_url_in_scope

    def validate_request(
        self,
        url: str,
        method: str = "GET",
        port: Optional[int] = None,
    ) -> ScopeDecision:
        """Central validation hook for Phase 2 Request Engine."""
        return self.is_url_in_scope(url)

    def validate_target(self, target: str) -> ScopeDecision:
        """Validate an arbitrary target URL, hostname, or IP against scope."""
        return self.is_asset_in_scope(target)

    @staticmethod
    def _matches_wildcard(host: str, base_domain: str) -> bool:
        """Strict wildcard matcher.

        `*.example.com` matches:
          - `api.example.com`
          - `dev.api.example.com`
        Does NOT match:
          - `example.com` (root domain)
          - `example.com.evil.com`
          - `evil-example.com`
          - `*.example.com` (wildcards in target host are rejected)
        """
        if not host or not base_domain or "*" in host:
            return False

        # Host must strictly end with .base_domain
        suffix = f".{base_domain}"
        if host.endswith(suffix):
            # Ensure host is longer than .base_domain (proper subdomain)
            prefix = host[: -len(suffix)]
            return len(prefix) > 0 and not prefix.endswith(".") and "*" not in prefix

        return False


    @staticmethod
    def _matches_path(target_path: str, rule_path: str) -> bool:
        """Path pattern matcher supporting prefix and wildcards."""
        if not rule_path or not target_path:
            return False

        clean_target = target_path.split("?")[0].split("#")[0]
        clean_rule = rule_path.strip()

        if clean_rule.endswith("*"):
            prefix = clean_rule[:-1].rstrip("/")
            return clean_target.startswith(prefix)

        return clean_target == clean_rule or clean_target.startswith(clean_rule.rstrip("/") + "/")
