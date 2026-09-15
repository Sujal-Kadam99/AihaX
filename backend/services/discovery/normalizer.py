"""Deterministic Asset, Domain, IP, URL, and Query Parameter Normalization Engine.

Zero-network, zero-subprocess deterministic normalization for bug bounty passive asset discovery.
Strictly decoupled from authorization and scope decisions.
"""

from __future__ import annotations

import ipaddress
import posixpath
import re
from enum import Enum
from typing import Optional, Tuple
from urllib.parse import quote_plus, unquote_plus, urlsplit


class AssetType(str, Enum):
    DOMAIN = "DOMAIN"
    SUBDOMAIN = "SUBDOMAIN"
    IP_ADDRESS = "IP_ADDRESS"
    URL = "URL"
    ENDPOINT = "ENDPOINT"


# RFC 1035 / RFC 1123 domain label pattern
# Labels: 1-63 chars, alphanumeric and internal hyphens, case-insensitive
_LABEL_REGEX = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$", re.IGNORECASE)


def normalize_domain(raw_domain: str) -> str:
    """Deterministically normalize domain and subdomain names.

    Rules:
    - Lowercase all characters.
    - Strip URI scheme and userinfo if provided as URL string (has '://').
    - Strip port suffixes if passed as host:port.
    - Remove trailing dot (DNS root zone).
    - Remove leading wildcard (*.example.com -> example.com).
    - Handle IDNs/Punycode deterministically (ASCII punycode representation).
    - Validate RFC 1035 / RFC 1123 syntax rules.
    - Perform zero network/DNS lookups.
    - Raise ValueError on invalid or malformed domain.
    """
    if not raw_domain or not isinstance(raw_domain, str):
        raise ValueError(f"Domain cannot be empty or non-string: {raw_domain!r}")

    cleaned = raw_domain.strip()

    # Reject whitespace or control characters inside domain
    if any(c.isspace() for c in cleaned):
        raise ValueError(f"Domain cannot contain internal whitespace: {raw_domain!r}")

    # 1. If passed as a valid URL (with '://'), extract the hostname component
    if "://" in cleaned:
        try:
            parsed = urlsplit(cleaned)
            cleaned = parsed.hostname or parsed.netloc
        except Exception as err:
            raise ValueError(f"Malformed URL string passed to domain normalizer: {raw_domain!r}") from err

    if not cleaned:
        raise ValueError(f"Domain cannot be empty: {raw_domain!r}")

    # 2. Strip userinfo if present
    if "@" in cleaned:
        cleaned = cleaned.split("@")[-1]

    # 3. Strip port if present (handle both host:port and [ipv6]:port)
    if cleaned.startswith("[") and "]" in cleaned:
        # IPv6 literal
        cleaned = cleaned[1:cleaned.index("]")]
    elif ":" in cleaned:
        cleaned = cleaned.split(":")[0]

    # 4. Strip wildcard prefixes (*. or *)
    if cleaned.startswith("*."):
        cleaned = cleaned[2:]
    elif cleaned.startswith("*"):
        cleaned = cleaned[1:]

    # 5. Strip trailing dot
    cleaned = cleaned.rstrip(".")

    if not cleaned:
        raise ValueError(f"Domain is empty after normalization: {raw_domain!r}")

    # 6. Lowercase
    cleaned = cleaned.lower()

    # 7. Convert IDN (Internationalized Domain Names) to Punycode deterministically
    try:
        cleaned = cleaned.encode("idna").decode("ascii")
    except Exception as err:
        raise ValueError(f"Invalid IDN domain encoding for {raw_domain!r}: {err}") from err

    # 8. Check total domain length (RFC 1035: max 253 characters)
    if len(cleaned) > 253:
        raise ValueError(f"Domain exceeds maximum length of 253 characters: {len(cleaned)} chars")

    # 9. Validate each label (RFC 1035 / 1123)
    labels = cleaned.split(".")
    for label in labels:
        if not label:
            raise ValueError(f"Domain contains empty label (consecutive dots): {raw_domain!r}")
        if len(label) > 63:
            raise ValueError(f"Domain label exceeds maximum length of 63 characters: {label!r}")
        if not _LABEL_REGEX.match(label):
            raise ValueError(f"Domain contains invalid characters or malformed label: {label!r}")

    return cleaned


def normalize_ip(raw_ip: str) -> str:
    """Deterministically normalize IPv4 and IPv6 addresses.

    Rules:
    - IPv4 returned in standard dotted-quad notation (e.g. 192.168.1.1).
    - IPv6 returned in canonical compressed RFC 5952 representation (lowercase).
    - Perform zero network requests or reverse DNS lookups.
    - Raise ValueError on malformed IP address.
    """
    if not raw_ip or not isinstance(raw_ip, str):
        raise ValueError(f"IP address cannot be empty or non-string: {raw_ip!r}")

    cleaned = raw_ip.strip()

    # Strip bracket notation if present (e.g. [::1])
    if cleaned.startswith("[") and cleaned.endswith("]"):
        cleaned = cleaned[1:-1]

    # Strip port if present in IPv4 (e.g. 192.168.1.1:8080)
    if "." in cleaned and ":" in cleaned:
        parts = cleaned.split(":")
        if len(parts) == 2 and parts[1].isdigit():
            cleaned = parts[0]

    try:
        ip_obj = ipaddress.ip_address(cleaned)
    except ValueError as err:
        raise ValueError(f"Malformed IP address: {raw_ip!r}") from err

    # Returns standard string: IPv4 -> '192.168.1.1', IPv6 -> compressed '2001:db8::1'
    return str(ip_obj)


def normalize_query(raw_query: Optional[str]) -> str:
    """Deterministically normalize URL query parameters.

    Rules:
    - Sort keys in ascending alphabetical order.
    - Sort duplicate keys by value ascending to ensure deterministic output.
    - Decode and re-quote properly to prevent double encoding or encoding variations.
    - Preserve empty values where specified (e.g. 'key=').
    - Perform zero network requests.
    """
    if not raw_query:
        return ""

    query = raw_query.strip()
    if query.startswith("?"):
        query = query[1:]

    if not query:
        return ""

    # Split by standard '&' or legacy ';'
    raw_pairs = re.split(r"[&;]", query)
    parsed_pairs: list[Tuple[str, Optional[str], bool]] = []

    for pair in raw_pairs:
        if not pair:
            continue
        has_equal = "=" in pair
        if has_equal:
            key, val = pair.split("=", 1)
            decoded_val = unquote_plus(val).strip()
            encoded_val = quote_plus(decoded_val, safe="-_.~")
        else:
            key = pair
            encoded_val = None

        # Decode safely to canonical string to remove varied URL encodings
        decoded_key = unquote_plus(key).strip()
        encoded_key = quote_plus(decoded_key, safe="-_.~")
        parsed_pairs.append((encoded_key, encoded_val, has_equal))

    # Sort primarily by key ascending, secondarily by value ascending
    parsed_pairs.sort(key=lambda item: (item[0], item[1] or ""))

    return "&".join(f"{k}={v}" if has_eq and v is not None else (f"{k}=" if has_eq else k) for k, v, has_eq in parsed_pairs)


def normalize_url(raw_url: str) -> str:
    """Deterministically normalize full HTTP / HTTPS URLs.

    Rules:
    - Lowercase scheme (http, https).
    - Lowercase hostname.
    - Remove URL userinfo/credentials from canonical identity.
    - Normalize default ports (http:80 -> omit, https:443 -> omit).
    - Preserve explicit non-default ports (e.g. :8080, :8443).
    - Normalize path: resolve dot segments (., ..), collapse duplicate slashes.
    - Preserve trailing slash where meaningful; default empty path to '/'.
    - Strip URL fragment identifiers (#fragment).
    - Sort query parameters deterministically.
    - Zero network requests.
    - Raise ValueError on malformed URL.
    """
    if not raw_url or not isinstance(raw_url, str):
        raise ValueError(f"URL cannot be empty or non-string: {raw_url!r}")

    cleaned = raw_url.strip()

    # Prepend scheme if passed as scheme-relative '//example.com/a'
    if cleaned.startswith("//"):
        cleaned = "https:" + cleaned

    try:
        parsed = urlsplit(cleaned)
    except Exception as err:
        raise ValueError(f"Malformed URL cannot be parsed: {raw_url!r}") from err

    scheme = parsed.scheme.lower()
    if not scheme:
        # Default to https if no scheme provided
        scheme = "https"
        cleaned = f"https://{cleaned}"
        try:
            parsed = urlsplit(cleaned)
        except Exception as err:
            raise ValueError(f"Malformed URL after adding default scheme: {raw_url!r}") from err

    if scheme not in ("http", "https"):
        raise ValueError(f"Unsupported URL scheme '{scheme}': must be http or https")

    netloc = parsed.netloc
    if not netloc:
        raise ValueError(f"URL missing hostname/netloc: {raw_url!r}")

    # 1. Strip userinfo (credentials)
    if "@" in netloc:
        netloc = netloc.split("@")[-1]

    # 2. Extract host and port
    port: Optional[int] = None
    host_str = netloc

    if netloc.startswith("[") and "]" in netloc:
        # IPv6 literal
        bracket_end = netloc.index("]")
        raw_host = netloc[1:bracket_end]
        normalized_host = f"[{normalize_ip(raw_host)}]"
        rest = netloc[bracket_end + 1:]
        if rest.startswith(":"):
            try:
                port = int(rest[1:])
            except ValueError:
                raise ValueError(f"Invalid port in URL: {raw_url!r}")
    elif ":" in netloc:
        parts = netloc.split(":")
        if len(parts) == 2 and parts[1].isdigit():
            raw_host = parts[0]
            port = int(parts[1])
            # Check if host is IPv4 or domain
            try:
                normalized_host = normalize_ip(raw_host)
            except ValueError:
                normalized_host = normalize_domain(raw_host)
        else:
            raise ValueError(f"Invalid host/port in URL: {raw_url!r}")
    else:
        raw_host = netloc
        try:
            normalized_host = normalize_ip(raw_host)
        except ValueError:
            normalized_host = normalize_domain(raw_host)

    # 3. Port Normalization: Strip default ports
    canonical_port_str = ""
    if port is not None:
        if (scheme == "http" and port == 80) or (scheme == "https" and port == 443):
            canonical_port_str = ""
        else:
            if not (1 <= port <= 65535):
                raise ValueError(f"Port out of valid range (1-65535): {port}")
            canonical_port_str = f":{port}"

    # 4. Path Normalization
    raw_path = parsed.path or "/"
    # Collapse multiple consecutive slashes
    collapsed_path = re.sub(r"/+", "/", raw_path)

    # Normalize dot segments with posixpath
    has_trailing_slash = raw_path.endswith("/") and len(raw_path) > 1
    normalized_path = posixpath.normpath(collapsed_path)

    # Ensure leading slash
    if not normalized_path.startswith("/"):
        normalized_path = "/" + normalized_path

    # Preserve trailing slash if originally present and not root
    if has_trailing_slash and not normalized_path.endswith("/"):
        normalized_path += "/"

    # 5. Query Normalization
    normalized_query = normalize_query(parsed.query)
    query_suffix = f"?{normalized_query}" if normalized_query else ""

    # Assembled Canonical URL (fragments are discarded)
    return f"{scheme}://{normalized_host}{canonical_port_str}{normalized_path}{query_suffix}"


def normalize_asset(raw_value: str, explicit_type: Optional[str] = None) -> Tuple[str, str]:
    """Deterministically identify and normalize an asset value.

    Returns:
        (canonical_asset_type, canonical_normalized_value)

    Strictly non-authoritative: Does not check scope or grant authorization.
    """
    if not raw_value or not isinstance(raw_value, str):
        raise ValueError(f"Raw asset value cannot be empty: {raw_value!r}")

    cleaned = raw_value.strip()

    # 1. Explicit Type Handling
    if explicit_type:
        type_upper = explicit_type.upper()
        if type_upper == AssetType.IP_ADDRESS.value:
            return (AssetType.IP_ADDRESS.value, normalize_ip(cleaned))
        elif type_upper in (AssetType.URL.value, AssetType.ENDPOINT.value):
            return (AssetType.URL.value, normalize_url(cleaned))
        elif type_upper in (AssetType.DOMAIN.value, AssetType.SUBDOMAIN.value):
            norm_dom = normalize_domain(cleaned)
            # Differentiate DOMAIN vs SUBDOMAIN based on label depth
            computed_type = AssetType.SUBDOMAIN.value if norm_dom.count(".") >= 2 else AssetType.DOMAIN.value
            return (computed_type, norm_dom)

    # 2. Heuristic Type Inference
    # Check if IPv4 / IPv6
    try:
        norm_ip = normalize_ip(cleaned)
        return (AssetType.IP_ADDRESS.value, norm_ip)
    except ValueError:
        pass

    # Check if URL with explicit scheme or path
    if "://" in cleaned or (cleaned.startswith("/") and len(cleaned) > 1):
        try:
            norm_url = normalize_url(cleaned)
            return (AssetType.URL.value, norm_url)
        except ValueError:
            pass

    # Default to Domain / Subdomain
    norm_domain = normalize_domain(cleaned)
    asset_type = AssetType.SUBDOMAIN.value if norm_domain.count(".") >= 2 else AssetType.DOMAIN.value
    return (asset_type, norm_domain)
