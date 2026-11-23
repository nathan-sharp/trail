"""OWASP ASVS V4 SSRF-safe URL validation and ASVS V5 input validation."""

import ipaddress
import re
import socket
from typing import Callable, List, Optional, Tuple
from urllib.parse import urljoin, urlparse, urlunparse

MAX_URL_LENGTH: int = 2048
MAX_QUERY_LENGTH: int = 200
MAX_QUERY_TOKENS: int = 16
MAX_DNS_RECORDS: int = 16
ALLOWED_SCHEMES: Tuple[str, ...] = ("http", "https")
ALLOWED_PORTS: Tuple[int, ...] = (80, 443)
QUERY_TOKEN_PATTERN = re.compile(r"^[A-Za-z0-9_\-]{1,64}$")

DnsResolver = Callable[[str, int], List[str]]


def default_dns_resolver(hostname: str, port: int) -> List[str]:
    """Resolve hostname to a bounded list of IP address strings."""
    assert isinstance(hostname, str) and len(hostname) > 0, "hostname required"
    assert isinstance(port, int) and 1 <= port <= 65535, "valid port required"
    try:
        infos = socket.getaddrinfo(hostname, port, proto=socket.IPPROTO_TCP)
    except (socket.gaierror, OSError, UnicodeError):
        return []
    addresses: List[str] = []
    upper_bound = min(len(infos), MAX_DNS_RECORDS)
    for idx in range(upper_bound):
        sockaddr = infos[idx][4]
        if sockaddr and isinstance(sockaddr[0], str):
            addresses.append(sockaddr[0])
    return addresses


def is_public_ip_address(ip_text: str) -> bool:
    """Return True if and only if ip_text is a globally routable public IP."""
    assert isinstance(ip_text, str), "ip_text must be a string"
    try:
        clean_text = ip_text.split("%")[0]
        ip_obj = ipaddress.ip_address(clean_text)
    except ValueError:
        return False

    if (
        ip_obj.is_private
        or ip_obj.is_loopback
        or ip_obj.is_link_local
        or ip_obj.is_multicast
        or ip_obj.is_reserved
        or ip_obj.is_unspecified
    ):
        return False
    return bool(ip_obj.is_global)


def normalize_and_validate_url(
    raw_url: str,
    base_url: Optional[str] = None,
    resolver: Optional[DnsResolver] = None,
) -> Tuple[bool, str, str]:
    """Validate URL syntax, scheme, port, and DNS targets against SSRF rules.

    Returns (is_valid, normalized_url_or_error, hostname).
    """
    if not isinstance(raw_url, str):
        return (False, "URL must be a string", "")
    candidate = raw_url.strip()
    if not candidate or len(candidate) > MAX_URL_LENGTH:
        return (False, "URL length out of bounds", "")

    if base_url is not None:
        candidate = urljoin(base_url, candidate)
        if len(candidate) > MAX_URL_LENGTH:
            return (False, "Resolved URL length out of bounds", "")

    try:
        parsed = urlparse(candidate)
    except ValueError:
        return (False, "Malformed URL syntax", "")

    scheme = parsed.scheme.lower()
    if scheme not in ALLOWED_SCHEMES:
        return (False, "Disallowed URL scheme", "")
    if parsed.username or parsed.password:
        return (False, "Credentials in URL are forbidden", "")

    hostname = (parsed.hostname or "").lower().strip(".")
    if not hostname or hostname == "localhost" or hostname.endswith(".local"):
        return (False, "Forbidden local hostname", "")

    try:
        port = parsed.port
    except ValueError:
        return (False, "Invalid URL port", "")

    effective_port = port if port is not None else (443 if scheme == "https" else 80)
    if effective_port not in ALLOWED_PORTS:
        return (False, "Disallowed destination port", "")

    active_resolver = resolver if resolver is not None else default_dns_resolver
    resolved_ips = active_resolver(hostname, effective_port)
    if not resolved_ips:
        return (False, "DNS resolution returned zero addresses", "")

    bound = min(len(resolved_ips), MAX_DNS_RECORDS)
    for idx in range(bound):
        if not is_public_ip_address(resolved_ips[idx]):
            return (False, "SSRF blocked non-public IP address", "")

    raw_path = parsed.path if parsed.path else "/"
    segments = raw_path.split("/")
    resolved_segments: List[str] = []
    seg_bound = min(len(segments), 128)
    for idx in range(seg_bound):
        seg = segments[idx]
        if seg in ("", "."):
            continue
        if seg == "..":
            if resolved_segments:
                resolved_segments.pop()
        else:
            resolved_segments.append(seg)
    trailing_slash = "/" if raw_path.endswith("/") and resolved_segments else ""
    path = "/" + "/".join(resolved_segments) + trailing_slash
    netloc = hostname if port is None or port in (80, 443) else f"{hostname}:{port}"
    normalized = urlunparse((scheme, netloc, path, "", parsed.query, ""))
    return (True, normalized, hostname)


def sanitize_fts5_query(raw_query: str) -> Tuple[bool, str, str]:
    """Validate search input against positive allow-list and build safe FTS5 query.

    Returns (is_valid, sanitized_display_query, fts5_match_expression).
    """
    if not isinstance(raw_query, str):
        return (False, "", "")
    trimmed = raw_query.strip()
    if not trimmed:
        return (True, "", "")
    if len(trimmed) > MAX_QUERY_LENGTH:
        return (False, "", "")

    for idx in range(len(trimmed)):
        code = ord(trimmed[idx])
        if code < 32 or code == 127:
            return (False, "", "")

    raw_words = re.findall(r"[A-Za-z0-9_\-]+", trimmed)
    if not raw_words:
        return (False, "", "")

    safe_tokens: List[str] = []
    upper_bound = min(len(raw_words), MAX_QUERY_TOKENS)
    for idx in range(upper_bound):
        token = raw_words[idx][:64]
        if QUERY_TOKEN_PATTERN.match(token):
            safe_tokens.append(f'"{token}"')

    if not safe_tokens:
        return (False, "", "")

    fts_expr = " AND ".join(safe_tokens)
    return (True, trimmed, fts_expr)
