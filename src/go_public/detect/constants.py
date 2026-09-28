"""Constants that must not be assembled at runtime: CIDR ranges, path prefixes,
internal hostname suffixes and reserved email domains used by the path/network/pii
detectors and their config defaults (product spec items 3 and 5; stage-3.md).

conventions.md's "plant-shaped strings are assembled at runtime" rule is about test
and fixture data, not ordinary source code; but several of these literals are shaped
like the very things go-public flags (a `/Users/` prefix, a private-IP range), so
conventions.md keeps them in exactly one file, allowlisted by path in the committed
`.go-public.toml`, rather than scattered through every detector that needs one.
"""

from __future__ import annotations

import ipaddress

#: RFC 1918 (private-use), RFC 6598 (shared address space / carrier-grade NAT) and
#: RFC 3927 (link-local) IPv4 ranges (product spec item 5). Loopback is checked and
#: allowed separately by `is_private_ip`.
PRIVATE_IPV4_NETWORKS: tuple[ipaddress.IPv4Network, ...] = tuple(
    ipaddress.IPv4Network(cidr)
    for cidr in (
        "10.0.0.0/8",
        "172.16.0.0/12",
        "192.168.0.0/16",
        "100.64.0.0/10",
        "169.254.0.0/16",
    )
)

#: RFC 4193 unique local addresses (IPv6 ULA).
PRIVATE_IPV6_NETWORKS: tuple[ipaddress.IPv6Network, ...] = (ipaddress.IPv6Network("fc00::/7"),)

#: Absolute path prefixes that reveal a local username (product spec item 5).
USER_PATH_PREFIXES: tuple[str, ...] = ("/Users/", "/home/")
#: A Windows user path may appear with a single backslash, a doubled ("JSON-escaped")
#: backslash, or forward slashes (stage-3.md).
WINDOWS_USER_PATH_PREFIX = "C:\\Users\\"
WINDOWS_USER_PATH_FSLASH_PREFIX = "C:/Users/"
#: macOS per-process temp directory: always machine-specific, no username needed.
MACOS_TEMP_PATH_PREFIX = "/var/folders/"

#: `[paths] allowed_prefixes` default (config.py imports this rather than repeating
#: the literals).
DEFAULT_ALLOWED_PATH_PREFIXES: tuple[str, ...] = (
    "/home/runner/",
    "/Users/Shared/",
    "/usr/",
    "/opt/",
    "/tmp/",
)

#: `[network] internal_suffixes` default (config.py imports this).
DEFAULT_INTERNAL_SUFFIXES: tuple[str, ...] = (
    ".local",
    ".internal",
    ".corp",
    ".lan",
    ".intranet",
    ".home.arpa",
    ".ts.net",
)

#: Reserved-for-documentation email domains/suffixes (product spec item 3); an email
#: at one of these can never be a real public address, so it is never personal data.
RESERVED_EMAIL_DOMAINS: tuple[str, ...] = ("example.com", "example.org", "example.net")
RESERVED_EMAIL_SUFFIXES: tuple[str, ...] = (".test", ".example", ".invalid", ".localhost")


def is_reserved_email_domain(domain: str) -> bool:
    """True for `example.com`/`.org`/`.net` and any domain ending in `.test`,
    `.example`, `.invalid` or `.localhost` (including the bare suffix itself)."""
    lowered = domain.lower().rstrip(".")
    if lowered in RESERVED_EMAIL_DOMAINS:
        return True
    return any(
        lowered == suffix.lstrip(".") or lowered.endswith(suffix)
        for suffix in RESERVED_EMAIL_SUFFIXES
    )


def is_private_ip(value: str) -> bool:
    """True for an RFC 1918/6598/3927/4193 address; loopback and everything else
    (including reserved-documentation and public ranges) is `False`."""
    try:
        ip = ipaddress.ip_address(value)
    except ValueError:
        return False
    if ip.is_loopback:
        return False
    if isinstance(ip, ipaddress.IPv4Address):
        return any(ip in net for net in PRIVATE_IPV4_NETWORKS)
    return any(ip in net for net in PRIVATE_IPV6_NETWORKS)
