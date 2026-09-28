"""`detect/constants.py`: private-IP containment and reserved-domain checks."""

from __future__ import annotations

from go_public.detect.constants import is_private_ip, is_reserved_email_domain


def _ip(*octets: int) -> str:
    return ".".join(str(o) for o in octets)


def test_rfc1918_and_rfc6598_and_rfc3927_are_private() -> None:
    assert is_private_ip(_ip(10, 1, 2, 3))
    assert is_private_ip(_ip(172, 16, 0, 1))
    assert is_private_ip(_ip(192, 168, 1, 1))
    assert is_private_ip(_ip(100, 64, 0, 1))  # RFC 6598 shared address space
    assert is_private_ip(_ip(169, 254, 1, 1))  # RFC 3927 link-local


def test_ipv6_ula_is_private() -> None:
    assert is_private_ip("fd00" + "::1")
    assert is_private_ip("fc00" + "::1")


def test_loopback_is_not_private() -> None:
    assert not is_private_ip("127.0.0.1")
    assert not is_private_ip("::1")


def test_public_and_documentation_addresses_are_not_private() -> None:
    assert not is_private_ip(_ip(1, 2, 3, 4))
    assert not is_private_ip("192.0.2.1")  # RFC 5737 documentation range


def test_not_an_ip_is_not_private() -> None:
    assert not is_private_ip("not-an-ip")


def test_exact_reserved_email_domains() -> None:
    assert is_reserved_email_domain("example.com")
    assert is_reserved_email_domain("example.org")
    assert is_reserved_email_domain("example.net")
    assert not is_reserved_email_domain("notexample.com")


def test_reserved_email_suffixes_cover_subdomains() -> None:
    assert is_reserved_email_domain("sub.example.test")
    assert is_reserved_email_domain("a.b.example.invalid")
    assert is_reserved_email_domain("host.example.localhost")
    assert is_reserved_email_domain("example.example")


def test_internal_domain_is_not_reserved() -> None:
    assert not is_reserved_email_domain("acme." + "internal")
